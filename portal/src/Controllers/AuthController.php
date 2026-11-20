<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Auth;
use DbPortal\Crypto;
use DbPortal\Ctx;
use DbPortal\Guard;
use DbPortal\HttpException;
use DbPortal\Response;
use Throwable;

/**
 * Sign-in with the identity provider, the one-time rules screen, sign-out and emergency access.
 */
final class AuthController
{
    private const AUTH_COOKIE = '__Host-dbp_auth';

    public static function home(Ctx $ctx): never
    {
        $signedIn = $ctx->auth->resolve($ctx->req->cookie(Auth::COOKIE), false) !== null;
        Response::redirect($signedIn ? '/servers' : '/signin', 303);
    }

    public static function health(Ctx $ctx): never
    {
        $ctx->db->scalar('SELECT 1');
        Response::text("ok\n");
    }

    public static function signin(Ctx $ctx): never
    {
        $next = Guard::safeNext($ctx->req->query('next', '/servers'));
        $resolved = $ctx->auth->resolve($ctx->req->cookie(Auth::COOKIE), false);
        if ($resolved !== null && $resolved['user']['agreed_at'] !== null) {
            Response::redirect($next, 303);
        }
        $notice = match ($ctx->req->query('notice')) {
            'signed-out' => 'You signed out.',
            default => '',
        };
        $ctx->render('signin', ['next' => $next, 'notice' => $notice, 'error' => '', 'suspended' => false], 200, 'bare');
    }

    public static function login(Ctx $ctx): never
    {
        self::limitSignins($ctx);
        $state = Crypto::randomToken(32);
        $nonce = Crypto::randomToken(32);
        $verifier = Crypto::randomToken(48);
        $challenge = Crypto::b64e(hash('sha256', $verifier, true));
        $next = Guard::safeNext($ctx->req->query('next', '/servers'));

        try {
            $url = $ctx->oidc->authorizationUrl($state, $nonce, $challenge, $ctx->req->query('select') === '1');
        } catch (Throwable $e) {
            error_log('[dbportal] OIDC discovery failed: ' . $e->getMessage());
            self::signinError($ctx, $ctx->cfg->providerName . ' sign-in is not reachable right now. Please try again in a minute.', 503);
        }

        $ctx->db->run(
            'INSERT INTO auth_requests (state_hash, nonce, verifier, next, created_at) VALUES (?, ?, ?, ?, ?)',
            [hash('sha256', $state), $nonce, $verifier, $next, time()],
        );
        Auth::setCookie(self::AUTH_COOKIE, $state, 'Lax', time() + 600);
        Response::redirect($url, 302);
    }

    public static function callback(Ctx $ctx): never
    {
        self::limitSignins($ctx);
        $provider = $ctx->cfg->providerName;
        $state = $ctx->req->query('state');
        $cookie = $ctx->req->cookie(self::AUTH_COOKIE);
        Auth::clearCookie(self::AUTH_COOKIE, 'Lax');

        if ($ctx->req->query('error') !== '') {
            self::signinError($ctx, "Sign-in was cancelled or failed at $provider.", 400);
        }
        if ($state === '' || $cookie === null || !hash_equals($cookie, $state)) {
            self::signinError($ctx, 'Your sign-in expired. Please try again.', 400);
        }
        $request = $ctx->db->one('SELECT * FROM auth_requests WHERE state_hash = ?', [hash('sha256', $state)]);
        $ctx->db->run('DELETE FROM auth_requests WHERE state_hash = ?', [hash('sha256', $state)]);
        if ($request === null || (int) $request['created_at'] < time() - 600) {
            self::signinError($ctx, 'Your sign-in expired. Please try again.', 400);
        }
        $iss = $ctx->req->query('iss');
        if ($iss !== '' && rtrim($iss, '/') !== $ctx->cfg->oidcIssuer) {
            self::signinError($ctx, 'The sign-in response came from an unexpected provider.', 400);
        }

        try {
            $claims = $ctx->oidc->finish($ctx->req->query('code'), (string) $request['verifier'], (string) $request['nonce']);
        } catch (Throwable $e) {
            error_log('[dbportal] OIDC sign-in failed: ' . $e->getMessage());
            $ctx->events->log(null, 'problem', 'Sign-in failed', "Login response from $provider could not be verified", 'failed', $ctx->req->ip());
            self::signinError($ctx, "We couldn't verify the sign-in from $provider. Please try again.", 400);
        }

        if ($ctx->cfg->oidcRequiredAmr !== []) {
            $amr = is_array($claims['amr'] ?? null) ? $claims['amr'] : [];
            if (array_intersect($ctx->cfg->oidcRequiredAmr, $amr) === []) {
                self::signinError($ctx, "Turn on 2-step verification for your $provider account, then sign in again.", 403);
            }
        }
        if ($ctx->cfg->oidcRequireEmailVerified && ($claims['email_verified'] ?? false) !== true) {
            self::signinError($ctx, "Verify your email address with $provider, then sign in again.", 403);
        }

        $subject = $claims[$ctx->cfg->oidcUserIdClaim] ?? null;
        if (is_int($subject)) {
            $subject = (string) $subject;
        }
        if (!is_string($subject) || $subject === '' || strlen($subject) > 255) {
            self::signinError($ctx, "Your $provider account did not provide a user ID.", 400);
        }
        $email = is_string($claims[$ctx->cfg->oidcEmailClaim] ?? null) ? mb_substr($claims[$ctx->cfg->oidcEmailClaim], 0, 255) : '';
        $nameClaim = $claims[$ctx->cfg->oidcNameClaim] ?? ($claims['preferred_username'] ?? '');
        $name = is_string($nameClaim) ? mb_substr($nameClaim, 0, 120) : '';

        $now = time();
        $ctx->db->run(
            'INSERT INTO users (subject, email, name, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(subject) DO UPDATE SET email = excluded.email, name = excluded.name',
            [$subject, $email, $name, $now],
        );
        $user = $ctx->db->one('SELECT * FROM users WHERE subject = ?', [$subject]);
        if ($user === null) {
            throw new HttpException(500, 'Could not create your account.');
        }
        if ($user['suspended_at'] !== null) {
            $ctx->events->log((int) $user['id'], 'problem', 'Sign-in blocked', 'Account is suspended', 'denied', $ctx->req->ip());
            $ctx->render('signin', ['next' => '/servers', 'notice' => '', 'error' => '', 'suspended' => true], 403, 'bare');
        }

        $ctx->auth->start((int) $user['id'], 'oidc', $ctx->req->ip(), $ctx->req->userAgent());
        $ctx->db->run('UPDATE users SET last_login_at = ? WHERE id = ?', [$now, (int) $user['id']]);
        $ctx->events->log((int) $user['id'], 'signin', "Signed in with $provider", self::device($ctx->req->userAgent()), 'ok', $ctx->req->ip());

        Response::redirect($user['agreed_at'] === null ? '/welcome' : Guard::safeNext((string) $request['next']), 303);
    }

    public static function logout(Ctx $ctx): never
    {
        Guard::user($ctx, false);
        Guard::csrf($ctx);
        $ctx->log('signin', 'Signed out', '');
        // Ending the session also ends every phpMyAdmin session opened from it.
        $ctx->auth->end($ctx->req->cookie(Auth::COOKIE));
        Response::redirect('/signin?notice=signed-out', 303);
    }

    public static function welcome(Ctx $ctx): never
    {
        Guard::user($ctx, false);
        if ($ctx->user['agreed_at'] !== null) {
            Response::redirect('/servers', 303);
        }
        $ctx->render('welcome', ['error' => ''], 200, 'bare');
    }

    public static function agree(Ctx $ctx): never
    {
        Guard::user($ctx, false);
        Guard::csrf($ctx);
        if ($ctx->req->post('agree') !== '1') {
            $ctx->render('welcome', ['error' => 'Tick the box to agree to the rules.'], 422, 'bare');
        }
        $ctx->db->run('UPDATE users SET agreed_at = ? WHERE id = ? AND agreed_at IS NULL', [time(), (int) $ctx->user['id']]);
        $ctx->log('change', 'Accepted the usage rules', '');
        Response::redirect('/servers', 303);
    }

    /** @param list<string> $params */
    public static function emergencyForm(Ctx $ctx, array $params): never
    {
        $row = self::emergencyToken($ctx, $params[0]);
        if ($row === null) {
            self::signinError($ctx, 'This emergency link is invalid, used or expired. Create a new one on the server.', 404);
        }
        $ctx->render('emergency', ['token' => $params[0]], 200, 'bare');
    }

    /** @param list<string> $params */
    public static function emergencyUse(Ctx $ctx, array $params): never
    {
        $hash = hash('sha256', $params[0]);
        $used = $ctx->db->run(
            'UPDATE emergency_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?',
            [time(), $hash, time()],
        );
        $row = $ctx->db->one('SELECT user_id FROM emergency_tokens WHERE token_hash = ?', [$hash]);
        $user = $row !== null ? $ctx->db->one('SELECT * FROM users WHERE id = ?', [(int) $row['user_id']]) : null;
        if ($used !== 1 || $user === null || $user['suspended_at'] !== null || !in_array($user['subject'], $ctx->cfg->adminSubjects, true)) {
            self::signinError($ctx, 'This emergency link is invalid, used or expired. Create a new one on the server.', 404);
        }
        $ctx->auth->start((int) $user['id'], 'emergency', $ctx->req->ip(), $ctx->req->userAgent());
        $ctx->events->log((int) $user['id'], 'signin', 'Emergency sign-in', 'One-time link created on the server', 'ok', $ctx->req->ip());
        Response::redirect($user['agreed_at'] === null ? '/welcome' : '/servers', 303);
    }

    /** @return array<string, mixed>|null */
    private static function emergencyToken(Ctx $ctx, string $token): ?array
    {
        return $ctx->db->one(
            'SELECT * FROM emergency_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?',
            [hash('sha256', $token), time()],
        );
    }

    private static function limitSignins(Ctx $ctx): void
    {
        $limit = $ctx->settings->get('signins_per_ip_minute');
        if (!$ctx->limiter->hit('signin:' . $ctx->req->ip(), $limit, 60)) {
            self::signinError($ctx, 'Too many sign-in attempts from your network. Wait a minute and try again.', 429);
        }
    }

    private static function signinError(Ctx $ctx, string $message, int $status): never
    {
        $ctx->render('signin', ['next' => '/servers', 'notice' => '', 'error' => $message, 'suspended' => false], $status, 'bare');
    }

    public static function device(string $userAgent): string
    {
        $browser = match (true) {
            str_contains($userAgent, 'Edg/') => 'Edge',
            str_contains($userAgent, 'OPR/') => 'Opera',
            str_contains($userAgent, 'Firefox/') => 'Firefox',
            str_contains($userAgent, 'Chrome/') => 'Chrome',
            str_contains($userAgent, 'Safari/') => 'Safari',
            default => 'Browser',
        };
        $os = match (true) {
            str_contains($userAgent, 'Windows') => 'Windows',
            str_contains($userAgent, 'Android') => 'Android',
            str_contains($userAgent, 'iPhone'), str_contains($userAgent, 'iPad') => 'iOS',
            str_contains($userAgent, 'Mac OS') => 'macOS',
            str_contains($userAgent, 'Linux') => 'Linux',
            default => 'unknown system',
        };

        return "$browser on $os";
    }
}
