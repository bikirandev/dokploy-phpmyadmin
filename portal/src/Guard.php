<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Access checks used by the request handlers.
 */
final class Guard
{
    public static function user(Ctx $ctx, bool $needsAgreement = true): void
    {
        $resolved = $ctx->auth->resolve($ctx->req->cookie(Auth::COOKIE));
        if ($resolved === null) {
            $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/servers');
            Response::redirect('/signin?next=' . rawurlencode(self::safeNext($uri)), 303);
        }
        $ctx->session = $resolved['session'];
        $ctx->user = $resolved['user'];
        if ($needsAgreement && $ctx->user['agreed_at'] === null) {
            Response::redirect('/welcome', 303);
        }
    }

    public static function csrf(Ctx $ctx): void
    {
        $token = $ctx->req->post('_csrf');
        if ($token === '') {
            $token = (string) $ctx->req->header('X-CSRF-Token');
        }
        if ($ctx->session === null || $token === '' || !hash_equals((string) $ctx->session['csrf'], $token)) {
            throw new HttpException(403, 'This form expired. Go back, reload the page and try again.');
        }
        $origin = $ctx->req->header('Origin');
        if ($origin !== null && $origin !== '' && $origin !== 'null' && $origin !== $ctx->cfg->publicUrl) {
            throw new HttpException(403, 'Cross-site request blocked.');
        }
    }

    public static function admin(Ctx $ctx): void
    {
        if (!$ctx->isAdmin()) {
            throw new HttpException(404, 'Page not found.');
        }
    }

    /**
     * Only same-site paths we know are safe to return to after sign-in.
     */
    public static function safeNext(string $next): string
    {
        if (
            strlen($next) > 2000
            || !str_starts_with($next, '/')
            || str_starts_with($next, '//')
            || str_contains($next, '\\')
            || preg_match('/[\x00-\x1f]/', $next)
        ) {
            return '/servers';
        }
        foreach (['/servers', '/activity', '/admin'] as $prefix) {
            if (str_starts_with($next, $prefix)) {
                return $next;
            }
        }

        return '/servers';
    }
}
