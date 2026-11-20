<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Portal sign-in sessions, stored server-side. The cookie holds a random token;
 * the database keeps only its SHA-256 hash.
 */
final class Auth
{
    public const COOKIE = '__Host-dbp_session';
    public const IDLE_SECONDS = 1800;      // signed out after 30 minutes without activity
    public const ABSOLUTE_SECONDS = 43200; // and after 12 hours at most

    public function __construct(private readonly Db $db)
    {
    }

    /**
     * @return array{session: array<string, mixed>, user: array<string, mixed>}|null
     */
    public function resolve(?string $cookie, bool $touch = true): ?array
    {
        if ($cookie === null || strlen($cookie) < 40 || strlen($cookie) > 64) {
            return null;
        }
        $hash = hash('sha256', $cookie);
        $session = $this->db->one('SELECT * FROM sessions WHERE id_hash = ?', [$hash]);
        if ($session === null) {
            return null;
        }
        $now = time();
        if ((int) $session['expires_at'] <= $now || (int) $session['last_seen_at'] + self::IDLE_SECONDS <= $now) {
            $this->destroy($hash);

            return null;
        }
        $user = $this->db->one('SELECT * FROM users WHERE id = ?', [(int) $session['user_id']]);
        if ($user === null || $user['suspended_at'] !== null) {
            $this->destroy($hash);

            return null;
        }
        if ($touch && (int) $session['last_seen_at'] + 60 <= $now) {
            $this->db->run('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?', [$now, $hash]);
        }

        return ['session' => $session, 'user' => $user];
    }

    public function start(int $userId, string $via, string $ip, string $userAgent): void
    {
        $token = Crypto::randomToken(32);
        $now = time();
        $this->db->run(
            'INSERT INTO sessions (id_hash, user_id, csrf, via, ip, user_agent, created_at, last_seen_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [hash('sha256', $token), $userId, Crypto::randomToken(32), $via, $ip, $userAgent, $now, $now, $now + self::ABSOLUTE_SECONDS],
        );
        self::setCookie(self::COOKIE, $token, 'Lax');
    }

    public function end(?string $cookie): void
    {
        if ($cookie !== null && $cookie !== '') {
            $this->destroy(hash('sha256', $cookie));
        }
        self::clearCookie(self::COOKIE, 'Lax');
    }

    public function endAllForUser(int $userId): void
    {
        $this->db->run('DELETE FROM tickets WHERE user_id = ?', [$userId]);
        $this->db->run('DELETE FROM sessions WHERE user_id = ?', [$userId]);
    }

    private function destroy(string $hash): void
    {
        $this->db->run('DELETE FROM tickets WHERE session_hash = ?', [$hash]);
        $this->db->run('DELETE FROM sessions WHERE id_hash = ?', [$hash]);
    }

    public static function setCookie(string $name, string $value, string $sameSite, int $expires = 0): void
    {
        setcookie($name, $value, [
            'expires' => $expires,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => $sameSite,
        ]);
    }

    public static function clearCookie(string $name, string $sameSite): void
    {
        self::setCookie($name, '', $sameSite, 1);
    }
}
