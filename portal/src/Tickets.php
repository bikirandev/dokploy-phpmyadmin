<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * An open phpMyAdmin ("pma") or pgAdmin ("pga") session: a "ticket".
 *
 * The connection details are encrypted with a fresh random key. The portal stores the
 * ciphertext and forgets the key; only the user's browser holds it (cookie "T.K", set on the
 * tool's own host name). The tool's container combines the two on each request, so a breach of
 * that container cannot read other users' credentials.
 */
final class Tickets
{
    public const COOKIE_PREFIX = '__Host-dbp_s';
    public const PGA_COOKIE_PREFIX = '__Host-dbp_g';
    public const MAX_SLOTS = 10;
    public const APPS = ['pma', 'pga'];
    private const MAX_LIFETIME = 43200;

    public function __construct(private readonly Db $db)
    {
    }

    public static function cookiePrefix(string $app): string
    {
        return $app === 'pga' ? self::PGA_COOKIE_PREFIX : self::COOKIE_PREFIX;
    }

    /**
     * pgAdmin lists one entry per server and database user; this names it, the same way in every
     * browser the user opens the server from.
     */
    public static function pgaRow(string $serverUid, string $dbUser): string
    {
        return substr(hash('sha256', 'dbportal/pga-row|' . $serverUid . '|' . $dbUser), 0, 40);
    }

    /**
     * @param array<string, mixed> $session
     * @param array<string, mixed> $server
     * @param array<string, mixed> $descriptor
     * @return array{0: int, 1: string} the slot (phpMyAdmin server number) and the cookie value "T.K"
     */
    public function issue(array $session, array $server, array $descriptor, int $maxSlots, string $app = 'pma'): array
    {
        $maxSlots = max(1, min(self::MAX_SLOTS, $maxSlots));
        $sessionHash = (string) $session['id_hash'];
        $userId = (int) $session['user_id'];
        $now = time();

        $ticket = random_bytes(32);
        $key = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $idHash = hash('sha256', $ticket);
        $descriptor['key'] = $idHash;
        [$ciphertext, $nonce] = Crypto::sealWithKey(
            $key,
            json_encode($descriptor, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'dbportal/ticket/' . $idHash,
        );

        $dbUser = (string) ($descriptor['user'] ?? '');
        $slot = $this->db->tx(function () use ($sessionHash, $userId, $server, $maxSlots, $now, $idHash, $ciphertext, $nonce, $session, $app, $dbUser): int {
            $mine = $this->db->all(
                'SELECT id_hash, slot, server_id FROM tickets WHERE session_hash = ? AND app = ? AND expires_at > ? ORDER BY last_used_at',
                [$sessionHash, $app, $now],
            );
            $slot = null;
            foreach ($mine as $row) {
                if ((int) $row['server_id'] === (int) $server['id']) {
                    $slot = (int) $row['slot'];
                }
            }
            if ($slot === null) {
                $used = array_map('intval', array_column($mine, 'slot'));
                for ($i = 1; $i <= $maxSlots; $i++) {
                    if (!in_array($i, $used, true)) {
                        $slot = $i;
                        break;
                    }
                }
            }
            $slot ??= (int) $mine[0]['slot']; // all slots busy: replace the least recently used
            $this->db->run('DELETE FROM tickets WHERE session_hash = ? AND app = ? AND slot = ?', [$sessionHash, $app, $slot]);

            // Account-wide limit across all devices (for each tool): close the oldest sessions first.
            $open = $this->db->all(
                'SELECT id_hash FROM tickets WHERE user_id = ? AND app = ? AND expires_at > ? ORDER BY last_used_at',
                [$userId, $app, $now],
            );
            while (count($open) >= $maxSlots) {
                $victim = array_shift($open);
                $this->db->run('DELETE FROM tickets WHERE id_hash = ?', [$victim['id_hash']]);
            }

            $this->db->run(
                'INSERT INTO tickets (id_hash, user_id, server_id, session_hash, slot, app, db_user, ciphertext, nonce,
                    created_at, last_used_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [$idHash, $userId, (int) $server['id'], $sessionHash, $slot, $app, $dbUser, new Blob($ciphertext),
                    new Blob($nonce), $now, $now, min((int) $session['expires_at'], $now + self::MAX_LIFETIME)],
            );

            return $slot;
        });

        $cookie = Crypto::b64e($ticket) . '.' . Crypto::b64e($key);
        sodium_memzero($key);

        return [$slot, $cookie];
    }

    /**
     * The ticket id hash from a cookie value "T.K", or null.
     */
    public static function idHashFromCookie(?string $cookie): ?string
    {
        if ($cookie === null) {
            return null;
        }
        $raw = Crypto::b64d(explode('.', $cookie, 2)[0]);

        return strlen($raw) === 32 ? hash('sha256', $raw) : null;
    }

    public function revoke(string $idHash): void
    {
        $this->db->run('DELETE FROM tickets WHERE id_hash = ?', [$idHash]);
    }

    public function revokeForServer(int $serverId): void
    {
        $this->db->run('DELETE FROM tickets WHERE server_id = ?', [$serverId]);
    }

    /** Closes every open session of servers that use this connection method. Returns how many. */
    public function revokeForMethod(string $method): int
    {
        return $this->db->run('DELETE FROM tickets WHERE server_id IN (SELECT id FROM servers WHERE method = ?)', [$method]);
    }

    /**
     * The user behind a ticket cookie, if the ticket, its portal session and the user are all still valid.
     * Also keeps the portal session alive while the user works in phpMyAdmin or pgAdmin.
     */
    public function activeUser(string $idHash, string $app = 'pma'): ?int
    {
        $now = time();
        $row = $this->db->one(
            'SELECT t.user_id, t.session_hash, s.last_seen_at FROM tickets t
             JOIN sessions s ON s.id_hash = t.session_hash
             JOIN users u ON u.id = t.user_id
             WHERE t.id_hash = ? AND t.app = ? AND t.expires_at > ? AND s.expires_at > ? AND s.last_seen_at > ?
               AND u.suspended_at IS NULL AND u.agreed_at IS NOT NULL',
            [$idHash, $app, $now, $now, $now - Auth::IDLE_SECONDS],
        );
        if ($row === null) {
            return null;
        }
        if ((int) $row['last_seen_at'] + 60 <= $now) {
            $this->db->run('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?', [$now, $row['session_hash']]);
        }

        return (int) $row['user_id'];
    }

    /**
     * Encrypted connection details for the tool, only for the asserting user's live tickets.
     *
     * @param array<int, string> $tickets base64url ticket ids by slot
     * @param bool $allowPlain false when an admin turned off unencrypted connections
     * @return list<array{slot: int, c: string, n: string}>
     */
    public function fetch(int $userId, array $tickets, string $app = 'pma', bool $allowPlain = true): array
    {
        $now = time();
        $out = [];
        foreach ($tickets as $slot => $encoded) {
            $raw = Crypto::b64d($encoded);
            if (strlen($raw) !== 32) {
                continue;
            }
            $row = $this->db->one(
                'SELECT t.*, s.expires_at AS session_expires, s.last_seen_at AS session_seen, sv.method AS server_method
                 FROM tickets t JOIN sessions s ON s.id_hash = t.session_hash
                 JOIN servers sv ON sv.id = t.server_id
                 WHERE t.id_hash = ?',
                [hash('sha256', $raw)],
            );
            if (
                $row === null
                || (int) $row['user_id'] !== $userId
                || (string) $row['app'] !== $app
                || (int) $row['slot'] !== (int) $slot
                || (int) $row['expires_at'] <= $now
                || (int) $row['session_expires'] <= $now
                || (int) $row['session_seen'] + Auth::IDLE_SECONDS <= $now
                || (!$allowPlain && $row['server_method'] === 'plain')
            ) {
                continue;
            }
            if ((int) $row['last_used_at'] + 60 <= $now) {
                $this->db->run('UPDATE tickets SET last_used_at = ? WHERE id_hash = ?', [$now, $row['id_hash']]);
            }
            $out[] = [
                'slot' => (int) $slot,
                'c' => Crypto::b64e((string) $row['ciphertext']),
                'n' => Crypto::b64e((string) $row['nonce']),
            ];
        }

        return $out;
    }

    /**
     * pgAdmin entries the user has open in any browser (live tickets), named as by pgaRow().
     *
     * @return list<string>
     */
    public function openPgaRows(int $userId, bool $allowPlain = true): array
    {
        $now = time();
        $rows = $this->db->all(
            'SELECT DISTINCT sv.uid, t.db_user FROM tickets t
             JOIN sessions s ON s.id_hash = t.session_hash
             JOIN servers sv ON sv.id = t.server_id
             WHERE t.user_id = ? AND t.app = \'pga\' AND t.expires_at > ? AND s.expires_at > ? AND s.last_seen_at > ?
               AND (? = 1 OR sv.method <> \'plain\')',
            [$userId, $now, $now, $now - Auth::IDLE_SECONDS, $allowPlain ? 1 : 0],
        );

        return array_values(array_unique(array_map(
            static fn (array $r): string => self::pgaRow((string) $r['uid'], (string) $r['db_user']),
            $rows,
        )));
    }

    /**
     * Which of these tickets (by id hash) are still usable. Never extends a session.
     *
     * @param list<string> $idHashes
     * @return list<string>
     */
    public function alive(array $idHashes, string $app, bool $allowPlain = true): array
    {
        if ($idHashes === []) {
            return [];
        }
        $now = time();
        $marks = implode(',', array_fill(0, count($idHashes), '?'));
        $rows = $this->db->all(
            "SELECT t.id_hash FROM tickets t
             JOIN sessions s ON s.id_hash = t.session_hash
             JOIN users u ON u.id = t.user_id
             JOIN servers sv ON sv.id = t.server_id
             WHERE t.id_hash IN ($marks) AND t.app = ? AND t.expires_at > ? AND s.expires_at > ? AND s.last_seen_at > ?
               AND u.suspended_at IS NULL AND (? = 1 OR sv.method <> 'plain')",
            [...$idHashes, $app, $now, $now, $now - Auth::IDLE_SECONDS, $allowPlain ? 1 : 0],
        );

        return array_map(static fn (array $r): string => (string) $r['id_hash'], $rows);
    }

    public function cleanup(): void
    {
        $this->db->run('DELETE FROM tickets WHERE expires_at <= ?', [time()]);
    }
}
