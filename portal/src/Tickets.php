<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * An open phpMyAdmin session ("ticket").
 *
 * The connection details are encrypted with a fresh random key. The portal stores the
 * ciphertext and forgets the key; only the user's browser holds it (cookie "T.K").
 * phpMyAdmin's container combines the two on each request, so a breach of that
 * container cannot read other users' credentials.
 */
final class Tickets
{
    public const COOKIE_PREFIX = '__Host-dbp_s';
    public const MAX_SLOTS = 10;
    private const MAX_LIFETIME = 43200;

    public function __construct(private readonly Db $db)
    {
    }

    /**
     * @param array<string, mixed> $session
     * @param array<string, mixed> $server
     * @param array<string, mixed> $descriptor
     * @return array{0: int, 1: string} the slot (phpMyAdmin server number) and the cookie value "T.K"
     */
    public function issue(array $session, array $server, array $descriptor, int $maxSlots): array
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

        $slot = $this->db->tx(function () use ($sessionHash, $userId, $server, $maxSlots, $now, $idHash, $ciphertext, $nonce, $session): int {
            $mine = $this->db->all(
                'SELECT id_hash, slot, server_id FROM tickets WHERE session_hash = ? AND expires_at > ? ORDER BY last_used_at',
                [$sessionHash, $now],
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
            $this->db->run('DELETE FROM tickets WHERE session_hash = ? AND slot = ?', [$sessionHash, $slot]);

            // Account-wide limit across all devices: close the oldest sessions first.
            $open = $this->db->all('SELECT id_hash FROM tickets WHERE user_id = ? AND expires_at > ? ORDER BY last_used_at', [$userId, $now]);
            while (count($open) >= $maxSlots) {
                $victim = array_shift($open);
                $this->db->run('DELETE FROM tickets WHERE id_hash = ?', [$victim['id_hash']]);
            }

            $this->db->run(
                'INSERT INTO tickets (id_hash, user_id, server_id, session_hash, slot, ciphertext, nonce, created_at, last_used_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [$idHash, $userId, (int) $server['id'], $sessionHash, $slot, new Blob($ciphertext), new Blob($nonce), $now, $now,
                    min((int) $session['expires_at'], $now + self::MAX_LIFETIME)],
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

    /**
     * The user behind a ticket cookie, if the ticket, its portal session and the user are all still valid.
     * Also keeps the portal session alive while the user works in phpMyAdmin.
     */
    public function activeUser(string $idHash): ?int
    {
        $now = time();
        $row = $this->db->one(
            'SELECT t.user_id, t.session_hash, s.last_seen_at FROM tickets t
             JOIN sessions s ON s.id_hash = t.session_hash
             JOIN users u ON u.id = t.user_id
             WHERE t.id_hash = ? AND t.expires_at > ? AND s.expires_at > ? AND s.last_seen_at > ?
               AND u.suspended_at IS NULL AND u.agreed_at IS NOT NULL',
            [$idHash, $now, $now, $now - Auth::IDLE_SECONDS],
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
     * Encrypted connection details for phpMyAdmin, only for the asserting user's live tickets.
     *
     * @param array<int, string> $tickets base64url ticket ids by slot
     * @return list<array{slot: int, c: string, n: string}>
     */
    public function fetch(int $userId, array $tickets): array
    {
        $now = time();
        $out = [];
        foreach ($tickets as $slot => $encoded) {
            $raw = Crypto::b64d($encoded);
            if (strlen($raw) !== 32) {
                continue;
            }
            $row = $this->db->one(
                'SELECT t.*, s.expires_at AS session_expires, s.last_seen_at AS session_seen
                 FROM tickets t JOIN sessions s ON s.id_hash = t.session_hash
                 WHERE t.id_hash = ?',
                [hash('sha256', $raw)],
            );
            if (
                $row === null
                || (int) $row['user_id'] !== $userId
                || (int) $row['slot'] !== (int) $slot
                || (int) $row['expires_at'] <= $now
                || (int) $row['session_expires'] <= $now
                || (int) $row['session_seen'] + Auth::IDLE_SECONDS <= $now
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

    public function cleanup(): void
    {
        $this->db->run('DELETE FROM tickets WHERE expires_at <= ?', [time()]);
    }
}
