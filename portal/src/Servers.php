<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Each account's database servers. Every query is scoped to the owner.
 */
final class Servers
{
    public const ENVIRONMENTS = ['Production', 'Staging', 'Development'];
    public const METHODS = ['internal', 'tls', 'pinned', 'ssh'];

    /** Database engines: MySQL / MariaDB open in phpMyAdmin, PostgreSQL in pgAdmin. */
    public const MYSQL = 'mysql';
    public const POSTGRES = 'postgres';

    /** The all-powerful account each engine refuses outright. */
    public static function blockedUser(string $kind): string
    {
        return $kind === self::POSTGRES ? 'postgres' : 'root';
    }

    public static function defaultPort(string $kind): int
    {
        return $kind === self::POSTGRES ? 5432 : 3306;
    }

    /** The tool (and its host name) that opens servers of this kind. */
    public static function app(string $kind): string
    {
        return $kind === self::POSTGRES ? 'pga' : 'pma';
    }

    public static function appName(string $kind): string
    {
        return $kind === self::POSTGRES ? 'pgAdmin' : 'phpMyAdmin';
    }

    public function __construct(private readonly Db $db, private readonly Crypto $crypto)
    {
    }

    /** @return list<array<string, mixed>> */
    public function listForUser(int $userId): array
    {
        return $this->db->all(
            'SELECT * FROM servers WHERE user_id = ? ORDER BY location = \'remote\', name COLLATE NOCASE',
            [$userId],
        );
    }

    public function countForUser(int $userId): int
    {
        return (int) $this->db->scalar('SELECT COUNT(*) FROM servers WHERE user_id = ?', [$userId]);
    }

    /** @return array<string, mixed>|null */
    public function find(int $userId, int $id): ?array
    {
        return $this->db->one('SELECT * FROM servers WHERE id = ? AND user_id = ?', [$id, $userId]);
    }

    /** @return array{db_password: string, ssh_secret: string} */
    public function secrets(array $server): array
    {
        $empty = ['db_password' => '', 'ssh_secret' => ''];
        if ($server['secret'] === null || $server['secret'] === '') {
            return $empty;
        }
        $json = $this->crypto->open(
            (string) $server['secret'],
            (string) $server['secret_nonce'],
            self::associatedData((string) $server['uid'], (int) $server['user_id']),
        );
        $data = json_decode($json, true);

        return [
            'db_password' => (string) ($data['db_password'] ?? ''),
            'ssh_secret' => (string) ($data['ssh_secret'] ?? ''),
        ];
    }

    /**
     * @param array<string, mixed> $data
     * @param array{db_password: string, ssh_secret: string} $secrets
     */
    public function create(int $userId, array $data, array $secrets): int
    {
        $uid = bin2hex(random_bytes(16));
        [$secret, $nonce] = $this->sealSecrets($uid, $userId, $secrets);
        $now = time();

        return $this->db->insert(
            'INSERT INTO servers (uid, user_id, name, environment, kind, location, method, host, port, db_user, db_name,
                cred_mode, secret, secret_nonce, ca_pem, pin_sha256, pin_pem, pin_strict, ssh_host, ssh_port, ssh_user,
                ssh_auth, ssh_hostkey, ssh_fingerprint, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $uid, $userId, $data['name'], $data['environment'], $data['kind'], $data['location'], $data['method'],
                $data['host'], (int) $data['port'], $data['db_user'], $data['db_name'], $data['cred_mode'],
                $secret, $nonce, $data['ca_pem'], $data['pin_sha256'], $data['pin_pem'], (int) $data['pin_strict'],
                $data['ssh_host'], (int) $data['ssh_port'], $data['ssh_user'], $data['ssh_auth'],
                $data['ssh_hostkey'], $data['ssh_fingerprint'], $now, $now,
            ],
        );
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $data
     * @param array{db_password: string, ssh_secret: string} $secrets the complete secrets to store
     */
    public function update(array $server, array $data, array $secrets): void
    {
        [$secret, $nonce] = $this->sealSecrets((string) $server['uid'], (int) $server['user_id'], $secrets);
        $this->db->run(
            'UPDATE servers SET name = ?, environment = ?, kind = ?, location = ?, method = ?, host = ?, port = ?,
                db_user = ?, db_name = ?, cred_mode = ?, secret = ?, secret_nonce = ?, ca_pem = ?, pin_sha256 = ?,
                pin_pem = ?, pin_strict = ?, ssh_host = ?, ssh_port = ?, ssh_user = ?, ssh_auth = ?, ssh_hostkey = ?,
                ssh_fingerprint = ?, engine = CASE WHEN kind = ? THEN engine ELSE \'\' END, updated_at = ?
             WHERE id = ? AND user_id = ?',
            [
                $data['name'], $data['environment'], $data['kind'], $data['location'], $data['method'], $data['host'],
                (int) $data['port'], $data['db_user'], $data['db_name'], $data['cred_mode'], $secret, $nonce,
                $data['ca_pem'], $data['pin_sha256'], $data['pin_pem'], (int) $data['pin_strict'], $data['ssh_host'],
                (int) $data['ssh_port'], $data['ssh_user'], $data['ssh_auth'], $data['ssh_hostkey'],
                $data['ssh_fingerprint'], $data['kind'], time(), (int) $server['id'], (int) $server['user_id'],
            ],
        );
    }

    public function delete(array $server): void
    {
        $this->db->run('DELETE FROM servers WHERE id = ? AND user_id = ?', [(int) $server['id'], (int) $server['user_id']]);
    }

    public function markOpened(int $id, string $engine): void
    {
        $this->db->run('UPDATE servers SET last_opened_at = ?, engine = CASE WHEN ? <> \'\' THEN ? ELSE engine END WHERE id = ?', [time(), $engine, $engine, $id]);
    }

    public function setEngine(int $id, string $engine): void
    {
        if ($engine !== '') {
            $this->db->run('UPDATE servers SET engine = ? WHERE id = ?', [$engine, $id]);
        }
    }

    /**
     * @param array{db_password: string, ssh_secret: string} $secrets
     * @return array{0: Blob|null, 1: Blob|null}
     */
    private function sealSecrets(string $uid, int $userId, array $secrets): array
    {
        $payload = array_filter([
            'db_password' => $secrets['db_password'],
            'ssh_secret' => $secrets['ssh_secret'],
        ], static fn (string $v): bool => $v !== '');
        if ($payload === []) {
            return [null, null];
        }
        [$ciphertext, $nonce] = $this->crypto->seal(
            json_encode($payload, JSON_THROW_ON_ERROR),
            self::associatedData($uid, $userId),
        );

        return [new Blob($ciphertext), new Blob($nonce)];
    }

    private static function associatedData(string $uid, int $userId): string
    {
        return 'dbportal/server/' . $uid . '/' . $userId;
    }

    /**
     * What phpMyAdmin's or pgAdmin's container needs to connect. Contains plaintext credentials:
     * only ever sent over the internal network or encrypted inside a ticket.
     *
     * @param array<string, mixed> $data
     * @param array{db_password: string, ssh_secret: string} $secrets
     * @return array<string, mixed>
     */
    public static function descriptor(array $data, array $secrets, string $user = '', string $key = ''): array
    {
        $kind = (string) ($data['kind'] ?? self::MYSQL) === self::POSTGRES ? self::POSTGRES : self::MYSQL;

        return [
            'v' => 1,
            'key' => $key,
            'name' => (string) $data['name'],
            'kind' => $kind,
            'environment' => (string) ($data['environment'] ?? ''),
            // PostgreSQL: the database pgAdmin connects to first
            'database' => $kind === self::POSTGRES ? ((string) ($data['db_name'] ?? '') ?: 'postgres') : '',
            'method' => (string) $data['method'],
            'host' => (string) $data['host'],
            'port' => (int) $data['port'],
            'user' => $user !== '' ? $user : (string) $data['db_user'],
            'password' => $secrets['db_password'],
            'ca_pem' => (string) $data['ca_pem'],
            'pin_sha256' => (string) $data['pin_sha256'],
            'pin_pem' => (string) $data['pin_pem'],
            'pin_strict' => (bool) $data['pin_strict'],
            'ssh' => $data['method'] === 'ssh' ? [
                'host' => (string) $data['ssh_host'],
                'port' => (int) $data['ssh_port'],
                'user' => (string) $data['ssh_user'],
                'auth' => (string) $data['ssh_auth'],
                'secret' => $secrets['ssh_secret'],
                'hostkey' => (string) $data['ssh_hostkey'],
            ] : null,
        ];
    }

    /**
     * Identifies a login target for lockouts (per account).
     *
     * @param array<string, mixed> $data
     */
    public static function lockTarget(int $userId, array $data, string $user): string
    {
        return hash('sha256', implode('|', [
            $userId, $data['method'], strtolower((string) $data['host']), $data['port'],
            strtolower((string) $data['ssh_host']), $user, $data['kind'] ?? self::MYSQL,
        ]));
    }
}
