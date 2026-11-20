<?php

declare(strict_types=1);

namespace DbPortal;

use PDO;
use Throwable;

/**
 * SQLite storage on the portal's data volume, with versioned migrations.
 */
final class Db
{
    private const MIGRATIONS = [
        // 1: initial schema
        <<<'SQL'
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            subject TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            last_login_at INTEGER,
            agreed_at INTEGER,
            suspended_at INTEGER,
            suspended_reason TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE sessions (
            id_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL,
            via TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX sessions_user ON sessions(user_id);
        CREATE TABLE auth_requests (
            state_hash TEXT PRIMARY KEY,
            nonce TEXT NOT NULL,
            verifier TEXT NOT NULL,
            next TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE servers (
            id INTEGER PRIMARY KEY,
            uid TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            environment TEXT NOT NULL,
            location TEXT NOT NULL,
            method TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            db_user TEXT NOT NULL,
            cred_mode TEXT NOT NULL,
            secret BLOB,
            secret_nonce BLOB,
            ca_pem TEXT NOT NULL DEFAULT '',
            pin_sha256 TEXT NOT NULL DEFAULT '',
            pin_pem TEXT NOT NULL DEFAULT '',
            pin_strict INTEGER NOT NULL DEFAULT 0,
            ssh_host TEXT NOT NULL DEFAULT '',
            ssh_port INTEGER NOT NULL DEFAULT 22,
            ssh_user TEXT NOT NULL DEFAULT '',
            ssh_auth TEXT NOT NULL DEFAULT '',
            ssh_hostkey TEXT NOT NULL DEFAULT '',
            ssh_fingerprint TEXT NOT NULL DEFAULT '',
            engine TEXT NOT NULL DEFAULT '',
            last_opened_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX servers_user ON servers(user_id);
        CREATE TABLE tickets (
            id_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            session_hash TEXT NOT NULL,
            slot INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX tickets_user ON tickets(user_id);
        CREATE INDEX tickets_session ON tickets(session_hash);
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            at INTEGER NOT NULL,
            kind TEXT NOT NULL,
            event TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL
        );
        CREATE INDEX events_user_at ON events(user_id, at);
        CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE counters (
            key TEXT PRIMARY KEY,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL
        );
        CREATE TABLE emergency_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            used_at INTEGER
        );
        CREATE TABLE cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE handoffs (
            code_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            slot INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            expires_at INTEGER NOT NULL
        );
        SQL,
        // 2: PostgreSQL servers, opened in pgAdmin ("pga") next to phpMyAdmin ("pma")
        <<<'SQL'
        ALTER TABLE servers ADD COLUMN kind TEXT NOT NULL DEFAULT 'mysql';
        ALTER TABLE servers ADD COLUMN db_name TEXT NOT NULL DEFAULT '';
        ALTER TABLE tickets ADD COLUMN app TEXT NOT NULL DEFAULT 'pma';
        ALTER TABLE tickets ADD COLUMN db_user TEXT NOT NULL DEFAULT '';
        ALTER TABLE handoffs ADD COLUMN app TEXT NOT NULL DEFAULT 'pma';
        SQL,
    ];

    private PDO $pdo;

    public function __construct(string $path)
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 10,
        ]);
        $this->pdo->exec('PRAGMA busy_timeout = 10000');
        $this->pdo->exec('PRAGMA journal_mode = WAL');
        $this->pdo->exec('PRAGMA synchronous = NORMAL');
        $this->pdo->exec('PRAGMA foreign_keys = ON');
        @chmod($path, 0600);
        $this->migrate();
    }

    /** @return array<string, mixed>|null */
    public function one(string $sql, array $params = []): ?array
    {
        $row = $this->execute($sql, $params)->fetch();

        return $row === false ? null : $row;
    }

    /** @return list<array<string, mixed>> */
    public function all(string $sql, array $params = []): array
    {
        return $this->execute($sql, $params)->fetchAll();
    }

    public function scalar(string $sql, array $params = []): mixed
    {
        return $this->execute($sql, $params)->fetchColumn();
    }

    public function run(string $sql, array $params = []): int
    {
        return $this->execute($sql, $params)->rowCount();
    }

    private function execute(string $sql, array $params): \PDOStatement
    {
        $stmt = $this->pdo->prepare($sql);
        foreach (array_values($params) as $i => $value) {
            $type = match (true) {
                is_int($value), is_bool($value) => PDO::PARAM_INT,
                is_null($value) => PDO::PARAM_NULL,
                $value instanceof Blob => PDO::PARAM_LOB,
                default => PDO::PARAM_STR,
            };
            $bound = match (true) {
                $value instanceof Blob => $value->bytes,
                is_bool($value) => (int) $value,
                default => $value,
            };
            $stmt->bindValue($i + 1, $bound, $type);
        }
        $stmt->execute();

        return $stmt;
    }

    public function insert(string $sql, array $params = []): int
    {
        $this->run($sql, $params);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * @template T
     * @param callable(): T $fn
     * @return T
     */
    public function tx(callable $fn): mixed
    {
        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            $result = $fn();
            $this->pdo->exec('COMMIT');

            return $result;
        } catch (Throwable $e) {
            $this->pdo->exec('ROLLBACK');
            throw $e;
        }
    }

    private function migrate(): void
    {
        $this->tx(function (): void {
            $version = (int) $this->pdo->query('PRAGMA user_version')->fetchColumn();
            foreach (self::MIGRATIONS as $index => $sql) {
                $target = $index + 1;
                if ($target > $version) {
                    $this->pdo->exec($sql);
                    $this->pdo->exec('PRAGMA user_version = ' . $target);
                }
            }
        });
    }
}
