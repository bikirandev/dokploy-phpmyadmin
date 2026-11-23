<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Abuse limits and security switches, edited by platform admins and stored in the portal's own database.
 */
final class Settings
{
    /** Security switches. Each one is off until an admin turns it on. */
    public const POLICIES = [
        'allow_plain' => 'Allow unencrypted connections to remote servers',
    ];

    public const LIMITS = [
        'servers_per_account' => ['label' => 'Servers per account', 'unit' => 'servers', 'default' => 25, 'min' => 1, 'max' => 500],
        'tests_per_minute' => ['label' => 'Connection tests per account', 'unit' => 'per minute', 'default' => 10, 'min' => 1, 'max' => 120],
        'failures_before_lock' => ['label' => 'Failed database logins before a server locks', 'unit' => 'attempts', 'default' => 5, 'min' => 1, 'max' => 50],
        'lock_minutes' => ['label' => 'Lock duration', 'unit' => 'minutes', 'default' => 15, 'min' => 1, 'max' => 1440],
        'sessions_per_account' => ['label' => 'Open sessions per account, in each of phpMyAdmin and pgAdmin', 'unit' => 'at once', 'default' => 3, 'min' => 1, 'max' => 10],
        'import_mb' => ['label' => 'Largest import file', 'unit' => 'MB', 'default' => 64, 'min' => 1, 'max' => 512],
        'signins_per_ip_minute' => ['label' => 'Sign-in attempts per IP address', 'unit' => 'per minute', 'default' => 10, 'min' => 1, 'max' => 300],
    ];

    /** @var array<string, string>|null stored values by key */
    private ?array $rows = null;

    public function __construct(private readonly Db $db)
    {
    }

    /** @return array<string, int> the abuse limits */
    public function all(): array
    {
        $rows = $this->rows();
        $values = [];
        foreach (self::LIMITS as $key => $limit) {
            $values[$key] = array_key_exists($key, $rows) ? (int) $rows[$key] : $limit['default'];
        }

        return $values;
    }

    public function get(string $key): int
    {
        return $this->all()[$key];
    }

    public function policy(string $key): bool
    {
        return array_key_exists($key, self::POLICIES) && ($this->rows()[$key] ?? '0') === '1';
    }

    /** Whether remote servers may connect without encryption ("Not encrypted"). */
    public function allowPlain(): bool
    {
        return $this->policy('allow_plain');
    }

    public function setPolicy(string $key, bool $on): void
    {
        if (!array_key_exists($key, self::POLICIES)) {
            throw new \InvalidArgumentException("Unknown policy $key");
        }
        $this->db->run(
            'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
            [$key, $on ? '1' : '0'],
        );
        $this->rows = null;
    }

    /** @return array<string, string> */
    private function rows(): array
    {
        if ($this->rows === null) {
            $this->rows = [];
            foreach ($this->db->all('SELECT key, value FROM settings') as $row) {
                $this->rows[(string) $row['key']] = (string) $row['value'];
            }
        }

        return $this->rows;
    }

    /**
     * @param array<string, string> $input
     * @return array<string, string> errors by key (empty when saved)
     */
    public function save(array $input): array
    {
        $errors = [];
        $clean = [];
        foreach (self::LIMITS as $key => $limit) {
            $raw = trim($input[$key] ?? '');
            if (!preg_match('/^\d{1,6}$/', $raw)) {
                $errors[$key] = 'Enter a whole number.';
                continue;
            }
            $value = (int) $raw;
            if ($value < $limit['min'] || $value > $limit['max']) {
                $errors[$key] = "Use a value from {$limit['min']} to {$limit['max']}.";
                continue;
            }
            $clean[$key] = $value;
        }
        if ($errors !== []) {
            return $errors;
        }
        $this->db->tx(function () use ($clean): void {
            foreach ($clean as $key => $value) {
                $this->db->run(
                    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
                    [$key, (string) $value],
                );
            }
        });
        $this->rows = null;

        return [];
    }

    /** Puts the abuse limits back to their defaults. Security switches are left as they are. */
    public function reset(): void
    {
        $keys = array_keys(self::LIMITS);
        $this->db->run(
            'DELETE FROM settings WHERE key IN (' . implode(',', array_fill(0, count($keys), '?')) . ')',
            $keys,
        );
        $this->rows = null;
    }
}
