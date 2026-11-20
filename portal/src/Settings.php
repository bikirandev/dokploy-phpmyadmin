<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Abuse limits, edited by platform admins and stored in the portal's own database.
 */
final class Settings
{
    public const LIMITS = [
        'servers_per_account' => ['label' => 'Servers per account', 'unit' => 'servers', 'default' => 25, 'min' => 1, 'max' => 500],
        'tests_per_minute' => ['label' => 'Connection tests per account', 'unit' => 'per minute', 'default' => 10, 'min' => 1, 'max' => 120],
        'failures_before_lock' => ['label' => 'Failed database logins before a server locks', 'unit' => 'attempts', 'default' => 5, 'min' => 1, 'max' => 50],
        'lock_minutes' => ['label' => 'Lock duration', 'unit' => 'minutes', 'default' => 15, 'min' => 1, 'max' => 1440],
        'sessions_per_account' => ['label' => 'Open phpMyAdmin sessions per account', 'unit' => 'at once', 'default' => 3, 'min' => 1, 'max' => 10],
        'import_mb' => ['label' => 'Largest import file', 'unit' => 'MB', 'default' => 64, 'min' => 1, 'max' => 512],
        'signins_per_ip_minute' => ['label' => 'Sign-in attempts per IP address', 'unit' => 'per minute', 'default' => 10, 'min' => 1, 'max' => 300],
    ];

    /** @var array<string, int>|null */
    private ?array $cache = null;

    public function __construct(private readonly Db $db)
    {
    }

    /** @return array<string, int> */
    public function all(): array
    {
        if ($this->cache === null) {
            $values = [];
            foreach (self::LIMITS as $key => $limit) {
                $values[$key] = $limit['default'];
            }
            foreach ($this->db->all('SELECT key, value FROM settings') as $row) {
                if (array_key_exists($row['key'], $values)) {
                    $values[$row['key']] = (int) $row['value'];
                }
            }
            $this->cache = $values;
        }

        return $this->cache;
    }

    public function get(string $key): int
    {
        return $this->all()[$key];
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
        $this->cache = null;

        return [];
    }

    public function reset(): void
    {
        $this->db->run('DELETE FROM settings');
        $this->cache = null;
    }
}
