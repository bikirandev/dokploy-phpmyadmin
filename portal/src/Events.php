<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * The activity log. Kinds: signin, open, change, problem. Results: ok, failed, locked, denied.
 */
final class Events
{
    public const RETENTION_DAYS = 90;

    public const FILTERS = [
        'all' => 'All',
        'signins' => 'Sign-ins',
        'opens' => 'phpMyAdmin',
        'changes' => 'Changes',
        'problems' => 'Problems',
    ];

    public function __construct(private readonly Db $db)
    {
    }

    public function log(?int $userId, string $kind, string $event, string $detail, string $result, string $ip): void
    {
        $this->db->run(
            'INSERT INTO events (user_id, at, kind, event, detail, ip, result) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [$userId, time(), $kind, mb_substr($event, 0, 120), mb_substr($detail, 0, 300), mb_substr($ip, 0, 64), $result],
        );
    }

    /** @return list<array<string, mixed>> */
    public function forUser(int $userId, string $filter, int $limit = 200): array
    {
        $where = match ($filter) {
            'signins' => "AND (kind = 'signin' OR event LIKE 'Sign-in%')",
            'opens' => "AND kind = 'open'",
            'changes' => "AND kind = 'change'",
            'problems' => "AND result <> 'ok'",
            default => '',
        };

        return $this->db->all(
            "SELECT * FROM events WHERE user_id = ? $where ORDER BY at DESC, id DESC LIMIT ?",
            [$userId, $limit],
        );
    }

    public function cleanup(): void
    {
        $this->db->run('DELETE FROM events WHERE at < ?', [time() - self::RETENTION_DAYS * 86400]);
    }
}
