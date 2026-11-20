<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Fixed-window counters in SQLite, used for rate limits and database-login lockouts.
 */
final class RateLimiter
{
    public function __construct(private readonly Db $db)
    {
    }

    /**
     * Counts one attempt. Returns false when the limit for this window is already used up.
     */
    public function hit(string $key, int $limit, int $windowSeconds): bool
    {
        $now = time();

        return $this->db->tx(function () use ($key, $limit, $windowSeconds, $now): bool {
            $row = $this->db->one('SELECT window_start, count FROM counters WHERE key = ?', [$key]);
            if ($row === null || (int) $row['window_start'] + $windowSeconds <= $now) {
                $this->db->run(
                    'INSERT INTO counters (key, window_start, count) VALUES (?, ?, 1)
                     ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = 1',
                    [$key, $now],
                );

                return true;
            }
            if ((int) $row['count'] >= $limit) {
                return false;
            }
            $this->db->run('UPDATE counters SET count = count + 1 WHERE key = ?', [$key]);

            return true;
        });
    }

    /**
     * Seconds until a lock on this target ends, or 0 when it is not locked.
     */
    public function lockedFor(string $target, int $lockSeconds): int
    {
        $row = $this->db->one('SELECT window_start FROM counters WHERE key = ?', ['lock:' . $target]);
        if ($row === null) {
            return 0;
        }
        $remaining = (int) $row['window_start'] + $lockSeconds - time();

        return max(0, $remaining);
    }

    /**
     * Records a failed database login. Returns true when this failure triggered a lock.
     */
    public function recordFailure(string $target, int $maxFailures, int $lockSeconds): bool
    {
        $now = time();

        return $this->db->tx(function () use ($target, $maxFailures, $lockSeconds, $now): bool {
            $key = 'fail:' . $target;
            $row = $this->db->one('SELECT window_start, count FROM counters WHERE key = ?', [$key]);
            $count = ($row === null || (int) $row['window_start'] + $lockSeconds <= $now) ? 1 : (int) $row['count'] + 1;
            $start = $count === 1 ? $now : (int) $row['window_start'];
            if ($count >= $maxFailures) {
                $this->db->run('DELETE FROM counters WHERE key = ?', [$key]);
                $this->db->run(
                    'INSERT INTO counters (key, window_start, count) VALUES (?, ?, 1)
                     ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = 1',
                    ['lock:' . $target, $now],
                );

                return true;
            }
            $this->db->run(
                'INSERT INTO counters (key, window_start, count) VALUES (?, ?, ?)
                 ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = excluded.count',
                [$key, $start, $count],
            );

            return false;
        });
    }

    public function recordSuccess(string $target): void
    {
        $this->db->run('DELETE FROM counters WHERE key = ?', ['fail:' . $target]);
    }

    public function cleanup(): void
    {
        // Counter windows are at most a day long.
        $this->db->run('DELETE FROM counters WHERE window_start < ?', [time() - 86400]);
    }
}
