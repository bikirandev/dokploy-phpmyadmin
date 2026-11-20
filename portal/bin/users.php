<?php

declare(strict_types=1);

/**
 * Lists accounts that have signed in, with the user ID to put in ADMIN_SUBJECTS.
 *
 *   docker exec <portal-container> php /app/bin/users.php
 */

use DbPortal\Config;
use DbPortal\Db;

require dirname(__DIR__) . '/vendor/autoload.php';

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$cfg = Config::fromEnv();
$db = new Db($cfg->dataDir . '/portal.sqlite');
$rows = $db->all('SELECT subject, email, name, last_login_at, suspended_at FROM users ORDER BY last_login_at DESC NULLS LAST');

printf("%-40s %-32s %-20s %-17s %s\n", 'USER ID (for ADMIN_SUBJECTS)', 'EMAIL', 'NAME', 'LAST SIGN-IN (UTC)', 'STATUS');
foreach ($rows as $row) {
    printf(
        "%-40s %-32s %-20s %-17s %s\n",
        $row['subject'],
        $row['email'],
        mb_substr((string) $row['name'], 0, 20),
        $row['last_login_at'] !== null ? gmdate('Y-m-d H:i', (int) $row['last_login_at']) : 'never',
        ($row['suspended_at'] !== null ? 'suspended' : 'active') . (in_array($row['subject'], $cfg->adminSubjects, true) ? ', admin' : ''),
    );
}
