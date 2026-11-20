<?php

declare(strict_types=1);

/**
 * Break-glass sign-in for when the identity provider is down.
 *
 * Run on the server (needs SSH access to it):
 *   docker exec -it <portal-container> php /app/bin/emergency-link.php --subject <admin-user-id>
 *   docker exec -it <portal-container> php /app/bin/emergency-link.php --email admin@example.com
 *
 * Prints a one-time link valid for 10 minutes. Only works for accounts listed in ADMIN_SUBJECTS
 * that have signed in at least once.
 */

use DbPortal\Config;
use DbPortal\Crypto;
use DbPortal\Db;
use DbPortal\Events;

require dirname(__DIR__) . '/vendor/autoload.php';

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$options = getopt('', ['subject:', 'email:']);
$subject = is_string($options['subject'] ?? null) ? $options['subject'] : null;
$email = is_string($options['email'] ?? null) ? $options['email'] : null;
if ($subject === null && $email === null) {
    fwrite(STDERR, "Usage: php bin/emergency-link.php --subject <user-id> | --email <address>\n");
    exit(2);
}

$cfg = Config::fromEnv();
$db = new Db($cfg->dataDir . '/portal.sqlite');
$user = $subject !== null
    ? $db->one('SELECT * FROM users WHERE subject = ?', [$subject])
    : $db->one('SELECT * FROM users WHERE email = ? COLLATE NOCASE', [$email]);

if ($user === null) {
    fwrite(STDERR, "No account found. The admin must have signed in at least once.\n");
    exit(3);
}
if (!in_array($user['subject'], $cfg->adminSubjects, true)) {
    fwrite(STDERR, "This account is not listed in ADMIN_SUBJECTS.\n");
    exit(4);
}
if ($user['suspended_at'] !== null) {
    fwrite(STDERR, "This account is suspended.\n");
    exit(5);
}

$token = Crypto::randomToken(32);
$db->run(
    'INSERT INTO emergency_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    [hash('sha256', $token), (int) $user['id'], time() + 600],
);
(new Events($db))->log((int) $user['id'], 'change', 'Emergency link created', 'On the server, valid 10 minutes', 'ok', 'server');

echo $cfg->publicUrl . '/emergency/' . $token . "\n";
echo "Valid for 10 minutes, works once.\n";
