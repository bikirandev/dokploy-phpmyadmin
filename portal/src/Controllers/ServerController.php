<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Blob;
use DbPortal\Crypto;
use DbPortal\Ctx;
use DbPortal\Guard;
use DbPortal\HttpException;
use DbPortal\Response;
use DbPortal\ServerForm;
use DbPortal\Servers;
use DbPortal\Tickets;

/**
 * My servers: list, add, edit, delete, test and open (MySQL / MariaDB in phpMyAdmin,
 * PostgreSQL in pgAdmin).
 */
final class ServerController
{
    private const NOTICES = [
        'added' => 'Server added.',
        'updated' => 'Server updated. Any open phpMyAdmin or pgAdmin session for it was closed.',
        'deleted' => 'Server deleted.',
        'closed' => 'phpMyAdmin session closed.',
        'pga-closed' => 'pgAdmin sessions closed.',
        'signin' => 'Open a server to continue in phpMyAdmin.',
        'pga-signin' => 'Open a PostgreSQL server to continue in pgAdmin.',
        'open-expired' => 'That link expired. Open the server again.',
    ];

    public static function index(Ctx $ctx): never
    {
        Guard::user($ctx);
        $userId = (int) $ctx->user['id'];
        $filter = in_array($ctx->req->query('filter'), ['local', 'remote'], true) ? $ctx->req->query('filter') : 'all';
        $query = trim($ctx->req->query('q'));
        $all = $ctx->servers->listForUser($userId);
        $lockSeconds = $ctx->settings->get('lock_minutes') * 60;

        $visible = array_values(array_filter($all, static function (array $s) use ($filter, $query): bool {
            if ($filter !== 'all' && $s['location'] !== $filter) {
                return false;
            }
            if ($query === '') {
                return true;
            }

            return mb_stripos((string) $s['name'], $query) !== false
                || mb_stripos((string) $s['host'], $query) !== false
                || mb_stripos((string) $s['ssh_host'], $query) !== false;
        }));
        foreach ($visible as &$server) {
            $server['locked_for'] = $ctx->limiter->lockedFor(Servers::lockTarget($userId, $server, (string) $server['db_user']), $lockSeconds);
        }
        unset($server);

        $notice = self::NOTICES[$ctx->req->query('notice')] ?? '';
        if ($ctx->req->query('pma_signin') !== '') {
            $notice = self::NOTICES['signin'];
        } elseif ($ctx->req->query('pga_signin') !== '') {
            $notice = self::NOTICES['pga-signin'];
        }

        $ctx->render('servers', [
            'servers' => $visible,
            'counts' => [
                'all' => count($all),
                'local' => count(array_filter($all, static fn (array $s): bool => $s['location'] === 'local')),
                'remote' => count(array_filter($all, static fn (array $s): bool => $s['location'] === 'remote')),
            ],
            'filter' => $filter,
            'query' => $query,
            'notice' => $notice,
            'limit' => $ctx->settings->get('servers_per_account'),
        ]);
    }

    public static function create(Ctx $ctx): never
    {
        Guard::user($ctx);
        self::form($ctx, null, [
            'kind' => $ctx->req->query('kind') === Servers::POSTGRES ? Servers::POSTGRES : Servers::MYSQL,
            'location' => 'remote', 'method' => 'tls', 'environment' => 'Production',
            'cred_mode' => 'ask', 'ssh_auth' => 'key',
        ], []);
    }

    public static function store(Ctx $ctx): never
    {
        Guard::user($ctx);
        Guard::csrf($ctx);
        $userId = (int) $ctx->user['id'];
        if ($ctx->servers->countForUser($userId) >= $ctx->settings->get('servers_per_account')) {
            throw new HttpException(403, 'You reached your account\'s server limit. Delete a server you no longer need first.');
        }
        $parsed = ServerForm::parse($ctx->req, $ctx, null, false);
        if ($parsed['errors'] !== []) {
            self::form($ctx, null, ServerForm::valuesFromRequest($ctx->req), $parsed['errors'], 422);
        }
        $secrets = $parsed['secrets'];
        if ($parsed['data']['cred_mode'] === 'ask') {
            $secrets['db_password'] = '';
        }
        $ctx->servers->create($userId, $parsed['data'], $secrets);
        $ctx->log('change', 'Server added', $parsed['data']['name'] . ($secrets['db_password'] !== '' ? ', password saved to vault' : ''));
        Response::redirect('/servers?notice=added', 303);
    }

    /** @param list<string> $params */
    public static function edit(Ctx $ctx, array $params): never
    {
        Guard::user($ctx);
        $server = self::owned($ctx, (int) $params[0]);
        self::form($ctx, $server, ServerForm::valuesFromServer($server), []);
    }

    /** @param list<string> $params */
    public static function update(Ctx $ctx, array $params): never
    {
        Guard::user($ctx);
        Guard::csrf($ctx);
        $server = self::owned($ctx, (int) $params[0]);
        $parsed = ServerForm::parse($ctx->req, $ctx, $server, false);
        if ($parsed['errors'] !== []) {
            self::form($ctx, $server, ServerForm::valuesFromRequest($ctx->req), $parsed['errors'], 422);
        }
        $secrets = $parsed['secrets'];
        if ($parsed['data']['cred_mode'] === 'ask') {
            $secrets['db_password'] = '';
        }
        $ctx->servers->update($server, $parsed['data'], $secrets);
        $ctx->tickets->revokeForServer((int) $server['id']);
        $ctx->log('change', 'Server updated', $parsed['data']['name']);
        Response::redirect('/servers?notice=updated', 303);
    }

    /** @param list<string> $params */
    public static function delete(Ctx $ctx, array $params): never
    {
        Guard::user($ctx);
        Guard::csrf($ctx);
        $server = self::owned($ctx, (int) $params[0]);
        $ctx->servers->delete($server);
        $ctx->log('change', 'Server deleted', (string) $server['name']);
        Response::redirect('/servers?notice=deleted', 303);
    }

    /**
     * Runs a connection test from the add/edit form (JSON for app.js).
     */
    public static function test(Ctx $ctx): never
    {
        Guard::user($ctx);
        Guard::csrf($ctx);
        $userId = (int) $ctx->user['id'];
        $perMinute = $ctx->settings->get('tests_per_minute');
        if (!$ctx->limiter->hit('test:' . $userId, $perMinute, 60)) {
            Response::json(['ok' => false, 'error' => "You ran $perMinute tests in the last minute. Wait a minute and try again."], 429);
        }

        $existingId = (int) $ctx->req->post('server_id', '0');
        $existing = $existingId > 0 ? self::owned($ctx, $existingId) : null;
        $parsed = ServerForm::parse($ctx->req, $ctx, $existing, true);
        if ($parsed['errors'] !== []) {
            Response::json(['ok' => false, 'error' => 'Fix the highlighted fields first.', 'errors' => $parsed['errors']], 422);
        }
        $data = $parsed['data'];
        $target = Servers::lockTarget($userId, $data, (string) $data['db_user']);
        $lockSeconds = $ctx->settings->get('lock_minutes') * 60;
        if (($left = $ctx->limiter->lockedFor($target, $lockSeconds)) > 0) {
            Response::json(['ok' => false, 'error' => self::lockedMessage($left)], 423);
        }

        $result = $ctx->tool((string) $data['kind'])->test(Servers::descriptor($data, $parsed['secrets']));
        $label = $data['name'] !== '' ? $data['name'] : $data['host'];
        if (!empty($result['auth_failed'])) {
            $locked = $ctx->limiter->recordFailure($target, $ctx->settings->get('failures_before_lock'), $lockSeconds);
            $ctx->log('problem', $locked ? 'Server locked' : 'Database login failed', $label . ($locked ? ', locked for ' . intdiv($lockSeconds, 60) . ' min' : ''), $locked ? 'locked' : 'failed');
            if ($locked) {
                $result['error'] = self::lockedMessage($lockSeconds);
            }
        } elseif (!empty($result['ok'])) {
            $ctx->limiter->recordSuccess($target);
            if ($existing !== null) {
                $ctx->servers->setEngine((int) $existing['id'], (string) ($result['version'] ?? ''));
            }
        }
        $ctx->log('change', 'Connection tested', $label . (!empty($result['ok']) ? ', ' . ($result['version'] ?? '') . ', ' . ($result['latency_ms'] ?? '?') . ' ms' : ''), !empty($result['ok']) ? 'ok' : 'failed');

        // Offer a signed "trust" token for a new certificate or SSH host key.
        $pin = is_array($result['pin'] ?? null) ? $result['pin'] : null;
        if ($pin !== null) {
            $kind = $data['method'] === 'ssh' ? 'ssh' : 'tls';
            $target = $kind === 'ssh'
                ? strtolower((string) $data['ssh_host']) . ':' . $data['ssh_port']
                : strtolower((string) $data['host']) . ':' . $data['port'];
            $pin['token'] = $ctx->crypto->signToken('pin', [
                'u' => $userId,
                'k' => $kind,
                't' => $target,
                'f' => (string) ($pin['fingerprint'] ?? ''),
                'v' => (string) ($pin['value'] ?? ''),
                's' => !empty($pin['strict']),
            ], 3600);
            unset($pin['value']);
            $result['pin'] = $pin;
        }

        Response::json([
            'ok' => !empty($result['ok']),
            'error' => $result['error'] ?? null,
            'checks' => array_values(array_map('strval', (array) ($result['checks'] ?? []))),
            'grants' => array_values(array_map('strval', (array) ($result['grants'] ?? []))),
            'superuser' => !empty($result['superuser']),
            'pin' => $result['pin'] ?? null,
        ]);
    }

    /** @param list<string> $params */
    public static function openForm(Ctx $ctx, array $params): never
    {
        Guard::user($ctx);
        $server = self::owned($ctx, (int) $params[0]);
        $ctx->render('open', ['server' => $server, 'error' => '', 'user' => (string) $server['db_user']]);
    }

    /** @param list<string> $params */
    public static function open(Ctx $ctx, array $params): never
    {
        Guard::user($ctx);
        Guard::csrf($ctx);
        $userId = (int) $ctx->user['id'];
        $server = self::owned($ctx, (int) $params[0]);
        $lockSeconds = $ctx->settings->get('lock_minutes') * 60;
        $kind = (string) $server['kind'];
        $app = Servers::app($kind);
        $appName = Servers::appName($kind);

        $asked = $server['cred_mode'] !== 'saved';
        $secrets = $ctx->servers->secrets($server);
        $dbUser = (string) $server['db_user'];
        if ($asked) {
            $dbUser = trim($ctx->req->post('db_user', $dbUser)) ?: $dbUser;
            $secrets['db_password'] = $ctx->req->post('db_password');
            if (strcasecmp($dbUser, Servers::blockedUser($kind)) === 0) {
                self::openFailed($ctx, $server, $dbUser, $kind === Servers::POSTGRES
                    ? 'postgres is blocked. Use a role with only the privileges it needs.'
                    : 'root is blocked. Use a user with only the privileges it needs.');
            }
            if ($secrets['db_password'] === '') {
                self::openFailed($ctx, $server, $dbUser, 'Enter the database password.');
            }
        }

        $target = Servers::lockTarget($userId, $server, $dbUser);
        if (($left = $ctx->limiter->lockedFor($target, $lockSeconds)) > 0) {
            self::openFailed($ctx, $server, $dbUser, self::lockedMessage($left));
        }

        $descriptor = Servers::descriptor($server, $secrets, $dbUser);
        if ($app === 'pga') {
            // pgAdmin lists the server under this name in every browser it is opened in.
            $descriptor['row'] = Tickets::pgaRow((string) $server['uid'], $dbUser);
        }
        $result = $ctx->tool($kind)->verify($descriptor);
        if (empty($result['ok'])) {
            $message = (string) ($result['error'] ?? 'Could not connect.');
            if (!empty($result['auth_failed'])) {
                $locked = $ctx->limiter->recordFailure($target, $ctx->settings->get('failures_before_lock'), $lockSeconds);
                $ctx->log('problem', $locked ? 'Server locked' : 'Database login failed', $server['name'] . ($locked ? ', locked for ' . intdiv($lockSeconds, 60) . ' min' : ''), $locked ? 'locked' : 'failed');
                $message = $locked ? self::lockedMessage($lockSeconds) : 'The database rejected this user name or password.';
            } else {
                $ctx->log('problem', "Could not open $appName", $server['name'] . ': ' . $message, 'failed');
            }
            self::openFailed($ctx, $server, $dbUser, $message);
        }

        $ctx->limiter->recordSuccess($target);
        $ctx->servers->markOpened((int) $server['id'], (string) ($result['version'] ?? ''));
        [$slot, $cookie] = $ctx->tickets->issue($ctx->session, $server, $descriptor, $ctx->settings->get('sessions_per_account'), $app);
        $ctx->log('open', "Opened $appName", $server['name'] . ' as ' . $dbUser . ($asked ? ', password typed' : ''));

        // Hand the ticket over to the tool's hostname with a one-time code (valid 60 seconds).
        $code = Crypto::randomToken(32);
        $codeHash = hash('sha256', $code);
        [$ciphertext, $nonce] = $ctx->crypto->seal($cookie, 'dbportal/handoff/' . $codeHash);
        $ctx->db->run(
            'INSERT INTO handoffs (code_hash, user_id, slot, app, ciphertext, nonce, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [$codeHash, $userId, $slot, $app, new Blob($ciphertext), new Blob($nonce), time() + 60],
        );
        $toolUrl = $app === 'pga' ? $ctx->cfg->pgaPublicUrl : $ctx->cfg->pmaPublicUrl;
        Response::redirect($toolUrl . '/__dbportal/enter?code=' . $code, 303);
    }

    /** @return array<string, mixed> */
    private static function owned(Ctx $ctx, int $id): array
    {
        $server = $ctx->servers->find((int) $ctx->user['id'], $id);
        if ($server === null) {
            throw new HttpException(404, 'Server not found.');
        }

        return $server;
    }

    /**
     * @param array<string, mixed>|null $server
     * @param array<string, string> $values
     * @param array<string, string> $errors
     */
    private static function form(Ctx $ctx, ?array $server, array $values, array $errors, int $status = 200): never
    {
        $ctx->render('server_form', [
            'server' => $server,
            'values' => $values,
            'errors' => $errors,
            'used' => $ctx->servers->countForUser((int) $ctx->user['id']),
            'limit' => $ctx->settings->get('servers_per_account'),
        ], $status);
    }

    /** @param array<string, mixed> $server */
    private static function openFailed(Ctx $ctx, array $server, string $dbUser, string $message): never
    {
        $ctx->render('open', ['server' => $server, 'error' => $message, 'user' => $dbUser], 422);
    }

    private static function lockedMessage(int $seconds): string
    {
        $minutes = max(1, (int) ceil($seconds / 60));

        return "Too many failed logins. This server is locked for $minutes more minute" . ($minutes === 1 ? '' : 's') . '.';
    }
}
