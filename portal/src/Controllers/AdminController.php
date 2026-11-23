<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Ctx;
use DbPortal\Guard;
use DbPortal\HttpException;
use DbPortal\Response;
use DbPortal\Settings;

/**
 * Platform admin: security switches, abuse limits and account suspension. Admins never see
 * database passwords.
 */
final class AdminController
{
    private const NOTICES = [
        'limits-saved' => 'Saved. New limits are in effect.',
        'limits-reset' => 'Limits reset to the defaults.',
        'suspended' => 'Account suspended and signed out everywhere.',
        'reactivated' => 'Account reactivated.',
        'plain-on' => 'Saved. Remote servers can now use “Not encrypted”.',
        'plain-off' => 'Saved. Unencrypted connections are off: those servers are blocked and their open sessions were closed.',
    ];

    public static function security(Ctx $ctx): never
    {
        Guard::user($ctx);
        Guard::admin($ctx);
        Guard::csrf($ctx);
        $on = $ctx->req->post('allow_plain') === '1';
        $was = $ctx->settings->allowPlain();
        $ctx->settings->setPolicy('allow_plain', $on);
        if ($on && !$was) {
            $ctx->log('change', 'Allowed unencrypted connections', 'Remote servers can use “Not encrypted”');
        } elseif (!$on && $was) {
            // Close the open phpMyAdmin and pgAdmin sessions of those servers right away.
            $closed = $ctx->tickets->revokeForMethod('plain');
            $stats = self::plainStats($ctx);
            $ctx->log('change', 'Turned off unencrypted connections', $stats['servers'] . ' server' . ($stats['servers'] === 1 ? '' : 's')
                . ' blocked, ' . $closed . ' open session' . ($closed === 1 ? '' : 's') . ' closed');
        }
        Response::redirect('/admin?notice=' . ($on ? 'plain-on' : 'plain-off'), 303);
    }

    public static function index(Ctx $ctx): never
    {
        Guard::user($ctx);
        Guard::admin($ctx);
        self::page($ctx, [], null, 200);
    }

    public static function limits(Ctx $ctx): never
    {
        Guard::user($ctx);
        Guard::admin($ctx);
        Guard::csrf($ctx);
        if ($ctx->req->post('reset') === '1') {
            $ctx->settings->reset();
            $ctx->log('change', 'Reset abuse limits', 'Back to defaults');
            Response::redirect('/admin?notice=limits-reset', 303);
        }
        $input = [];
        foreach (array_keys(Settings::LIMITS) as $key) {
            $input[$key] = $ctx->req->post($key);
        }
        $errors = $ctx->settings->save($input);
        if ($errors !== []) {
            self::page($ctx, $errors, $input, 422);
        }
        $ctx->log('change', 'Changed abuse limits', implode(', ', array_map(
            static fn (string $k, string $v): string => "$k=$v",
            array_keys($input),
            array_values($input),
        )));
        Response::redirect('/admin?notice=limits-saved', 303);
    }

    /** @param list<string> $params */
    public static function account(Ctx $ctx, array $params): never
    {
        Guard::user($ctx);
        Guard::admin($ctx);
        Guard::csrf($ctx);
        $target = $ctx->db->one('SELECT * FROM users WHERE id = ?', [(int) $params[0]]);
        if ($target === null) {
            throw new HttpException(404, 'Account not found.');
        }
        $label = $target['email'] !== '' ? (string) $target['email'] : (string) $target['subject'];
        if ($params[1] === 'suspend') {
            if ((int) $target['id'] === (int) $ctx->user['id']) {
                throw new HttpException(400, 'You can\'t suspend your own account.');
            }
            $reason = mb_substr(trim($ctx->req->post('reason')), 0, 200);
            $ctx->db->run('UPDATE users SET suspended_at = ?, suspended_reason = ? WHERE id = ?', [time(), $reason, (int) $target['id']]);
            $ctx->auth->endAllForUser((int) $target['id']);
            $ctx->log('change', 'Suspended an account', $label . ($reason !== '' ? ": $reason" : ''));
            $ctx->log('problem', 'Account suspended', $reason !== '' ? $reason : 'Suspended by an admin', 'denied', (int) $target['id']);
            Response::redirect('/admin?notice=suspended', 303);
        }
        $ctx->db->run('UPDATE users SET suspended_at = NULL, suspended_reason = \'\' WHERE id = ?', [(int) $target['id']]);
        $ctx->log('change', 'Reactivated an account', $label);
        $ctx->log('change', 'Account reactivated', 'By an admin', 'ok', (int) $target['id']);
        Response::redirect('/admin?notice=reactivated', 303);
    }

    /**
     * @param array<string, string> $errors
     * @param array<string, string>|null $input
     */
    private static function page(Ctx $ctx, array $errors, ?array $input, int $status): never
    {
        $query = trim($ctx->req->query('q'));
        $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $query) . '%';
        $accounts = $ctx->db->all(
            "SELECT u.*, (SELECT COUNT(*) FROM servers s WHERE s.user_id = u.id) AS server_count
             FROM users u
             WHERE ? = '' OR u.email LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\' OR u.subject LIKE ? ESCAPE '\\'
             ORDER BY u.last_login_at DESC NULLS LAST, u.id DESC
             LIMIT 200",
            [$query, $like, $like, $like],
        );
        $values = $input ?? array_map('strval', $ctx->settings->all());

        $ctx->render('admin', [
            'values' => $values,
            'errors' => $errors,
            'accounts' => $accounts,
            'query' => $query,
            'notice' => self::NOTICES[$ctx->req->query('notice')] ?? '',
            'allowPlain' => $ctx->settings->allowPlain(),
            'plain' => self::plainStats($ctx),
        ], $status);
    }

    /** @return array{servers: int, accounts: int} servers set to "Not encrypted", in all accounts */
    private static function plainStats(Ctx $ctx): array
    {
        $row = $ctx->db->one("SELECT COUNT(*) AS servers, COUNT(DISTINCT user_id) AS accounts FROM servers WHERE method = 'plain'");

        return ['servers' => (int) ($row['servers'] ?? 0), 'accounts' => (int) ($row['accounts'] ?? 0)];
    }
}
