<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Ctx;
use DbPortal\Events;
use DbPortal\Guard;

/**
 * Your activity: this account's own log.
 */
final class ActivityController
{
    public static function index(Ctx $ctx): never
    {
        Guard::user($ctx);
        $userId = (int) $ctx->user['id'];
        $filter = array_key_exists($ctx->req->query('filter'), Events::FILTERS) ? $ctx->req->query('filter') : 'all';

        $ctx->render('activity', [
            'events' => $ctx->events->forUser($userId, $filter),
            'filter' => $filter,
            'serverCount' => $ctx->servers->countForUser($userId),
            'savedCount' => (int) $ctx->db->scalar('SELECT COUNT(*) FROM servers WHERE user_id = ? AND secret IS NOT NULL', [$userId]),
            'limit' => $ctx->settings->get('servers_per_account'),
        ]);
    }
}
