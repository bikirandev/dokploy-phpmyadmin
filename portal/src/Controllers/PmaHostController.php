<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Auth;
use DbPortal\Ctx;
use DbPortal\Response;
use DbPortal\Tickets;
use Throwable;

/**
 * Served on phpMyAdmin's and pgAdmin's hostnames (the gateway routes /__dbportal/ there to the
 * portal, with X-DBP-Host: pma or pga). Sets and clears the ticket cookies, which therefore
 * belong to that tool's hostname only.
 */
final class PmaHostController
{
    public static function enter(Ctx $ctx): never
    {
        $app = self::requireToolHost($ctx);
        $code = $ctx->req->query('code');
        $hash = hash('sha256', $code);
        $row = $code !== '' ? $ctx->db->one('SELECT * FROM handoffs WHERE code_hash = ?', [$hash]) : null;
        $ctx->db->run('DELETE FROM handoffs WHERE code_hash = ? OR expires_at <= ?', [$hash, time()]);
        if ($row === null || (int) $row['expires_at'] <= time() || (string) $row['app'] !== $app) {
            Response::redirect($ctx->cfg->publicUrl . '/servers?notice=open-expired', 303);
        }
        try {
            $cookie = $ctx->crypto->open((string) $row['ciphertext'], (string) $row['nonce'], 'dbportal/handoff/' . $hash);
        } catch (Throwable) {
            Response::redirect($ctx->cfg->publicUrl . '/servers?notice=open-expired', 303);
        }
        $slot = (int) $row['slot'];
        Auth::setCookie(Tickets::cookiePrefix($app) . $slot, $cookie, 'Lax');
        if ($app === 'pga') {
            // pgAdmin shows every open server in one tree.
            Response::redirect('/', 303);
        }
        // phpMyAdmin selects the server by number, and keeps it in every link of this tab.
        $idHash = Tickets::idHashFromCookie($cookie);
        $ticket = $idHash !== null ? $ctx->db->one('SELECT server_id FROM tickets WHERE id_hash = ?', [$idHash]) : null;
        Response::redirect($ticket !== null
            ? '/index.php?server=' . (Tickets::PMA_NUMBER_OFFSET + (int) $ticket['server_id'])
            : '/index.php', 303);
    }

    /**
     * phpMyAdmin's "Log out" for one server, or pgAdmin's "Log out" (all of this browser's
     * pgAdmin sessions): closes them and returns to the portal.
     */
    public static function close(Ctx $ctx): never
    {
        $app = self::requireToolHost($ctx);
        $prefix = Tickets::cookiePrefix($app);
        $slots = $app === 'pga' ? range(1, Tickets::MAX_SLOTS) : [(int) $ctx->req->query('slot')];
        foreach ($slots as $slot) {
            if ($slot < 1 || $slot > Tickets::MAX_SLOTS) {
                continue;
            }
            $name = $prefix . $slot;
            $idHash = Tickets::idHashFromCookie($ctx->req->cookie($name));
            if ($idHash !== null) {
                $ctx->tickets->revoke($idHash);
                Auth::clearCookie($name, 'Lax');
            } elseif ($app === 'pma') {
                Auth::clearCookie($name, 'Lax');
            }
        }
        Response::redirect($ctx->cfg->publicUrl . '/servers?notice=' . ($app === 'pga' ? 'pga-closed' : 'closed'), 303);
    }

    /** @return string "pma" or "pga" */
    private static function requireToolHost(Ctx $ctx): string
    {
        $host = (string) $ctx->req->header('X-DBP-Host');
        if (!in_array($host, Tickets::APPS, true)) {
            Response::status(404);
        }

        return $host;
    }
}
