<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Auth;
use DbPortal\Ctx;
use DbPortal\Response;
use DbPortal\Tickets;
use Throwable;

/**
 * Served on phpMyAdmin's hostname (the gateway routes /__dbportal/ there to the portal).
 * Sets and clears the ticket cookies, which therefore belong to phpMyAdmin's hostname only.
 */
final class PmaHostController
{
    public static function enter(Ctx $ctx): never
    {
        self::requirePmaHost($ctx);
        $code = $ctx->req->query('code');
        $hash = hash('sha256', $code);
        $row = $code !== '' ? $ctx->db->one('SELECT * FROM handoffs WHERE code_hash = ?', [$hash]) : null;
        $ctx->db->run('DELETE FROM handoffs WHERE code_hash = ? OR expires_at <= ?', [$hash, time()]);
        if ($row === null || (int) $row['expires_at'] <= time()) {
            Response::redirect($ctx->cfg->publicUrl . '/servers?notice=open-expired', 303);
        }
        try {
            $cookie = $ctx->crypto->open((string) $row['ciphertext'], (string) $row['nonce'], 'dbportal/handoff/' . $hash);
        } catch (Throwable) {
            Response::redirect($ctx->cfg->publicUrl . '/servers?notice=open-expired', 303);
        }
        $slot = (int) $row['slot'];
        Auth::setCookie(Tickets::COOKIE_PREFIX . $slot, $cookie, 'Lax');
        Response::redirect('/index.php?server=' . $slot, 303);
    }

    /**
     * phpMyAdmin's "Log out" for one server: closes that session and returns to the portal.
     */
    public static function close(Ctx $ctx): never
    {
        self::requirePmaHost($ctx);
        $slot = (int) $ctx->req->query('slot');
        if ($slot >= 1 && $slot <= Tickets::MAX_SLOTS) {
            $name = Tickets::COOKIE_PREFIX . $slot;
            $idHash = Tickets::idHashFromCookie($ctx->req->cookie($name));
            if ($idHash !== null) {
                $ctx->tickets->revoke($idHash);
            }
            Auth::clearCookie($name, 'Lax');
        }
        Response::redirect($ctx->cfg->publicUrl . '/servers?notice=closed', 303);
    }

    private static function requirePmaHost(Ctx $ctx): void
    {
        if ($ctx->req->header('X-DBP-Host') !== 'pma') {
            Response::status(404);
        }
    }
}
