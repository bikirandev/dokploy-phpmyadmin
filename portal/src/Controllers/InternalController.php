<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Ctx;
use DbPortal\Response;
use DbPortal\Tickets;

/**
 * Endpoints for the gateway and phpMyAdmin's container only. The gateway never
 * routes /internal/ from outside, and each caller has its own secret token.
 */
final class InternalController
{
    /**
     * Called by the gateway before every request to phpMyAdmin's hostname.
     * Access needs a live ticket cookie whose portal session and user are still valid.
     * 204 + signed assertion = allowed; 401 = no valid session; 403 = upload too large.
     */
    public static function pmaAuth(Ctx $ctx): never
    {
        self::requireToken($ctx, $ctx->cfg->gatewayToken);
        $userId = null;
        for ($slot = 1; $slot <= Tickets::MAX_SLOTS && $userId === null; $slot++) {
            $idHash = Tickets::idHashFromCookie($ctx->req->cookie(Tickets::COOKIE_PREFIX . $slot));
            if ($idHash !== null) {
                $userId = $ctx->tickets->activeUser($idHash);
            }
        }
        if ($userId === null) {
            Response::status(401);
        }
        $method = strtoupper((string) $ctx->req->header('X-Original-Method'));
        $length = (int) $ctx->req->header('X-Original-Length');
        if (in_array($method, ['POST', 'PUT'], true) && $length > $ctx->settings->get('import_mb') * 1024 * 1024) {
            Response::status(403, ['X-DBP-Reason' => 'too-large']);
        }
        $assertion = $ctx->crypto->signToken('assert', ['u' => $userId], 120);
        Response::status(204, ['X-DBP-Assertion' => $assertion]);
    }

    /**
     * Called by phpMyAdmin's container: returns encrypted connection details for the
     * signed-in user's own open sessions. Decrypting them needs the key from that user's cookie.
     */
    public static function descriptors(Ctx $ctx): never
    {
        self::requireToken($ctx, $ctx->cfg->pmaToken);
        $body = $ctx->req->jsonBody();
        $assertion = $ctx->crypto->verifyToken('assert', (string) ($body['assertion'] ?? ''));
        if ($assertion === null || !is_int($assertion['u'] ?? null)) {
            Response::json(['servers' => []], 200);
        }
        $tickets = [];
        foreach ((array) ($body['tickets'] ?? []) as $slot => $ticket) {
            if (is_numeric($slot) && is_string($ticket) && (int) $slot >= 1 && (int) $slot <= Tickets::MAX_SLOTS) {
                $tickets[(int) $slot] = $ticket;
            }
        }
        Response::json(['servers' => $ctx->tickets->fetch($assertion['u'], $tickets)]);
    }

    private static function requireToken(Ctx $ctx, string $expected): void
    {
        $given = (string) $ctx->req->header('X-Internal-Token');
        if ($given === '' || !hash_equals($expected, $given)) {
            Response::status(404);
        }
    }
}
