<?php

declare(strict_types=1);

namespace DbPortal\Controllers;

use DbPortal\Ctx;
use DbPortal\Response;
use DbPortal\Tickets;

/**
 * Endpoints for the gateway and the tools' containers only. The gateway never routes
 * /internal/ from outside, and each caller has its own secret token.
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
        self::toolAuth($ctx, 'pma');
    }

    /** The same check for pgAdmin's hostname. */
    public static function pgaAuth(Ctx $ctx): never
    {
        self::toolAuth($ctx, 'pga');
    }

    /**
     * Called by phpMyAdmin's container: returns encrypted connection details for the
     * signed-in user's own open sessions. Decrypting them needs the key from that user's cookie.
     */
    public static function descriptors(Ctx $ctx): never
    {
        self::requireToken($ctx, $ctx->cfg->pmaToken);
        $body = $ctx->req->jsonBody();
        $userId = self::assertedUser($ctx, (string) ($body['assertion'] ?? ''), 'pma');
        if ($userId === null) {
            Response::json(['servers' => []], 200);
        }
        Response::json(['servers' => $ctx->tickets->fetch($userId, self::tickets($body), 'pma')]);
    }

    /**
     * Called by pgAdmin's container on each request: who the user is (a stable pgAdmin user name),
     * the encrypted connection details of the sessions this browser opened, and which of the
     * user's servers are open in any browser.
     */
    public static function pgaSession(Ctx $ctx): never
    {
        self::requireToken($ctx, $ctx->cfg->pgaToken);
        $body = $ctx->req->jsonBody();
        $userId = self::assertedUser($ctx, (string) ($body['assertion'] ?? ''), 'pga');
        $user = $userId !== null ? $ctx->db->one('SELECT subject FROM users WHERE id = ?', [$userId]) : null;
        if ($user === null) {
            Response::status(403);
        }
        Response::json([
            'user' => 'dbp-' . substr(hash('sha256', 'dbportal/pga-user|' . $user['subject']), 0, 24),
            'servers' => $ctx->tickets->fetch($userId, self::tickets($body), 'pga'),
            'open_rows' => $ctx->tickets->openPgaRows($userId),
        ]);
    }

    /**
     * Called by pgAdmin's container about once a minute: which of its open sessions are still
     * valid, so it can close the connections of the others.
     */
    public static function pgaAlive(Ctx $ctx): never
    {
        self::requireToken($ctx, $ctx->cfg->pgaToken);
        $body = $ctx->req->jsonBody();
        $hashes = array_values(array_unique(array_filter(
            (array) ($body['tickets'] ?? []),
            static fn (mixed $h): bool => is_string($h) && preg_match('/^[a-f0-9]{64}$/', $h) === 1,
        )));
        Response::json(['alive' => $ctx->tickets->alive(array_slice($hashes, 0, 500), 'pga')]);
    }

    private static function toolAuth(Ctx $ctx, string $app): never
    {
        self::requireToken($ctx, $ctx->cfg->gatewayToken);
        $prefix = Tickets::cookiePrefix($app);
        $userId = null;
        for ($slot = 1; $slot <= Tickets::MAX_SLOTS && $userId === null; $slot++) {
            $idHash = Tickets::idHashFromCookie($ctx->req->cookie($prefix . $slot));
            if ($idHash !== null) {
                $userId = $ctx->tickets->activeUser($idHash, $app);
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
        // Bound to the tool, so one tool's container can't replay it to the other.
        $assertion = $ctx->crypto->signToken('assert', ['u' => $userId, 'a' => $app], 120);
        Response::status(204, ['X-DBP-Assertion' => $assertion]);
    }

    private static function assertedUser(Ctx $ctx, string $assertion, string $app): ?int
    {
        $payload = $ctx->crypto->verifyToken('assert', $assertion);
        if ($payload === null || !is_int($payload['u'] ?? null) || ($payload['a'] ?? null) !== $app) {
            return null;
        }

        return $payload['u'];
    }

    /**
     * @param array<string, mixed> $body
     * @return array<int, string> base64url ticket ids by slot
     */
    private static function tickets(array $body): array
    {
        $tickets = [];
        foreach ((array) ($body['tickets'] ?? []) as $slot => $ticket) {
            if (is_numeric($slot) && is_string($ticket) && (int) $slot >= 1 && (int) $slot <= Tickets::MAX_SLOTS) {
                $tickets[(int) $slot] = $ticket;
            }
        }

        return $tickets;
    }

    private static function requireToken(Ctx $ctx, string $expected): void
    {
        $given = (string) $ctx->req->header('X-Internal-Token');
        if ($given === '' || !hash_equals($expected, $given)) {
            Response::status(404);
        }
    }
}
