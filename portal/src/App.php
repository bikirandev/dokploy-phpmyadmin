<?php

declare(strict_types=1);

namespace DbPortal;

use DbPortal\Controllers\ActivityController;
use DbPortal\Controllers\AdminController;
use DbPortal\Controllers\AuthController;
use DbPortal\Controllers\InternalController;
use DbPortal\Controllers\PmaHostController;
use DbPortal\Controllers\ServerController;
use Throwable;

/**
 * Front controller: builds the context and dispatches routes.
 */
final class App
{
    /** @var list<array{0: string, 1: string, 2: callable}> */
    private const ROUTES = [
        ['GET', '#^/$#', [AuthController::class, 'home']],
        ['GET', '#^/healthz$#', [AuthController::class, 'health']],
        ['GET', '#^/signin$#', [AuthController::class, 'signin']],
        ['GET', '#^/auth/login$#', [AuthController::class, 'login']],
        ['GET', '#^/auth/callback$#', [AuthController::class, 'callback']],
        ['POST', '#^/auth/logout$#', [AuthController::class, 'logout']],
        ['GET', '#^/welcome$#', [AuthController::class, 'welcome']],
        ['POST', '#^/welcome$#', [AuthController::class, 'agree']],
        ['GET', '#^/emergency/([A-Za-z0-9_-]{40,64})$#', [AuthController::class, 'emergencyForm']],
        ['POST', '#^/emergency/([A-Za-z0-9_-]{40,64})$#', [AuthController::class, 'emergencyUse']],

        ['GET', '#^/servers$#', [ServerController::class, 'index']],
        ['GET', '#^/servers/new$#', [ServerController::class, 'create']],
        ['POST', '#^/servers$#', [ServerController::class, 'store']],
        ['POST', '#^/servers/test$#', [ServerController::class, 'test']],
        ['GET', '#^/servers/(\d{1,10})/edit$#', [ServerController::class, 'edit']],
        ['POST', '#^/servers/(\d{1,10})$#', [ServerController::class, 'update']],
        ['POST', '#^/servers/(\d{1,10})/delete$#', [ServerController::class, 'delete']],
        ['GET', '#^/servers/(\d{1,10})/open$#', [ServerController::class, 'openForm']],
        ['POST', '#^/servers/(\d{1,10})/open$#', [ServerController::class, 'open']],

        // On phpMyAdmin's hostname (routed by the gateway with X-DBP-Host: pma)
        ['GET', '#^/__dbportal/enter$#', [PmaHostController::class, 'enter']],
        ['GET', '#^/__dbportal/close$#', [PmaHostController::class, 'close']],

        ['GET', '#^/activity$#', [ActivityController::class, 'index']],

        ['GET', '#^/admin$#', [AdminController::class, 'index']],
        ['POST', '#^/admin/limits$#', [AdminController::class, 'limits']],
        ['POST', '#^/admin/accounts/(\d{1,10})/(suspend|reactivate)$#', [AdminController::class, 'account']],

        ['GET', '#^/internal/pma-auth$#', [InternalController::class, 'pmaAuth']],
        ['POST', '#^/internal/descriptors$#', [InternalController::class, 'descriptors']],
    ];

    public static function run(): void
    {
        $req = Request::fromGlobals();
        try {
            $cfg = Config::fromEnv();
        } catch (Throwable $e) {
            error_log('[dbportal] configuration error: ' . $e->getMessage());
            Response::text("The portal is not configured correctly. Check the container logs.\n", 500);
        }

        // Opening a server submits a form that redirects to phpMyAdmin's hostname.
        Response::$formAction = "'self' " . $cfg->pmaPublicUrl;

        $db = new Db($cfg->dataDir . '/portal.sqlite');
        $crypto = new Crypto($cfg->vaultKey);
        $ctx = new Ctx(
            cfg: $cfg,
            db: $db,
            crypto: $crypto,
            req: $req,
            view: new View(dirname(__DIR__) . '/templates'),
            settings: new Settings($db),
            events: new Events($db),
            limiter: new RateLimiter($db),
            auth: new Auth($db),
            servers: new Servers($db, $crypto),
            tickets: new Tickets($db),
            pma: new PmaClient($cfg),
            oidc: new Oidc($cfg, $db),
        );

        if (random_int(1, 200) === 1) {
            self::cleanup($ctx);
        }

        try {
            self::dispatch($ctx);
        } catch (HttpException $e) {
            self::fail($ctx, $e->status, $e->getMessage());
        } catch (Throwable $e) {
            error_log('[dbportal] ' . get_class($e) . ': ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
            self::fail($ctx, 500, 'Something went wrong. Please try again.');
        }
    }

    private static function dispatch(Ctx $ctx): void
    {
        $allowed = false;
        foreach (self::ROUTES as [$method, $pattern, $handler]) {
            if (!preg_match($pattern, $ctx->req->path, $m)) {
                continue;
            }
            $allowed = true;
            if ($method !== $ctx->req->method) {
                continue;
            }
            array_shift($m);
            $handler($ctx, $m);

            return;
        }

        throw new HttpException($allowed ? 405 : 404, $allowed ? 'This action is not allowed here.' : 'Page not found.');
    }

    private static function fail(Ctx $ctx, int $status, string $message): never
    {
        if (str_starts_with($ctx->req->path, '/internal/')) {
            Response::status($status === 404 ? 404 : 500);
        }
        if ($ctx->req->header('Accept') === 'application/json' || $ctx->req->path === '/servers/test') {
            Response::json(['ok' => false, 'error' => $message], $status);
        }
        $ctx->render('error', ['status' => $status, 'message' => $message], $status, $ctx->user !== null ? 'layout' : 'bare');
    }

    private static function cleanup(Ctx $ctx): void
    {
        $now = time();
        $ctx->events->cleanup();
        $ctx->limiter->cleanup();
        $ctx->tickets->cleanup();
        $ctx->db->run('DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?', [$now, $now - Auth::IDLE_SECONDS]);
        $ctx->db->run('DELETE FROM auth_requests WHERE created_at <= ?', [$now - 600]);
        $ctx->db->run('DELETE FROM emergency_tokens WHERE expires_at <= ?', [$now - 86400]);
        $ctx->db->run('DELETE FROM cache WHERE expires_at <= ?', [$now]);
        $ctx->db->run('DELETE FROM handoffs WHERE expires_at <= ?', [$now]);
    }
}
