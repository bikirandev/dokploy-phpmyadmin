<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Sends responses with the portal's security headers.
 */
final class Response
{
    /** Allowed form targets (set at startup to include phpMyAdmin's hostname). */
    public static string $formAction = "'self'";

    public static function html(string $body, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        self::securityHeaders();
        echo $body;
        exit;
    }

    /** @param array<string, mixed> $data */
    public static function json(array $data, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        self::securityHeaders();
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        exit;
    }

    public static function redirect(string $location, int $status = 303): never
    {
        http_response_code($status);
        header('Location: ' . $location);
        self::securityHeaders();
        exit;
    }

    /** @param array<string, string> $headers */
    public static function status(int $status, array $headers = []): never
    {
        http_response_code($status);
        foreach ($headers as $name => $value) {
            header($name . ': ' . $value);
        }
        header('Cache-Control: no-store');
        exit;
    }

    public static function text(string $body, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        echo $body;
        exit;
    }

    private static function securityHeaders(): void
    {
        header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            . "font-src 'self'; connect-src 'self'; form-action " . self::$formAction . "; frame-ancestors 'none'; base-uri 'none'");
        header('X-Frame-Options: DENY');
        header('Cache-Control: no-store');
    }
}
