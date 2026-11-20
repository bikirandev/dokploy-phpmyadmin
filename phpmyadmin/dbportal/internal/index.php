<?php

declare(strict_types=1);

/*
 * Internal API for the portal (port 8081, internal network only, token-protected).
 * POST /test    full connection test
 * POST /verify  quick login check before opening phpMyAdmin
 */
require '/opt/dbportal/lib.php';

use DbPortalPma\Env;
use DbPortalPma\Tester;

header('Content-Type: application/json');
header('Cache-Control: no-store');

$token = $_SERVER['HTTP_X_INTERNAL_TOKEN'] ?? '';
if (!is_string($token) || Env::token() === '' || !hash_equals(Env::token(), $token)) {
    http_response_code(404);
    exit;
}

$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !in_array($path, ['/test', '/verify'], true)) {
    http_response_code(404);
    exit;
}

$body = json_decode((string) file_get_contents('php://input'), true);
$descriptor = is_array($body) && is_array($body['descriptor'] ?? null) ? $body['descriptor'] : null;
if ($descriptor === null) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Bad request.']);
    exit;
}

echo json_encode(Tester::run($descriptor, $path === '/test'), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
