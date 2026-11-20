<?php

declare(strict_types=1);

namespace DbPortal;

use RuntimeException;

/**
 * Minimal outbound HTTP client (curl), no redirects, TLS verified.
 */
final class HttpClient
{
    /**
     * @param list<string> $headers
     * @return array{status: int, body: string}
     */
    public static function request(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $timeout = 10,
    ): array {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('Could not start HTTP request.');
        }
        $options = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_USERAGENT => 'dbportal/1.0',
        ];
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
        } else {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if ($response === false || !is_string($response)) {
            throw new RuntimeException('HTTP request failed: ' . $error);
        }

        return ['status' => $status, 'body' => $response];
    }

    /**
     * @param list<string> $headers
     * @return array<string, mixed>
     */
    public static function getJson(string $url, array $headers = [], int $timeout = 10): array
    {
        $res = self::request('GET', $url, array_merge(['Accept: application/json'], $headers), null, $timeout);
        if ($res['status'] !== 200) {
            throw new RuntimeException("GET $url returned HTTP {$res['status']}");
        }
        $data = json_decode($res['body'], true);
        if (!is_array($data)) {
            throw new RuntimeException("GET $url did not return JSON");
        }

        return $data;
    }
}
