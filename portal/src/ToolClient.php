<?php

declare(strict_types=1);

namespace DbPortal;

use RuntimeException;

/**
 * Asks a tool's container (phpMyAdmin's or pgAdmin's: the only parts allowed to reach databases)
 * to test a connection.
 */
final class ToolClient
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $token,
        public readonly string $label,
    ) {
    }

    /**
     * Full test: reachability, encryption, version, privileges and fingerprints.
     *
     * @param array<string, mixed> $descriptor
     * @return array<string, mixed>
     */
    public function test(array $descriptor): array
    {
        return $this->call('test', $descriptor, 45);
    }

    /**
     * Quick login check before opening the tool.
     *
     * @param array<string, mixed> $descriptor
     * @return array<string, mixed>
     */
    public function verify(array $descriptor): array
    {
        return $this->call('verify', $descriptor, 35);
    }

    /**
     * @param array<string, mixed> $descriptor
     * @return array<string, mixed>
     */
    private function call(string $action, array $descriptor, int $timeout): array
    {
        try {
            $res = HttpClient::request(
                'POST',
                $this->baseUrl . '/' . $action,
                ['Content-Type: application/json', 'X-Internal-Token: ' . $this->token],
                json_encode(['descriptor' => $descriptor], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
                $timeout,
            );
        } catch (RuntimeException) {
            return ['ok' => false, 'error' => $this->label . ' is not reachable right now. Try again in a minute.'];
        }
        $data = json_decode($res['body'], true);
        if ($res['status'] !== 200 || !is_array($data)) {
            return ['ok' => false, 'error' => $this->label . ' returned an unexpected answer.'];
        }

        return $data;
    }
}
