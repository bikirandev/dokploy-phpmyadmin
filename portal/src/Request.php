<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * The incoming HTTP request.
 */
final class Request
{
    /**
     * @param array<string, mixed> $query
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     * @param array<string, mixed> $files
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        private readonly array $query,
        private readonly array $post,
        private readonly array $cookies,
        private readonly array $server,
        private readonly array $files,
    ) {
    }

    public static function fromGlobals(): self
    {
        $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);

        return new self(
            strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
            is_string($path) && $path !== '' ? $path : '/',
            $_GET,
            $_POST,
            $_COOKIE,
            $_SERVER,
            $_FILES,
        );
    }

    public function query(string $key, string $default = ''): string
    {
        $value = $this->query[$key] ?? $default;

        return is_string($value) ? $value : $default;
    }

    public function post(string $key, string $default = ''): string
    {
        $value = $this->post[$key] ?? $default;

        return is_string($value) ? $value : $default;
    }

    public function has(string $key): bool
    {
        return isset($this->post[$key]);
    }

    public function cookie(string $key): ?string
    {
        $value = $this->cookies[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    public function header(string $name): ?string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        $value = $this->server[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    public function ip(): string
    {
        return (string) ($this->server['REMOTE_ADDR'] ?? '');
    }

    public function userAgent(): string
    {
        return mb_substr((string) ($this->server['HTTP_USER_AGENT'] ?? ''), 0, 255);
    }

    /**
     * An uploaded file's contents, or null when nothing was uploaded.
     */
    public function uploadedFile(string $key, int $maxBytes): ?string
    {
        $file = $this->files[$key] ?? null;
        if (!is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            return null;
        }
        if (($file['error'] ?? 1) !== UPLOAD_ERR_OK || !is_uploaded_file((string) $file['tmp_name'])) {
            throw new HttpException(400, 'The file could not be uploaded.');
        }
        if ((int) $file['size'] > $maxBytes) {
            throw new HttpException(400, 'The file is too large.');
        }

        return (string) file_get_contents((string) $file['tmp_name']);
    }

    /** @return array<string, mixed> */
    public function jsonBody(): array
    {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw === false ? '' : $raw, true);

        return is_array($data) ? $data : [];
    }
}
