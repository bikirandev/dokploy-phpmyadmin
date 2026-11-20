<?php

declare(strict_types=1);

namespace DbPortal;

use RuntimeException;

/**
 * Vault encryption (XChaCha20-Poly1305) and signed tokens, all derived from VAULT_KEY.
 */
final class Crypto
{
    private string $vaultKey;
    private string $macKey;

    public function __construct(string $masterKey)
    {
        $this->vaultKey = sodium_crypto_kdf_derive_from_key(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            1,
            'dbpvault',
            $masterKey,
        );
        $this->macKey = sodium_crypto_kdf_derive_from_key(32, 2, 'dbpmacs1', $masterKey);
    }

    /** @return array{0: string, 1: string} ciphertext, nonce */
    public function seal(string $plaintext, string $associatedData): array
    {
        return self::sealWithKey($this->vaultKey, $plaintext, $associatedData);
    }

    public function open(string $ciphertext, string $nonce, string $associatedData): string
    {
        return self::openWithKey($this->vaultKey, $ciphertext, $nonce, $associatedData);
    }

    /** @return array{0: string, 1: string} ciphertext, nonce */
    public static function sealWithKey(string $key, string $plaintext, string $associatedData): array
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $associatedData, $nonce, $key);

        return [$ciphertext, $nonce];
    }

    public static function openWithKey(string $key, string $ciphertext, string $nonce, string $associatedData): string
    {
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $associatedData, $nonce, $key);
        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed.');
        }

        return $plaintext;
    }

    /**
     * Signed, expiring token: base64url(json) "." base64url(hmac).
     */
    public function signToken(string $purpose, array $payload, int $ttlSeconds): string
    {
        $payload['exp'] = time() + $ttlSeconds;
        $body = self::b64e(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $body . '.' . self::b64e($this->mac($purpose, $body));
    }

    /** @return array<string, mixed>|null */
    public function verifyToken(string $purpose, string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return null;
        }
        [$body, $signature] = $parts;
        if (!hash_equals(self::b64e($this->mac($purpose, $body)), $signature)) {
            return null;
        }
        $payload = json_decode(self::b64d($body), true);
        if (!is_array($payload) || !is_int($payload['exp'] ?? null) || $payload['exp'] < time()) {
            return null;
        }

        return $payload;
    }

    public static function randomToken(int $bytes = 32): string
    {
        return self::b64e(random_bytes($bytes));
    }

    public static function b64e(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function b64d(string $data): string
    {
        if ($data === '' || preg_match('/[^A-Za-z0-9_-]/', $data)) {
            return '';
        }
        $padded = strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4);
        $decoded = base64_decode($padded, true);

        return $decoded === false ? '' : $decoded;
    }

    private function mac(string $purpose, string $data): string
    {
        return hash_hmac('sha256', $purpose . "\0" . $data, $this->macKey, true);
    }
}
