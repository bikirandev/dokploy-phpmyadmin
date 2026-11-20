<?php

declare(strict_types=1);

namespace DbPortal;

use RuntimeException;

/**
 * Settings read from environment variables (Dokploy's Environment tab).
 */
final class Config
{
    /**
     * @param list<string> $oidcRequiredAmr
     * @param list<string> $adminSubjects
     * @param list<string> $egressAllowCidrs
     */
    public function __construct(
        public readonly string $publicUrl,
        public readonly string $pmaPublicUrl,
        public readonly string $pgaPublicUrl,
        public readonly string $portalName,
        public readonly string $providerName,
        public readonly string $oidcIssuer,
        public readonly string $oidcClientId,
        public readonly string $oidcClientSecret,
        public readonly string $oidcScopes,
        public readonly string $oidcTokenAuth,
        public readonly string $oidcUserIdClaim,
        public readonly string $oidcEmailClaim,
        public readonly string $oidcNameClaim,
        public readonly array $oidcRequiredAmr,
        public readonly bool $oidcRequireEmailVerified,
        public readonly bool $oidcAllowHttp,
        public readonly string $vaultKey,
        public readonly string $gatewayToken,
        public readonly string $pmaToken,
        public readonly string $pmaInternalUrl,
        public readonly string $pgaToken,
        public readonly string $pgaInternalUrl,
        public readonly array $adminSubjects,
        public readonly string $dataDir,
        public readonly string $egressIp,
        public readonly array $egressAllowCidrs,
    ) {
    }

    public static function fromEnv(): self
    {
        $publicUrl = rtrim(self::required('PUBLIC_URL'), '/');
        if (!preg_match('#^https://[A-Za-z0-9.-]+(:\d{1,5})?$#', $publicUrl)) {
            throw new RuntimeException('PUBLIC_URL must look like https://db.example.com (https, no path).');
        }
        // phpMyAdmin lives on its own hostname so its pages can never act on the portal's origin.
        $pmaPublicUrl = rtrim(self::required('PMA_PUBLIC_URL'), '/');
        if (!preg_match('#^https://[A-Za-z0-9.-]+(:\d{1,5})?$#', $pmaPublicUrl)) {
            throw new RuntimeException('PMA_PUBLIC_URL must look like https://pma.db.example.com (https, no path).');
        }
        if (strcasecmp($pmaPublicUrl, $publicUrl) === 0) {
            throw new RuntimeException('PMA_PUBLIC_URL must use a different hostname from PUBLIC_URL.');
        }
        // pgAdmin too, and apart from phpMyAdmin.
        $pgaPublicUrl = rtrim(self::required('PGA_PUBLIC_URL'), '/');
        if (!preg_match('#^https://[A-Za-z0-9.-]+(:\d{1,5})?$#', $pgaPublicUrl)) {
            throw new RuntimeException('PGA_PUBLIC_URL must look like https://pg.db.example.com (https, no path).');
        }
        if (strcasecmp($pgaPublicUrl, $publicUrl) === 0 || strcasecmp($pgaPublicUrl, $pmaPublicUrl) === 0) {
            throw new RuntimeException('PGA_PUBLIC_URL must use a hostname of its own (not the portal\'s or phpMyAdmin\'s).');
        }

        $allowHttp = self::bool('OIDC_ALLOW_HTTP', false);
        $issuer = rtrim(self::required('OIDC_ISSUER'), '/');
        if (!$allowHttp && !str_starts_with($issuer, 'https://')) {
            throw new RuntimeException('OIDC_ISSUER must use https.');
        }

        $tokenAuth = strtolower(self::value('OIDC_TOKEN_AUTH', 'basic') ?? 'basic');
        if (!in_array($tokenAuth, ['basic', 'post'], true)) {
            throw new RuntimeException('OIDC_TOKEN_AUTH must be "basic" or "post".');
        }

        $vaultKey = base64_decode(self::required('VAULT_KEY'), true);
        if ($vaultKey === false || strlen($vaultKey) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
            throw new RuntimeException('VAULT_KEY must be 32 random bytes, base64-encoded (openssl rand -base64 32).');
        }

        $tokens = ['GATEWAY_TOKEN', 'PMA_TOKEN', 'PGA_TOKEN'];
        foreach ($tokens as $name) {
            if (strlen(self::required($name)) < 32) {
                throw new RuntimeException("$name must be at least 32 characters.");
            }
        }
        foreach ([[0, 1], [0, 2], [1, 2]] as [$a, $b]) {
            if (hash_equals(self::required($tokens[$a]), self::required($tokens[$b]))) {
                throw new RuntimeException("{$tokens[$a]} and {$tokens[$b]} must be different.");
            }
        }

        return new self(
            publicUrl: $publicUrl,
            pmaPublicUrl: $pmaPublicUrl,
            pgaPublicUrl: $pgaPublicUrl,
            portalName: self::value('PORTAL_NAME', 'DB Portal') ?? 'DB Portal',
            providerName: self::value('OIDC_PROVIDER_NAME', 'Bikiran') ?? 'Bikiran',
            oidcIssuer: $issuer,
            oidcClientId: self::required('OIDC_CLIENT_ID'),
            oidcClientSecret: self::value('OIDC_CLIENT_SECRET', '') ?? '',
            oidcScopes: self::value('OIDC_SCOPES', 'openid email profile') ?? 'openid email profile',
            oidcTokenAuth: $tokenAuth,
            oidcUserIdClaim: self::value('OIDC_USER_ID_CLAIM', 'sub') ?? 'sub',
            oidcEmailClaim: self::value('OIDC_EMAIL_CLAIM', 'email') ?? 'email',
            oidcNameClaim: self::value('OIDC_NAME_CLAIM', 'name') ?? 'name',
            oidcRequiredAmr: self::list('OIDC_REQUIRED_AMR'),
            oidcRequireEmailVerified: self::bool('OIDC_REQUIRE_EMAIL_VERIFIED', false),
            oidcAllowHttp: $allowHttp,
            vaultKey: $vaultKey,
            gatewayToken: self::required('GATEWAY_TOKEN'),
            pmaToken: self::required('PMA_TOKEN'),
            pmaInternalUrl: rtrim(self::value('PMA_INTERNAL_URL', 'http://pma:8081') ?? 'http://pma:8081', '/'),
            pgaToken: self::required('PGA_TOKEN'),
            pgaInternalUrl: rtrim(self::value('PGA_INTERNAL_URL', 'http://pga:8081') ?? 'http://pga:8081', '/'),
            adminSubjects: self::list('ADMIN_SUBJECTS'),
            dataDir: rtrim(self::value('DATA_DIR', '/data') ?? '/data', '/'),
            egressIp: self::value('EGRESS_IP', '') ?? '',
            egressAllowCidrs: self::list('EGRESS_ALLOW_CIDRS'),
        );
    }

    public function redirectUri(): string
    {
        return $this->publicUrl . '/auth/callback';
    }

    private static function value(string $key, ?string $default = null): ?string
    {
        $value = getenv($key);
        if ($value === false) {
            return $default;
        }
        $value = trim($value);

        return $value === '' ? $default : $value;
    }

    private static function required(string $key): string
    {
        $value = self::value($key);
        if ($value === null) {
            throw new RuntimeException("Missing required setting: $key");
        }

        return $value;
    }

    private static function bool(string $key, bool $default): bool
    {
        $value = self::value($key);

        return $value === null ? $default : filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /** @return list<string> */
    private static function list(string $key): array
    {
        $parts = array_map('trim', explode(',', self::value($key, '') ?? ''));

        return array_values(array_filter($parts, static fn (string $p): bool => $p !== ''));
    }
}
