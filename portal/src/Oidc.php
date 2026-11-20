<?php

declare(strict_types=1);

namespace DbPortal;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use RuntimeException;
use Throwable;
use UnexpectedValueException;

/**
 * "Continue with Bikiran": OpenID Connect authorization code flow with PKCE.
 */
final class Oidc
{
    private const SUPPORTED_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'EdDSA'];

    public function __construct(private readonly Config $cfg, private readonly Db $db)
    {
    }

    /** @return array<string, mixed> */
    public function discovery(): array
    {
        return $this->cached('oidc:discovery', 3600, function (): array {
            $doc = HttpClient::getJson($this->cfg->oidcIssuer . '/.well-known/openid-configuration');
            if (rtrim((string) ($doc['issuer'] ?? ''), '/') !== $this->cfg->oidcIssuer) {
                throw new RuntimeException('The identity provider reported a different issuer.');
            }
            foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
                $url = (string) ($doc[$field] ?? '');
                if (!$this->isAllowedUrl($url)) {
                    throw new RuntimeException("The identity provider's $field is missing or not https.");
                }
            }

            return $doc;
        });
    }

    public function authorizationUrl(string $state, string $nonce, string $codeChallenge, bool $selectAccount): string
    {
        $params = [
            'response_type' => 'code',
            'client_id' => $this->cfg->oidcClientId,
            'redirect_uri' => $this->cfg->redirectUri(),
            'scope' => $this->cfg->oidcScopes,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];
        if ($selectAccount) {
            $params['prompt'] = 'select_account';
        }
        $endpoint = (string) $this->discovery()['authorization_endpoint'];

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchanges the code and returns the verified ID token claims.
     *
     * @return array<string, mixed>
     */
    public function finish(string $code, string $verifier, string $nonce): array
    {
        $disc = $this->discovery();
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->cfg->redirectUri(),
            'code_verifier' => $verifier,
        ];
        $headers = ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'];
        if ($this->cfg->oidcTokenAuth === 'basic' && $this->cfg->oidcClientSecret !== '') {
            $headers[] = 'Authorization: Basic ' . base64_encode(
                rawurlencode($this->cfg->oidcClientId) . ':' . rawurlencode($this->cfg->oidcClientSecret),
            );
        } else {
            $form['client_id'] = $this->cfg->oidcClientId;
            if ($this->cfg->oidcClientSecret !== '') {
                $form['client_secret'] = $this->cfg->oidcClientSecret;
            }
        }
        $res = HttpClient::request('POST', (string) $disc['token_endpoint'], $headers, http_build_query($form, '', '&'), 15);
        $tokens = json_decode($res['body'], true);
        if ($res['status'] !== 200 || !is_array($tokens) || !is_string($tokens['id_token'] ?? null)) {
            throw new RuntimeException('The identity provider did not return an ID token (HTTP ' . $res['status'] . ').');
        }

        return $this->verifyIdToken($tokens['id_token'], $nonce);
    }

    /** @return array<string, mixed> */
    private function verifyIdToken(string $jwt, string $nonce): array
    {
        $disc = $this->discovery();
        $advertised = $disc['id_token_signing_alg_values_supported'] ?? ['RS256'];
        $algs = array_values(array_intersect(is_array($advertised) ? $advertised : ['RS256'], self::SUPPORTED_ALGS));
        if ($algs === []) {
            throw new RuntimeException('The identity provider uses no supported signing algorithm.');
        }

        JWT::$leeway = 60;
        try {
            $claims = $this->decode($jwt, $algs, false);
        } catch (UnexpectedValueException $e) {
            // The provider may have rotated its keys: fetch them again once.
            if (!str_contains(strtolower($e->getMessage()), 'kid')) {
                throw $e;
            }
            $claims = $this->decode($jwt, $algs, true);
        }

        if (($claims['iss'] ?? null) !== $disc['issuer']) {
            throw new RuntimeException('ID token issuer mismatch.');
        }
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->cfg->oidcClientId, $audiences, true)) {
            throw new RuntimeException('ID token audience mismatch.');
        }
        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $this->cfg->oidcClientId) {
            throw new RuntimeException('ID token authorized party mismatch.');
        }
        if (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce'])) {
            throw new RuntimeException('ID token nonce mismatch.');
        }
        if (!is_int($claims['iat'] ?? null) || !is_int($claims['exp'] ?? null)) {
            throw new RuntimeException('ID token is missing its time claims.');
        }

        return $claims;
    }

    /**
     * @param list<string> $algs
     * @return array<string, mixed>
     */
    private function decode(string $jwt, array $algs, bool $refreshKeys): array
    {
        $jwks = $this->jwks($refreshKeys);
        $header = json_decode(Crypto::b64d(explode('.', $jwt)[0] ?? ''), true);
        $alg = is_array($header) ? ($header['alg'] ?? '') : '';
        if (!in_array($alg, $algs, true)) {
            throw new RuntimeException('ID token uses an unexpected signing algorithm.');
        }
        $keys = JWK::parseKeySet($jwks, $alg);
        $decoded = JWT::decode($jwt, $keys);
        $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), true);

        return is_array($claims) ? $claims : [];
    }

    /** @return array<string, mixed> */
    private function jwks(bool $refresh): array
    {
        if ($refresh) {
            $this->db->run('DELETE FROM cache WHERE key = ?', ['oidc:jwks']);
        }

        return $this->cached('oidc:jwks', 3600, function (): array {
            $jwks = HttpClient::getJson((string) $this->discovery()['jwks_uri']);
            if (!is_array($jwks['keys'] ?? null)) {
                throw new RuntimeException('The identity provider returned no signing keys.');
            }
            // Keep signing keys only.
            $jwks['keys'] = array_values(array_filter(
                $jwks['keys'],
                static fn ($k): bool => is_array($k) && ($k['use'] ?? 'sig') === 'sig',
            ));

            return $jwks;
        });
    }

    private function isAllowedUrl(string $url): bool
    {
        if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        return str_starts_with($url, 'https://') || ($this->cfg->oidcAllowHttp && str_starts_with($url, 'http://'));
    }

    /**
     * @param callable(): array<string, mixed> $load
     * @return array<string, mixed>
     */
    private function cached(string $key, int $ttl, callable $load): array
    {
        $row = $this->db->one('SELECT value, expires_at FROM cache WHERE key = ?', [$key]);
        if ($row !== null && (int) $row['expires_at'] > time()) {
            $value = json_decode((string) $row['value'], true);
            if (is_array($value)) {
                return $value;
            }
        }
        try {
            $value = $load();
        } catch (Throwable $e) {
            throw new RuntimeException('Could not reach the identity provider: ' . $e->getMessage(), 0, $e);
        }
        $this->db->run(
            'INSERT INTO cache (key, value, expires_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at',
            [$key, json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), time() + $ttl],
        );

        return $value;
    }
}
