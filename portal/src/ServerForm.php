<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Reads and validates the add/edit server form.
 */
final class ServerForm
{
    /**
     * @param array<string, mixed>|null $existing the stored server when editing
     * @return array{data: array<string, mixed>, secrets: array{db_password: string, ssh_secret: string}, errors: array<string, string>}
     */
    public static function parse(Request $req, Ctx $ctx, ?array $existing, bool $forTest): array
    {
        $errors = [];
        $userId = (int) $ctx->user['id'];
        $stored = $existing !== null ? $ctx->servers->secrets($existing) : ['db_password' => '', 'ssh_secret' => ''];

        $name = trim($req->post('name'));
        if (!$forTest && ($name === '' || mb_strlen($name) > 80)) {
            $errors['name'] = 'Enter a name of up to 80 characters.';
        }
        $environment = $req->post('environment', 'Production');
        if (!in_array($environment, Servers::ENVIRONMENTS, true)) {
            $errors['environment'] = 'Choose an environment.';
            $environment = 'Production';
        }

        $location = $req->post('location') === 'local' ? 'local' : 'remote';
        $method = $location === 'local' ? 'internal' : $req->post('method', 'tls');
        if (!in_array($method, ['tls', 'pinned', 'ssh', 'internal'], true) || ($location === 'remote' && $method === 'internal')) {
            $errors['method'] = 'Choose how to connect.';
            $method = 'tls';
        }

        // Database endpoint. For SSH it is the address as seen from the SSH server.
        if ($method === 'ssh') {
            $host = trim($req->post('ssh_db_host')) ?: '127.0.0.1';
            $portRaw = trim($req->post('ssh_db_port')) ?: '3306';
        } elseif ($method === 'internal') {
            $host = trim($req->post('internal_host'));
            $portRaw = trim($req->post('internal_port')) ?: '3306';
        } else {
            $host = trim($req->post('host'));
            $portRaw = trim($req->post('port')) ?: '3306';
        }
        $allow = $ctx->cfg->egressAllowCidrs;
        $selfMessage = 'This is this Dokploy server\'s address. For its databases, choose "On this server".';
        if ($method === 'internal') {
            if (!NetPolicy::isHostname($host, true) && !NetPolicy::isIp($host)) {
                $errors['host'] = 'Enter the database\'s Internal Host from Dokploy.';
            } elseif (NetPolicy::isIp($host) && NetPolicy::isSelf($host, $ctx->cfg)) {
                $errors['host'] = 'This is this server\'s public address. Enter the database\'s Internal Host from Dokploy (Internal Credentials → Internal Host).';
            } elseif (NetPolicy::isIp($host) && NetPolicy::isPublicIp($host)) {
                $errors['host'] = 'This is a public address. Choose "Remote server" for it.';
            }
        } elseif ($method === 'ssh') {
            if (!NetPolicy::isHostname($host, true) && !NetPolicy::isIp($host)) {
                $errors['host'] = 'Enter the database host as seen from the SSH server, for example 127.0.0.1.';
            }
        } elseif (!NetPolicy::isHostname($host) && !NetPolicy::isIp($host)) {
            $errors['host'] = 'Enter a host name or IP address.';
        } elseif (NetPolicy::isIp($host) && NetPolicy::isSelf($host, $ctx->cfg)) {
            $errors['host'] = $selfMessage;
        } elseif (NetPolicy::isIp($host) && !NetPolicy::isPublicIp($host) && !NetPolicy::inCidrs($host, $allow)) {
            $errors['host'] = 'Use the server\'s public address, or connect through an SSH tunnel.';
        }
        $port = self::port($portRaw);
        if ($port === null) {
            $errors['port'] = 'Enter a port from 1 to 65535.';
            $port = 3306;
        }

        // SSH settings
        $sshHost = '';
        $sshPort = 22;
        $sshUser = '';
        $sshAuth = '';
        $sshSecret = '';
        if ($method === 'ssh') {
            $sshHost = trim($req->post('ssh_host'));
            if (!NetPolicy::isHostname($sshHost) && !NetPolicy::isIp($sshHost)) {
                $errors['ssh_host'] = 'Enter the SSH server\'s host name or IP address.';
            } elseif (NetPolicy::isIp($sshHost) && NetPolicy::isSelf($sshHost, $ctx->cfg)) {
                $errors['ssh_host'] = $selfMessage;
            } elseif (NetPolicy::isIp($sshHost) && !NetPolicy::isPublicIp($sshHost) && !NetPolicy::inCidrs($sshHost, $allow)) {
                $errors['ssh_host'] = 'Use the SSH server\'s public address.';
            }
            $sshPort = self::port(trim($req->post('ssh_port')) ?: '22') ?? 0;
            if ($sshPort === 0) {
                $errors['ssh_port'] = 'Enter a port from 1 to 65535.';
                $sshPort = 22;
            }
            $sshUser = trim($req->post('ssh_user'));
            if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $sshUser)) {
                $errors['ssh_user'] = 'Enter the SSH user name.';
            }
            $sshAuth = $req->post('ssh_auth') === 'password' ? 'password' : 'key';
            if ($sshAuth === 'key') {
                $key = str_replace(["\r\n", "\r"], "\n", trim($req->post('ssh_key')));
                if ($key !== '') {
                    if (strlen($key) > 16384 || !preg_match('/^-----BEGIN [A-Z ]*PRIVATE KEY-----\n.+\n-----END [A-Z ]*PRIVATE KEY-----$/s', $key)) {
                        $errors['ssh_key'] = 'Paste the whole private key, including the BEGIN and END lines.';
                    }
                    $sshSecret = $key . "\n";
                }
            } else {
                $password = $req->post('ssh_password');
                if (strlen($password) > 256) {
                    $errors['ssh_password'] = 'The SSH password is too long.';
                }
                $sshSecret = $password;
            }
            $sameSsh = $existing !== null && $existing['method'] === 'ssh' && $existing['ssh_auth'] === $sshAuth;
            if ($sshSecret === '' && $sameSsh && $stored['ssh_secret'] !== '') {
                $sshSecret = $stored['ssh_secret'];
            }
            if ($sshSecret === '' && !isset($errors['ssh_key'])) {
                $errors[$sshAuth === 'key' ? 'ssh_key' : 'ssh_password'] = $sshAuth === 'key'
                    ? 'Paste the SSH private key.'
                    : 'Enter the SSH password.';
            }
        }

        // Database login
        $dbUser = trim($req->post('db_user'));
        if ($dbUser === '' || mb_strlen($dbUser) > 80) {
            $errors['db_user'] = 'Enter the database user.';
        } elseif (strcasecmp($dbUser, 'root') === 0) {
            $errors['db_user'] = 'root is blocked. Use a user with only the privileges it needs.';
        }
        $credMode = $req->post('cred_mode') === 'saved' ? 'saved' : 'ask';
        $dbPassword = $req->post('db_password');
        if (strlen($dbPassword) > 256) {
            $errors['db_password'] = 'The password is too long.';
        }
        if ($dbPassword === '' && $existing !== null && $stored['db_password'] !== '' && $existing['db_user'] === $dbUser) {
            $dbPassword = $stored['db_password'];
        }
        if ($dbPassword === '') {
            if ($forTest) {
                $errors['db_password'] = 'Enter the password to run a test.';
            } elseif ($credMode === 'saved') {
                $errors['db_password'] = 'Enter the password to save it, or choose "Ask every time".';
            }
        }

        // Custom CA for verified TLS
        $caPem = '';
        if ($method === 'tls') {
            $upload = $req->uploadedFile('ca_file', 65536);
            if ($upload !== null) {
                $cert = @openssl_x509_read($upload);
                if ($cert === false || !openssl_x509_export($cert, $caPem)) {
                    $errors['ca_file'] = 'This file is not a PEM certificate.';
                    $caPem = '';
                }
            } elseif ($req->post('ca_remove') !== '1' && $existing !== null && $existing['method'] === 'tls') {
                $caPem = (string) $existing['ca_pem'];
            }
        }

        // Pinned certificate or SSH host key
        $pin = ['pin_sha256' => '', 'pin_pem' => '', 'pin_strict' => 0, 'ssh_hostkey' => '', 'ssh_fingerprint' => ''];
        if ($method === 'pinned' || $method === 'ssh') {
            $kind = $method === 'pinned' ? 'tls' : 'ssh';
            $target = $method === 'pinned' ? strtolower($host) . ':' . $port : strtolower($sshHost) . ':' . $sshPort;
            $token = $req->post('pin_token');
            $payload = $token !== '' ? $ctx->crypto->verifyToken('pin', $token) : null;
            if ($payload !== null && ($payload['u'] ?? null) === $userId && ($payload['k'] ?? '') === $kind && ($payload['t'] ?? '') === $target) {
                $pin = self::pinFields($kind, $payload);
            } elseif ($existing !== null && $existing['method'] === $method && self::existingTarget($existing) === $target) {
                $pin = [
                    'pin_sha256' => (string) $existing['pin_sha256'],
                    'pin_pem' => (string) $existing['pin_pem'],
                    'pin_strict' => (int) $existing['pin_strict'],
                    'ssh_hostkey' => (string) $existing['ssh_hostkey'],
                    'ssh_fingerprint' => (string) $existing['ssh_fingerprint'],
                ];
            } elseif ($token !== '' && !$forTest) {
                $errors['pin'] = 'The trusted fingerprint expired or no longer matches. Run the test again.';
            }
            $missing = $kind === 'tls' ? $pin['pin_sha256'] === '' : $pin['ssh_hostkey'] === '';
            if ($missing && !$forTest && !isset($errors['pin'])) {
                $errors['pin'] = $kind === 'tls'
                    ? 'Run "Test connection" and trust the certificate before saving.'
                    : 'Run "Test connection" and trust the SSH host key before saving.';
            }
        }

        $data = [
            'name' => $name,
            'environment' => $environment,
            'location' => $location,
            'method' => $method,
            'host' => $host,
            'port' => $port,
            'db_user' => $dbUser,
            'cred_mode' => $credMode,
            'ca_pem' => $caPem,
            'ssh_host' => $sshHost,
            'ssh_port' => $sshPort,
            'ssh_user' => $sshUser,
            'ssh_auth' => $sshAuth,
        ] + $pin;

        $secrets = [
            'db_password' => $dbPassword,
            'ssh_secret' => $sshSecret,
        ];

        return ['data' => $data, 'secrets' => $secrets, 'errors' => $errors];
    }

    /**
     * Form values to show again after a validation error, or when editing.
     *
     * @param array<string, mixed> $server
     * @return array<string, string>
     */
    public static function valuesFromServer(array $server): array
    {
        $isSsh = $server['method'] === 'ssh';
        $isInternal = $server['method'] === 'internal';

        return [
            'name' => (string) $server['name'],
            'environment' => (string) $server['environment'],
            'location' => (string) $server['location'],
            'method' => $isInternal ? 'tls' : (string) $server['method'],
            'host' => !$isSsh && !$isInternal ? (string) $server['host'] : '',
            'port' => !$isSsh && !$isInternal ? (string) $server['port'] : '',
            'internal_host' => $isInternal ? (string) $server['host'] : '',
            'internal_port' => $isInternal ? (string) $server['port'] : '',
            'ssh_host' => (string) $server['ssh_host'],
            'ssh_port' => $isSsh ? (string) $server['ssh_port'] : '',
            'ssh_user' => (string) $server['ssh_user'],
            'ssh_auth' => (string) ($server['ssh_auth'] ?: 'key'),
            'ssh_db_host' => $isSsh ? (string) $server['host'] : '',
            'ssh_db_port' => $isSsh ? (string) $server['port'] : '',
            'db_user' => (string) $server['db_user'],
            'cred_mode' => (string) $server['cred_mode'],
        ];
    }

    /** @return array<string, string> */
    public static function valuesFromRequest(Request $req): array
    {
        $keys = ['name', 'environment', 'location', 'method', 'host', 'port', 'internal_host', 'internal_port',
            'ssh_host', 'ssh_port', 'ssh_user', 'ssh_auth', 'ssh_db_host', 'ssh_db_port', 'db_user', 'cred_mode'];
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $req->post($key);
        }

        return $values;
    }

    /**
     * @param array<string, mixed> $payload
     * @return array{pin_sha256: string, pin_pem: string, pin_strict: int, ssh_hostkey: string, ssh_fingerprint: string}
     */
    private static function pinFields(string $kind, array $payload): array
    {
        if ($kind === 'tls') {
            return [
                'pin_sha256' => (string) $payload['f'],
                'pin_pem' => (string) $payload['v'],
                'pin_strict' => !empty($payload['s']) ? 1 : 0,
                'ssh_hostkey' => '',
                'ssh_fingerprint' => '',
            ];
        }

        return [
            'pin_sha256' => '',
            'pin_pem' => '',
            'pin_strict' => 0,
            'ssh_hostkey' => (string) $payload['v'],
            'ssh_fingerprint' => (string) $payload['f'],
        ];
    }

    /** @param array<string, mixed> $server */
    private static function existingTarget(array $server): string
    {
        return $server['method'] === 'ssh'
            ? strtolower((string) $server['ssh_host']) . ':' . $server['ssh_port']
            : strtolower((string) $server['host']) . ':' . $server['port'];
    }

    private static function port(string $raw): ?int
    {
        if (!preg_match('/^\d{1,5}$/', $raw)) {
            return null;
        }
        $port = (int) $raw;

        return $port >= 1 && $port <= 65535 ? $port : null;
    }
}
