<?php

declare(strict_types=1);

/**
 * DB Portal helpers inside phpMyAdmin's container (the only part that talks to databases).
 * This container holds no long-term secrets: connection details arrive per request,
 * encrypted with a key that only the user's own browser cookie carries.
 */

namespace DbPortalPma;

use mysqli;
use mysqli_sql_exception;
use RuntimeException;
use Throwable;

final class Env
{
    public static function get(string $key, string $default = ''): string
    {
        $value = getenv($key);

        return $value === false || trim($value) === '' ? $default : trim($value);
    }

    public static function pmaUrl(): string
    {
        return rtrim(self::get('PMA_PUBLIC_URL'), '/');
    }

    public static function portalUrl(): string
    {
        return rtrim(self::get('PORTAL_PUBLIC_URL'), '/');
    }

    public static function portalInternal(): string
    {
        return rtrim(self::get('PORTAL_INTERNAL_URL', 'http://portal:8080'), '/');
    }

    public static function token(): string
    {
        return self::get('PMA_TOKEN');
    }

    /** @return list<string> */
    public static function allowCidrs(): array
    {
        return self::list('EGRESS_ALLOW_CIDRS');
    }

    /** @return list<string> */
    public static function blockCidrs(): array
    {
        return self::list('EGRESS_BLOCK_CIDRS');
    }

    /** @return list<string> */
    private static function list(string $key): array
    {
        return array_values(array_filter(array_map('trim', explode(',', self::get($key))), 'strlen'));
    }
}

/** A problem the user can fix; the message is safe to show. */
final class UserError extends RuntimeException
{
}

/** The database rejected the user name or password. */
final class AuthFailed extends RuntimeException
{
}

final class B64
{
    public static function d(string $data): string
    {
        if ($data === '' || preg_match('/[^A-Za-z0-9_-]/', $data)) {
            return '';
        }
        $decoded = base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4), true);

        return $decoded === false ? '' : $decoded;
    }
}

final class Http
{
    /**
     * @param array<string, mixed> $payload
     * @param list<string> $headers
     * @return array<string, mixed>
     */
    public static function postJson(string $url, array $payload, array $headers, int $timeout): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], $headers),
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES),
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $data = is_string($body) ? json_decode($body, true) : null;

        return $status === 200 && is_array($data) ? $data : [];
    }
}

/**
 * Fetches this request's connection details from the portal and decrypts them with the cookie keys.
 */
final class Bridge
{
    public const PREFIX = '__Host-dbp_s';
    public const MAX_SLOTS = 10;

    /**
     * phpMyAdmin's number for an open server is the portal's server id plus this offset (the portal's
     * Tickets::PMA_NUMBER_OFFSET). A number always means the same server, so a tab can't end up on
     * another one, and it never matches a cookie slot (1-10), which earlier versions used as the number.
     */
    public const NUMBER_OFFSET = 1000;

    /** @return array<int, array<string, mixed>> descriptors by phpMyAdmin server number, each with its cookie 'slot' */
    public static function load(): array
    {
        $assertion = $_SERVER['HTTP_X_DBP_ASSERTION'] ?? '';
        if (!is_string($assertion) || $assertion === '') {
            return [];
        }
        $tickets = [];
        $keys = [];
        for ($slot = 1; $slot <= self::MAX_SLOTS; $slot++) {
            $cookie = $_COOKIE[self::PREFIX . $slot] ?? null;
            if (!is_string($cookie) || substr_count($cookie, '.') !== 1) {
                continue;
            }
            [$tickets[$slot], $keys[$slot]] = explode('.', $cookie, 2);
        }
        if ($tickets === []) {
            return [];
        }
        $response = Http::postJson(
            Env::portalInternal() . '/internal/descriptors',
            ['assertion' => $assertion, 'tickets' => (object) $tickets],
            ['X-Internal-Token: ' . Env::token()],
            5,
        );

        $out = [];
        foreach ((array) ($response['servers'] ?? []) as $row) {
            $slot = (int) ($row['slot'] ?? 0);
            $serverId = (int) ($row['server'] ?? 0);
            if (!isset($keys[$slot]) || $serverId < 1) {
                continue;
            }
            $key = B64::d($keys[$slot]);
            $ciphertext = B64::d((string) ($row['c'] ?? ''));
            $nonce = B64::d((string) ($row['n'] ?? ''));
            $idHash = hash('sha256', B64::d($tickets[$slot]));
            if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES || $ciphertext === ''
                || strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
                continue;
            }
            $json = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, 'dbportal/ticket/' . $idHash, $nonce, $key);
            sodium_memzero($key);
            $descriptor = $json !== false ? json_decode($json, true) : null;
            if (!is_array($descriptor)) {
                continue;
            }
            $descriptor['key'] = $idHash;
            $descriptor['slot'] = $slot;
            $descriptor['opened'] = (int) ($row['opened'] ?? 0);
            // The same server in two cookies (one left from an earlier portal session): the newest wins.
            $number = self::NUMBER_OFFSET + $serverId;
            if (!isset($out[$number]) || $descriptor['opened'] > $out[$number]['opened']) {
                $out[$number] = $descriptor;
            }
        }

        return $out;
    }
}

/**
 * Which open server serves this request. phpMyAdmin writes server=N into its links and forms only
 * for servers other than $cfg['ServerDefault'], so ServerDefault stays 0 ("none") and every page
 * names its own server. A request is never handed to a server it didn't name.
 */
final class Selection
{
    /**
     * @param array<int, array<string, mixed>> $open descriptors by server number
     * @return int the server number, or 0 for none (phpMyAdmin then connects to nothing)
     */
    public static function choose(array $open): int
    {
        $raw = $_REQUEST['server'] ?? null;
        if ($raw !== null && (!is_string($raw) || !preg_match('/^[1-9][0-9]{0,9}$/', $raw))) {
            // phpMyAdmin would look anything else up by server name or host; nothing here needs that.
            unset($_GET['server'], $_POST['server'], $_REQUEST['server']);
            $raw = null;
        }
        if ($raw !== null) {
            $number = (int) $raw;
            if (!isset($open[$number])) {
                Page::ended($number);
            }

            return $number;
        }
        // Nothing named: only the start page picks a server, and only when exactly one is open.
        // With several, phpMyAdmin shows its server list.
        if (count($open) === 1 && self::isStartPage()) {
            $number = (int) array_key_first($open);
            $_GET['server'] = $_REQUEST['server'] = (string) $number;

            return $number;
        }
        if (!empty($_REQUEST['ajax_request'])
            && (isset($_REQUEST['db']) || isset($_REQUEST['table']) || isset($_REQUEST['sql_query']))) {
            // A click or query in a page that doesn't name its server (such as one loaded before
            // this version): phpMyAdmin would only say "No databases selected."
            Page::unnamed();
        }

        return 0;
    }

    /**
     * phpMyAdmin's "Log out" while other servers are still open in this browser: closes only this
     * server's session. phpMyAdmin itself would also delete its own session, which every tab shares,
     * so the other tabs' next form would fail with "Token mismatch".
     *
     * @param array<int, array<string, mixed>> $open
     */
    public static function logOutOne(array $open, int $number): void
    {
        if ($number === 0 || count($open) < 2 || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
            || ($_GET['route'] ?? $_POST['route'] ?? '') !== '/logout') {
            return;
        }
        header('Cache-Control: no-store');
        header('Location: ' . Env::pmaUrl() . '/__dbportal/close?slot=' . (int) $open[$number]['slot'], true, 302);
        exit;
    }

    private static function isStartPage(): bool
    {
        $script = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));
        $route = $_GET['route'] ?? $_POST['route'] ?? '/';

        return ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && $script === 'index.php' && ($route === '/' || $route === '')
            && !isset($_REQUEST['db']) && !isset($_REQUEST['table']) && !isset($_REQUEST['sql_query']);
    }
}

/**
 * Address policy. The network guard enforces the same rules at the packet level.
 */
final class Net
{
    /** @return list<string> */
    public static function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }
        if (!preg_match('/^[A-Za-z0-9_.-]{1,253}$/', $host)) {
            return [];
        }
        $ips = gethostbynamel($host) ?: [];
        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            if (!empty($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    public static function isPublic(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false;
    }

    /** @param list<string> $cidrs */
    public static function inCidrs(string $ip, array $cidrs): bool
    {
        $addr = @inet_pton($ip);
        if ($addr === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
            $netAddr = @inet_pton((string) $net);
            if ($netAddr === false || strlen($netAddr) !== strlen($addr)) {
                continue;
            }
            $bits = $bits === null ? strlen($addr) * 8 : (int) $bits;
            $bytes = intdiv($bits, 8);
            $rest = $bits % 8;
            if (substr($addr, 0, $bytes) !== substr($netAddr, 0, $bytes)) {
                continue;
            }
            if ($rest === 0) {
                return true;
            }
            $mask = (0xff << (8 - $rest)) & 0xff;
            if ((ord($addr[$bytes]) & $mask) === (ord($netAddr[$bytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Remote databases and SSH servers must use public addresses (or an explicitly allowed range).
     * This server's own public address counts as remote too.
     */
    public static function checkRemote(string $host): void
    {
        $ips = self::resolve($host);
        if ($ips === []) {
            throw new UserError("Can't find $host. Check the host name.");
        }
        foreach ($ips as $ip) {
            if (self::inCidrs($ip, Env::blockCidrs())) {
                throw new UserError("Connections to $host are blocked by this portal's settings.");
            }
            if (!self::isPublic($ip) && !self::inCidrs($ip, Env::allowCidrs())) {
                throw new UserError("$host points to a private address. Remote servers need a public address; use an SSH tunnel for private databases.");
            }
        }
    }

    /** Databases "on this server" must be on the private pma-databases network. */
    public static function checkInternal(string $host): void
    {
        $ips = self::resolve($host);
        if ($ips === []) {
            throw new UserError("Can't find $host. In Dokploy, attach the database to the pma-databases network, then try again.");
        }
        $portal = self::resolve(parse_url(Env::portalInternal(), PHP_URL_HOST) ?: 'portal');
        foreach ($ips as $ip) {
            if (in_array($ip, $portal, true) || !self::inCidrs($ip, ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'])) {
                throw new UserError("$host is not a database on the pma-databases network. For other servers choose \"Remote server\".");
            }
        }
    }
}

/**
 * Reads a MySQL/MariaDB server's TLS certificate (TLS starts inside the MySQL protocol).
 */
final class Probe
{
    /** The server capability flag that says it offers TLS. */
    private const CLIENT_SSL = 0x0800;

    /**
     * Whether the server offers TLS, from its greeting alone (no login). Null when that can't be told.
     */
    public static function offersTls(string $host, int $port): ?bool
    {
        $target = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? "[$host]" : $host;
        $fp = @stream_socket_client("tcp://$target:$port", $errno, $errstr, 5);
        if ($fp === false) {
            return null;
        }
        try {
            stream_set_timeout($fp, 5);
            [, $capabilities] = self::greeting($fp, $host, $port);

            return ($capabilities & self::CLIENT_SSL) !== 0;
        } catch (Throwable) {
            return null;
        } finally {
            fclose($fp);
        }
    }

    /** @return array{pem: string, sha256: string, strict: bool, tls: string} */
    public static function certificate(string $host, int $port): array
    {
        $context = stream_context_create(['ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'SNI_enabled' => true,
            'peer_name' => $host,
        ]]);
        $target = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? "[$host]" : $host;
        $fp = @stream_socket_client("tcp://$target:$port", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $context);
        if ($fp === false) {
            throw new UserError("Can't reach $host:$port. Check the address, the port and the firewall.");
        }
        try {
            stream_set_timeout($fp, 8);
            [$sequence, $capabilities] = self::greeting($fp, $host, $port);
            if (($capabilities & self::CLIENT_SSL) === 0) {
                throw new UserError("$host:$port doesn't offer TLS. Turn on TLS on the database server, or use an SSH tunnel.");
            }
            // SSLRequest: client flags, max packet size, charset (utf8mb4), 23 zero bytes
            $flags = 0x00000001 | 0x00000200 | 0x00000800 | 0x00008000 | 0x00080000;
            $body = pack('V', $flags) . pack('V', 16777216) . chr(45) . str_repeat("\0", 23);
            fwrite($fp, substr(pack('V', strlen($body)), 0, 3) . chr(($sequence + 1) & 0xff) . $body);
            if (@stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) !== true) {
                throw new UserError("The TLS handshake with $host:$port failed.");
            }
            $params = stream_context_get_params($fp);
            $cert = $params['options']['ssl']['peer_certificate'] ?? null;
            $meta = stream_get_meta_data($fp);
            if ($cert === null || !openssl_x509_export($cert, $pem)) {
                throw new UserError("$host:$port did not present a certificate.");
            }
            $sha = strtoupper(implode(':', str_split((string) openssl_x509_fingerprint($cert, 'sha256'), 2)));

            return [
                'pem' => $pem,
                'sha256' => $sha,
                'strict' => self::strictEligible($cert, $host),
                'tls' => (string) ($meta['crypto']['protocol'] ?? ''),
            ];
        } finally {
            fclose($fp);
        }
    }

    /**
     * Fingerprint check before connecting, cached for a few minutes per open session.
     */
    public static function cachedFingerprint(string $key, string $host, int $port): string
    {
        $dir = '/run/dbportal/probe';
        @mkdir($dir, 0700, true);
        $file = $dir . '/' . preg_replace('/[^a-f0-9-]/', '', $key) . '.json';
        $cached = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
        if (is_array($cached) && ($cached['at'] ?? 0) > time() - 300 && ($cached['target'] ?? '') === "$host:$port") {
            return (string) $cached['sha256'];
        }
        $probe = self::certificate($host, $port);
        file_put_contents($file, json_encode(['at' => time(), 'target' => "$host:$port", 'sha256' => $probe['sha256']]));

        return $probe['sha256'];
    }

    /**
     * A self-signed certificate whose name matches the host can be verified by the MySQL client
     * itself (true pinning). Otherwise the fingerprint is checked before each connection.
     */
    private static function strictEligible(mixed $cert, string $host): bool
    {
        $info = openssl_x509_parse($cert);
        $key = openssl_pkey_get_public($cert);
        if (!is_array($info) || $key === false || ($info['subject'] ?? null) != ($info['issuer'] ?? null)
            || openssl_x509_verify($cert, $key) !== 1) {
            return false;
        }
        $names = [];
        foreach (explode(',', (string) ($info['extensions']['subjectAltName'] ?? '')) as $entry) {
            $entry = trim($entry);
            if (str_starts_with($entry, 'DNS:')) {
                $names[] = strtolower(substr($entry, 4));
            } elseif (str_starts_with($entry, 'IP Address:')) {
                $names[] = strtolower(trim(substr($entry, 11)));
            }
        }
        if ($names === [] && isset($info['subject']['CN'])) {
            $names[] = strtolower((string) $info['subject']['CN']);
        }
        $host = strtolower($host);
        foreach ($names as $name) {
            if ($name === $host) {
                return true;
            }
            if (str_starts_with($name, '*.')) {
                $suffix = substr($name, 1); // ".example.com"
                $left = str_ends_with($host, $suffix) ? substr($host, 0, -strlen($suffix)) : '';
                if ($left !== '' && !str_contains($left, '.')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Reads the server's greeting. Returns its packet sequence number and lower capability flags.
     *
     * @param resource $fp
     * @return array{0: int, 1: int}
     */
    private static function greeting($fp, string $host, int $port): array
    {
        $header = self::read($fp, 4);
        $length = ord($header[0]) | (ord($header[1]) << 8) | (ord($header[2]) << 16);
        $sequence = ord($header[3]);
        $payload = self::read($fp, $length);
        if ($payload === '' || $payload[0] === "\xff") {
            throw new UserError("$host:$port refused the connection. It may block this portal's IP address.");
        }
        if (ord($payload[0]) !== 10) {
            throw new UserError("$host:$port doesn't answer like MySQL or MariaDB.");
        }
        $pos = strpos($payload, "\0", 1);
        if ($pos === false) {
            throw new UserError("$host:$port sent an unexpected greeting.");
        }
        $pos += 1 + 4 + 8 + 1; // connection id, auth data part 1, filler
        $capabilities = ord($payload[$pos] ?? "\0") | (ord($payload[$pos + 1] ?? "\0") << 8);

        return [$sequence, $capabilities];
    }

    /** @param resource $fp */
    private static function read($fp, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && !feof($fp)) {
            $chunk = fread($fp, $length - strlen($data));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $data .= $chunk;
        }
        if (strlen($data) < $length) {
            throw new UserError('The server closed the connection.');
        }

        return $data;
    }
}

/**
 * Client for the SSH tunnel service (tunneld), which runs as its own process.
 */
final class Tunnels
{
    private const SOCKET = '/run/dbportal/tunneld.sock';

    /**
     * Opens (or reuses) a tunnel. With $learn and no host key, the SSH server's key is
     * recorded on this first login and returned for the user to trust; later connections
     * require that exact key.
     *
     * @param array<string, mixed> $ssh
     * @return array{port: int, hostkey: string, fingerprint: string}
     */
    public static function open(string $key, array $ssh, string $hostKey, string $dbHost, int $dbPort, bool $learn = false): array
    {
        $res = self::call([
            'action' => 'open', 'key' => $key,
            'host' => (string) ($ssh['host'] ?? ''), 'port' => (int) ($ssh['port'] ?? 22),
            'user' => (string) ($ssh['user'] ?? ''), 'auth' => (string) ($ssh['auth'] ?? 'key'),
            'secret' => (string) ($ssh['secret'] ?? ''), 'hostkey' => $hostKey, 'learn' => $learn,
            'db_host' => $dbHost, 'db_port' => $dbPort,
        ], 30);
        if (empty($res['ok'])) {
            throw new UserError((string) ($res['error'] ?? 'Could not open the SSH tunnel.'));
        }

        return [
            'port' => (int) $res['port'],
            'hostkey' => (string) ($res['hostkey'] ?? ''),
            'fingerprint' => (string) ($res['fingerprint'] ?? ''),
        ];
    }

    public static function close(string $key): void
    {
        try {
            self::call(['action' => 'close', 'key' => $key], 10);
        } catch (Throwable) {
            // The tunnel service cleans up idle tunnels on its own.
        }
    }

    /** @return array{line: string, fingerprint: string} */
    public static function scan(string $host, int $port): array
    {
        $res = self::call(['action' => 'scan', 'host' => $host, 'port' => $port], 20);
        if (empty($res['ok'])) {
            throw new UserError((string) ($res['error'] ?? "Couldn't read the SSH host key."));
        }

        return ['line' => (string) $res['line'], 'fingerprint' => (string) $res['fingerprint']];
    }

    /** Compares two known_hosts lines by key type and key, ignoring the host part. */
    public static function sameKey(string $a, string $b): bool
    {
        $pa = preg_split('/\s+/', trim($a)) ?: [];
        $pb = preg_split('/\s+/', trim($b)) ?: [];

        return count($pa) >= 3 && count($pb) >= 3 && $pa[1] === $pb[1] && hash_equals($pa[2], $pb[2]);
    }

    /**
     * @param array<string, mixed> $message
     * @return array<string, mixed>
     */
    private static function call(array $message, int $timeout): array
    {
        $fp = @stream_socket_client('unix://' . self::SOCKET, $errno, $errstr, 3);
        if ($fp === false) {
            throw new UserError('The SSH tunnel service is not running. Try again in a moment.');
        }
        stream_set_timeout($fp, $timeout);
        fwrite($fp, json_encode($message, JSON_UNESCAPED_SLASHES) . "\n");
        $line = fgets($fp);
        fclose($fp);
        $res = is_string($line) ? json_decode($line, true) : null;
        if (!is_array($res)) {
            throw new UserError('The SSH tunnel service did not answer in time.');
        }

        return $res;
    }
}

final class Files
{
    /**
     * The system's trusted CAs. PHP's MySQL driver silently skips certificate checks when no
     * CA file is given (even with "verify" on), so verified TLS always passes a CA file.
     */
    public const SYSTEM_CA = '/etc/ssl/certs/ca-certificates.crt';

    /** The uploaded CA, or the system's trusted CAs. */
    public static function caOrSystem(string $pem): string
    {
        $path = self::ca($pem);

        return $path !== '' ? $path : self::SYSTEM_CA;
    }

    /** Writes a PEM certificate once and returns its path ('' for no certificate). */
    public static function ca(string $pem): string
    {
        if (trim($pem) === '') {
            return '';
        }
        $dir = '/run/dbportal/ca';
        @mkdir($dir, 0700, true);
        $path = $dir . '/' . hash('sha256', $pem) . '.pem';
        if (!is_file($path)) {
            file_put_contents($path, $pem, LOCK_EX);
            chmod($path, 0600);
        }

        return $path;
    }
}

final class Db
{
    /** @param array{verify: bool, ca: string}|null $ssl */
    public static function connect(string $host, int $port, string $user, string $password, ?array $ssl): mysqli
    {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $mysqli = mysqli_init();
        $mysqli->options(MYSQLI_OPT_CONNECT_TIMEOUT, 8);
        $mysqli->options(MYSQLI_OPT_READ_TIMEOUT, 15);
        $mysqli->options(MYSQLI_OPT_LOCAL_INFILE, 0);
        $flags = 0;
        if ($ssl !== null) {
            $flags |= MYSQLI_CLIENT_SSL;
            if ($ssl['ca'] !== '') {
                $mysqli->ssl_set(null, null, $ssl['ca'], null, null);
            }
            if ($ssl['verify']) {
                $mysqli->options(MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, 1);
            } else {
                $flags |= MYSQLI_CLIENT_SSL_DONT_VERIFY_SERVER_CERT;
            }
        }
        try {
            $mysqli->real_connect($host, $user, $password, null, $port, null, $flags);
        } catch (mysqli_sql_exception $e) {
            if (in_array($e->getCode(), [1045, 1698], true)) {
                throw new AuthFailed('Access denied', 0, $e);
            }
            throw $e;
        }

        return $mysqli;
    }

    public static function version(mysqli $mysqli): string
    {
        $raw = (string) $mysqli->query('SELECT VERSION()')->fetch_row()[0];
        $number = preg_match('/^(\d+\.\d+\.\d+)/', $raw, $m) ? $m[1] : $raw;

        return (stripos($raw, 'mariadb') !== false ? 'MariaDB ' : 'MySQL ') . $number;
    }

    public static function tlsVersion(mysqli $mysqli): string
    {
        $row = $mysqli->query("SHOW SESSION STATUS LIKE 'Ssl_version'")->fetch_row();

        return (string) ($row[1] ?? '');
    }

    /** @return array{grants: list<string>, superuser: bool, user: string} */
    public static function privileges(mysqli $mysqli): array
    {
        $current = (string) $mysqli->query('SELECT CURRENT_USER()')->fetch_row()[0];
        $grants = [];
        $superuser = false;
        $result = $mysqli->query('SHOW GRANTS');
        while ($row = $result->fetch_row()) {
            $line = (string) $row[0];
            if (preg_match('/ ON \*\.\* /i', $line . ' ') && preg_match('/ALL PRIVILEGES|\bSUPER\b|\bCREATE USER\b|\bSYSTEM_USER\b/i', $line)) {
                $superuser = true;
            }
            $short = preg_replace(['/^GRANT\s+/i', '/\s+TO\s+.*$/is', '/\s+IDENTIFIED BY .*$/is'], '', $line);
            if (is_string($short) && $short !== '' && stripos($short, 'USAGE ON *.*') !== 0) {
                $grants[] = $short;
            }
        }

        return ['grants' => array_slice($grants, 0, 12), 'superuser' => $superuser, 'user' => $current];
    }

    /** A connection error explained for the owner, without internal details. */
    public static function friendly(Throwable $e, string $target, bool $viaSsh): string
    {
        $message = $e->getMessage();
        $code = $e->getCode();

        return match (true) {
            str_contains($message, 'certificate verify failed') || str_contains($message, 'SSL operation failed') || str_contains($message, 'using SSL')
                || str_contains($message, 'Peer certificate CN') =>
                "TLS failed: the certificate of $target couldn't be verified. Upload its CA certificate, or choose \"TLS, self-signed certificate\".",
            str_contains($message, 'reading initial communication packet') || $code === 2013 => $viaSsh
                ? "The SSH tunnel works, but $target isn't reachable from the SSH server."
                : "$target accepted the connection but didn't answer like MySQL or MariaDB.",
            str_contains($message, 'Connection refused') => $viaSsh
                ? "The SSH tunnel works, but nothing is listening on $target."
                : "Can't reach $target. Check the address, the port and the firewall.",
            str_contains($message, 'timed out') || str_contains($message, 'No route') || str_contains($message, 'unreachable')
                || $code === 2002 => "Can't reach $target. Check the address, the port and the firewall.",
            str_contains($message, "doesn't support SSL") || str_contains($message, 'SSL is required') =>
                "$target doesn't offer TLS. Turn on TLS on the database server, or use an SSH tunnel.",
            str_contains($message, 'insecure transport') || str_contains($message, 'requires secure connection') =>
                "$target only accepts encrypted connections. Choose \"TLS, self-signed certificate\" instead.",
            $code === 1044 => 'Signed in, but this user has no access to any database.',
            default => 'Could not connect: ' . mb_substr(preg_replace('/\s+/', ' ', $message) ?? '', 0, 160),
        };
    }
}

/**
 * Connection test used by the portal (full test and quick check before opening).
 */
final class Tester
{
    /**
     * @param array<string, mixed> $d
     * @return array<string, mixed>
     */
    public static function run(array $d, bool $full): array
    {
        $out = ['ok' => false, 'auth_failed' => false, 'checks' => [], 'grants' => [], 'superuser' => false,
            'pin' => null, 'error' => null, 'version' => '', 'latency_ms' => null];
        $user = (string) ($d['user'] ?? '');
        $password = (string) ($d['password'] ?? '');
        $method = (string) ($d['method'] ?? '');
        $host = (string) ($d['host'] ?? '');
        $port = (int) ($d['port'] ?? 3306);
        $target = "$host:$port";
        if ($user === '' || strcasecmp($user, 'root') === 0) {
            $out['error'] = 'root is blocked. Use a user with only the privileges it needs.';

            return $out;
        }

        $tunnelKey = null;
        $transport = '';
        try {
            $connectHost = $host;
            $connectPort = $port;
            $ssl = null;
            switch ($method) {
                case 'internal':
                    Net::checkInternal($host);
                    $transport = 'Internal network, nothing exposed to the internet';
                    break;
                case 'tls':
                    Net::checkRemote($host);
                    $ssl = ['verify' => true, 'ca' => Files::caOrSystem((string) ($d['ca_pem'] ?? ''))];
                    $transport = 'certificate verified';
                    break;
                case 'pinned':
                    Net::checkRemote($host);
                    $probe = Probe::certificate($host, $port);
                    $pinned = (string) ($d['pin_sha256'] ?? '');
                    if ($pinned !== '' && !hash_equals($pinned, $probe['sha256'])) {
                        $out['pin'] = ['kind' => 'tls', 'fingerprint' => $probe['sha256'], 'value' => $probe['pem'], 'strict' => $probe['strict'], 'mismatch' => true];
                        $out['error'] = "The certificate of $target changed since you trusted it. Connections are blocked until you confirm the new one.";

                        return $out;
                    }
                    if ($pinned === '') {
                        $out['pin'] = ['kind' => 'tls', 'fingerprint' => $probe['sha256'], 'value' => $probe['pem'], 'strict' => $probe['strict'], 'mismatch' => false];
                    }
                    $strict = $pinned !== '' ? !empty($d['pin_strict']) : $probe['strict'];
                    $pem = $pinned !== '' ? (string) ($d['pin_pem'] ?? '') : $probe['pem'];
                    $ssl = $strict ? ['verify' => true, 'ca' => Files::ca($pem)] : ['verify' => false, 'ca' => ''];
                    $transport = $pinned === '' ? 'self-signed certificate (trust it below)'
                        : ($strict ? 'pinned certificate verified' : 'certificate fingerprint matched');
                    break;
                case 'plain':
                    // "Not encrypted", allowed by an admin: no TLS at all.
                    Net::checkRemote($host);
                    break;
                case 'ssh':
                    $ssh = is_array($d['ssh'] ?? null) ? $d['ssh'] : [];
                    $sshHost = (string) ($ssh['host'] ?? '');
                    Net::checkRemote($sshHost);
                    $pinned = (string) ($ssh['hostkey'] ?? '');
                    $tunnelKey = 'test-' . bin2hex(random_bytes(6));
                    try {
                        // No separate key scan: OpenSSH penalises connections that never log in.
                        $tunnel = Tunnels::open($tunnelKey, $ssh, $pinned, $host, $port, $pinned === '');
                    } catch (UserError $e) {
                        if ($pinned !== '' && str_contains($e->getMessage(), "doesn't match")) {
                            // Only now read the new key, so the owner can review it.
                            $scan = Tunnels::scan($sshHost, (int) ($ssh['port'] ?? 22));
                            $out['pin'] = ['kind' => 'ssh', 'fingerprint' => $scan['fingerprint'], 'value' => $scan['line'], 'strict' => true, 'mismatch' => true];
                            $out['error'] = "The host key of $sshHost changed since you trusted it. Connections are blocked until you confirm the new one.";

                            return $out;
                        }
                        throw $e;
                    }
                    if ($pinned === '') {
                        $out['pin'] = ['kind' => 'ssh', 'fingerprint' => $tunnel['fingerprint'], 'value' => $tunnel['hostkey'], 'strict' => true, 'mismatch' => false];
                    }
                    $connectPort = $tunnel['port'];
                    $connectHost = '127.0.0.1';
                    $out['checks'][] = "SSH connected to $sshHost as " . ($ssh['user'] ?? '');
                    $out['checks'][] = "Tunnel open to $target";
                    $transport = 'encrypted by the SSH tunnel';
                    break;
                default:
                    throw new UserError('Unknown connection method.');
            }

            $started = hrtime(true);
            $mysqli = Db::connect($connectHost, $connectPort, $user, $password, $ssl);
            $out['latency_ms'] = (int) round((hrtime(true) - $started) / 1e6);
            $out['version'] = Db::version($mysqli);
            if ($ssl !== null) {
                $tls = Db::tlsVersion($mysqli);
                if ($tls === '') {
                    throw new UserError("The connection to $target is not encrypted. Turn on TLS on the database server.");
                }
                $transport = str_replace('TLSv', 'TLS ', $tls) . ', ' . $transport;
            }
            if ($method !== 'ssh') {
                array_unshift($out['checks'], "Reached the server in {$out['latency_ms']} ms");
            }
            $out['checks'][] = $method === 'ssh' ? $out['version'] . ', ' . $transport : $out['version'];
            if ($method === 'plain') {
                $out['checks'][] = ['text' => 'Not encrypted. Queries and results travel in clear text.', 'warn' => true];
            } elseif ($method !== 'ssh') {
                $out['checks'][] = ucfirst($transport);
            }
            if ($full) {
                $privileges = Db::privileges($mysqli);
                $out['checks'][] = 'Signed in as ' . $privileges['user'];
                $out['grants'] = $privileges['grants'];
                $out['superuser'] = $privileges['superuser'];
                if (!$privileges['superuser']) {
                    $out['checks'][] = 'Not a superuser, root is not used';
                }
            }
            $mysqli->close();
            if ($full && $method === 'plain' && Probe::offersTls($host, $port) === true) {
                // The owner could encrypt this connection: the portal suggests it.
                $out['tls_offered'] = true;
            }
            $out['ok'] = true;
        } catch (AuthFailed) {
            $out['auth_failed'] = true;
            $out['error'] = 'The database rejected this user name or password.';
        } catch (UserError $e) {
            $out['error'] = $e->getMessage();
        } catch (Throwable $e) {
            $out['error'] = Db::friendly($e, $target, $method === 'ssh');
        } finally {
            if ($tunnelKey !== null) {
                Tunnels::close($tunnelKey);
            }
        }

        return $out;
    }
}

/**
 * Builds phpMyAdmin's server list for this request from the user's open sessions.
 */
final class Servers
{
    /**
     * @param array<string, mixed> $d
     * @return array<string, mixed>
     */
    public static function config(int $slot, array $d, bool $current): array
    {
        $host = (string) ($d['host'] ?? '');
        $port = (int) ($d['port'] ?? 3306);
        $server = [
            'verbose' => (string) ($d['name'] ?? 'Server ' . $slot),
            'auth_type' => 'signon',
            'SignonScript' => '/opt/dbportal/signon.php',
            'SignonSession' => '',
            'SignonURL' => Env::portalUrl() . '/servers?pma_signin=1',
            'LogoutURL' => Env::pmaUrl() . '/__dbportal/close?slot=' . $slot,
            'AllowRoot' => false,
            'AllowNoPassword' => false,
            'compress' => false,
            'dbportal_slot' => $slot,
            'host' => $host,
            'port' => (string) $port,
            'ssl' => false,
        ];

        try {
            switch ($d['method'] ?? '') {
                case 'internal':
                    if ($current) {
                        Net::checkInternal($host);
                    }
                    break;
                case 'tls':
                    if ($current) {
                        Net::checkRemote($host);
                    }
                    $server['ssl'] = true;
                    $server['ssl_verify'] = true;
                    $server['ssl_ca'] = Files::caOrSystem((string) ($d['ca_pem'] ?? ''));
                    break;
                case 'pinned':
                    $strict = !empty($d['pin_strict']);
                    if ($current) {
                        Net::checkRemote($host);
                        if (!$strict && !hash_equals((string) ($d['pin_sha256'] ?? ''), Probe::cachedFingerprint((string) $d['key'], $host, $port))) {
                            Page::blocked("The certificate of $host:$port changed since you trusted it. Open the server's settings in the portal and run a test to review it.");
                        }
                    }
                    $server['ssl'] = true;
                    $server['ssl_verify'] = $strict;
                    $server['ssl_ca'] = $strict ? Files::ca((string) ($d['pin_pem'] ?? '')) : '';
                    break;
                case 'plain':
                    // "Not encrypted": the portal hands these out only while an admin allows them.
                    if ($current) {
                        Net::checkRemote($host);
                    }
                    break;
                case 'ssh':
                    $server['host'] = '127.0.0.1';
                    $server['port'] = '1';
                    if ($current) {
                        $ssh = is_array($d['ssh'] ?? null) ? $d['ssh'] : [];
                        Net::checkRemote((string) ($ssh['host'] ?? ''));
                        $server['port'] = (string) Tunnels::open((string) $d['key'], $ssh, (string) ($ssh['hostkey'] ?? ''), $host, $port)['port'];
                    }
                    break;
                default:
                    Page::blocked('This server has an unknown connection method.');
            }
        } catch (UserError $e) {
            Page::blocked($e->getMessage());
        }

        $GLOBALS['dbportal_credentials'][$slot] = [(string) ($d['user'] ?? ''), (string) ($d['password'] ?? '')];

        return $server;
    }

    /** With no open session, phpMyAdmin sends the visitor back to the portal. */
    public static function placeholder(): array
    {
        return [
            'verbose' => 'DB Portal',
            'auth_type' => 'signon',
            'SignonScript' => '/opt/dbportal/signon.php',
            'SignonSession' => '',
            'SignonURL' => Env::portalUrl() . '/servers?pma_signin=1',
            'LogoutURL' => Env::portalUrl() . '/servers',
            'host' => 'localhost',
            'AllowRoot' => false,
            'AllowNoPassword' => false,
            'dbportal_slot' => 0,
        ];
    }
}

final class Page
{
    public static function blocked(string $message): never
    {
        self::show('Connection blocked', $message, [['Back to my servers', Env::portalUrl() . '/servers']]);
    }

    /** The page names a server that isn't open in this browser (closed, expired or never opened here). */
    public static function ended(int $number): never
    {
        $serverId = $number - Bridge::NUMBER_OFFSET;
        $links = $serverId > 0 ? [['Open it again', Env::portalUrl() . '/servers/' . $serverId . '/open']] : [];
        $links[] = ['My servers', Env::portalUrl() . '/servers'];
        self::show(
            'Session ended',
            "This page's server is no longer open in phpMyAdmin: its session was closed or has expired. Open the server again from DB Portal.",
            $links,
        );
    }

    /** A request inside phpMyAdmin that doesn't name its server: it goes to none. */
    public static function unnamed(): never
    {
        self::show(
            'Which server?',
            "This page doesn't say which server it is for, so nothing was sent to a database. Reload the page, or open the server again from DB Portal.",
            [['My servers', Env::portalUrl() . '/servers']],
        );
    }

    /** @param list<array{0: string, 1: string}> $links */
    private static function show(string $title, string $message, array $links): never
    {
        header('Cache-Control: no-store');
        $text = htmlspecialchars($message, ENT_QUOTES);
        $anchors = implode(' · ', array_map(
            static fn (array $l): string => '<a class="disableAjax" href="' . htmlspecialchars($l[1], ENT_QUOTES) . '">'
                . htmlspecialchars($l[0], ENT_QUOTES) . '</a>',
            $links,
        ));
        if (!empty($_REQUEST['ajax_request'])) {
            // Inside phpMyAdmin's page: its scripts show "error" as a message.
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'success' => false,
                'error' => '<div class="alert alert-danger" role="alert">' . $text . ' ' . $anchors . '</div>',
            ], JSON_UNESCAPED_SLASHES);
            exit;
        }
        http_response_code(409);
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
        $heading = htmlspecialchars($title, ENT_QUOTES);
        echo <<<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$heading</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0e1013;color:#eceef1;font:15px/1.5 system-ui,sans-serif;padding:20px}
main{max-width:520px;background:#15181d;border:1px solid #262b34;border-radius:14px;padding:28px;display:flex;flex-direction:column;gap:14px}
h1{margin:0;font-size:24px}p{margin:0;color:#a7aeba}a{color:#f2b33d}</style></head>
<body><main><h1>$heading</h1><p>$text</p><p>$anchors</p></main></body></html>
HTML;
        exit;
    }
}
