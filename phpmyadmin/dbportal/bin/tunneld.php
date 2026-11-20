<?php

declare(strict_types=1);

/*
 * SSH tunnel service. The only process in this container allowed to start programs
 * (the web server has exec functions disabled). Started by the entrypoint with:
 *   php -d disable_functions= /opt/dbportal/bin/tunneld.php
 *
 * Protocol: one JSON request per connection on a unix socket, one JSON line back.
 * Tunnels close after 30 minutes without use and after 12 hours at most.
 */

const SOCKET = '/run/dbportal/tunneld.sock';
const DIR = '/run/dbportal/tunnels';
const IDLE_SECONDS = 1800;
const MAX_AGE_SECONDS = 43200;
const PATH_ENV = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

/** @var array<string, array{proc: resource, port: int, started: int, used: int}> $tunnels */
$tunnels = [];

@mkdir(DIR, 0700, true);
@unlink(SOCKET);
$server = @stream_socket_server('unix://' . SOCKET, $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "[tunneld] cannot listen: $errstr\n");
    exit(1);
}
chmod(SOCKET, 0600);
fwrite(STDERR, "[tunneld] ready\n");

while (true) {
    $read = [$server];
    $write = $except = null;
    if (@stream_select($read, $write, $except, 5) > 0) {
        $client = @stream_socket_accept($server, 1);
        if ($client !== false) {
            stream_set_timeout($client, 5);
            $line = fgets($client, 65536);
            $request = is_string($line) ? json_decode($line, true) : null;
            try {
                $response = handle(is_array($request) ? $request : []);
            } catch (Throwable $e) {
                $response = ['ok' => false, 'error' => 'The SSH tunnel service hit an error.'];
                fwrite(STDERR, '[tunneld] ' . $e->getMessage() . "\n");
            }
            @fwrite($client, json_encode($response, JSON_UNESCAPED_SLASHES) . "\n");
            fclose($client);
        }
    }
    reap();
}

/** @param array<string, mixed> $r */
function handle(array $r): array
{
    return match ($r['action'] ?? '') {
        'open' => open_tunnel($r),
        'close' => close_tunnel((string) ($r['key'] ?? '')) ?? ['ok' => true],
        'scan' => scan((string) ($r['host'] ?? ''), (int) ($r['port'] ?? 22)),
        default => ['ok' => false, 'error' => 'Unknown request.'],
    };
}

function valid_key(string $key): bool
{
    return (bool) preg_match('/^([a-f0-9]{64}|test-[a-f0-9]{12})$/', $key);
}

function valid_host(string $host): bool
{
    return filter_var($host, FILTER_VALIDATE_IP) !== false
        || (bool) preg_match('/^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$/', $host);
}

function valid_port(int $port): bool
{
    return $port >= 1 && $port <= 65535;
}

/** @param array<string, mixed> $r */
function open_tunnel(array $r): array
{
    global $tunnels;
    $key = (string) ($r['key'] ?? '');
    $host = (string) ($r['host'] ?? '');
    $port = (int) ($r['port'] ?? 22);
    $user = (string) ($r['user'] ?? '');
    $auth = (string) ($r['auth'] ?? 'key');
    $secret = (string) ($r['secret'] ?? '');
    $hostKey = trim((string) ($r['hostkey'] ?? ''));
    $learn = !empty($r['learn']) && $hostKey === '';
    $dbHost = (string) ($r['db_host'] ?? '');
    $dbPort = (int) ($r['db_port'] ?? 3306);

    if (!valid_key($key) || !valid_host($host) || !valid_port($port) || !valid_host($dbHost) || !valid_port($dbPort)
        || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', $user) || !in_array($auth, ['key', 'password'], true)
        || $secret === '' || ($hostKey === '' && !$learn) || str_contains($hostKey, "\n")) {
        return ['ok' => false, 'error' => 'The SSH settings are incomplete.'];
    }

    if (isset($tunnels[$key])) {
        if (alive($tunnels[$key]['proc']) && port_open($tunnels[$key]['port'])) {
            $tunnels[$key]['used'] = time();

            return ['ok' => true, 'port' => $tunnels[$key]['port']];
        }
        close_tunnel($key);
    }

    $local = free_port();
    $knownHosts = DIR . "/$key.known_hosts";
    $keyFile = DIR . "/$key.key";
    $log = DIR . "/$key.log";
    // First login (learn): record whatever key the server presents, for the user to confirm.
    // Afterwards: only the trusted key is accepted.
    file_put_contents($knownHosts, $learn ? '' : $hostKey . "\n");
    chmod($knownHosts, 0600);
    @unlink($log);

    $cmd = [
        'ssh', '-N', '-T', '-F', '/dev/null',
        '-o', 'StrictHostKeyChecking=' . ($learn ? 'accept-new' : 'yes'),
        '-o', "UserKnownHostsFile=$knownHosts",
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'UpdateHostKeys=no',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'ServerAliveInterval=15',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'ConnectTimeout=10',
        '-o', 'LogLevel=ERROR',
        '-o', 'ForwardAgent=no',
        '-o', 'ForwardX11=no',
        '-o', 'PermitLocalCommand=no',
        '-o', 'ClearAllForwardings=no',
        '-p', (string) $port,
        '-l', $user,
        '-L', "127.0.0.1:$local:$dbHost:$dbPort",
    ];
    $env = ['HOME' => '/run/dbportal', 'PATH' => PATH_ENV];
    if ($auth === 'key') {
        file_put_contents($keyFile, rtrim($secret) . "\n");
        chmod($keyFile, 0600);
        array_push($cmd, '-i', $keyFile, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no');
    } else {
        $cmd = array_merge(['sshpass', '-e'], $cmd, ['-o', 'PreferredAuthentications=password,keyboard-interactive',
            '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1']);
        $env['SSHPASS'] = $secret;
    }
    $cmd[] = $host;

    $proc = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes, '/run/dbportal', $env);
    if (!is_resource($proc)) {
        @unlink($keyFile);

        return ['ok' => false, 'error' => 'Could not start SSH.'];
    }

    $deadline = microtime(true) + 15;
    $up = false;
    while (microtime(true) < $deadline) {
        if (!alive($proc)) {
            break;
        }
        if (port_open($local)) {
            $up = true;
            break;
        }
        usleep(150000);
    }
    @unlink($keyFile); // ssh has read it by now (or failed)

    if (!$up) {
        $error = is_file($log) ? (string) file_get_contents($log) : '';
        @proc_terminate($proc, 15);
        @proc_close($proc);
        cleanup_files($key);

        return ['ok' => false, 'error' => ssh_error($error, $host)];
    }

    $tunnels[$key] = ['proc' => $proc, 'port' => $local, 'started' => time(), 'used' => time()];

    $learned = '';
    if ($learn) {
        foreach (file($knownHosts, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            if (!str_starts_with(trim($line), '#')) {
                $learned = trim($line);
                break;
            }
        }
        if ($learned === '') {
            close_tunnel($key);

            return ['ok' => false, 'error' => "Couldn't read the SSH host key of $host."];
        }
    }

    return ['ok' => true, 'port' => $local, 'hostkey' => $learned, 'fingerprint' => $learned !== '' ? fingerprint($learned) : ''];
}

/** "SHA256:… (ED25519)" for a known_hosts line. */
function fingerprint(string $line): string
{
    $out = trim(run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'], $line . "\n"));
    $parts = preg_split('/\s+/', $out) ?: [];
    $type = trim((string) end($parts), '()');

    return ($parts[1] ?? $out) . ($type !== '' ? " ($type)" : '');
}

function close_tunnel(string $key): ?array
{
    global $tunnels;
    if (!valid_key($key)) {
        return ['ok' => false];
    }
    if (isset($tunnels[$key])) {
        @proc_terminate($tunnels[$key]['proc'], 15);
        @proc_close($tunnels[$key]['proc']);
        unset($tunnels[$key]);
    }
    cleanup_files($key);

    return null;
}

function cleanup_files(string $key): void
{
    foreach (['known_hosts', 'key', 'log'] as $ext) {
        @unlink(DIR . "/$key.$ext");
    }
}

function reap(): void
{
    global $tunnels;
    $now = time();
    foreach ($tunnels as $key => $tunnel) {
        if (!alive($tunnel['proc']) || $tunnel['used'] + IDLE_SECONDS < $now || $tunnel['started'] + MAX_AGE_SECONDS < $now) {
            close_tunnel($key);
        }
    }
}

/** @param resource $proc */
function alive($proc): bool
{
    $status = @proc_get_status($proc);

    return is_array($status) && $status['running'];
}

function port_open(int $port): bool
{
    $fp = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.3);
    if ($fp === false) {
        return false;
    }
    fclose($fp);

    return true;
}

function free_port(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = (string) stream_socket_get_name($socket, false);
    fclose($socket);

    return (int) substr((string) strrchr($name, ':'), 1);
}

/** Reads the SSH server's host key so the user can trust it. */
function scan(string $host, int $port): array
{
    if (!valid_host($host) || !valid_port($port)) {
        return ['ok' => false, 'error' => 'Enter a valid SSH host and port.'];
    }
    $out = run(['ssh-keyscan', '-T', '6', '-p', (string) $port, '-t', 'ed25519,ecdsa,rsa', $host], '');
    $lines = [];
    foreach (preg_split('/\R/', $out) ?: [] as $line) {
        $parts = preg_split('/\s+/', trim($line)) ?: [];
        if (count($parts) >= 3 && !str_starts_with($parts[0], '#')) {
            $lines[$parts[1]] = $parts[0] . ' ' . $parts[1] . ' ' . $parts[2];
        }
    }
    $line = $lines['ssh-ed25519'] ?? ($lines['ecdsa-sha2-nistp256'] ?? ($lines['ssh-rsa'] ?? (reset($lines) ?: '')));
    if ($line === '') {
        return ['ok' => false, 'error' => "Can't reach the SSH server $host:$port, or it didn't send a host key."];
    }

    return ['ok' => true, 'line' => $line, 'fingerprint' => fingerprint($line)];
}

/** @param list<string> $cmd */
function run(array $cmd, string $stdin): string
{
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, '/run/dbportal', ['PATH' => PATH_ENV, 'HOME' => '/run/dbportal']);
    if (!is_resource($proc)) {
        return '';
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $output = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    return $output;
}

function ssh_error(string $log, string $host): string
{
    return match (true) {
        str_contains($log, 'Host key verification failed') || str_contains($log, 'REMOTE HOST IDENTIFICATION HAS CHANGED') =>
            "The host key of $host doesn't match the one you trusted.",
        str_contains($log, 'Permission denied') => 'The SSH server rejected the user, key or password.',
        str_contains($log, 'Connection refused') => "The SSH server $host refused the connection. Check the port.",
        str_contains($log, 'timed out') || str_contains($log, 'No route') || str_contains($log, 'unreachable') =>
            "Can't reach the SSH server $host. Check the address and its firewall.",
        str_contains($log, 'Could not resolve') => "Can't find the SSH server $host.",
        str_contains($log, 'invalid format') || str_contains($log, 'load pubkey') || str_contains($log, 'Load key') =>
            'The private key could not be read. Paste the whole key, including the BEGIN and END lines.',
        str_contains($log, 'administratively prohibited') || str_contains($log, 'forwarding') =>
            'The SSH server does not allow port forwarding for this user (AllowTcpForwarding).',
        default => 'Could not open the SSH tunnel.',
    };
}
