<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Address checks done in the portal for friendly error messages.
 * The real enforcement happens in phpMyAdmin's container and its network guard.
 */
final class NetPolicy
{
    public static function isHostname(string $host, bool $allowUnderscore = false): bool
    {
        if ($host === '' || strlen($host) > 253) {
            return false;
        }
        $label = $allowUnderscore ? '[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?' : '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';

        return (bool) preg_match('/^' . $label . '(?:\.' . $label . ')*\.?$/', $host);
    }

    public static function isIp(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    public static function isPublicIp(string $ip): bool
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
            $mask = chr((0xff << (8 - $rest)) & 0xff);
            if ((ord($addr[$bytes]) & ord($mask)) === (ord($netAddr[$bytes]) & ord($mask))) {
                return true;
            }
        }

        return false;
    }
}
