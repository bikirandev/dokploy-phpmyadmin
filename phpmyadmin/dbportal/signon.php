<?php

declare(strict_types=1);

/*
 * phpMyAdmin "signon" script: returns the credentials for the server being used in this request.
 * They were decrypted in config.user.inc.php with the key from the user's own cookie.
 */
if (!function_exists('get_login_credentials')) {
    /**
     * @return array{0: string, 1: string}
     */
    function get_login_credentials($user): array
    {
        $slot = (int) ($GLOBALS['cfg']['Server']['dbportal_slot'] ?? 0);
        $credentials = $GLOBALS['dbportal_credentials'][$slot] ?? null;

        return is_array($credentials) ? [(string) $credentials[0], (string) $credentials[1]] : ['', ''];
    }
}
