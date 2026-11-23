<?php

declare(strict_types=1);

/*
 * DB Portal configuration for phpMyAdmin, loaded after the image's own config.inc.php.
 * phpMyAdmin is only reachable through the gateway, which first asks the portal whether
 * the request carries a live session. The server list is built per request from the
 * signed-in user's own open sessions.
 */
require_once '/opt/dbportal/lib.php';

use DbPortalPma\Bridge;
use DbPortalPma\Env;
use DbPortalPma\Selection;
use DbPortalPma\Servers;

// Secrets and addresses
$cfg['blowfish_secret'] = sodium_crypto_generichash('dbportal-blowfish|' . Env::token(), '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
$cfg['PmaAbsoluteUri'] = Env::pmaUrl() . '/';

// Hardening
$cfg['AllowArbitraryServer'] = false;
$cfg['AllowThirdPartyFraming'] = false;
$cfg['LoginCookieValidity'] = 1440;
$cfg['LoginCookieStore'] = 0;
$cfg['LoginCookieRecall'] = false;
$cfg['CookieSameSite'] = 'Lax';
$cfg['ShowServerInfo'] = false;
$cfg['ShowPhpInfo'] = false;
$cfg['ShowGitRevision'] = false;
$cfg['SendErrorReports'] = 'never';
$cfg['VersionCheck'] = false;
$cfg['ZeroConf'] = false;                      // never offer to create phpMyAdmin tables in users' databases
$cfg['PmaNoRelation_DisableWarning'] = true;
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';
$cfg['ExecTimeLimit'] = 300;
$cfg['ShowCreateDb'] = true;

// Servers: only the current user's open sessions (decrypted with keys from their cookies), numbered
// by portal server. Each tab stays on the server its page names (see Selection).
$cfg['Servers'] = [];
$dbportalOpen = Bridge::load();
if ($dbportalOpen === []) {
    // Nothing open: phpMyAdmin sends the visitor back to the portal.
    $cfg['Servers'][1] = Servers::placeholder();
    $cfg['ServerDefault'] = 1;
} else {
    $dbportalCurrent = Selection::choose($dbportalOpen);
    Selection::logOutOne($dbportalOpen, $dbportalCurrent);
    foreach ($dbportalOpen as $dbportalNumber => $dbportalDescriptor) {
        $cfg['Servers'][$dbportalNumber] = Servers::config((int) $dbportalDescriptor['slot'], $dbportalDescriptor, $dbportalNumber === $dbportalCurrent);
    }
    // 0: phpMyAdmin puts server=N into every link and form, and uses no server for a request without one.
    $cfg['ServerDefault'] = 0;
}
unset($dbportalOpen, $dbportalCurrent, $dbportalNumber, $dbportalDescriptor);
