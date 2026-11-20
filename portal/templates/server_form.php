<?php
/** @var DbPortal\Ctx $ctx */
/** @var array<string, mixed>|null $server */
/** @var array<string, string> $values */
/** @var array<string, string> $errors */
/** @var int $used */
/** @var int $limit */
$isEdit = $server !== null;
$ctx->title = $isEdit ? 'Edit server' : 'Add server';

$val = static fn (string $key, string $default = ''): string => isset($values[$key]) && $values[$key] !== '' ? $values[$key] : $default;
$checked = static fn (string $key, string $value, string $default): string => $val($key, $default) === $value ? ' checked' : '';
$error = static fn (string $key): string => isset($errors[$key])
    ? '<span class="field-error" id="err-' . e($key) . '">' . e($errors[$key]) . '</span>'
    : '';
$invalid = static fn (string $key): string => isset($errors[$key]) ? ' aria-invalid="true" aria-describedby="err-' . e($key) . '"' : '';

$egressIp = $ctx->cfg->egressIp;
$savedPassword = $isEdit && $server['cred_mode'] === 'saved' && $server['secret'] !== null;
$hasSshSecret = $isEdit && $server['method'] === 'ssh' && $server['secret'] !== null;
$pinnedNow = '';
if ($isEdit && $server['method'] === 'pinned' && $server['pin_sha256'] !== '') {
    $pinnedNow = 'Certificate ' . $server['pin_sha256'];
} elseif ($isEdit && $server['method'] === 'ssh' && $server['ssh_fingerprint'] !== '') {
    $pinnedNow = 'SSH host key ' . $server['ssh_fingerprint'];
}
$testsPerMinute = $ctx->settings->get('tests_per_minute');
$isPg = $val('kind', 'mysql') === 'postgres';
// Placeholders follow the engine (app.js switches them when the engine changes).
$ph = static fn (string $mysql, string $postgres): string => ' placeholder="' . e($isPg ? $postgres : $mysql) . '"'
    . ' data-placeholder-mysql="' . e($mysql) . '" data-placeholder-postgres="' . e($postgres) . '"';
?>
<nav class="breadcrumb" aria-label="Breadcrumb">
  <a href="/servers">My servers</a>
  <span aria-hidden="true">/</span>
  <span aria-current="page"><?= $isEdit ? e($server['name']) : 'Add server' ?></span>
</nav>
<div class="page-head">
  <div class="stack-8 head-text">
    <h1><?= $isEdit ? 'Edit server' : 'Add a server' ?></h1>
    <p class="muted"><?= $isEdit
        ? 'Saving changes closes any open phpMyAdmin or pgAdmin session for this server.'
        : 'Connect a database you manage. Only you will see it on your servers page.' ?></p>
  </div>
</div>

<?php if ($errors !== []): ?>
  <div class="callout callout-danger" role="alert"><?= icon('alert', 20) ?>
    <span>Check the highlighted fields.<?= isset($errors['pin']) ? ' ' . e($errors['pin']) : '' ?></span>
  </div>
<?php endif; ?>

<form id="server-form" class="server-form" method="post" enctype="multipart/form-data"
      action="<?= $isEdit ? '/servers/' . (int) $server['id'] : '/servers' ?>">
  <?= csrf_field($ctx) ?>
  <?php if ($isEdit): ?><input type="hidden" name="server_id" value="<?= (int) $server['id'] ?>"><?php endif; ?>
  <input type="hidden" name="pin_token" value="" data-pin-token>

  <div class="form-layout">
    <div class="form-main">

      <section class="card form-section" aria-labelledby="sec-where">
        <div class="stack-4">
          <h2 id="sec-where">1. Where is the database?</h2>
          <p class="small muted">This decides how we connect and what protects the traffic.</p>
        </div>
        <fieldset class="stack-8">
          <legend class="label">Database engine</legend>
          <div class="chips">
            <label class="chip"><input class="sr-only" type="radio" name="kind" value="mysql"<?= $checked('kind', 'mysql', 'mysql') ?>><span>MySQL / MariaDB</span></label>
            <label class="chip"><input class="sr-only" type="radio" name="kind" value="postgres"<?= $checked('kind', 'postgres', 'mysql') ?>><span>PostgreSQL</span></label>
          </div>
          <span class="small muted"><span class="when-mysql">Opens in phpMyAdmin.</span><span class="when-postgres">Opens in pgAdmin.</span></span>
        </fieldset>
        <fieldset class="options">
          <legend class="sr-only">Location</legend>
          <label class="option">
            <input class="sr-only" type="radio" name="location" value="local"<?= $checked('location', 'local', 'remote') ?>>
            <span class="option-icon"><?= icon('server', 20) ?></span>
            <span class="option-text"><span class="option-title">On this server</span>
              <span class="option-desc">A Dokploy database on the pma-databases network. Nothing is exposed to the internet.</span></span>
            <span class="radio-dot" aria-hidden="true"></span>
          </label>
          <label class="option">
            <input class="sr-only" type="radio" name="location" value="remote"<?= $checked('location', 'remote', 'remote') ?>>
            <span class="option-icon"><?= icon('globe', 20) ?></span>
            <span class="option-text"><span class="option-title">Remote server</span>
              <span class="option-desc">Any database server you manage, reached over TLS or an SSH tunnel.</span></span>
            <span class="radio-dot" aria-hidden="true"></span>
          </label>
        </fieldset>

        <div class="when-local stack-18">
          <div class="field-row">
            <label class="field grow">Internal host
              <input class="mono" type="text" name="internal_host" value="<?= e($val('internal_host')) ?>"<?= $ph('shop-mysql-k2j9x1', 'shop-postgres-k2j9x1') ?> autocomplete="off" spellcheck="false"<?= $invalid('host') ?>>
              <?= $error('host') ?>
            </label>
            <label class="field port">Port
              <input class="mono" type="text" name="internal_port" value="<?= e($val('internal_port')) ?>"<?= $ph('3306', '5432') ?> inputmode="numeric"<?= $invalid('port') ?>>
              <?= $error('port') ?>
            </label>
          </div>
          <div class="callout callout-info"><?= icon('info', 20) ?>
            <div class="stack-4">
              <span>In Dokploy, open the database, go to Advanced → Networks and add <code>pma-databases</code>. Then copy Internal Credentials → Internal Host.</span>
              <span class="small">phpMyAdmin and pgAdmin can only reach databases on that network, never Dokploy itself or other apps.</span>
            </div>
          </div>
        </div>

        <div class="when-remote stack-18">
          <fieldset class="stack-8">
            <legend class="label">How should we connect?</legend>
            <div class="options">
              <label class="option">
                <input class="sr-only" type="radio" name="method" value="tls"<?= $checked('method', 'tls', 'tls') ?>>
                <span class="option-icon ok"><?= icon('lock', 20) ?></span>
                <span class="option-text"><span class="option-title">TLS, verified certificate <span class="tag-ok">Recommended</span></span>
                  <span class="option-desc">For servers with a certificate from a trusted authority or your cloud provider.</span></span>
                <span class="radio-dot" aria-hidden="true"></span>
              </label>
              <label class="option">
                <input class="sr-only" type="radio" name="method" value="pinned"<?= $checked('method', 'pinned', 'tls') ?>>
                <span class="option-icon ok"><?= icon('pin', 20) ?></span>
                <span class="option-text"><span class="option-title">TLS, self-signed certificate</span>
                  <span class="option-desc">We pin the certificate on the first test. You confirm its fingerprint once.</span></span>
                <span class="radio-dot" aria-hidden="true"></span>
              </label>
              <label class="option">
                <input class="sr-only" type="radio" name="method" value="ssh"<?= $checked('method', 'ssh', 'tls') ?>>
                <span class="option-icon info"><?= icon('terminal', 20) ?></span>
                <span class="option-text"><span class="option-title">SSH tunnel</span>
                  <span class="option-desc">For databases that aren't open to the internet. We connect over SSH first.</span></span>
                <span class="radio-dot" aria-hidden="true"></span>
              </label>
            </div>
            <?= $error('method') ?>
            <span class="small muted">Unencrypted connections aren't allowed.</span>
          </fieldset>

          <div class="when-direct stack-18">
            <div class="field-row">
              <label class="field grow">Host
                <input class="mono" type="text" name="host" value="<?= e($val('host')) ?>" placeholder="db.example.com" autocomplete="off" spellcheck="false"<?= $invalid('host') ?>>
                <?= $error('host') ?>
              </label>
              <label class="field port">Port
                <input class="mono" type="text" name="port" value="<?= e($val('port')) ?>"<?= $ph('3306', '5432') ?> inputmode="numeric"<?= $invalid('port') ?>>
                <?= $error('port') ?>
              </label>
            </div>
            <div class="when-tls">
              <label class="field">CA certificate (optional)
                <input type="file" name="ca_file" accept=".pem,.crt,.cer"<?= $invalid('ca_file') ?>>
                <span class="hint">Only if your server uses its own certificate authority, such as a cloud provider's CA.</span>
                <?= $error('ca_file') ?>
              </label>
              <?php if ($isEdit && $server['method'] === 'tls' && $server['ca_pem'] !== ''): ?>
                <label class="check-row small"><input type="checkbox" name="ca_remove" value="1"> Remove the uploaded CA certificate</label>
              <?php endif; ?>
            </div>
            <p class="when-pinned small muted">Run a test to see the certificate's fingerprint, then confirm it matches your server. If it ever changes, connections stop until you confirm again.</p>
            <div class="callout callout-info"><?= icon('info', 20) ?>
              <div class="stack-6 min0">
                <?php if ($egressIp !== ''): ?>
                  <span>On your server, open the database port only to this IP:</span>
                  <span class="row-wrap"><code class="ip"><?= e($egressIp) ?></code>
                    <button type="button" class="btn btn-small btn-ghost" data-copy="<?= e($egressIp) ?>" hidden>Copy IP</button></span>
                <?php else: ?>
                  <span>On your server, open the database port only to this portal's public IP address.</span>
                <?php endif; ?>
                <span class="small">If the database runs in Docker, UFW won't block the port. Use your provider's firewall instead.</span>
              </div>
            </div>
          </div>

          <div class="when-ssh stack-18">
            <div class="field-row">
              <label class="field grow">SSH host
                <input class="mono" type="text" name="ssh_host" value="<?= e($val('ssh_host')) ?>" placeholder="bastion.example.org" autocomplete="off" spellcheck="false"<?= $invalid('ssh_host') ?>>
                <?= $error('ssh_host') ?>
              </label>
              <label class="field port">SSH port
                <input class="mono" type="text" name="ssh_port" value="<?= e($val('ssh_port')) ?>" placeholder="22" inputmode="numeric"<?= $invalid('ssh_port') ?>>
                <?= $error('ssh_port') ?>
              </label>
            </div>
            <label class="field">SSH user
              <input class="mono" type="text" name="ssh_user" value="<?= e($val('ssh_user')) ?>" placeholder="deploy" autocomplete="off" spellcheck="false"<?= $invalid('ssh_user') ?>>
              <?= $error('ssh_user') ?>
            </label>
            <fieldset class="stack-8">
              <legend class="label">Sign in to SSH with</legend>
              <div class="chips">
                <label class="chip"><input class="sr-only" type="radio" name="ssh_auth" value="key"<?= $checked('ssh_auth', 'key', 'key') ?>><span>Private key</span></label>
                <label class="chip"><input class="sr-only" type="radio" name="ssh_auth" value="password"<?= $checked('ssh_auth', 'password', 'key') ?>><span>Password</span></label>
              </div>
            </fieldset>
            <label class="field when-key">Private key
              <textarea class="mono" name="ssh_key" rows="4" spellcheck="false" placeholder="<?= $hasSshSecret ? 'Leave empty to keep the saved key' : '-----BEGIN OPENSSH PRIVATE KEY-----' ?>"<?= $invalid('ssh_key') ?>></textarea>
              <span class="hint">Stored encrypted, like passwords. Use a key made only for this portal.</span>
              <?= $error('ssh_key') ?>
            </label>
            <label class="field when-password">SSH password
              <input type="password" name="ssh_password" autocomplete="new-password" placeholder="<?= $hasSshSecret ? 'Leave empty to keep the saved password' : '' ?>"<?= $invalid('ssh_password') ?>>
              <?= $error('ssh_password') ?>
            </label>
            <div class="field-row">
              <label class="field grow">Database host, as seen from the SSH server
                <input class="mono" type="text" name="ssh_db_host" value="<?= e($val('ssh_db_host')) ?>" placeholder="127.0.0.1" autocomplete="off" spellcheck="false">
              </label>
              <label class="field port">Database port
                <input class="mono" type="text" name="ssh_db_port" value="<?= e($val('ssh_db_port')) ?>"<?= $ph('3306', '5432') ?> inputmode="numeric">
              </label>
            </div>
            <div class="callout callout-info"><?= icon('info', 20) ?>
              <div class="stack-6 min0">
                <?php if ($egressIp !== ''): ?>
                  <span>On your SSH server, allow SSH only from this IP:</span>
                  <span class="row-wrap"><code class="ip"><?= e($egressIp) ?></code>
                    <button type="button" class="btn btn-small btn-ghost" data-copy="<?= e($egressIp) ?>" hidden>Copy IP</button></span>
                <?php else: ?>
                  <span>On your SSH server, allow SSH only from this portal's public IP address.</span>
                <?php endif; ?>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="card form-section" aria-labelledby="sec-name">
        <h2 id="sec-name">2. Name and environment</h2>
        <label class="field">Display name
          <input type="text" name="name" value="<?= e($val('name')) ?>" placeholder="Shop – Production" maxlength="80"<?= $invalid('name') ?>>
          <?= $error('name') ?>
        </label>
        <fieldset class="stack-8">
          <legend class="label">Environment</legend>
          <div class="chips">
            <?php foreach (['Production' => 'env-prod', 'Staging' => 'env-staging', 'Development' => 'env-dev'] as $env => $class): ?>
              <label class="chip <?= $class ?>">
                <input class="sr-only" type="radio" name="environment" value="<?= e($env) ?>"<?= $checked('environment', $env, 'Production') ?>>
                <span><span class="dot" aria-hidden="true"></span><?= e($env) ?></span>
              </label>
            <?php endforeach; ?>
          </div>
          <span class="small muted">Production servers default to “Ask every time”.</span>
        </fieldset>
      </section>

      <section class="card form-section" aria-labelledby="sec-login">
        <h2 id="sec-login">3. Database login</h2>
        <div class="field-row">
          <label class="field grow">Database user
            <input class="mono" type="text" name="db_user" value="<?= e($val('db_user')) ?>" placeholder="shop_admin" autocomplete="off" spellcheck="false"<?= $invalid('db_user') ?>>
            <?= $error('db_user') ?>
          </label>
          <label class="field grow">
            <span class="when-saved-text">Password</span><span class="when-ask-text">Password (used for the test only)</span>
            <span class="input-with-button">
              <input type="password" name="db_password" id="db_password" autocomplete="new-password"
                     placeholder="<?= $savedPassword ? 'Leave empty to keep the saved password' : '' ?>"<?= $invalid('db_password') ?>>
              <button type="button" class="btn btn-icon-inline" data-toggle-password="db_password" aria-label="Show password" hidden><?= icon('eye', 18) ?></button>
            </span>
            <?= $error('db_password') ?>
          </label>
        </div>
        <label class="field when-postgres">Database (optional)
          <input class="mono" type="text" name="db_name" value="<?= e($val('db_name')) ?>" placeholder="postgres" autocomplete="off" spellcheck="false"<?= $invalid('db_name') ?>>
          <span class="hint">pgAdmin connects to this database first and lists the others the user may open. Leave it empty for postgres.</span>
          <?= $error('db_name') ?>
        </label>
        <p class="small muted">Use a user with only the privileges it needs. <span class="when-mysql">root is always blocked.</span><span class="when-postgres">The postgres superuser is always blocked.</span></p>
        <fieldset class="stack-8">
          <legend class="label">When you open this server</legend>
          <div class="options">
            <label class="option">
              <input class="sr-only" type="radio" name="cred_mode" value="saved"<?= $checked('cred_mode', 'saved', 'ask') ?>>
              <span class="option-icon accent"><?= icon('key', 20) ?></span>
              <span class="option-text"><span class="option-title">Save in the vault</span>
                <span class="option-desc">Encrypted on the server. Opens in one click.</span></span>
              <span class="radio-dot" aria-hidden="true"></span>
            </label>
            <label class="option">
              <input class="sr-only" type="radio" name="cred_mode" value="ask"<?= $checked('cred_mode', 'ask', 'ask') ?>>
              <span class="option-icon"><?= icon('ask', 20) ?></span>
              <span class="option-text"><span class="option-title">Ask every time</span>
                <span class="option-desc">Nothing is stored. You type the password when opening.</span></span>
              <span class="radio-dot" aria-hidden="true"></span>
            </label>
          </div>
        </fieldset>
      </section>

      <div class="form-actions">
        <button type="button" class="btn btn-secondary" data-test-connection hidden><?= icon('plug', 18) ?> Test connection</button>
        <button type="submit" class="btn btn-primary">Save server</button>
        <a class="btn btn-link" href="/servers">Cancel</a>
        <span class="small muted"><?= $used ?> of <?= $limit ?> servers used</span>
      </div>
    </div>

    <aside class="form-aside" aria-label="Connection test and storage">
      <section class="card aside-card" aria-labelledby="test-title" data-test-panel>
        <div class="row-between">
          <h2 id="test-title">Connection test</h2>
          <span class="status-pill" data-test-status>Not run</span>
        </div>
        <div class="stack-12" data-test-body aria-live="polite">
          <p class="small muted">Run a test to check the host, the encryption and what this user is allowed to do. Tests are limited to <?= $testsPerMinute ?> a minute.</p>
        </div>
        <?php if ($pinnedNow !== ''): ?>
          <p class="small muted">Currently trusted: <code class="wrap"><?= e($pinnedNow) ?></code></p>
        <?php endif; ?>
        <noscript><p class="small muted">Testing and trusting fingerprints need JavaScript.</p></noscript>
      </section>
      <section class="card aside-card" aria-labelledby="store-title">
        <h2 id="store-title">What gets saved</h2>
        <div class="stack-4">
          <span class="label">Name, host, port, settings</span>
          <span class="small muted">Stored in the portal, visible only to you.</span>
        </div>
        <div class="stack-4">
          <span class="label">Database password</span>
          <span class="small muted when-saved-text">Encrypted in the vault. Decrypted only when you open the server, and never sent to your browser.</span>
          <span class="small muted when-ask-text">Not stored. You type it each time you open this server.</span>
        </div>
        <div class="stack-4 when-ssh">
          <span class="label">SSH key or password</span>
          <span class="small muted">Encrypted in the vault, like database passwords.</span>
        </div>
      </section>
    </aside>
  </div>
</form>

<?php if ($isEdit): ?>
  <section class="card danger-zone" aria-labelledby="delete-title">
    <details>
      <summary id="delete-title"><?= icon('trash') ?> Delete this server</summary>
      <form method="post" action="/servers/<?= (int) $server['id'] ?>/delete" class="stack-12">
        <?= csrf_field($ctx) ?>
        <p class="small muted">This removes the server and its saved password from the vault, and closes its open phpMyAdmin or pgAdmin sessions. The database itself is not touched.</p>
        <button class="btn btn-danger" type="submit">Delete <?= e($server['name']) ?></button>
      </form>
    </details>
  </section>
<?php endif; ?>
