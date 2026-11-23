<?php
/** @var DbPortal\Ctx $ctx */
/** @var array<string, string> $values */
/** @var array<string, string> $errors */
/** @var list<array<string, mixed>> $accounts */
/** @var string $query */
/** @var string $notice */
/** @var bool $allowPlain */
/** @var array{servers: int, accounts: int} $plain servers set to "Not encrypted" */
use DbPortal\Settings;
use DbPortal\View;

$ctx->title = 'Admin';
$me = (int) $ctx->user['id'];
$plainCount = $plain['servers'] . ' server' . ($plain['servers'] === 1 ? '' : 's') . ' in '
    . $plain['accounts'] . ' account' . ($plain['accounts'] === 1 ? '' : 's');
?>
<div class="page-head">
  <div class="stack-8 head-text">
    <h1>Admin</h1>
    <p class="muted">Platform controls for <?= e($ctx->cfg->providerName) ?> staff. Admins can change security settings and limits and suspend accounts, but never see anyone's database passwords.</p>
  </div>
</div>

<?php if ($notice !== ''): ?>
  <div class="callout callout-success" role="status"><?= icon('check', 20) ?><span><?= e($notice) ?></span></div>
<?php endif; ?>

<section class="card form-section" aria-labelledby="security-title">
  <div class="stack-4">
    <h2 id="security-title">Security</h2>
    <p class="small muted">Applies to every account. Changes apply immediately.</p>
  </div>
  <form method="post" action="/admin/security" class="stack-18">
    <?= csrf_field($ctx) ?>
    <label class="policy-row">
      <input type="checkbox" name="allow_plain" value="1"<?= $allowPlain ? ' checked' : '' ?>>
      <span class="stack-4">
        <span class="policy-title"><?= e(Settings::POLICIES['allow_plain']) ?></span>
        <span class="small muted">Off by default. When on, people can choose “Not encrypted” when they add a remote server. Queries, results and sessions to those servers travel without encryption.</span>
      </span>
    </label>
    <?php if ($plain['servers'] > 0): ?>
      <div class="callout callout-info"><?= icon('info', 20) ?>
        <div class="stack-4 min0">
          <?php if ($allowPlain): ?>
            <span><?= e($plainCount) ?> connect<?= $plain['servers'] === 1 ? 's' : '' ?> without encryption.</span>
            <span class="small">Turning this off blocks them and closes their open sessions. They stay saved, so their owners can switch them to TLS or an SSH tunnel.</span>
          <?php else: ?>
            <span><?= e($plainCount) ?> <?= $plain['servers'] === 1 ? 'is' : 'are' ?> blocked because they connect without encryption.</span>
            <span class="small">Turning this on lets them open again. Their owners can also switch them to TLS or an SSH tunnel.</span>
          <?php endif; ?>
        </div>
      </div>
    <?php endif; ?>
    <div class="row-wrap">
      <button class="btn btn-primary" type="submit">Save security settings</button>
    </div>
  </form>
</section>

<section class="card form-section" aria-labelledby="limits-title">
  <div class="stack-4">
    <h2 id="limits-title">Abuse limits</h2>
    <p class="small muted">Enforced by the portal itself and stored in its own database, not in Dokploy. Changes apply immediately.</p>
  </div>
  <form method="post" action="/admin/limits" class="stack-18">
    <?= csrf_field($ctx) ?>
    <div class="limits-grid">
      <?php foreach (Settings::LIMITS as $key => $limit): ?>
        <label class="field"><?= e($limit['label']) ?>
          <span class="row-wrap">
            <input class="mono limit-input" type="number" name="<?= e($key) ?>" value="<?= e($values[$key] ?? '') ?>"
                   min="<?= $limit['min'] ?>" max="<?= $limit['max'] ?>" required
                   <?= isset($errors[$key]) ? 'aria-invalid="true" aria-describedby="err-' . e($key) . '"' : '' ?>>
            <span class="small muted"><?= e($limit['unit']) ?></span>
          </span>
          <?php if (isset($errors[$key])): ?><span class="field-error" id="err-<?= e($key) ?>"><?= e($errors[$key]) ?></span><?php endif; ?>
        </label>
      <?php endforeach; ?>
    </div>
    <div class="row-wrap">
      <button class="btn btn-primary" type="submit">Save limits</button>
      <button class="btn btn-ghost" type="submit" name="reset" value="1" formnovalidate>Reset to defaults</button>
    </div>
  </form>
</section>

<section class="stack-14" aria-labelledby="accounts-title">
  <div class="row-between wrap-gap">
    <div class="stack-4">
      <h2 id="accounts-title" class="h-section">Accounts</h2>
      <p class="small muted">Suspending signs the account out everywhere and closes its phpMyAdmin and pgAdmin sessions. Its saved passwords stay encrypted.</p>
    </div>
    <form class="search" method="get" action="/admin" role="search">
      <?= icon('search', 18) ?>
      <label class="sr-only" for="account-q">Search accounts</label>
      <input id="account-q" type="search" name="q" value="<?= e($query) ?>" placeholder="Search by email or name">
    </form>
  </div>
  <div class="table-box">
    <div class="acct-grid log-head" aria-hidden="true">
      <span><?= e($ctx->cfg->providerName) ?> account</span><span>Servers</span><span>Last sign-in</span><span>Status</span><span>Action</span>
    </div>
    <?php if ($accounts === []): ?>
      <p class="empty-inline">No accounts match “<?= e($query) ?>”.</p>
    <?php else: ?>
      <ul class="log-list">
        <?php foreach ($accounts as $a):
            $suspended = $a['suspended_at'] !== null;
            $label = $a['email'] !== '' ? $a['email'] : $a['subject']; ?>
          <li class="acct-grid log-row">
            <span class="stack-2 min0">
              <span class="strong wrap"><?= e($label) ?></span>
              <?php if ($a['name'] !== ''): ?><span class="small muted wrap"><?= e($a['name']) ?></span><?php endif; ?>
            </span>
            <span class="mono"><?= (int) $a['server_count'] ?></span>
            <span class="muted"><?= $a['last_login_at'] !== null ? e(View::ago((int) $a['last_login_at'])) : 'never' ?></span>
            <span class="stack-4 min0">
              <span><span class="result <?= $suspended ? 'r-locked' : 'r-ok' ?>"><?= $suspended ? 'Suspended' : 'Active' ?></span></span>
              <?php if ($suspended && $a['suspended_reason'] !== ''): ?><span class="small muted wrap"><?= e($a['suspended_reason']) ?></span><?php endif; ?>
            </span>
            <span>
              <?php if ((int) $a['id'] === $me): ?>
                <span class="small muted">You</span>
              <?php elseif ($suspended): ?>
                <form method="post" action="/admin/accounts/<?= (int) $a['id'] ?>/reactivate">
                  <?= csrf_field($ctx) ?>
                  <button class="btn btn-small btn-ghost" type="submit" aria-label="Reactivate <?= e($label) ?>">Reactivate</button>
                </form>
              <?php else: ?>
                <details class="suspend">
                  <summary class="btn btn-small btn-danger-outline">Suspend</summary>
                  <form method="post" action="/admin/accounts/<?= (int) $a['id'] ?>/suspend" class="stack-8 suspend-form">
                    <?= csrf_field($ctx) ?>
                    <label class="field small">Reason (shown in their activity)
                      <input type="text" name="reason" maxlength="200" placeholder="For example: scanning other servers">
                    </label>
                    <button class="btn btn-small btn-danger" type="submit">Suspend <?= e($label) ?></button>
                  </form>
                </details>
              <?php endif; ?>
            </span>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</section>
