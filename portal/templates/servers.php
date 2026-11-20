<?php
/** @var DbPortal\Ctx $ctx */
/** @var list<array<string, mixed>> $servers */
/** @var array{all: int, local: int, remote: int} $counts */
/** @var string $filter */
/** @var string $query */
/** @var string $notice */
/** @var int $limit */
use DbPortal\View;

$ctx->title = 'My servers';
$envClass = ['Production' => 'env-prod', 'Staging' => 'env-staging', 'Development' => 'env-dev'];
$groups = [
    'local' => ['On this server', 'Dokploy databases on the pma-databases network', 'server'],
    'remote' => ['Remote', 'Your other servers, over TLS or an SSH tunnel', 'globe'],
];
$connection = static fn (array $s): array => match ($s['method']) {
    'internal' => ['network', 'Internal network', 'conn-internal'],
    'tls' => ['lock', 'TLS · certificate verified', 'conn-tls'],
    'pinned' => ['pin', 'TLS · pinned certificate', 'conn-tls'],
    default => ['terminal', 'SSH tunnel via ' . $s['ssh_host'], 'conn-ssh'],
};
$atLimit = $counts['all'] >= $limit;
?>
<div class="page-head">
  <div class="stack-8 head-text">
    <h1>My servers</h1>
    <p class="muted">Only you can see the servers you add. Saved passwords are encrypted in the vault and never sent to your browser.</p>
  </div>
  <div class="head-actions">
    <span class="small muted"><?= $counts['all'] ?> of <?= $limit ?> servers</span>
    <?php if ($atLimit): ?>
      <span class="btn btn-primary is-disabled" aria-disabled="true">Server limit reached</span>
    <?php else: ?>
      <a class="btn btn-primary" href="/servers/new"><?= icon('plus', 18) ?> Add server</a>
    <?php endif; ?>
  </div>
</div>

<?php if ($notice !== ''): ?>
  <div class="callout callout-success" role="status"><?= icon('check', 20) ?><span><?= e($notice) ?></span></div>
<?php endif; ?>

<?php if ($counts['all'] === 0): ?>
  <section class="empty" aria-labelledby="empty-title">
    <span class="empty-icon"><?= icon('db', 26) ?></span>
    <h2 id="empty-title">No servers yet</h2>
    <p class="muted">Add a database on this server or a remote one. Only you will see it.</p>
    <a class="btn btn-primary" href="/servers/new"><?= icon('plus', 18) ?> Add server</a>
  </section>
<?php else: ?>
  <div class="toolbar">
    <nav class="segmented" aria-label="Filter servers">
      <?php foreach (['all' => 'All', 'local' => 'This server', 'remote' => 'Remote'] as $key => $label): ?>
        <a class="segmented-item" href="/servers?filter=<?= e($key) ?><?= $query !== '' ? '&amp;q=' . e(rawurlencode($query)) : '' ?>"<?= $filter === $key ? ' aria-current="true"' : '' ?>>
          <?= e($label) ?> <span class="count"><?= $counts[$key] ?></span>
        </a>
      <?php endforeach; ?>
    </nav>
    <form class="search" method="get" action="/servers" role="search">
      <?= icon('search', 18) ?>
      <label class="sr-only" for="q">Search your servers</label>
      <input id="q" type="search" name="q" value="<?= e($query) ?>" placeholder="Search by name or host">
      <?php if ($filter !== 'all'): ?><input type="hidden" name="filter" value="<?= e($filter) ?>"><?php endif; ?>
    </form>
  </div>

  <?php if ($servers === []): ?>
    <div class="empty-inline">No servers match “<?= e($query) ?>”.</div>
  <?php endif; ?>

  <?php foreach ($groups as $location => [$groupTitle, $groupHint, $groupIcon]):
      $items = array_values(array_filter($servers, static fn (array $s): bool => $s['location'] === $location));
      if ($items === []) {
          continue;
      } ?>
    <section class="group" aria-labelledby="group-<?= e($location) ?>">
      <div class="group-head">
        <?= icon($groupIcon) ?>
        <h2 id="group-<?= e($location) ?>"><?= e($groupTitle) ?></h2>
        <span class="small muted"><?= e($groupHint) ?></span>
      </div>
      <ul class="server-list">
        <?php foreach ($items as $s):
            [$connIcon, $connLabel, $connClass] = $connection($s);
            $locked = (int) $s['locked_for'] > 0; ?>
          <li class="server-row">
            <div class="server-main">
              <span class="server-icon" aria-hidden="true"><?= icon('db', 18) ?></span>
              <div class="stack-4 min0">
                <div class="row-wrap">
                  <span class="server-name"><?= e($s['name']) ?></span>
                  <span class="env <?= e($envClass[$s['environment']] ?? '') ?>"><?= e($s['environment']) ?></span>
                </div>
                <span class="small muted"><?= e($s['engine'] !== '' ? $s['engine'] : 'MySQL / MariaDB') ?> · <?= $s['last_opened_at'] !== null ? 'opened ' . e(View::ago((int) $s['last_opened_at'])) : 'never opened' ?></span>
              </div>
            </div>
            <div class="server-conn stack-4 min0">
              <span class="mono host"><?= e($s['host']) ?>:<?= (int) $s['port'] ?></span>
              <span class="conn <?= e($connClass) ?>"><?= icon($connIcon, 15) ?><?= e($connLabel) ?></span>
            </div>
            <div class="server-creds">
              <?php if ($s['cred_mode'] === 'saved'): ?>
                <span class="creds creds-saved"><?= icon('key') ?> Saved as <span class="mono"><?= e($s['db_user']) ?></span></span>
              <?php else: ?>
                <span class="creds"><?= icon('ask') ?> Ask every time</span>
              <?php endif; ?>
              <?php if ($locked): ?>
                <span class="badge badge-danger">Locked <?= (int) ceil($s['locked_for'] / 60) ?> min</span>
              <?php endif; ?>
            </div>
            <div class="server-actions">
              <a class="btn btn-icon" href="/servers/<?= (int) $s['id'] ?>/edit" aria-label="Edit <?= e($s['name']) ?>"><?= icon('edit', 18) ?></a>
              <?php if ($s['cred_mode'] === 'saved'): ?>
                <form method="post" action="/servers/<?= (int) $s['id'] ?>/open" target="_blank">
                  <?= csrf_field($ctx) ?>
                  <button class="btn btn-outline" type="submit"<?= $locked ? ' disabled' : '' ?>>Open <?= icon('open') ?></button>
                </form>
              <?php elseif ($locked): ?>
                <span class="btn btn-outline is-disabled" aria-disabled="true">Open <?= icon('open') ?></span>
              <?php else: ?>
                <a class="btn btn-outline" href="/servers/<?= (int) $s['id'] ?>/open">Open <?= icon('open') ?></a>
              <?php endif; ?>
            </div>
          </li>
        <?php endforeach; ?>
      </ul>
    </section>
  <?php endforeach; ?>
<?php endif; ?>

<p class="small muted with-icon footnote"><?= icon('shield') ?>
  <span>phpMyAdmin runs on its own address, is only reachable through this portal, and can't reach Dokploy itself or other apps. Root logins are blocked on every server.</span>
</p>
