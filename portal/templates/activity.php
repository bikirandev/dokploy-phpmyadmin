<?php
/** @var DbPortal\Ctx $ctx */
/** @var list<array<string, mixed>> $events */
/** @var string $filter */
/** @var int $serverCount */
/** @var int $savedCount */
/** @var int $limit */
use DbPortal\Events;
use DbPortal\View;

$ctx->title = 'Your activity';
$kindIcon = ['open' => ['open', 'k-open'], 'signin' => ['signin', 'k-signin'], 'change' => ['edit', 'k-change'], 'problem' => ['alert', 'k-problem']];
$results = ['ok' => ['Success', 'r-ok'], 'failed' => ['Failed', 'r-failed'], 'locked' => ['Locked', 'r-locked'], 'denied' => ['Denied', 'r-locked']];
?>
<div class="page-head">
  <div class="stack-8 head-text">
    <h1>Your activity</h1>
    <p class="muted">Everything that happened in your account. Entries are kept for <?= Events::RETENTION_DAYS ?> days.</p>
  </div>
</div>

<div class="tiles">
  <section class="card tile" aria-labelledby="tile-signin">
    <h2 id="tile-signin">Sign-in</h2>
    <span class="tile-value ok"><?= icon('shield', 20) ?> <?= e($ctx->cfg->providerName) ?> account</span>
    <span class="small muted">Password and 2FA happen at <?= e($ctx->cfg->providerName) ?>.</span>
  </section>
  <section class="card tile" aria-labelledby="tile-servers">
    <h2 id="tile-servers">Servers</h2>
    <span class="tile-value"><?= $serverCount ?> of <?= $limit ?></span>
    <span class="small muted">Your account's server limit.</span>
  </section>
  <section class="card tile" aria-labelledby="tile-vault">
    <h2 id="tile-vault">Saved passwords</h2>
    <span class="tile-value accent"><?= icon('key', 20) ?> <?= $savedCount ?> in the vault</span>
    <span class="small muted">Encrypted, and never sent to your browser.</span>
  </section>
</div>

<section class="stack-14" aria-labelledby="log-title">
  <div class="row-between wrap-gap">
    <h2 id="log-title" class="h-section">Log</h2>
    <nav class="segmented" aria-label="Filter the log">
      <?php foreach (Events::FILTERS as $key => $label): ?>
        <a class="segmented-item" href="/activity?filter=<?= e($key) ?>"<?= $filter === $key ? ' aria-current="true"' : '' ?>><?= e($label) ?></a>
      <?php endforeach; ?>
    </nav>
  </div>
  <div class="table-box">
    <div class="log-grid log-head" aria-hidden="true">
      <span>Time</span><span>Event</span><span>Details</span><span>From</span><span>Result</span>
    </div>
    <?php if ($events === []): ?>
      <p class="empty-inline">Nothing here for this filter.</p>
    <?php else: ?>
      <ul class="log-list">
        <?php foreach ($events as $ev):
            [$icon, $iconClass] = $kindIcon[$ev['kind']] ?? ['info', 'k-change'];
            [$resultLabel, $resultClass] = $results[$ev['result']] ?? [ucfirst((string) $ev['result']), 'r-failed']; ?>
          <li class="log-grid log-row">
            <span class="muted"><time datetime="<?= e(View::iso((int) $ev['at'])) ?>" data-local><?= e(View::utc((int) $ev['at'])) ?></time></span>
            <span class="log-event"><span class="<?= e($iconClass) ?>"><?= icon($icon, 17) ?></span><?= e($ev['event']) ?></span>
            <span class="log-detail"><?= e($ev['detail']) ?></span>
            <span class="mono small muted"><?= e($ev['ip']) ?></span>
            <span><span class="result <?= e($resultClass) ?>"><?= e($resultLabel) ?></span></span>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</section>
