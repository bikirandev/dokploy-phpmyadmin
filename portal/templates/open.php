<?php
/** @var DbPortal\Ctx $ctx */
/** @var array<string, mixed> $server */
/** @var string $error */
/** @var string $user */
$saved = $server['cred_mode'] === 'saved';
$ctx->title = 'Open ' . $server['name'];
$connection = match ($server['method']) {
    'internal' => 'Internal network',
    'tls' => 'TLS · certificate verified',
    'pinned' => 'TLS · pinned certificate',
    default => 'SSH tunnel via ' . $server['ssh_host'],
};
?>
<nav class="breadcrumb" aria-label="Breadcrumb">
  <a href="/servers">My servers</a>
  <span aria-hidden="true">/</span>
  <span aria-current="page">Open <?= e($server['name']) ?></span>
</nav>
<section class="card narrow-card stack-18" aria-labelledby="open-title">
  <div class="stack-6">
    <h1 id="open-title"><?= $saved ? 'Open' : 'Sign in to' ?> <?= e($server['name']) ?></h1>
    <p class="muted"><?= $saved
        ? 'phpMyAdmin signs in with the password saved in the vault.'
        : 'This server asks for its password every time. It is used for this session only and never stored.' ?></p>
    <span class="mono small muted wrap"><?= e($server['host']) ?>:<?= (int) $server['port'] ?> · <?= e($connection) ?></span>
  </div>

  <?php if ($error !== ''): ?>
    <div class="callout callout-danger" role="alert"><?= icon('alert', 20) ?><span><?= e($error) ?></span></div>
  <?php endif; ?>

  <form method="post" action="/servers/<?= (int) $server['id'] ?>/open" class="stack-16">
    <?= csrf_field($ctx) ?>
    <?php if (!$saved): ?>
      <label class="field">Database user
        <input class="mono" type="text" name="db_user" value="<?= e($user) ?>" autocomplete="username" spellcheck="false" required>
      </label>
      <label class="field">Password
        <input type="password" name="db_password" autocomplete="current-password" required autofocus>
      </label>
    <?php endif; ?>
    <div class="row-end">
      <a class="btn btn-secondary" href="/servers">Cancel</a>
      <button class="btn btn-primary" type="submit">Open phpMyAdmin <?= icon('open') ?></button>
    </div>
  </form>
</section>
