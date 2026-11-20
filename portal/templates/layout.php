<?php
/** @var DbPortal\Ctx $ctx */
/** @var string $content */
$path = $ctx->req->path;
$nav = [['/servers', 'My servers'], ['/activity', 'Activity']];
if ($ctx->isAdmin()) {
    $nav[] = ['/admin', 'Admin'];
}
$displayName = (string) ($ctx->user['name'] ?: ($ctx->user['email'] ?: 'Your account'));
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="csrf-token" content="<?= e($ctx->csrf()) ?>">
<title><?= e($ctx->title !== '' ? $ctx->title . ' – ' . $ctx->cfg->portalName : $ctx->cfg->portalName) ?></title>
<link rel="icon" href="/assets/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/app.css">
<script src="/assets/app.js" defer></script>
</head>
<body>
<header class="topbar">
  <a class="brand" href="/servers">
    <img src="/assets/logo.svg" alt="" width="30" height="30">
    <span><?= e($ctx->cfg->portalName) ?></span>
  </a>
  <nav class="topnav" aria-label="Main">
    <?php foreach ($nav as [$href, $label]): ?>
      <a href="<?= e($href) ?>" class="topnav-link"<?= str_starts_with($path, $href) ? ' aria-current="page"' : '' ?>><?= e($label) ?></a>
    <?php endforeach; ?>
  </nav>
  <div class="topbar-user">
    <span class="pill"><?= icon('id', 16) ?> Signed in with <?= e($ctx->cfg->providerName) ?></span>
    <span class="user-name"><?= e($displayName) ?></span>
    <form method="post" action="/auth/logout">
      <?= csrf_field($ctx) ?>
      <button class="btn btn-ghost" type="submit"><?= icon('logout') ?> Sign out</button>
    </form>
  </div>
</header>
<main class="page">
<?= $content ?>
</main>
</body>
</html>
