<?php
/** @var DbPortal\Ctx $ctx */
/** @var string $content */
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= e($ctx->title !== '' ? $ctx->title . ' – ' . $ctx->cfg->portalName : $ctx->cfg->portalName) ?></title>
<link rel="icon" href="/assets/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/app.css">
<script src="/assets/app.js" defer></script>
</head>
<body class="bare">
<main class="bare-main">
<?= $content ?>
</main>
<p class="bare-foot">Each account sees only its own servers. Every sign-in is logged.</p>
</body>
</html>
