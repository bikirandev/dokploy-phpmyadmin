<?php
/** @var DbPortal\Ctx $ctx */
/** @var string $token */
$ctx->title = 'Emergency sign-in';
?>
<section class="card auth-card" aria-labelledby="emergency-title">
  <div class="brand-row">
    <img src="/assets/logo.svg" alt="" width="34" height="34">
    <span><?= e($ctx->cfg->portalName) ?></span>
  </div>
  <div class="stack-6">
    <h1 id="emergency-title">Emergency sign-in</h1>
    <p class="muted">This one-time link was created on the server for an admin account. It works once and is recorded in the activity log.</p>
  </div>
  <form method="post" action="/emergency/<?= e($token) ?>">
    <button class="btn btn-primary btn-lg btn-block" type="submit">Sign in now</button>
  </form>
</section>
