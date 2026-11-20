<?php
/** @var DbPortal\Ctx $ctx */
/** @var string $next */
/** @var string $notice */
/** @var string $error */
/** @var bool $suspended */
$ctx->title = 'Sign in';
$provider = $ctx->cfg->providerName;
$href = '/auth/login?next=' . rawurlencode($next) . ($suspended ? '&select=1' : '');
?>
<section class="card auth-card" aria-labelledby="signin-title">
  <div class="brand-row">
    <img src="/assets/logo.svg" alt="" width="34" height="34">
    <span><?= e($ctx->cfg->portalName) ?></span>
  </div>
  <div class="stack-6">
    <h1 id="signin-title">Sign in</h1>
    <p class="muted">Sign in with your <?= e($provider) ?> account to manage your databases.</p>
  </div>

  <?php if ($notice !== ''): ?>
    <div class="callout callout-info" role="status"><?= icon('info', 20) ?><span><?= e($notice) ?></span></div>
  <?php endif; ?>
  <?php if ($error !== ''): ?>
    <div class="callout callout-danger" role="alert"><?= icon('alert', 20) ?><span><?= e($error) ?></span></div>
  <?php endif; ?>
  <?php if ($suspended): ?>
    <div class="callout callout-danger" role="alert">
      <?= icon('info', 20) ?>
      <div class="stack-2">
        <strong>This account is suspended</strong>
        <span>It broke the usage rules, for example by connecting to servers it doesn't own. Contact <?= e($provider) ?> support if you think this is a mistake.</span>
      </div>
    </div>
  <?php endif; ?>

  <a class="btn btn-primary btn-lg btn-block" href="<?= e($href) ?>">
    <span class="provider-mark"><?= icon('id', 18) ?></span>
    <?= $suspended ? 'Use a different ' . e($provider) . ' account' : 'Continue with ' . e($provider) ?>
  </a>

  <p class="small muted with-icon"><?= icon('lock') ?>
    <span>Your password and 2-step verification stay on <?= e($provider) ?>'s sign-in page. This portal never sees them.</span>
  </p>
</section>
