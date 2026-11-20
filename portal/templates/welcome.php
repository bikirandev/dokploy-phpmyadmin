<?php
/** @var DbPortal\Ctx $ctx */
/** @var string $error */
$ctx->title = 'Before you start';
?>
<section class="card auth-card" aria-labelledby="rules-title">
  <div class="brand-row">
    <img src="/assets/logo.svg" alt="" width="34" height="34">
    <span><?= e($ctx->cfg->portalName) ?></span>
  </div>
  <div class="stack-6">
    <h1 id="rules-title">Before you start</h1>
    <p class="muted">You'll see this once, the first time you sign in.</p>
  </div>
  <ul class="rules">
    <li><?= icon('check', 18) ?><span>Only add database servers you own or are allowed to manage.</span></li>
    <li><?= icon('check', 18) ?><span>Sign-ins, connections and changes are logged with your IP address.</span></li>
    <li><?= icon('check', 18) ?><span>Scanning, password guessing or overloading servers gets an account suspended.</span></li>
  </ul>
  <?php if ($error !== ''): ?>
    <div class="callout callout-danger" role="alert"><?= icon('alert', 20) ?><span><?= e($error) ?></span></div>
  <?php endif; ?>
  <form method="post" action="/welcome" class="stack-16 agree-form">
    <?= csrf_field($ctx) ?>
    <label class="check-row">
      <input type="checkbox" name="agree" value="1" required>
      <span>I agree to these rules</span>
    </label>
    <button class="btn btn-primary btn-lg btn-block" type="submit">Agree and continue</button>
  </form>
</section>
