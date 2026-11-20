<?php
/** @var DbPortal\Ctx $ctx */
/** @var int $status */
/** @var string $message */
$ctx->title = $status === 404 ? 'Not found' : 'Something went wrong';
?>
<section class="card narrow-card" aria-labelledby="error-title">
  <h1 id="error-title"><?= e($ctx->title) ?></h1>
  <p class="muted"><?= e($message) ?></p>
  <p><a class="btn btn-secondary" href="<?= $ctx->user !== null ? '/servers' : '/signin' ?>">Back to <?= $ctx->user !== null ? 'my servers' : 'sign in' ?></a></p>
</section>
