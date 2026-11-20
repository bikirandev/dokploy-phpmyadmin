<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Everything a request handler needs.
 */
final class Ctx
{
    /** @var array<string, mixed>|null */
    public ?array $user = null;

    /** @var array<string, mixed>|null */
    public ?array $session = null;

    /** Page title, set by the template being rendered. */
    public string $title = '';

    public function __construct(
        public readonly Config $cfg,
        public readonly Db $db,
        public readonly Crypto $crypto,
        public readonly Request $req,
        public readonly View $view,
        public readonly Settings $settings,
        public readonly Events $events,
        public readonly RateLimiter $limiter,
        public readonly Auth $auth,
        public readonly Servers $servers,
        public readonly Tickets $tickets,
        public readonly PmaClient $pma,
        public readonly Oidc $oidc,
    ) {
    }

    public function isAdmin(): bool
    {
        return $this->user !== null && in_array((string) $this->user['subject'], $this->cfg->adminSubjects, true);
    }

    public function csrf(): string
    {
        return (string) ($this->session['csrf'] ?? '');
    }

    public function log(string $kind, string $event, string $detail, string $result = 'ok', ?int $userId = null): void
    {
        $this->events->log($userId ?? ($this->user !== null ? (int) $this->user['id'] : null), $kind, $event, $detail, $result, $this->req->ip());
    }

    /** @param array<string, mixed> $vars */
    public function render(string $template, array $vars = [], int $status = 200, ?string $layout = 'layout'): never
    {
        Response::html($this->view->render($template, $vars, $this, $layout), $status);
    }
}
