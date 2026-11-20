<?php

declare(strict_types=1);

namespace DbPortal;

/**
 * Renders PHP templates. Every dynamic value must go through e().
 */
final class View
{
    public function __construct(private readonly string $dir)
    {
    }

    /** @param array<string, mixed> $vars */
    public function render(string $template, array $vars, Ctx $ctx, ?string $layout = 'layout'): string
    {
        $content = $this->capture($template, $vars, $ctx);
        if ($layout === null) {
            return $content;
        }

        return $this->capture($layout, $vars + ['content' => $content], $ctx);
    }

    /** @param array<string, mixed> $vars */
    private function capture(string $template, array $vars, Ctx $ctx): string
    {
        $file = $this->dir . '/' . $template . '.php';
        $render = static function (string $__file, array $__vars, Ctx $ctx): void {
            extract($__vars, EXTR_SKIP);
            include $__file;
        };
        ob_start();
        try {
            $render($file, $vars, $ctx);
        } finally {
            $output = (string) ob_get_clean();
        }

        return $output;
    }

    public static function e(mixed $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function ago(?int $timestamp): string
    {
        if ($timestamp === null) {
            return 'never';
        }
        $diff = time() - $timestamp;

        return match (true) {
            $diff < 60 => 'just now',
            $diff < 3600 => intdiv($diff, 60) . ' min ago',
            $diff < 86400 => intdiv($diff, 3600) . ' h ago',
            $diff < 172800 => 'yesterday',
            $diff < 2592000 => intdiv($diff, 86400) . ' days ago',
            default => gmdate('M j, Y', $timestamp),
        };
    }

    public static function iso(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }

    public static function utc(int $timestamp): string
    {
        return gmdate('M j, H:i', $timestamp) . ' UTC';
    }
}
