<?php

declare(strict_types=1);

/**
 * Escapes a value for HTML text and attributes.
 */
function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Inline stroke icons (decorative; hidden from screen readers).
 */
function icon(string $name, int $size = 16): string
{
    static $paths = [
        'db' => '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v6.2c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8V5.5"/><path d="M4.5 11.7v6.5c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8v-6.5"/>',
        'server' => '<rect x="3.5" y="4" width="17" height="7" rx="1.8"/><rect x="3.5" y="13" width="17" height="7" rx="1.8"/><path d="M7.5 7.5h.01" stroke-width="2.6"/><path d="M7.5 16.5h.01" stroke-width="2.6"/>',
        'globe' => '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.3 2.4 3.5 5.3 3.5 8.5s-1.2 6.1-3.5 8.5c-2.3-2.4-3.5-5.3-3.5-8.5s1.2-6.1 3.5-8.5z"/>',
        'network' => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><path d="M6.5 10v4.5a2 2 0 0 0 2 2H14"/>',
        'lock' => '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"/>',
        'unlock' => '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 6.8-1.1"/>',
        'pin' => '<path d="M12 21s-6-5.3-6-10a6 6 0 0 1 12 0c0 4.7-6 10-6 10z"/><circle cx="12" cy="11" r="2.2"/>',
        'terminal' => '<rect x="3" y="4.5" width="18" height="15" rx="2.5"/><path d="M7.5 9.5l3 2.5-3 2.5"/><path d="M12.5 15h4"/>',
        'key' => '<circle cx="8" cy="15.5" r="4"/><path d="M10.9 12.6L19.5 4"/><path d="M16.5 7l2.5 2.5"/><path d="M14 9.5l2 2"/>',
        'ask' => '<rect x="2.5" y="7" width="19" height="10" rx="2.5"/><path d="M7.5 12h.01" stroke-width="2.8"/><path d="M12 12h.01" stroke-width="2.8"/><path d="M16.5 12h.01" stroke-width="2.8"/>',
        'plus' => '<path d="M12 5v14"/><path d="M5 12h14"/>',
        'search' => '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
        'open' => '<path d="M7 17L17 7"/><path d="M9 7h8v8"/>',
        'edit' => '<path d="M4 20h4.2L19 9.2a2.1 2.1 0 0 0 0-3L17.8 5a2.1 2.1 0 0 0-3 0L4 15.8V20z"/><path d="M13.5 6.5l4 4"/>',
        'check' => '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
        'x' => '<path d="M6 6l12 12"/><path d="M18 6L6 18"/>',
        'shield' => '<path d="M12 3l7.5 2.8v5.7c0 4.4-3.1 8.1-7.5 9.5-4.4-1.4-7.5-5.1-7.5-9.5V5.8L12 3z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
        'logout' => '<path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3"/><path d="M14 16l4-4-4-4"/><path d="M18 12H9"/>',
        'signin' => '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="M10 16l4-4-4-4"/><path d="M14 12H4"/>',
        'alert' => '<path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4"/><path d="M12 17h.01" stroke-width="2.6"/>',
        'info' => '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><path d="M12 8h.01" stroke-width="2.6"/>',
        'eye' => '<path d="M2.5 12s3.5-6.5 9.5-6.5 9.5 6.5 9.5 6.5-3.5 6.5-9.5 6.5S2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
        'plug' => '<path d="M9 2.5v5"/><path d="M15 2.5v5"/><path d="M6.5 7.5h11v3.5a5.5 5.5 0 0 1-11 0V7.5z"/><path d="M12 16.5v5"/>',
        'id' => '<rect x="3" y="5" width="18" height="14" rx="2.5"/><circle cx="9" cy="11" r="2.2"/><path d="M5.8 16c.6-1.6 1.8-2.4 3.2-2.4s2.6.8 3.2 2.4"/><path d="M14.5 10h4"/><path d="M14.5 13.5h3"/>',
        'trash' => '<path d="M4 7h16"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12"/><path d="M9 7V4h6v3"/>',
    ];
    $path = $paths[$name] ?? '';

    return '<svg class="icon" width="' . $size . '" height="' . $size . '" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        . 'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $path . '</svg>';
}

/**
 * Hidden CSRF field for forms.
 */
function csrf_field(\DbPortal\Ctx $ctx): string
{
    return '<input type="hidden" name="_csrf" value="' . e($ctx->csrf()) . '">';
}
