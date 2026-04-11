<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/storage/config.php';
require_once __DIR__ . '/auth.php';

/**
 * Заголовки для HTML-страниц (index, login).
 */
function vm_send_html_security_headers(): void
{
    if (headers_sent()) {
        return;
    }
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    // Совместимость с inline-стилями/скриптами в index.php и fetch к Supabase
    header(
        "Content-Security-Policy: default-src 'self'; " .
        "base-uri 'self'; " .
        "frame-ancestors 'none'; " .
        "img-src 'self' data: blob:; " .
        "font-src 'self' data:; " .
        "style-src 'self' 'unsafe-inline'; " .
        "script-src 'self' 'unsafe-inline'; " .
        "connect-src 'self' https://*.supabase.co https://*.supabase.io; " .
        "form-action 'self'"
    );
}
