<?php
declare(strict_types=1);

function vm_redirect_to_login(): void
{
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('Location: /login.php');
    exit;
}

function vm_clear_auth_cookies_hard(): void
{
    $paths = ['/', ''];
    $secures = [false, true];

    foreach ($paths as $path) {
        foreach ($secures as $secure) {
            $opts = [
                'expires'  => time() - 3600,
                'path'     => $path,
                'secure'   => $secure,
                'httponly' => true,
                'samesite' => 'Lax',
            ];
            setcookie(COOKIE_ACCESS, '', $opts);
            setcookie(COOKIE_REFRESH, '', $opts);
        }
    }

    unset($_COOKIE[COOKIE_ACCESS], $_COOKIE[COOKIE_REFRESH]);
}

function vm_set_auth_cookie(string $name, string $value): void
{
    setcookie($name, $value, [
        'expires'  => time() + TOKEN_LIFETIME,
        'path'     => '/',
        'secure'   => COOKIE_SECURE,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE[$name] = $value;
}

function vm_supabase_refresh_tokens(): bool
{
    $rt = $_COOKIE[COOKIE_REFRESH] ?? '';
    if ($rt === '' || !function_exists('curl_init')) {
        return false;
    }

    $ch = curl_init(SUPABASE_URL . '/auth/v1/token?grant_type=refresh_token');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'apikey: ' . SUPABASE_ANON_KEY,
        ],
        CURLOPT_POSTFIELDS     => json_encode(['refresh_token' => $rt], JSON_UNESCAPED_UNICODE),
        CURLOPT_TIMEOUT        => 10,
    ]);

    $resp = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code !== 200 || !$resp) {
        return false;
    }

    $json = json_decode((string)$resp, true);
    if (!is_array($json) || empty($json['access_token']) || empty($json['refresh_token'])) {
        return false;
    }

    vm_set_auth_cookie(COOKIE_ACCESS, (string)$json['access_token']);
    vm_set_auth_cookie(COOKIE_REFRESH, (string)$json['refresh_token']);
    return true;
}

/**
 * Проверка access token через Supabase /auth/v1/user.
 * При 401 — одна попытка refresh.
 */
function vm_supabase_validate_access_token(string $token): ?array
{
    if (!function_exists('curl_init') || $token === '') {
        return null;
    }

    $try = function (string $t) {
        $ch = curl_init(SUPABASE_URL . '/auth/v1/user');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => [
                'apikey: ' . SUPABASE_ANON_KEY,
                'Authorization: Bearer ' . $t,
            ],
            CURLOPT_TIMEOUT => 5,
        ]);
        $resp = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($code !== 200 || $resp === false || $resp === '' || $err) {
            return null;
        }
        $user = json_decode((string)$resp, true);
        return is_array($user) ? $user : null;
    };

    $user = $try($token);
    if ($user !== null) {
        return $user;
    }

    if (vm_supabase_refresh_tokens()) {
        $new = $_COOKIE[COOKIE_ACCESS] ?? '';
        if ($new !== '') {
            return $try($new);
        }
    }

    return null;
}

function vm_user_from_supabase(array $user): array
{
    $meta = $user['user_metadata'] ?? [];
    if (!is_array($meta)) {
        $meta = [];
    }

    $login = trim((string)($meta['login'] ?? $meta['username'] ?? $meta['name'] ?? ''));
    if ($login === '') {
        $email = trim((string)($user['email'] ?? ''));
        if ($email !== '') {
            $pos = strpos($email, '@');
            $login = $pos === false ? $email : substr($email, 0, $pos);
        }
    }
    if ($login === '') {
        $login = 'User';
    }

    $initial = mb_strtoupper(mb_substr($login, 0, 1, 'UTF-8'), 'UTF-8');

    return ['login' => $login, 'initial' => $initial];
}

/**
 * Пользователь для HTML-страниц (index). null при необходимости редиректа на логин.
 */
function vm_get_session_user_for_page(): ?array
{
    if (defined('AUTH_DISABLED') && AUTH_DISABLED) {
        // Локальная разработка: как будто вошёл администратор
        return ['login' => 'admin', 'initial' => 'A'];
    }

    $token = $_COOKIE[COOKIE_ACCESS] ?? '';
    if ($token === '') {
        return null;
    }

    $user = vm_supabase_validate_access_token($token);
    if ($user === null) {
        vm_clear_auth_cookies_hard();
        return null;
    }

    return vm_user_from_supabase($user);
}

/**
 * API: авторизованный пользователь или null (401).
 */
function vm_get_session_user_for_api(): ?array
{
    if (defined('AUTH_DISABLED') && AUTH_DISABLED) {
        return ['login' => 'admin', 'initial' => 'A', 'guest' => false, 'role' => 'admin'];
    }

    $token = $_COOKIE[COOKIE_ACCESS] ?? '';
    if ($token === '') {
        return null;
    }

    $user = vm_supabase_validate_access_token($token);
    if ($user === null) {
        vm_clear_auth_cookies_hard();
        return null;
    }

    return vm_user_from_supabase($user);
}

function vm_send_json_headers(int $status = 200): void
{
    if (headers_sent()) {
        return;
    }
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
}

function vm_json_unauthorized(string $message = 'Unauthorized'): void
{
    vm_send_json_headers(401);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
}
