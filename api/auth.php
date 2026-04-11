<?php
// api/auth.php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

function clearAuthCookies(): void {
    // максимально “надёжно”: удаляем и старым способом, и через options-массив
    @setcookie(COOKIE_ACCESS, '', time() - 3600, '/');
    @setcookie(COOKIE_REFRESH, '', time() - 3600, '/');

    $opts = [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => COOKIE_SECURE,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
    @setcookie(COOKIE_ACCESS, '', $opts);
    @setcookie(COOKIE_REFRESH, '', $opts);
}

function loginUser($email, $password) {
    try {
        $url = SUPABASE_URL . '/auth/v1/token?grant_type=password';

        $data = [
            'email' => $email,
            'password' => $password
        ];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'apikey: ' . SUPABASE_ANON_KEY
        ]);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            return ['success' => false, 'error' => 'Network error: ' . $curlError];
        }

        if ($httpCode === 200) {
            $result = json_decode($response, true);

            // Лучше тоже перейти на options-массив, чтобы совпадало с удалением
            setcookie(COOKIE_ACCESS, $result['access_token'], [
                'expires' => time() + TOKEN_LIFETIME,
                'path' => '/',
                'secure' => COOKIE_SECURE,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);

            setcookie(COOKIE_REFRESH, $result['refresh_token'], [
                'expires' => time() + TOKEN_LIFETIME,
                'path' => '/',
                'secure' => COOKIE_SECURE,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);

            return ['success' => true, 'user' => ($result['user'] ?? null)];
        }

        $error = json_decode($response, true);
        return [
            'success' => false,
            'error' => $error['error_description'] ?? 'Invalid email or password'
        ];

    } catch (Throwable $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

function logoutUser(): void {
    vm_clear_auth_cookies_hard();
}

// ===== Endpoint handler =====
$action = $_GET['action'] ?? '';

if ($action === 'logout') {
    // важно: даже если logout вызывается без сессии — чистим только cookies
    logoutUser();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => true]);
    exit;
}

// если вдруг откроют напрямую без action
http_response_code(400);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['ok' => false, 'error' => 'Unknown action']);
