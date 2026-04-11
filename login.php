<?php
// login.php
declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

vm_send_html_security_headers();

function setAuthCookie(string $name, string $value): void {
  vm_set_auth_cookie($name, $value);
}

function clearAuthCookies(): void {
  setcookie(COOKIE_ACCESS, '', [
    'expires' => time() - 3600,
    'path' => '/',
    'secure' => COOKIE_SECURE,
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
  setcookie(COOKIE_REFRESH, '', [
    'expires' => time() - 3600,
    'path' => '/',
    'secure' => COOKIE_SECURE,
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
}

$error = '';
$email = '';

if (defined('AUTH_DISABLED') && AUTH_DISABLED) {
  header('Location: /');
  exit;
}

if (($_COOKIE[COOKIE_ACCESS] ?? '') !== '') {
  header('Location: /');
  exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $email = trim((string)($_POST['email'] ?? ''));
  $password = trim((string)($_POST['password'] ?? ''));

  if ($email === '' || $password === '') {
    $error = 'Email и пароль обязательны.';
  } elseif (!function_exists('curl_init')) {
    $error = 'На сервере не включено расширение cURL (нужен curl).';
  } else {
    $ch = curl_init(SUPABASE_URL . '/auth/v1/token?grant_type=password');
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        'apikey: ' . SUPABASE_ANON_KEY,
      ],
      CURLOPT_POSTFIELDS => json_encode(['email' => $email, 'password' => $password], JSON_UNESCAPED_UNICODE),
      CURLOPT_TIMEOUT => 10,
    ]);

    $resp = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($err) {
      $error = 'Ошибка сети: ' . $err;
    } elseif ($code === 200 && $resp) {
      $json = json_decode($resp, true);
      if (!is_array($json) || empty($json['access_token']) || empty($json['refresh_token'])) {
        $error = 'Неожиданный ответ Supabase.';
      } else {
        setAuthCookie(COOKIE_ACCESS, (string)$json['access_token']);
        setAuthCookie(COOKIE_REFRESH, (string)$json['refresh_token']);
        header('Location: /');
        exit;
      }
    } else {
      clearAuthCookies();
      $json = json_decode((string)$resp, true);
      $error = is_array($json)
        ? (string)($json['error_description'] ?? $json['error'] ?? 'Неверный email или пароль.')
        : 'Неверный email или пароль.';
    }
  }
}
?>
<!DOCTYPE html>
<html lang="ru" data-color-scheme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VM RGU — Вход</title>

  <link rel="stylesheet" href="css/app.css" />

  <style>
    body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;}
    .login-wrap{width:100%;max-width:440px;}
    .login-card{padding:24px;}
    .login-head{display:flex;align-items:center;gap:12px;margin-bottom:14px;}
    .login-logo{width:44px;height:44px;object-fit:contain;}
    .login-title{margin:0;line-height:1.1;}
    .login-sub{margin:4px 0 0 0;color:var(--color-text-secondary);font-size:13px;}
    .err{margin-bottom:12px;color:var(--color-error);}

    .pw-wrap{position:relative;}
    .pw-input{padding-right:44px;}
    .pw-toggle{
      position:absolute; right:10px; top:50%; transform:translateY(-50%);
      width:34px; height:34px;
      border:0; background:transparent;
      border-radius:10px;
      display:flex; align-items:center; justify-content:center;
      cursor:pointer;
      color: var(--color-text-secondary);
    }
    .pw-toggle:focus-visible{outline:2px solid rgba(45,212,191,.45); outline-offset:2px;}
    .pw-toggle:hover{background: rgba(255,255,255,.06);}
    .pw-toggle svg{width:18px;height:18px;display:block;}
  </style>
</head>
<body>
  <div class="login-wrap">
    <div class="card">
      <div class="card__body login-card">

        <div class="login-head">
          <img class="login-logo" src="/assets/vm-rgu-logo.png" alt="VM RGU" />
          <div>
            <h2 class="login-title">VM RGU</h2>
            <div class="login-sub">Система управления уязвимостями</div>
          </div>
        </div>

        <?php if ($error !== ''): ?>
          <div class="err"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <form method="POST" autocomplete="on">
          <div class="form-group">
            <label class="form-label" for="email">Email</label>
            <input class="form-control" id="email" name="email" type="email"
                   value="<?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>"
                   placeholder="example@mail.com" required />
          </div>

          <div class="form-group">
            <label class="form-label" for="password">Пароль</label>

            <div class="pw-wrap">
              <input class="form-control pw-input" id="password" name="password" type="password" required />

              <button
                type="button"
                class="pw-toggle"
                id="pw-toggle"
                aria-label="Показать пароль"
                aria-pressed="false"
                title="Показать пароль"
              >
                <!-- eye icon (inline SVG) -->
                <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                  <path fill="currentColor" d="M12 5c-5 0-9.27 3.11-11 7c1.73 3.89 6 7 11 7s9.27-3.11 11-7c-1.73-3.89-6-7-11-7zm0 12a5 5 0 1 1 0-10a5 5 0 0 1 0 10zm0-2.5a2.5 2.5 0 1 0 0-5a2.5 2.5 0 0 0 0 5z"/>
                </svg>
              </button>
            </div>
          </div>

          <button class="btn btn--primary btn--full-width" type="submit">Войти</button>
        </form>

      </div>
    </div>
  </div>

  <script>
    (function () {
      const input = document.getElementById('password');
      const btn = document.getElementById('pw-toggle');
      if (!input || !btn) return;

      const setState = (visible) => {
        input.type = visible ? 'text' : 'password';
        btn.setAttribute('aria-pressed', visible ? 'true' : 'false');
        btn.setAttribute('aria-label', visible ? 'Скрыть пароль' : 'Показать пароль');
        btn.title = visible ? 'Скрыть пароль' : 'Показать пароль';
      };

      btn.addEventListener('click', () => {
        const visible = input.type === 'password';
        setState(visible);
        input.focus();
      });

      setState(false);
    })();
  </script>
</body>
</html>
