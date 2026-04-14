<?php
/**
 * index.php
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

vm_send_html_security_headers();

if (isset($_GET['force_logout'])) {
  vm_clear_auth_cookies_hard();
  vm_redirect_to_login();
}

$user = vm_get_session_user_for_page();
if ($user === null) {
  vm_redirect_to_login();
}

$login = $user['login'];
$initial = $user['initial'];

function e(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function asset_url(string $path): string {
  $full = __DIR__ . '/' . ltrim($path, '/');
  $v = is_file($full) ? (string)filemtime($full) : (string)time();
  return $path . '?v=' . rawurlencode($v);
}
?>
<!DOCTYPE html>
<html lang="ru" data-color-scheme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VM RGU</title>

  <link rel="stylesheet" href="<?= e(asset_url('css/app.css')) ?>" />

  <!-- Доп. токены навбара / попапа (фон страницы — в theme-dark-shell.css) -->
  <style>
    :root {
      --panel: rgba(16, 18, 24, 0.94);
      --panel-border: rgba(255, 255, 255, 0.1);
      --text-strong: rgba(255, 255, 255, 0.92);
      --accent: #2dd4bf;
      --accent-soft: rgba(45, 212, 191, 0.16);
      --accent-border: rgba(45, 212, 191, 0.45);
    }

    /* ===== Navbar logo ===== */
    .navbar-logo{ gap: 12px; }
    .navbar-logo-icon{
      width: 40px; height: 40px;
      border-radius: 12px;
      background: rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.10);
      display:flex; align-items:center; justify-content:center;
      overflow:hidden;
    }
    .navbar-logo-img{ width: 32px; height: 32px; object-fit: contain; display:block; }
    .navbar-logo span{ color: var(--text-strong) !important; }

    /* ===== Menu items readability ===== */
    .navbar-item{ color: var(--text-strong) !important; }
    .navbar-item:hover{ background: rgba(255,255,255,.05) !important; }

    .navbar-item.active{
      background: var(--accent-soft) !important;
      border: 1px solid var(--accent-border) !important;
      box-shadow: 0 0 0 3px rgba(45, 212, 191, 0.08) !important;
      color: var(--text-strong) !important;
    }

    /* Primary кнопки (модалка) */
    .btn--primary{
      background: var(--accent) !important;
      border-color: var(--accent) !important;
      color: rgba(0,0,0,.88) !important;
      font-weight: 900 !important;
    }

    /* ===== User block ===== */
    .navbar-user{
      cursor: pointer;
      user-select: none;
      border-radius: 14px;
      padding: 10px 12px;
      border: 1px solid rgba(255,255,255,.08);
      transition: background .14s ease, border-color .14s ease, transform .08s ease;
    }
    .navbar-user:hover{
      background: rgba(255,255,255,.04);
      border-color: rgba(255,255,255,.14);
    }
    #userName{ color: var(--text-strong) !important; }

    /* Аватар: железно по центру */
    .user-avatar{
      width: 44px !important;
      height: 44px !important;
      border-radius: 999px !important;

      display: flex !important;
      align-items: center !important;
      justify-content: center !important;

      line-height: 1 !important;
      font-size: 18px !important;
      font-weight: 900 !important;
      text-align: center !important;

      padding: 0 !important;

      background: var(--accent-soft) !important;
      border: 1px solid var(--accent-border) !important;
      color: var(--text-strong) !important;
    }

    /* ===== Floating user menu (popover) ===== */
    #userMenu.user-menu{
      position: fixed !important;
      z-index: 99999 !important;
      display: none;

      width: 240px !important;
      max-width: calc(100vw - 24px) !important;

      background: var(--panel) !important;
      border: 1px solid var(--panel-border) !important;
      border-radius: 14px !important;
      box-shadow: 0 22px 70px rgba(0,0,0,.55) !important;
      backdrop-filter: blur(12px) !important;

      overflow: hidden !important;
      box-sizing: border-box !important;
    }
    #userMenu.user-menu.show{ display:block !important; }

    #userMenu .user-menu-item{
      width: 100% !important;
      text-align: left !important;
      padding: 12px 14px !important;
      background: transparent !important;
      border: 0 !important;

      color: var(--text-strong) !important; /* FIX: в светлой теме не белый */
      font-weight: 800 !important;
      cursor: pointer !important;
      transition: background .14s ease !important;
    }
    #userMenu .user-menu-item:hover{ background: rgba(255,255,255,.06) !important; }
    #userMenu .user-menu-item.logout{ color: #FF5B5B !important; }
  </style>
</head>

<body>
  <div id="appWrapper" style="display:flex;">
    <nav class="navbar">
      <div class="navbar-left">
        <div class="navbar-logo">
          <div class="navbar-logo-icon">
            <img class="navbar-logo-img" src="assets/vm-rgu-logo.png" alt="VM RGU" />
          </div>
          <span>VM RGU</span>
        </div>

        <div class="navbar-menu">
          <button class="navbar-item active" data-page="dashboard" onclick="router.navigate('dashboard')">Панель</button>
          <button class="navbar-item" data-page="assets" onclick="router.navigate('assets')">Активы</button>
          <button class="navbar-item" data-page="findings" onclick="router.navigate('findings')">Уязвимости</button>
          <button class="navbar-item" data-page="scans" onclick="router.navigate('scans')">Сканы</button>
          <button class="navbar-item" data-page="reports" onclick="router.navigate('reports')">Отчёты</button>
          <button class="navbar-item" data-page="settings" onclick="router.navigate('settings')">Настройки</button>
        </div>
      </div>

      <div class="navbar-right">
        <div class="navbar-user" id="navbarUser">
          <div class="user-avatar" id="userInitial"><?= e($initial) ?></div>
          <span id="userName"><?= e($login) ?></span>
        </div>
      </div>
    </nav>

    <div class="app-content">
      <div id="pageContainer"></div>
    </div>
  </div>

  <!-- Меню пользователя: отдельный popover -->
  <div id="userMenu" class="user-menu" role="menu" aria-hidden="true">
    <button class="user-menu-item" type="button" onclick="app.showProfile()">Профиль</button>
    <button class="user-menu-item logout" type="button" onclick="app.openLogoutModal()">Выйти</button>
  </div>

  <!-- Logout modal -->
  <div id="logoutModal" class="modal-overlay" style="display:none;">
    <div class="modal">
      <div class="modal-title">Выход</div>
      <div class="modal-content">
        <div class="modal-text">Выйти из системы?</div>
      </div>
      <div class="modal-actions">
        <button class="btn btn--secondary" onclick="app.closeLogoutModal()">Отмена</button>
        <button class="btn btn--primary" onclick="app.confirmLogout()">Выйти</button>
      </div>
    </div>
  </div>

  <!-- Core scripts -->
  <script src="<?= e(asset_url('js/utils.js')) ?>"></script>
  <script src="<?= e(asset_url('js/data-loader.js')) ?>"></script>
  <script src="<?= e(asset_url('js/router.js')) ?>"></script>

  <!-- Pages -->
  <script src="<?= e(asset_url('js/pages/dashboard.js')) ?>"></script>
  <script src="<?= e(asset_url('js/pages/assets.js')) ?>"></script>
  <script src="<?= e(asset_url('js/pages/findings.js')) ?>"></script>
  <script src="<?= e(asset_url('js/pages/scans.js')) ?>"></script>
  <script src="<?= e(asset_url('js/pages/reports.js')) ?>"></script>
  <script src="<?= e(asset_url('js/pages/settings.js')) ?>"></script>

  <script>
    function closeUserMenu() {
      const menu = document.getElementById('userMenu');
      if (!menu) return;
      menu.classList.remove('show');
      menu.setAttribute('aria-hidden', 'true');
    }

    function openUserMenuNearAnchor(anchorEl) {
      const menu = document.getElementById('userMenu');
      if (!menu || !anchorEl) return;

      menu.classList.add('show');
      menu.setAttribute('aria-hidden', 'false');

      // reset to measure properly
      menu.style.left = '0px';
      menu.style.top = '0px';

      const a = anchorEl.getBoundingClientRect();
      const m = menu.getBoundingClientRect();
      const pad = 12;
      const gap = 10;

      // right-aligned to the anchor (dropdown)
      let left = a.right - m.width;
      let top  = a.bottom + gap;

      // flip вверх если снизу не помещается
      if (top + m.height > window.innerHeight - pad) {
        top = a.top - m.height - gap;
      }

      // clamp
      left = Math.min(Math.max(pad, left), window.innerWidth - m.width - pad);
      top  = Math.min(Math.max(pad, top),  window.innerHeight - m.height - pad);

      menu.style.left = left + 'px';
      menu.style.top  = top + 'px';
    }

    window.app = {
      toggleUserMenu() {
        const menu = document.getElementById('userMenu');
        const anchor = document.getElementById('navbarUser');
        if (!menu || !anchor) return;

        if (menu.classList.contains('show')) closeUserMenu();
        else openUserMenuNearAnchor(anchor);
      },

      openLogoutModal() {
        const m = document.getElementById('logoutModal');
        if (m) m.style.display = 'flex';
        closeUserMenu();
      },

      closeLogoutModal() {
        const m = document.getElementById('logoutModal');
        if (m) m.style.display = 'none';
      },

      async confirmLogout() {
        try { await fetch('/api/auth.php?action=logout', { method: 'POST' }); } catch (e) {}
        window.location.replace('/login.php');
      },

      showProfile() {
        alert('Профиль (заглушка)');
        closeUserMenu();
      }
    };

    document.getElementById('navbarUser')?.addEventListener('click', (e) => {
      e.stopPropagation();
      window.app.toggleUserMenu();
    });

    document.addEventListener('click', () => closeUserMenu());
    window.addEventListener('resize', closeUserMenu);
    window.addEventListener('scroll', closeUserMenu, { passive: true });

    document.getElementById('logoutModal')?.addEventListener('click', (e) => {
      if (e.target && e.target.id === 'logoutModal') window.app.closeLogoutModal();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeUserMenu();
        window.app.closeLogoutModal();
      }
    });
  </script>
</body>
</html>
