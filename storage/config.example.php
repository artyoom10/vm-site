<?php
/**
 * Скопируйте в config.php и подставьте значения, либо задайте переменные окружения.
 * Файл storage/config.php в репозиторий не коммитится.
 */
declare(strict_types=1);

$vmStorageDir = __DIR__;
$vmDatasetPath = $vmStorageDir . DIRECTORY_SEPARATOR . 'multihost_openvas_dataset.json';

if (!defined('SUPABASE_URL')) {
    define(
        'SUPABASE_URL',
        getenv('SUPABASE_URL') ?: 'https://YOUR_PROJECT.supabase.co'
    );
}
if (!defined('SUPABASE_ANON_KEY')) {
    define(
        'SUPABASE_ANON_KEY',
        getenv('SUPABASE_ANON_KEY') ?: ''
    );
}

define('COOKIE_ACCESS', 'vm_access_token');
define('COOKIE_REFRESH', 'vm_refresh_token');
define('TOKEN_LIFETIME', 60 * 60 * 24 * 7);

$https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$cookieSecureEnv = getenv('VM_COOKIE_SECURE');
if ($cookieSecureEnv !== false && $cookieSecureEnv !== '') {
    define('COOKIE_SECURE', filter_var($cookieSecureEnv, FILTER_VALIDATE_BOOLEAN));
} else {
    define('COOKIE_SECURE', $https);
}

define('AUTH_DISABLED', filter_var(
    getenv('VM_AUTH_DISABLED') ?: '1',
    FILTER_VALIDATE_BOOLEAN
));

define('VM_DATASET_PATH', $vmDatasetPath);

define(
    'REPORT_API_BASE',
    rtrim(getenv('REPORT_API_BASE') ?: 'https://telegram-report-api.onrender.com', '/')
);
