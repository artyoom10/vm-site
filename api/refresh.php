<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/includes/bootstrap.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    vm_send_json_headers(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (defined('AUTH_DISABLED') && AUTH_DISABLED) {
    vm_send_json_headers(200);
    echo json_encode(['ok' => true, 'skipped' => true], JSON_UNESCAPED_UNICODE);
    exit;
}

if (vm_supabase_refresh_tokens()) {
    vm_send_json_headers(200);
    echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
    exit;
}

vm_json_unauthorized('Refresh failed');
