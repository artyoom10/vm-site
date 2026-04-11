<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/includes/bootstrap.php';

$user = vm_get_session_user_for_api();
if ($user === null) {
    vm_json_unauthorized();
    exit;
}

$path = VM_DATASET_PATH;
if (!is_readable($path)) {
    vm_send_json_headers(500);
    echo json_encode(['ok' => false, 'error' => 'Dataset unavailable'], JSON_UNESCAPED_UNICODE);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
readfile($path);
