<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/includes/bootstrap.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET' && (string)($_GET['ping'] ?? '') === '1') {
    $user = vm_get_session_user_for_api();
    if ($user === null) {
        vm_json_unauthorized();
        exit;
    }

    $base = REPORT_API_BASE;
    if (!function_exists('curl_init')) {
        vm_send_json_headers(500);
        echo json_encode(['ok' => false, 'error' => 'cURL unavailable'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $ch = curl_init($base . '/');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_FOLLOWLOCATION => true,
    ]);
    $resp = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $json = json_decode((string)$resp, true);
    $ok = $code === 200 && is_array($json) && ($json['ok'] ?? null) === true;

    vm_send_json_headers(200);
    echo json_encode(['ok' => $ok, 'upstream_status' => $code], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($method !== 'POST') {
    vm_send_json_headers(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed'], JSON_UNESCAPED_UNICODE);
    exit;
}

$user = vm_get_session_user_for_api();
if ($user === null) {
    vm_json_unauthorized();
    exit;
}

$raw = file_get_contents('php://input');
$data = json_decode((string)$raw, true);
if (!is_array($data)) {
    vm_send_json_headers(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid JSON'], JSON_UNESCAPED_UNICODE);
    exit;
}

$department = trim((string)($data['department'] ?? ''));
if ($department === '' || strlen($department) > 200) {
    vm_send_json_headers(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid department'], JSON_UNESCAPED_UNICODE);
    exit;
}

$kpis = $data['kpis'] ?? null;
if (!is_array($kpis)) {
    vm_send_json_headers(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid kpis'], JSON_UNESCAPED_UNICODE);
    exit;
}

$openRows = $data['open_rows'] ?? null;
if (!is_array($openRows)) {
    vm_send_json_headers(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid open_rows'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (count($openRows) > 100) {
    vm_send_json_headers(400);
    echo json_encode(['ok' => false, 'error' => 'open_rows too large'], JSON_UNESCAPED_UNICODE);
    exit;
}

$out = [
    'department' => $department,
    'kpis'       => [
        'total'        => (int)($kpis['total'] ?? 0),
        'open'         => (int)($kpis['open'] ?? 0),
        'open_high7'   => (int)($kpis['open_high7'] ?? 0),
        'hosts'        => (int)($kpis['hosts'] ?? 0),
        'hosts_open'   => (int)($kpis['hosts_open'] ?? 0),
    ],
    'open_rows'  => array_values($openRows),
];

$url = REPORT_API_BASE . '/send_report';

if (!function_exists('curl_init')) {
    vm_send_json_headers(500);
    echo json_encode(['ok' => false, 'error' => 'cURL unavailable'], JSON_UNESCAPED_UNICODE);
    exit;
}

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/json',
        'Accept: application/json'],
    CURLOPT_POSTFIELDS     => json_encode($out, JSON_UNESCAPED_UNICODE),
    CURLOPT_TIMEOUT        => 60,
]);

$resp = curl_exec($ch);
$code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
$cerr = curl_error($ch);
curl_close($ch);

if ($resp === false || $cerr) {
    vm_send_json_headers(502);
    echo json_encode(['ok' => false, 'error' => 'Upstream error'], JSON_UNESCAPED_UNICODE);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
http_response_code($code >= 200 && $code < 300 ? 200 : $code);
echo $resp;
