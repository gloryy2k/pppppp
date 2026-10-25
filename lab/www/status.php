<?php
header('Content-Type: application/json');
$data = [
    'status' => 'ok',
    'php_version' => phpversion(),
    'sapi' => php_sapi_name(),
    'time' => date('c'),
    'worker_pid' => getmypid(),
    'memory_limit' => ini_get('memory_limit'),
];
if (isset($_SERVER['HTTP_X_P2S_NONCE'])) {
    $data['nonce'] = $_SERVER['HTTP_X_P2S_NONCE'];
}
if (isset($_SERVER['HTTP_X_P2S_REQUEST_ID'])) {
    $data['request_id'] = $_SERVER['HTTP_X_P2S_REQUEST_ID'];
}
echo json_encode($data);
