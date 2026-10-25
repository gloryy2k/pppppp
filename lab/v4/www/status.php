<?php
// Lab status endpoint for the v4 scanner.  It intentionally echoes a
// per-request nonce and request id so the scanner can verify that this
// response is bound to its own request.  Only use this in a lab.
$rid = $_SERVER['HTTP_X_P2S_REQUEST_ID'] ?? '';
$nonce = $_SERVER['HTTP_X_P2S_NONCE'] ?? '';
header('Content-Type: application/json');
header('X-P2S-Request-ID: ' . $rid);
header('X-P2S-Nonce: ' . $nonce);
header('X-P2S-Worker-PID: ' . getmypid());
echo json_encode([
    'status' => 'ok',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'worker_pid' => getmypid(),
    'request_id' => $rid,
    'nonce' => $nonce,
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'session_upload_progress' => ini_get('session.upload_progress.enabled'),
    'fatal_error_backtraces' => ini_get('fatal_error_backtraces'),
    'time' => date('c'),
]);
