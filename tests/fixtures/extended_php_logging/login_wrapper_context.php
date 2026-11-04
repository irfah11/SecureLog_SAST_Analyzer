<?php
// Source-only fixture: upload for analysis; do not run as a real login endpoint.
function record_login_failure(string $attemptedIdentity): void
{
    error_log(json_encode([
        'timestamp' => date('c'),
        'event' => 'LOGIN_FAILED',
        'claimed_identity' => $attemptedIdentity,
        'source_ip' => $_SERVER['REMOTE_ADDR'],
        'result' => 'FAILURE',
        'reason' => 'INVALID_CREDENTIALS'
    ]));
}

if (!authenticate($_POST['username'], $_POST['password'])) {
    record_login_failure($_POST['username']);
}
