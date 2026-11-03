<?php
// Source-only scanner fixture. Do not execute as an application endpoint.
if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL) === false) {
    error_log(json_encode([
        'timestamp' => date('c'),
        'event' => 'INPUT_VALIDATION_FAILED',
        'actor_type' => 'unauthenticated',
        'source_ip' => $_SERVER['REMOTE_ADDR'],
        'field' => 'email',
        'result' => 'FAILURE',
        'reason' => 'INVALID_EMAIL_FORMAT'
    ]));
}
