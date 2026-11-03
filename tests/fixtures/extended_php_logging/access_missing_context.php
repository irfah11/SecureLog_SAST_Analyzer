<?php
// Source-only scanner fixture. Do not execute as an application endpoint.
if ($_SESSION['role'] !== 'customer') {
    error_log(json_encode([
        'timestamp' => date('c'),
        'event' => 'ACCESS_DENIED',
        'result' => 'FAILURE'
    ]));
}
