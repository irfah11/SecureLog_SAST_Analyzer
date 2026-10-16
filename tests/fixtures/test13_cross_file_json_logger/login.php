
<?php
require_once __DIR__ . '/logger.php';

function test13_login(
    string $password,
    string $storedHash
): bool {

    if (!password_verify($password, $storedHash)) {

        log_activity(
            'LOGIN_FAILED',
            null,
            'Authentication failure detected'
        );

        return false;
    }

    return true;
}

