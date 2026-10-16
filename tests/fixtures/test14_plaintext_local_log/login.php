<?php

// Intentionally insecure scanner fixture. Upload for analysis, not deployment.
function test14_login(string $password, string $storedHash): bool
{
    if (!password_verify($password, $storedHash)) {
        error_log("LOGIN_FAILED\n", 3, __DIR__ . '/auth.txt');
        return false;
    }

    return true;
}
