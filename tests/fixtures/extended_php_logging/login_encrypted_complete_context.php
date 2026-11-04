<?php
// Source-only upload fixture. The caller supplies the stored password hash
// and a securely managed secretbox key; no real key is embedded here.
function checkLogin(string $storedHash, string $logKey): bool
{
    if (strlen($logKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        throw new InvalidArgumentException('Invalid logging key length.');
    }

    if (!password_verify($_POST['password'] ?? '', $storedHash)) {
        $record = json_encode([
            'timestamp' => date('c'),
            'event' => 'LOGIN_FAILED',
            'claimed_identity' => $_POST['username'] ?? '',
            'actor_type' => 'unauthenticated',
            'source_ip' => $_SERVER['REMOTE_ADDR'],
            'result' => 'FAILURE',
            'reason' => 'INVALID_CREDENTIALS'
        ], JSON_THROW_ON_ERROR);

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encrypted = sodium_crypto_secretbox($record, $nonce, $logKey);
        $payload = base64_encode($nonce . $encrypted);
        file_put_contents(
            __DIR__ . '/security.txt',
            $payload . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
        return false;
    }

    return true;
}
