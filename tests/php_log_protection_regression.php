<?php
// Source strings are analyzed only, never executed. No key or log is created.
require_once __DIR__ . '/../Engine_Process/Scanner/PHPScanner.php';

$assert = static function (bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
    echo "PASS: {$label}\n";
};
$source = <<<'PHP'
<?php
function test_login(string $password, string $storedHash, string $logKey): bool
{
    if (strlen($logKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        throw new InvalidArgumentException('Invalid log key length.');
    }
    if (!password_verify($password, $storedHash)) {
        $username = $_POST['username'] ?? '';
        $safeUsername = str_replace(["\r", "\n"], '_', $username);
        $message = 'LOGIN_FAILED user=' . $safeUsername;
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encryptedLog = sodium_crypto_secretbox($message, $nonce, $logKey);
        $payload = base64_encode($nonce . $encryptedLog);
        // PAYLOAD_COMMENT
        file_put_contents(
            __DIR__ . '/security.txt',
            PAYLOAD . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
        return false;
    }
    return true;
}
PHP;
$make = static fn(string $payload, string $comment = ''): string =>
    str_replace(['PAYLOAD_COMMENT', 'PAYLOAD'], [$comment, $payload], $source);
$check = static function (string $code, array $expected, string $label) use ($assert): void {
    $actual = array_column(scanPHP('fixture.php', $code), 'status');
    $assert($actual === $expected, $label . ' actual=' . implode('/', $actual));
};
$check($make('$payload'), ['PASS', 'PASS', 'PASS', 'PASS'], 'Test 21 encrypted payload');
$check($make('$message', 'Sengaja salah: tulis plaintext, bukan $encryptedLog.'),
    ['PASS', 'PASS', 'PASS', 'FAIL'], 'Test 22 plaintext payload despite encryption comment');
$check($make('$message'), ['PASS', 'PASS', 'PASS', 'FAIL'], 'Removing comment does not change plaintext result');
$check($make('$payload', 'Plaintext $message is not written.'),
    ['PASS', 'PASS', 'PASS', 'PASS'], 'Plaintext variable in comment does not poison ciphertext');
$check(str_replace("'/security.txt'", "'/security.json'", $make('$payload')),
    ['PASS', 'PASS', 'FAIL', 'PASS'], 'Non-txt destination still fails storage policy');
$check(str_replace("__DIR__ . '/security.txt'", '$logDestination', $make('$payload')),
    ['PASS', 'PASS', 'N/A', 'PASS'], 'Dynamic destination remains unresolved');
$check(str_replace('FILE_APPEND | LOCK_EX', '$encryptedLog', $make('$message')),
    ['PASS', 'PASS', 'PASS', 'FAIL'], 'Ciphertext in flags argument is not logged data');
$check(str_replace("__DIR__ . '/security.txt'", '$encryptedLog', $make('$message')),
    ['PASS', 'PASS', 'N/A', 'N/A'], 'Ciphertext in destination argument cannot prove protection');
$check($make('"literal $encryptedLog"'), ['PASS', 'PASS', 'PASS', 'N/A'],
    'Interpolated string is conservatively unresolved');
$overwritten = str_replace('// PAYLOAD_COMMENT', '$encryptedLog = $message;', $source);
$check(str_replace('PAYLOAD', '$encryptedLog', $overwritten),
    ['PASS', 'PASS', 'PASS', 'FAIL'], 'Plaintext overwrite invalidates encryption evidence');
$check($make('$encryptedLog . $message'), ['PASS', 'PASS', 'PASS', 'FAIL'],
    'Ciphertext mixed with sensitive plaintext does not pass');
$check($make('base64_encode($message)'), ['PASS', 'PASS', 'PASS', 'FAIL'],
    'Base64 encoding alone is not encryption');

$raw = <<<'PHP'
<?php
if (!password_verify($password, $hash)) {
    $raw = $_POST['username'];
    // str_replace(["\r", "\n"], '_', $raw);
    error_log($raw);
}
PHP;
$check($raw, ['PASS', 'FAIL', 'N/A', 'N/A'], 'Sanitizer inside comment is not neutralization');
$assert(securelogPhpStorageEvidence("error_log('message, with comma', 3, __DIR__ . '/security.txt');")['status'] === 'PASS',
    'Argument splitting preserves commas inside strings');
$assert(securelogPhpStorageEvidence("// file_put_contents('security.txt', 'x');")['status'] === 'N/A',
    'Comment is not storage evidence');
$assert(!findPhpEncryptionToLogFlow('error_log("openssl_encrypt($message)");')['encrypted'],
    'Encryption function inside a string is not protection evidence');
