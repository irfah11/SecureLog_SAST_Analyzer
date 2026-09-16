<?php
/**
 * SecureLog — activity_logger.php
 */

// Guna if(!defined(...)) untuk mengelakkan ralat "Constant already defined"
if (!defined('LOG_ENCRYPT_KEY')) {
    // PASTIKAN INI ADALAH 64 CHAR HEX (Contoh: 64756... atau jana guna openssl rand -hex 32)
    define('LOG_ENCRYPT_KEY', $_ENV['LOG_ENCRYPT_KEY'] ?? 'd8225547432f7543883a9a1306b98616'); 
}

if (!defined('LOG_CIPHER')) define('LOG_CIPHER', 'AES-256-CBC');
if (!defined('LOG_DIR'))    define('LOG_DIR', __DIR__ . '/logs/');
if (!defined('LOG_FILE'))   define('LOG_FILE', LOG_DIR . 'securelog_audit.txt');

// Event type constants - Dibalut dengan check defined
if (!defined('LOG_LOGIN_SUCCESS')) {
    define('LOG_LOGIN_SUCCESS',   'LOGIN_SUCCESS');
    define('LOG_LOGIN_FAILED',    'LOGIN_FAILED');
    define('LOG_LOGOUT',          'LOGOUT');
    define('LOG_REGISTER',        'REGISTER');
    define('LOG_SCAN_RUN',        'SCAN_RUN');
    define('LOG_ROLE_CHANGED',    'ROLE_CHANGED');
    define('LOG_USER_ADDED',      'USER_ADDED');
    define('LOG_USER_DEACTIVATED','USER_DEACTIVATED');
    define('LOG_ADMIN_VIEW',      'ADMIN_VIEW');
    define('LOG_LOG_EXPORTED',    'LOG_EXPORTED');
}

/**
 * Menulis log ke dalam fail
 */
function log_activity(string $event_type, ?int $user_id, string $detail): void
{
    if (!is_dir(LOG_DIR)) {
        mkdir(LOG_DIR, 0750, true);
        file_put_contents(LOG_DIR . '.htaccess', "Deny from all\n");
    }

    $timestamp = date('Y-m-d H:i:s');
    $ip        = $_SERVER['REMOTE_ADDR'] ?? 'CLI';
    // Gunakan UserID selaras dengan database
    $uid_str   = $user_id !== null ? (string)$user_id : 'SYSTEM';

    $plain = implode(' | ', [$timestamp, $event_type, "UID:{$uid_str}", "IP:{$ip}", $detail]);

    $iv_length = openssl_cipher_iv_length(LOG_CIPHER);
    $iv        = openssl_random_pseudo_bytes($iv_length);

    // Semakan hex sebelum hex2bin
    if (!ctype_xdigit(LOG_ENCRYPT_KEY) || strlen(LOG_ENCRYPT_KEY) % 2 !== 0) {
        error_log("SecureLog Error: LOG_ENCRYPT_KEY mestilah string hex genap.");
        return;
    }

    $key_raw    = hex2bin(LOG_ENCRYPT_KEY);
    $ciphertext = openssl_encrypt($plain, LOG_CIPHER, $key_raw, OPENSSL_RAW_DATA, $iv);

    // Simpan sebagai hex supaya konsisten (menyelesaikan ralat hex2bin baris 110)
    $encoded_line = bin2hex($iv . $ciphertext) . "\n";
    file_put_contents(LOG_FILE, $encoded_line, FILE_APPEND | LOCK_EX);
}

/**
 * Membaca dan mendekripsi log
 */
function read_logs(): array
{
    if (!file_exists(LOG_FILE)) {
        return [];
    }

    if (!ctype_xdigit(LOG_ENCRYPT_KEY) || strlen(LOG_ENCRYPT_KEY) % 2 !== 0) {
        return [];
    }

    $key_raw = hex2bin(LOG_ENCRYPT_KEY);
    $lines   = file(LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    if (!$lines) return [];

    $decoded = [];
    foreach (array_reverse($lines) as $line) {
        // Pastikan baris adalah hex yang sah
        if (!ctype_xdigit($line) || strlen($line) % 2 !== 0) {
            continue;
        }

        $raw_data   = hex2bin($line);
        $iv_len     = openssl_cipher_iv_length(LOG_CIPHER);
        $iv         = substr($raw_data, 0, $iv_len);
        $ciphertext = substr($raw_data, $iv_len);

        $plain = openssl_decrypt($ciphertext, LOG_CIPHER, $key_raw, OPENSSL_RAW_DATA, $iv);

        if ($plain) {
            $decoded[] = $plain;
        }
    }
    return $decoded;
}


/**
 * Parses a decrypted log line into an associative array.
 * Format: timestamp | event_type | UID:x | IP:x | UA:x | detail
 */
function parse_log_line(string $line): array
{
    $parts = array_map('trim', explode(' | ', $line));
    if (count($parts) < 6) {
        return ['raw' => $line, 'valid' => false];
    }

    return [
        'valid'      => true,
        'timestamp'  => $parts[0],
        'event_type' => $parts[1],
        'user_id'    => ltrim($parts[2], 'UID:'),
        'ip'         => ltrim($parts[3], 'IP:'),
        'ua'         => ltrim($parts[4], 'UA:'),
        'detail'     => $parts[5],
    ];
}

/**
 * Exports the RAW encrypted log file as a download.
 * Only call this from an admin-protected page.
 */
function export_encrypted_log(): void
{
    if (!file_exists(LOG_FILE)) {
        http_response_code(404);
        exit("No log file found.");
    }

    $filename = 'securelog_audit_' . date('Ymd_His') . '.txt';
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . filesize(LOG_FILE));
    header('Cache-Control: no-store');
    readfile(LOG_FILE);
    exit();
}



