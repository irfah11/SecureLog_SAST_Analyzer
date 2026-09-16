<?php

require_once __DIR__ . '/ScannerEngine.php';

/**
 * SecureLog C Scanner
 *
 * Decision Flow:
 *
 * 1. Logging exists?
 *    No -> HIGH -> STOP
 *
 * 2. Log stored in .txt format?
 *    No -> MEDIUM -> STOP
 *
 * 3. Log encrypted / protected?
 *    No -> MEDIUM -> STOP
 *
 * 4. All conditions passed
 *    -> INFO
 */
function scanC(
    string $fileName,
    string $content
): array {

    $lines = preg_split(
        "/\r\n|\n|\r/",
        $content
    );

    if ($lines === false) {
        return [];
    }

    /*
    |--------------------------------------------------------------------------
    | Detection Flags
    |--------------------------------------------------------------------------
    */

    $hasLogging = false;
    $hasTxtFormat = false;
    $hasEncryption = false;

    /*
    |--------------------------------------------------------------------------
    | Detection Line Numbers
    |--------------------------------------------------------------------------
    */

    $loggingLine = 0;
    $txtLine = 0;
    $encryptionLine = 0;


    /*
    |--------------------------------------------------------------------------
    | Scan C Source Code
    |--------------------------------------------------------------------------
    */

    foreach ($lines as $index => $lineContent) {

        $lineNumber = $index + 1;

        $line = trim($lineContent);

        if ($line === '') {
            continue;
        }


        /*
        |--------------------------------------------------------------------------
        | CONDITION 1
        | Detect C Logging
        |--------------------------------------------------------------------------
        |
        | Examples:
        |
        | FILE *logFile = fopen(...)
        | fprintf(logFile, ...)
        | fputs(...)
        | fwrite(...)
        | syslog(...)
        |
        */

        if (
            preg_match(
                '/\b(fopen|fprintf|fputs|fwrite|syslog|openlog|closelog)\b/i',
                $line
            )
        ) {

            $hasLogging = true;

            if ($loggingLine === 0) {
                $loggingLine = $lineNumber;
            }
        }


        /*
        |--------------------------------------------------------------------------
        | CONDITION 2
        | Detect .TXT Log Format
        |--------------------------------------------------------------------------
        |
        | Examples:
        |
        | fopen("security.txt", "a")
        | fopen("audit.txt", "w")
        |
        */

        if (
            preg_match(
                '/\.txt\b/i',
                $line
            )
            &&
            preg_match(
                '/\b(fopen|fprintf|fputs|fwrite)\b/i',
                $line
            )
        ) {

            $hasTxtFormat = true;

            if ($txtLine === 0) {
                $txtLine = $lineNumber;
            }
        }


        /*
        |--------------------------------------------------------------------------
        | CONDITION 3
        | Detect Encryption / Protection
        |--------------------------------------------------------------------------
        |
        | OpenSSL EVP examples:
        |
        | EVP_EncryptInit_ex(...)
        | EVP_EncryptUpdate(...)
        | EVP_EncryptFinal_ex(...)
        |
        | AES examples:
        |
        | AES_set_encrypt_key(...)
        | AES_encrypt(...)
        | AES_cbc_encrypt(...)
        |
        */

        if (
            preg_match(
                '/\b(EVP_EncryptInit_ex|EVP_EncryptUpdate|EVP_EncryptFinal_ex|AES_set_encrypt_key|AES_encrypt|AES_cbc_encrypt|encrypt_log|encryptLog|encrypt|cipher)\b/i',
                $line
            )
        ) {

            $hasEncryption = true;

            if ($encryptionLine === 0) {
                $encryptionLine = $lineNumber;
            }
        }
    }


    /*
    |--------------------------------------------------------------------------
    | STEP 1 FAILED
    | No Logging
    |--------------------------------------------------------------------------
    */

    if (!$hasLogging) {

        return [
            createFinding(
                13,
                'Missing Security Logging',
                'HIGH',
                $fileName,
                0,
                'No security logging mechanism was detected in the uploaded C source code.',
                'Implement security logging using file-based logging functions such as fopen(), fprintf(), fwrite(), or the syslog facility.'
            )
        ];
    }


    /*
    |--------------------------------------------------------------------------
    | STEP 2 FAILED
    | Logging exists but .txt format not detected
    |--------------------------------------------------------------------------
    */

    if (!$hasTxtFormat) {

        return [
            createFinding(
                14,
                'Improper Log File Format',
                'MEDIUM',
                $fileName,
                $loggingLine,
                'C logging was detected, but SecureLog could not identify a .txt log file destination.',
                'Store security logs in an approved .txt file or other configured secure logging destination.'
            )
        ];
    }


    /*
    |--------------------------------------------------------------------------
    | STEP 3 FAILED
    | .txt exists but encryption not detected
    |--------------------------------------------------------------------------
    */

    if (!$hasEncryption) {

        return [
            createFinding(
                15,
                'Unprotected Log Data',
                'MEDIUM',
                $fileName,
                $txtLine,
                'A .txt log file was detected, but SecureLog could not identify encryption or protection for the C log data.',
                'Protect sensitive log contents using an appropriate cryptographic mechanism before writing them to persistent storage.'
            )
        ];
    }


    /*
    |--------------------------------------------------------------------------
    | ALL CONDITIONS PASSED
    |--------------------------------------------------------------------------
    */

    return [
        createFinding(
            16,
            'Secure Logging Configuration',
            'INFO',
            $fileName,
            $encryptionLine,
            'SecureLog detected C logging, .txt log storage, and encryption or protection.',
            'Continue maintaining secure logging practices and keep encryption keys separate from stored log files.'
        )
    ];
}