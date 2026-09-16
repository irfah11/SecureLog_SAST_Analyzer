<?php

require_once __DIR__ . '/ScannerEngine.php';

/**
 * SecureLog JavaScript Scanner
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
function scanJavaScript(
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
    | Scan JavaScript Source Code
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
        | Detect JavaScript Logging
        |--------------------------------------------------------------------------
        |
        | Examples:
        |
        | console.log(...)
        | console.error(...)
        | console.warn(...)
        | logger.info(...)
        | logger.error(...)
        | fs.appendFile(...)
        | fs.appendFileSync(...)
        | fs.writeFile(...)
        | fs.writeFileSync(...)
        |
        */

        if (
            preg_match(
                '/\b(console\.(log|error|warn|info)|logger\.(info|error|warn|debug)|fs\.(appendFile|appendFileSync|writeFile|writeFileSync)|winston|pino|bunyan)\b/i',
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
        | fs.appendFile("security.txt", ...)
        | fs.writeFile("activity.txt", ...)
        | fs.appendFileSync("audit.txt", ...)
        |
        */

        if (
            preg_match(
                '/\.txt\b/i',
                $line
            )
            &&
            preg_match(
                '/\b(fs\.(appendFile|appendFileSync|writeFile|writeFileSync)|createWriteStream|writeFile|appendFile)\b/i',
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
        | Detect JavaScript Encryption / Protection
        |--------------------------------------------------------------------------
        |
        | Examples:
        |
        | crypto.createCipheriv(...)
        | cipher.update(...)
        | cipher.final(...)
        | crypto.publicEncrypt(...)
        | crypto.privateEncrypt(...)
        |
        */

        if (
            preg_match(
                '/\b(crypto\.createCipheriv|createCipheriv|cipher\.update|cipher\.final|crypto\.publicEncrypt|crypto\.privateEncrypt|crypto\.createSecretKey|encrypt|encryption|cipher)\b/i',
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
                9,
                'Missing Security Logging',
                'HIGH',
                $fileName,
                0,
                'No security logging mechanism was detected in the uploaded JavaScript source code.',
                'Implement application security logging using console logging for development or a production logging library such as Winston or Pino.'
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
                10,
                'Improper Log File Format',
                'MEDIUM',
                $fileName,
                $loggingLine,
                'JavaScript logging was detected, but SecureLog could not identify a .txt log file destination.',
                'Store security logs in an approved .txt log file or a configured secure logging destination.'
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
                11,
                'Unprotected Log Data',
                'MEDIUM',
                $fileName,
                $txtLine,
                'A .txt log file was detected, but SecureLog could not identify encryption or protection for the JavaScript log data.',
                'Encrypt or securely protect sensitive log information before writing it to persistent storage.'
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
            12,
            'Secure Logging Configuration',
            'INFO',
            $fileName,
            $encryptionLine,
            'SecureLog detected JavaScript logging, .txt log storage, and encryption or protection.',
            'Continue maintaining secure logging practices and keep encryption keys separate from stored log files.'
        )
    ];
}