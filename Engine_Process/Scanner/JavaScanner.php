<?php

require_once __DIR__ . '/ScannerEngine.php';

/**
 * SecureLog Java Scanner
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
function scanJava(
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
    | Scan Java Source Code
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
        | Detect Java Logging
        |--------------------------------------------------------------------------
        |
        | Examples:
        |
        | logger.info(...)
        | logger.warning(...)
        | logger.severe(...)
        | Logger.getLogger(...)
        | System.err.println(...)
        | FileWriter(...)
        | BufferedWriter(...)
        |
        */

        if (
            preg_match(
                '/\b(Logger|getLogger|logger\.(info|warning|severe|fine|log)|System\.err\.println|FileWriter|BufferedWriter)\b/i',
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
        | new FileWriter("activity.txt", true)
        | new File("security.txt")
        | Paths.get("audit.txt")
        |
        */

        if (
            preg_match(
                '/\.txt\b/i',
                $line
            )
            &&
            preg_match(
                '/\b(FileWriter|BufferedWriter|File|Paths|get|Files\.write|PrintWriter)\b/i',
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
        | Detect Java Encryption / Protection
        |--------------------------------------------------------------------------
        |
        | Examples:
        |
        | Cipher.getInstance(...)
        | cipher.init(...)
        | cipher.doFinal(...)
        | SecretKeySpec(...)
        | GCMParameterSpec(...)
        |
        */

        if (
            preg_match(
                '/\b(Cipher|getInstance|cipher\.init|cipher\.doFinal|SecretKeySpec|GCMParameterSpec|IvParameterSpec|encrypt|encryption)\b/i',
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
                5,
                'Missing Security Logging',
                'HIGH',
                $fileName,
                0,
                'No security logging mechanism was detected in the uploaded Java source code.',
                'Implement Java security logging using java.util.logging, SLF4J, Log4j, or another appropriate logging mechanism.'
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
                6,
                'Improper Log File Format',
                'MEDIUM',
                $fileName,
                $loggingLine,
                'Java logging was detected, but SecureLog could not identify a .txt log file destination.',
                'Store application security logs in an approved .txt log file or configured secure log destination.'
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
                7,
                'Unprotected Log Data',
                'MEDIUM',
                $fileName,
                $txtLine,
                'A .txt log file was detected, but SecureLog could not identify encryption or protection for the Java log data.',
                'Encrypt or securely protect sensitive log data before writing it to persistent storage.'
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
            8,
            'Secure Logging Configuration',
            'INFO',
            $fileName,
            $encryptionLine,
            'SecureLog detected Java logging, .txt log storage, and encryption or protection.',
            'Continue protecting log confidentiality and keep encryption keys separate from the stored log files.'
        )
    ];
}