<?php

require_once __DIR__ . '/ScannerEngine.php';

/**
 * ============================================================
 * SecureLog PHP Static Analyzer
 * ============================================================
 *
 * FINAL PIPELINE
 *
 * Security Event
 *      |
 *      v
 * [1] SECURITY LOGGING
 *     CWE-778
 *
 *      |
 *      v
 * [2] LOG NEUTRALIZATION
 *     CWE-117
 *
 *      |
 *      v
 * [3] LOG STORAGE
 *     SecureLog Policy (.txt)
 *
 *      |
 *      v
 * [4] LOG PROTECTION
 *     SecureLog Policy (Encryption)
 *
 *
 * STATUS
 * ------------------------------------------------------------
 * PASS = requirement satisfied
 * FAIL = weakness/problem detected
 * N/A  = cannot/does not need to be evaluated
 *
 *
 * RULES
 * ------------------------------------------------------------
 *
 * CWE-778
 * 77801 - Authentication Failure Without Logging      HIGH
 * 77802 - Access Control Failure Without Logging       HIGH
 * 77803 - Exception Handling Without Logging           MEDIUM
 *
 * CWE-117
 * 11701 - Unneutralized User Input in Log              HIGH
 *
 * SecureLog Policy
 * 90001 - Non-approved Log Storage                     MEDIUM
 * 90002 - Unprotected Log Data                         MEDIUM
 *
 *
 * IMPORTANT
 * ------------------------------------------------------------
 *
 * .txt is a SecureLog project-specific policy.
 * CWE-117 does NOT require .txt.
 *
 * Encryption is also a SecureLog project-specific policy.
 * It is NOT classified as CWE-778 or CWE-117.
 */


/* ============================================================
   RESULT CREATOR
   ============================================================ */

/**
 * Create one PASS / FAIL / N/A analysis result.
 *
 * IMPORTANT:
 * rule_id is only populated when an actual weakness exists.
 *
 * PASS and N/A use rule_id = null.
 */
function createPhpCheckResult(
    string $status,
    string $check,
    ?int $ruleId,
    string $standard,
    string $severity,
    string $filePath,
    int $lineNumber,
    string $description,
    string $recommendation = ''
): array {

    return [
        'status'             => strtoupper($status),
        'check'              => $check,
        'rule_id'            => $ruleId,
        'standard'           => $standard,
        'vulnerability_name' => $check,
        'severity'           => $severity,
        'file_path'          => $filePath,
        'line_number'        => $lineNumber,
        'description'        => $description,
        'recommendation'     => $recommendation
    ];
}


/* ============================================================
   MAIN PHP SCANNER
   ============================================================ */

function scanPHP(
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

    $results = [];

    /*
     * Prevent duplicate security events.
     */
    $reportedEvents = [];


    foreach ($lines as $index => $lineContent) {

        $lineNumber = $index + 1;

        $line = trim($lineContent);

        if ($line === '') {
            continue;
        }


        /*
         * Security conditions may span multiple lines.
         */
        $eventWindow = getPhpEventWindow(
            $lines,
            $index,
            8
        );


        /* =====================================================
           EVENT 1
           AUTHENTICATION FAILURE
           ===================================================== */

        if (isPhpAuthenticationFailure($eventWindow)) {

            $eventKey = 'AUTH:' . $lineNumber;

            if (!isset($reportedEvents[$eventKey])) {

                $context = getPhpAnalysisContext(
                    $lines,
                    $index,
                    40,
                    20
                );

                analyzePhpSecurityEventStatus(
                    $results,
                    $fileName,
                    $lineNumber,
                    $context,

                    77801,
                    'Authentication Failure',

                    'SecureLog detected an authentication failure path without an associated security logging operation.',

                    'Record failed authentication attempts using an appropriate security logging mechanism. Do not log passwords, tokens, or credentials.'
                );

                $reportedEvents[$eventKey] = true;
            }
        }


        /* =====================================================
           EVENT 2
           ACCESS CONTROL FAILURE
           ===================================================== */

        if (isPhpAccessControlFailure($eventWindow)) {

            $eventKey = 'ACCESS:' . $lineNumber;

            if (!isset($reportedEvents[$eventKey])) {

                $context = getPhpAnalysisContext(
                    $lines,
                    $index,
                    40,
                    20
                );

                analyzePhpSecurityEventStatus(
                    $results,
                    $fileName,
                    $lineNumber,
                    $context,

                    77802,
                    'Access Control Failure',

                    'SecureLog detected an access-control denial or authorization failure without an associated security logging operation.',

                    'Record denied or unauthorized access attempts using an appropriate security logging mechanism.'
                );

                $reportedEvents[$eventKey] = true;
            }
        }


        /* =====================================================
           EVENT 3
           EXCEPTION HANDLING
           ===================================================== */

        if (isPhpExceptionHandling($eventWindow)) {

            $eventKey = 'EXCEPTION:' . $lineNumber;

            if (!isset($reportedEvents[$eventKey])) {

                $context = getPhpAnalysisContext(
                    $lines,
                    $index,
                    50,
                    20
                );

                analyzePhpSecurityEventStatus(
                    $results,
                    $fileName,
                    $lineNumber,
                    $context,

                    77803,
                    'Exception Handling',

                    'SecureLog detected exception handling without an associated logging operation.',

                    'Record security-relevant or operational exceptions using an appropriate logger while avoiding sensitive information.'
                );

                $reportedEvents[$eventKey] = true;
            }
        }
    }


    /*
     * ---------------------------------------------------------
     * NO SECURITY EVENT DETECTED
     * ---------------------------------------------------------
     *
     * This is NOT CWE-778.
     *
     * CWE-778 should only be evaluated when SecureLog detects
     * a security-relevant event that should be logged.
     */
    if (empty($results)) {

        $results[] = createPhpCheckResult(
            'N/A',
            'Security Logging',
            null,
            'CWE-778',
            'INFO',
            $fileName,
            0,

            'No supported security event was detected in this PHP file.',

            'No CWE-778 conclusion was produced because SecureLog did not identify an authentication failure, access-control failure, or exception-handling event.'
        );

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Neutralization',
            null,
            'CWE-117',
            'INFO',
            $fileName,
            0,

            'Log neutralization was not evaluated because no supported security event was detected.'
        );

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Storage',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            0,

            'Log storage was not evaluated because no supported security event was detected.'
        );

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Protection',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            0,

            'Log protection was not evaluated because no supported security event was detected.'
        );
    }


    return $results;
}


/* ============================================================
   SECURITY EVENT ANALYSIS
   ============================================================ */

function analyzePhpSecurityEventStatus(
    array &$results,
    string $fileName,
    int $lineNumber,
    string $context,

    int $cwe778RuleId,
    string $eventName,
    string $cwe778FailureDescription,
    string $cwe778Recommendation
): void {


    /* =========================================================
       CHECK 1
       SECURITY LOGGING — CWE-778
       ========================================================= */

    $hasLogSink = hasPhpLogSink($context);


    if (!$hasLogSink) {

        /*
         * FAIL
         *
         * A security event exists but no LOG_SINK exists.
         */

        $results[] = createPhpCheckResult(
            'FAIL',
            'Security Logging',
            $cwe778RuleId,
            'CWE-778',
            (
                $cwe778RuleId === 77803
                    ? 'MEDIUM'
                    : 'HIGH'
            ),
            $fileName,
            $lineNumber,

            $eventName . ': ' .
            $cwe778FailureDescription,

            $cwe778Recommendation
        );


        /*
         * CWE-117 cannot be evaluated because there is
         * no logging operation.
         */

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Neutralization',
            null,
            'CWE-117',
            'INFO',
            $fileName,
            $lineNumber,

            'Not evaluated because no security logging operation exists for this event.'
        );


        /*
         * Storage cannot be evaluated because there is
         * no log operation.
         */

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Storage',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            $lineNumber,

            'Not evaluated because no security logging operation exists for this event.'
        );


        /*
         * Encryption cannot be evaluated because there is
         * no log data being written.
         */

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Protection',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            $lineNumber,

            'Not evaluated because no security logging operation exists for this event.'
        );


        return;
    }


    /*
     * PASS — CWE-778
     */

    $results[] = createPhpCheckResult(
        'PASS',
        'Security Logging',
        null,
        'CWE-778',
        'INFO',
        $fileName,
        $lineNumber,

        'Required security event logging was detected for: ' .
        $eventName . '.'
    );



    /* =========================================================
       CHECK 2
       LOG NEUTRALIZATION — CWE-117
       ========================================================= */

    $flow = findPhpUserInputToLogFlow(
        $context
    );


    /*
     * CASE A:
     *
     * User-controlled input reaches LOG_SINK.
     */
    if ($flow['reaches_sink']) {


        /*
         * User input reaches the log AND is neutralized.
         */
        if ($flow['neutralized']) {

            $results[] = createPhpCheckResult(
                'PASS',
                'Log Neutralization',
                null,
                'CWE-117',
                'INFO',
                $fileName,
                $lineNumber,

                'Logged external input is properly neutralized before reaching the logging operation.'
            );

        } else {

            /*
             * User input reaches the log but is NOT neutralized.
             *
             * CWE-117
             */

            $findingLine = $lineNumber;

            if (
                isset($flow['sink_line'])
                &&
                $flow['sink_line'] > 0
            ) {

                $findingLine = max(
                    1,
                    $lineNumber
                    + $flow['sink_line']
                    - ($flow['event_offset'] ?? 1)
                );
            }


            $results[] = createPhpCheckResult(
                'FAIL',
                'Log Neutralization',
                11701,
                'CWE-117',
                'HIGH',
                $fileName,
                $findingLine,

                'Logged external input is not properly neutralized.',

                'Neutralize carriage returns, line feeds, and unsafe control characters before user-controlled data is written to logs.'
            );
        }

    } else {

        /*
         * CASE B:
         *
         * No user-controlled input reaches LOG_SINK.
         *
         * This is NOT a CWE-117 failure.
         */

        $results[] = createPhpCheckResult(
            'PASS',
            'Log Neutralization',
            null,
            'CWE-117',
            'INFO',
            $fileName,
            $lineNumber,

            'No unneutralized user-controlled input was detected reaching the logging operation.'
        );
    }



    /* =========================================================
       CHECK 3
       LOG STORAGE — SECURELOG .TXT POLICY
       ========================================================= */

    $hasTxtStorage = hasPhpTxtLogTarget(
        $context
    );


    if ($hasTxtStorage) {

        $results[] = createPhpCheckResult(
            'PASS',
            'Log Storage',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            $lineNumber,

            'Approved .txt log storage was detected.'
        );

    } else {

        $results[] = createPhpCheckResult(
            'FAIL',
            'Log Storage',
            90001,
            'SecureLog Policy',
            'MEDIUM',
            $fileName,
            $lineNumber,

            'Log is not stored using the approved .txt storage policy.',

            'Use an approved .txt log target according to the SecureLog project logging policy.'
        );
    }



    /* =========================================================
       CHECK 4
       LOG PROTECTION — SECURELOG ENCRYPTION POLICY
       ========================================================= */

    /*
     * Encryption analysis is independent from CWE-117.
     *
     * SecureLog checks whether encrypted/protected data
     * actually reaches LOG_SINK.
     */

    $encryptionFlow = findPhpEncryptionToLogFlow(
        $context
    );


    if ($encryptionFlow['encrypted']) {

        $results[] = createPhpCheckResult(
            'PASS',
            'Log Protection',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            (
                isset($encryptionFlow['sink_line'])
                &&
                $encryptionFlow['sink_line'] > 0
                    ? $encryptionFlow['sink_line']
                    : $lineNumber
            ),

            'Log data protection or encryption was detected before the data reached the logging operation.'
        );

    } else {

        $results[] = createPhpCheckResult(
            'FAIL',
            'Log Protection',
            90002,
            'SecureLog Policy',
            'MEDIUM',
            $fileName,
            $lineNumber,

            'Log data is not encrypted or otherwise protected before storage.',

            'Encrypt or otherwise protect log data before writing it to the approved log file. Keep encryption keys separate from stored log data.'
        );
    }
}


/* ============================================================
   IMPORTANT
   ============================================================

   KEEP ALL YOUR EXISTING FUNCTIONS BELOW THIS POINT:

   hasPhpLogSink()
   hasPhpTxtLogTarget()
   containsPhpUserInputSource()
   hasPhpLogNeutralization()
   findPhpUserInputToLogFlow()
   hasPhpEncryptionOperation()
   findPhpEncryptionToLogFlow()
   isPhpAuthenticationFailure()
   isPhpAccessControlFailure()
   isPhpExceptionHandling()
   getPhpEventWindow()
   getPhpCodeBlock()
   getPhpAnalysisContext()
   getPhpLogicalStatements()

   DO NOT DELETE THEM.
   ============================================================ */


    /* =========================================================
       GATE 1
       CWE-778 — SECURITY LOGGING REQUIRED
       ========================================================= */


/* ============================================================
   NORMALIZED PHP LOG SINK DETECTOR
   ============================================================ */

/**
 * Different PHP/framework logging implementations are
 * normalized into:
 *
 *                  LOG_SINK
 *
 * Supported examples:
 *
 * error_log(...)
 * syslog(...)
 *
 * $logger->warning(...)
 * $logger->error(...)
 *
 * Log::warning(...)
 * Log::error(...)
 *
 * logger(...)
 *
 * log_activity(...)
 * writeLog(...)
 * auditLog(...)
 *
 * file_put_contents(...)
 * fwrite(...)
 */
function hasPhpLogSink(
    string $code
): bool {

    $patterns = [

        /* Native PHP */

        '/\berror_log\s*\(/i',

        '/\bsyslog\s*\(/i',


        /* PSR / Monolog */

        '/->\s*(?:debug|info|notice|warning|error|critical|alert|emergency|log)\s*\(/i',


        /* Laravel Log facade */

        '/\bLog::\s*(?:debug|info|notice|warning|error|critical|alert|emergency|log)\s*\(/i',


        /* Laravel logger() helper */

        '/\blogger\s*\(/i',


        /* Custom / SecureLog functions */

        '/\blog_activity\s*\(/i',

        '/\bwriteLog\s*\(/i',

        '/\bauditLog\s*\(/i',

        '/\bsecurityLog\s*\(/i',

        '/\bwriteSecurityLog\s*\(/i',


        /*
         * File-based logging.
         *
         * Destination should appear related to:
         *
         * log
         * audit
         * security
         */

        '/\bfile_put_contents\s*\([^;]*(?:log|audit|security)[^;]*\)/is',


        /*
         * fwrite($handle, ...)
         *
         * Accepted when surrounding context indicates
         * logging/audit/security.
         */

        '/\bfwrite\s*\([^;]*(?:log|audit|security|message|event)[^;]*\)/is'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   SECURELOG APPROVED .TXT STORAGE POLICY
   ============================================================ */

/**
 * IMPORTANT:
 *
 * .txt is a SecureLog project-specific requirement.
 *
 * CWE-117 itself does NOT require logs to use .txt.
 */
function hasPhpTxtLogTarget(
    string $code
): bool {

    $patterns = [

        /*
         * file_put_contents(
         *     'security.txt',
         *     ...
         * )
         */

        '/\bfile_put_contents\s*\(\s*[\'"][^\'"]+\.txt[\'"]/is',


        /*
         * fopen(
         *     'audit.txt',
         *     'a'
         * )
         */

        '/\bfopen\s*\(\s*[\'"][^\'"]+\.txt[\'"]/is',


        /*
         * $logFile = 'security.txt';
         * $auditFile = 'audit.txt';
         */

        '/\$[A-Za-z_][A-Za-z0-9_]*(?:log|audit|security)[A-Za-z0-9_]*\s*=\s*[\'"][^\'"]+\.txt[\'"]/i',


        /*
         * $file = 'security_log.txt';
         */

        '/\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\'"][^\'"]*(?:log|audit|security)[^\'"]*\.txt[\'"]/i',


        /*
         * Literal .txt log-related target anywhere
         * inside the local analysis context.
         */

        '/[\'"][^\'"]*(?:log|audit|security)[^\'"]*\.txt[\'"]/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   USER-CONTROLLED INPUT SOURCE DETECTOR
   ============================================================ */

/**
 * Normalize common PHP/Laravel external input into:
 *
 *                  SOURCE
 */
function containsPhpUserInputSource(
    string $code
): bool {

    $patterns = [

        /* PHP superglobals */

        '/\$_POST\s*\[/i',

        '/\$_GET\s*\[/i',

        '/\$_REQUEST\s*\[/i',

        '/\$_COOKIE\s*\[/i',

        '/\$_FILES\s*\[/i',


        /* Laravel request helper */

        '/\brequest\s*\(/i',


        /*
         * Laravel Request object:
         *
         * $request->input(...)
         * $request->get(...)
         * $request->query(...)
         * $request->all(...)
         */

        '/\$request\s*->\s*(?:input|get|query|all|string)\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   CWE-117
   LOG NEUTRALIZATION DETECTOR
   ============================================================ */

/**
 * Detect recognized log-neutralization operations.
 *
 * Example:
 *
 * $safeUsername = str_replace(
 *     ["\r", "\n"],
 *     '',
 *     $username
 * );
 *
 * This is different from encryption.
 *
 * Neutralization protects the STRUCTURE of log records.
 * Encryption protects stored log DATA.
 */
function hasPhpLogNeutralization(
    string $code
): bool {

    $patterns = [

        /*
         * Remove CR/LF with str_replace().
         */

        '/\bstr_replace\s*\([^;]*(?:\\\\r|\\\\n)[^;]*\)/is',


        /*
         * Remove CR/LF/control characters with preg_replace().
         */

        '/\bpreg_replace\s*\([^;]*(?:\\\\r|\\\\n|\\\\x0D|\\\\x0A|\\\\x00)[^;]*\)/is',


        /* Custom neutralizers */

        '/\bsanitizeLog\s*\(/i',

        '/\bsanitize_log\s*\(/i',

        '/\bneutralizeLog\s*\(/i',

        '/\bneutralize_log\s*\(/i',

        '/\bescapeLog\s*\(/i',

        '/\bescape_log\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   CWE-117
   LIGHTWEIGHT SOURCE → LOG_SINK DATA FLOW
   ============================================================ */

/**
 * Supported flows:
 *
 * DIRECT
 * ------
 *
 * file_put_contents(
 *     'security.txt',
 *     $_POST['username']
 * );
 *
 *
 * VARIABLE
 * --------
 *
 * $username = $_POST['username'];
 *
 * file_put_contents(
 *     'security.txt',
 *     $username
 * );
 *
 *
 * PROPAGATION
 * -----------
 *
 * $username = $_POST['username'];
 *
 * $message =
 *     "Login failed: " . $username;
 *
 * file_put_contents(
 *     'security.txt',
 *     $message
 * );
 */
function findPhpUserInputToLogFlow(
    string $code
): array {

    $result = [

        'reaches_sink' => false,

        'neutralized' => false,

        'sink_line' => 0,

        'source' => null,

        'variable' => null,

        'event_offset' => 1
    ];


    $statements =
        getPhpLogicalStatements($code);


    if (empty($statements)) {
        return $result;
    }


    /*
     * Variables containing user-controlled data.
     */
    $taintedVariables = [];


    foreach ($statements as $statementData) {

        $statement =
            $statementData['code'];

        $statementLine =
            $statementData['line'];


        /* =====================================================
           STEP 1
           DIRECT SOURCE → LOG_SINK
           ===================================================== */

        if (
            hasPhpLogSink($statement)
            &&
            containsPhpUserInputSource($statement)
        ) {

            $result['reaches_sink'] =
                true;

            $result['sink_line'] =
                $statementLine;

            $result['source'] =
                'direct-user-input';

            $result['neutralized'] =
                hasPhpLogNeutralization(
                    $statement
                );

            return $result;
        }


        /* =====================================================
           STEP 2
           SOURCE → VARIABLE
           ===================================================== */

        if (
            preg_match(
                '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?$/is',
                $statement,
                $assignment
            ) === 1
        ) {

            $variableName =
                $assignment[1];

            $expression =
                $assignment[2];


            /*
             * Example:
             *
             * $username = $_POST['username'];
             */
            if (
                containsPhpUserInputSource(
                    $expression
                )
            ) {

                $taintedVariables[$variableName] = [

                    'neutralized' =>
                        hasPhpLogNeutralization(
                            $expression
                        ),

                    'source' =>
                        trim($expression)
                ];

                continue;
            }


            /* =================================================
               STEP 3
               TAINT PROPAGATION
               ================================================= */

            foreach (
                $taintedVariables
                as $taintedName => $taintInfo
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $taintedName,
                            '/'
                        ) .
                        '\b/',
                        $expression
                    ) === 1
                ) {

                    $isNeutralized =
                        $taintInfo['neutralized']
                        ||
                        hasPhpLogNeutralization(
                            $expression
                        );


                    $taintedVariables[$variableName] = [

                        'neutralized' =>
                            $isNeutralized,

                        'source' =>
                            $taintInfo['source']
                    ];

                    break;
                }
            }
        }


        /* =====================================================
           STEP 4
           TAINTED VARIABLE → LOG_SINK
           ===================================================== */

        if (hasPhpLogSink($statement)) {

            foreach (
                $taintedVariables
                as $variableName => $taintInfo
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $variableName,
                            '/'
                        ) .
                        '\b/',
                        $statement
                    ) === 1
                ) {

                    $result['reaches_sink'] =
                        true;

                    $result['sink_line'] =
                        $statementLine;

                    $result['source'] =
                        $taintInfo['source'];

                    $result['variable'] =
                        '$' . $variableName;


                    $result['neutralized'] =
                        $taintInfo['neutralized']
                        ||
                        hasPhpLogNeutralization(
                            $statement
                        );


                    return $result;
                }
            }
        }
    }


    return $result;
}


/* ============================================================
   SECURELOG ENCRYPTION OPERATION DETECTOR
   ============================================================ */

/**
 * Recognized encryption/protection operations.
 *
 * IMPORTANT:
 *
 * Finding openssl_encrypt() somewhere in the source file
 * does NOT automatically mean the log is encrypted.
 *
 * The encrypted result must reach LOG_SINK.
 *
 * hash_hmac() is intentionally NOT treated as encryption.
 */
function hasPhpEncryptionOperation(
    string $code
): bool {

    $patterns = [

        /* PHP OpenSSL */

        '/\bopenssl_encrypt\s*\(/i',


        /* Sodium Secretbox */

        '/\bsodium_crypto_secretbox\s*\(/i',


        /* Sodium AEAD encryption */

        '/\bsodium_crypto_aead_[A-Za-z0-9_]+_encrypt\s*\(/i',


        /* Custom SecureLog encryption wrappers */

        '/\bencryptLog\s*\(/i',

        '/\bencrypt_log\s*\(/i',

        '/\bprotectLog\s*\(/i',

        '/\bprotect_log\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   SECURELOG ENCRYPTION
   LIGHTWEIGHT ENCRYPTION → LOG_SINK DATA FLOW
   ============================================================ */

/**
 * Supported flows:
 *
 * DIRECT
 * ------
 *
 * file_put_contents(
 *     'security.txt',
 *     openssl_encrypt($message, ...)
 * );
 *
 *
 * VARIABLE
 * --------
 *
 * $encryptedLog =
 *     openssl_encrypt($message, ...);
 *
 * file_put_contents(
 *     'security.txt',
 *     $encryptedLog
 * );
 *
 *
 * PROPAGATION
 * -----------
 *
 * $encryptedLog =
 *     openssl_encrypt($message, ...);
 *
 * $payload =
 *     $encryptedLog;
 *
 * file_put_contents(
 *     'security.txt',
 *     $payload
 * );
 */
function findPhpEncryptionToLogFlow(
    string $code
): array {

    $result = [

        'encrypted' => false,

        'sink_line' => 0,

        'variable' => null
    ];


    $statements =
        getPhpLogicalStatements($code);


    if (empty($statements)) {
        return $result;
    }


    /*
     * Variables known to contain encrypted data.
     */
    $encryptedVariables = [];


    foreach ($statements as $statementData) {

        $statement =
            $statementData['code'];

        $statementLine =
            $statementData['line'];


        /* =====================================================
           STEP 1
           DIRECT ENCRYPTION → LOG_SINK
           ===================================================== */

        if (
            hasPhpLogSink($statement)
            &&
            hasPhpEncryptionOperation($statement)
        ) {

            $result['encrypted'] =
                true;

            $result['sink_line'] =
                $statementLine;

            return $result;
        }


        /* =====================================================
           STEP 2
           ENCRYPTION → VARIABLE
           ===================================================== */

        if (
            preg_match(
                '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?$/is',
                $statement,
                $assignment
            ) === 1
        ) {

            $variableName =
                $assignment[1];

            $expression =
                $assignment[2];


            /*
             * Example:
             *
             * $encryptedLog =
             *     openssl_encrypt(...);
             */
            if (
                hasPhpEncryptionOperation(
                    $expression
                )
            ) {

                $encryptedVariables[$variableName] =
                    true;

                continue;
            }


            /* =================================================
               STEP 3
               ENCRYPTED DATA PROPAGATION
               ================================================= */

            foreach (
                $encryptedVariables
                as $encryptedName => $status
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $encryptedName,
                            '/'
                        ) .
                        '\b/',
                        $expression
                    ) === 1
                ) {

                    $encryptedVariables[$variableName] =
                        true;

                    break;
                }
            }
        }


        /* =====================================================
           STEP 4
           ENCRYPTED VARIABLE → LOG_SINK
           ===================================================== */

        if (hasPhpLogSink($statement)) {

            /*
             * Remember where a LOG_SINK exists even if
             * its data is not encrypted.
             */
            if ($result['sink_line'] === 0) {

                $result['sink_line'] =
                    $statementLine;
            }


            foreach (
                $encryptedVariables
                as $variableName => $status
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $variableName,
                            '/'
                        ) .
                        '\b/',
                        $statement
                    ) === 1
                ) {

                    $result['encrypted'] =
                        true;

                    $result['sink_line'] =
                        $statementLine;

                    $result['variable'] =
                        '$' . $variableName;

                    return $result;
                }
            }
        }
    }


    return $result;
}


/* ============================================================
   AUTHENTICATION FAILURE DETECTOR
   ============================================================ */

function isPhpAuthenticationFailure(
    string $code
): bool {

    $patterns = [

        /*
         * Native PHP:
         *
         * if (!password_verify(...))
         */

        '/!\s*password_verify\s*\(/i',


        /*
         * password_verify(...) === false
         */

        '/password_verify\s*\([^;]*?\)\s*(?:===|==)\s*false/i',


        /*
         * Laravel:
         *
         * if (!Auth::attempt(...))
         */

        '/!\s*Auth::attempt\s*\(/i',


        /*
         * Auth::attempt(...) === false
         */

        '/Auth::attempt\s*\([^;]*?\)\s*(?:===|==)\s*false/i',


        /*
         * Generic authentication functions.
         */

        '/!\s*(?:authenticate|authenticateUser|loginUser|verifyLogin)\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   ACCESS CONTROL FAILURE DETECTOR
   ============================================================ */

function isPhpAccessControlFailure(
    string $code
): bool {

    $patterns = [

        /*
         * Laravel:
         *
         * Gate::denies(...)
         */

        '/\bGate::denies\s*\(/i',


        /*
         * !$user->can(...)
         * !$user->hasRole(...)
         * !$user->hasPermissionTo(...)
         */

        '/!\s*[^;\n]*(?:->|::)\s*(?:can|hasRole|hasPermissionTo|isAuthorized)\s*\(/i',


        /*
         * Role / permission comparisons.
         *
         * $_SESSION['role'] !== 'admin'
         */

        '/(?:role|permission|is_admin|isAdmin|authorized|authorization)[^;\n]*(?:!==|!=)\s*[\'"][^\'"]+[\'"]/i',


        /*
         * HTTP 403 denial.
         */

        '/\babort\s*\(\s*403\b/i',

        '/\bhttp_response_code\s*\(\s*403\s*\)/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   EXCEPTION HANDLING DETECTOR
   ============================================================ */

function isPhpExceptionHandling(
    string $code
): bool {

    /*
     * Examples:
     *
     * catch (Exception $e)
     *
     * catch (Throwable $e)
     *
     * catch (\RuntimeException $e)
     *
     * catch (Exception | RuntimeException $e)
     */

    return preg_match(
        '/\bcatch\s*\(\s*(?:\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*)(?:\s*\|\s*\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*)*\s+\$[A-Za-z_][A-Za-z0-9_]*\s*\)/i',
        $code
    ) === 1;
}


/* ============================================================
   EVENT WINDOW
   ============================================================ */

/**
 * Security conditions can span several lines.
 */
function getPhpEventWindow(
    array $lines,
    int $startIndex,
    int $lineCount = 8
): string {

    $result = [];

    $maxIndex = min(
        count($lines),
        $startIndex + $lineCount
    );


    for (
        $i = $startIndex;
        $i < $maxIndex;
        $i++
    ) {

        $result[] =
            $lines[$i];
    }


    return implode(
        "\n",
        $result
    );
}


/* ============================================================
   PHP EVENT BLOCK EXTRACTOR
   ============================================================ */

/**
 * Extract the block belonging to the detected event.
 */
function getPhpCodeBlock(
    array $lines,
    int $startIndex,
    int $maxLines = 40
): string {

    $context = [];

    $braceDepth = 0;

    $foundOpeningBrace = false;


    $lineLimit = min(
        count($lines),
        $startIndex + $maxLines
    );


    for (
        $i = $startIndex;
        $i < $lineLimit;
        $i++
    ) {

        $currentLine =
            $lines[$i];


        $context[] =
            $currentLine;


        $openingBraces =
            substr_count(
                $currentLine,
                '{'
            );


        $closingBraces =
            substr_count(
                $currentLine,
                '}'
            );


        if ($openingBraces > 0) {

            $foundOpeningBrace =
                true;
        }


        $braceDepth +=
            $openingBraces;


        $braceDepth -=
            $closingBraces;


        if (
            $foundOpeningBrace
            &&
            $braceDepth <= 0
        ) {

            break;
        }
    }


    return implode(
        "\n",
        $context
    );
}


/* ============================================================
   ANALYSIS CONTEXT
   ============================================================ */

/**
 * Creates a wider analysis context.
 *
 * Why?
 *
 * User input may be assigned BEFORE the security event:
 *
 * $username = $_POST['username'];
 *
 * if (!password_verify(...)) {
 *     ...
 * }
 *
 * If SecureLog only analyzes the IF block, it cannot see
 * that $username originated from $_POST.
 *
 * Therefore:
 *
 * - look backwards for source/variable assignments
 * - analyze the security-event block itself
 */
function getPhpAnalysisContext(
    array $lines,
    int $eventIndex,
    int $maxBlockLines = 40,
    int $lookBackLines = 20
): string {

    $startIndex = max(
        0,
        $eventIndex - $lookBackLines
    );


    $prefix = [];


    for (
        $i = $startIndex;
        $i < $eventIndex;
        $i++
    ) {

        $prefix[] =
            $lines[$i];
    }


    $eventBlock =
        getPhpCodeBlock(
            $lines,
            $eventIndex,
            $maxBlockLines
        );


    if (!empty($prefix)) {

        return implode(
            "\n",
            $prefix
        )
        .
        "\n"
        .
        $eventBlock;
    }


    return $eventBlock;
}


/* ============================================================
   PHP LOGICAL STATEMENT NORMALIZER
   ============================================================ */

/**
 * Convert multi-line PHP statements into logical statements.
 *
 * Example:
 *
 * $encryptedLog =
 *     openssl_encrypt(
 *         $message,
 *         'AES-256-CBC',
 *         $key,
 *         0,
 *         $iv
 *     );
 *
 * becomes one statement.
 *
 *
 * Same for:
 *
 * file_put_contents(
 *     'security.txt',
 *     $encryptedLog,
 *     FILE_APPEND
 * );
 */
function getPhpLogicalStatements(
    string $code
): array {

    $lines = preg_split(
        "/\r\n|\n|\r/",
        $code
    );


    if ($lines === false) {
        return [];
    }


    $statements = [];

    $buffer = '';

    $startLine = 1;

    $parenthesisDepth = 0;


    foreach ($lines as $index => $line) {

        $trimmedLine =
            trim($line);


        if ($trimmedLine === '') {
            continue;
        }


        if ($buffer === '') {

            $startLine =
                $index + 1;
        }


        $buffer .=
            ($buffer === '' ? '' : ' ')
            .
            $trimmedLine;


        /*
         * Lightweight parenthesis tracking.
         */
        $parenthesisDepth +=
            substr_count(
                $trimmedLine,
                '('
            );


        $parenthesisDepth -=
            substr_count(
                $trimmedLine,
                ')'
            );


        /*
         * Statement normally ends at ;
         * when parentheses are balanced.
         */
        if (
            str_contains(
                $trimmedLine,
                ';'
            )
            &&
            $parenthesisDepth <= 0
        ) {

            $statements[] = [

                'code' =>
                    trim($buffer),

                'line' =>
                    $startLine
            ];


            $buffer = '';

            $parenthesisDepth = 0;

            continue;
        }


        /*
         * Handle structural braces.
         */
        if (
            (
                $trimmedLine === '}'
                ||
                str_ends_with(
                    $trimmedLine,
                    '{'
                )
            )
            &&
            $parenthesisDepth <= 0
        ) {

            if (trim($buffer) !== '') {

                $statements[] = [

                    'code' =>
                        trim($buffer),

                    'line' =>
                        $startLine
                ];
            }


            $buffer = '';

            $parenthesisDepth = 0;
        }
    }


    if (trim($buffer) !== '') {

        $statements[] = [

            'code' =>
                trim($buffer),

            'line' =>
                $startLine
        ];
    }


    return $statements;
}