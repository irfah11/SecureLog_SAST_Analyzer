<?php
/**
 * SecureLog - Centralized Security Activity Logger
 *
 * Active audit log architecture:
 *
 * Application Event
 *      ↓
 * ActivityLogger.php
 *      ↓
 * Structured JSON event
 *      ↓
 * Dashboard/logs/securelog_audit.txt
 *
 * IMPORTANT:
 * - Active log is NOT encrypted here.
 * - Encryption will be handled later by Secure Log Vault.
 * - Never log passwords, tokens, encryption keys or source code.
 */


/* ============================================================
   LOG STORAGE
   ============================================================ */

if (!defined('LOG_DIR')) {
    define('LOG_DIR', __DIR__ . '/logs/');
}

if (!defined('LOG_FILE')) {
    define('LOG_FILE', LOG_DIR . 'securelog_audit.txt');
}


/* ============================================================
   EVENT TYPES
   ============================================================ */

// Authentication
if (!defined('LOG_LOGIN_SUCCESS')) {
    define('LOG_LOGIN_SUCCESS', 'LOGIN_SUCCESS');
}

if (!defined('LOG_LOGIN_FAILED')) {
    define('LOG_LOGIN_FAILED', 'LOGIN_FAILED');
}

if (!defined('LOG_LOGOUT')) {
    define('LOG_LOGOUT', 'LOGOUT');
}


// Access Control
if (!defined('LOG_ACCESS_DENIED')) {
    define('LOG_ACCESS_DENIED', 'ACCESS_DENIED');
}


// User Management
if (!defined('LOG_USER_CREATED')) {
    define('LOG_USER_CREATED', 'USER_CREATED');
}

if (!defined('LOG_USER_APPROVED')) {
    define('LOG_USER_APPROVED', 'USER_APPROVED');
}

if (!defined('LOG_USER_DEACTIVATED')) {
    define('LOG_USER_DEACTIVATED', 'USER_DEACTIVATED');
}

if (!defined('LOG_USER_DELETED')) {
    define('LOG_USER_DELETED', 'USER_DELETED');
}

if (!defined('LOG_ROLE_CHANGED')) {
    define('LOG_ROLE_CHANGED', 'ROLE_CHANGED');
}


// File / Scanner
if (!defined('LOG_FILE_UPLOAD_COMPLETED')) {
    define('LOG_FILE_UPLOAD_COMPLETED', 'FILE_UPLOAD_COMPLETED');
}

if (!defined('LOG_SCAN_STARTED')) {
    define('LOG_SCAN_STARTED', 'SCAN_STARTED');
}

if (!defined('LOG_SCAN_COMPLETED')) {
    define('LOG_SCAN_COMPLETED', 'SCAN_COMPLETED');
}

if (!defined('LOG_SCAN_FAILED')) {
    define('LOG_SCAN_FAILED', 'SCAN_FAILED');
}


// Scanner Rules
if (!defined('LOG_RULE_CREATED')) {
    define('LOG_RULE_CREATED', 'RULE_CREATED');
}

if (!defined('LOG_RULE_UPDATED')) {
    define('LOG_RULE_UPDATED', 'RULE_UPDATED');
}

if (!defined('LOG_RULE_ACTIVATED')) {
    define('LOG_RULE_ACTIVATED', 'RULE_ACTIVATED');
}

if (!defined('LOG_RULE_DISABLED')) {
    define('LOG_RULE_DISABLED', 'RULE_DISABLED');
}

if (!defined('LOG_RULE_TESTED')) {
    define('LOG_RULE_TESTED', 'RULE_TESTED');
}

// Secure Log Vault
if (!defined('LOG_LOG_VIEWED')) {
    define('LOG_LOG_VIEWED', 'LOG_VIEWED');
}

if (!defined('LOG_LOG_EXPORTED')) {
    define('LOG_LOG_EXPORTED', 'LOG_EXPORTED');
}

if (!defined('LOG_INTEGRITY_CHECK_FAILED')) {
    define('LOG_INTEGRITY_CHECK_FAILED', 'INTEGRITY_CHECK_FAILED');
}


/*
 * Temporary compatibility constant.
 *
 * activityLog.php currently uses LOG_ADMIN_VIEW.
 * We will remove this event when Activity Log UI is redesigned.
 */
if (!defined('LOG_ADMIN_VIEW')) {
    define('LOG_ADMIN_VIEW', 'ADMIN_VIEW');
}


/* ============================================================
   SECURITY CONFIGURATION
   ============================================================ */

/**
 * Keys that must never be stored directly in audit logs.
 */
function securelog_sensitive_keys(): array
{
    return [
        'password',
        'passwd',
        'pwd',

        'token',
        'access_token',
        'refresh_token',

        'session_id',
        'sessionid',

        'secret',
        'api_key',
        'apikey',

        'encryption_key',
        'private_key',

        'smtp_password',
        'database_password',
        'db_password',

        'authorization',
        'cookie',

        'source_code'
    ];
}


/* ============================================================
   HELPER: SANITIZE STRING
   ============================================================ */

/**
 * Removes characters that could make log entries confusing
 * or facilitate log injection.
 */
function securelog_sanitize_string(string $value): string
{
    // Remove null bytes.
    $value = str_replace("\0", '', $value);

    // Prevent CR/LF based log forging.
    $value = str_replace(
        ["\r", "\n"],
        ['\\r', '\\n'],
        $value
    );

    return trim($value);
}


/* ============================================================
   HELPER: SANITIZE CONTEXT
   ============================================================ */

/**
 * Recursively sanitizes contextual information and redacts
 * known sensitive fields.
 */
function securelog_sanitize_context(array $data): array
{
    $sensitiveKeys = securelog_sensitive_keys();

    $clean = [];

    foreach ($data as $key => $value) {

        $normalizedKey = strtolower((string) $key);

        /*
         * Never write sensitive values.
         */
        if (in_array($normalizedKey, $sensitiveKeys, true)) {
            $clean[$key] = '[REDACTED]';
            continue;
        }

        /*
         * Nested context.
         */
        if (is_array($value)) {
            $clean[$key] = securelog_sanitize_context($value);
            continue;
        }

        /*
         * Strings.
         */
        if (is_string($value)) {
            $clean[$key] = securelog_sanitize_string($value);
            continue;
        }

        /*
         * Keep safe primitive types.
         */
        if (
            is_int($value)
            || is_float($value)
            || is_bool($value)
            || $value === null
        ) {
            $clean[$key] = $value;
            continue;
        }

        /*
         * Unexpected objects/resources should not be logged.
         */
        $clean[$key] = '[UNSUPPORTED_VALUE]';
    }

    return $clean;
}


/* ============================================================
   HELPER: EVENT ID
   ============================================================ */

function securelog_generate_event_id(): string
{
    try {
        return 'EVT-' . strtoupper(bin2hex(random_bytes(8)));
    } catch (Throwable $e) {
        /*
         * Logging must never crash the main application.
         */
        return 'EVT-' . strtoupper(uniqid());
    }
}


/* ============================================================
   HELPER: ACTOR INFORMATION
   ============================================================ */

function securelog_get_actor(?int $userId, array $context): array
{
    /*
     * Context has priority.
     *
     * This is important for LOGIN_FAILED because the user
     * may not have a valid authenticated session yet.
     */

    $username =
        $context['actor_username']
        ?? $_SESSION['username']
        ?? null;

    $role =
        $context['actor_role']
        ?? $_SESSION['role']
        ?? null;

    return [
        'user_id' => $userId,
        'username' => $username !== null
            ? securelog_sanitize_string((string) $username)
            : null,

        'role' => $role !== null
            ? securelog_sanitize_string((string) $role)
            : null
    ];
}


/* ============================================================
   HELPER: REQUEST SOURCE
   ============================================================ */

function securelog_get_source(): array
{
    return [
        'ip' => securelog_sanitize_string(
            $_SERVER['REMOTE_ADDR'] ?? 'CLI'
        ),

        'request_uri' => securelog_sanitize_string(
            $_SERVER['REQUEST_URI'] ?? 'CLI'
        ),

        'http_method' => securelog_sanitize_string(
            $_SERVER['REQUEST_METHOD'] ?? 'CLI'
        )
    ];
}


/* ============================================================
   MAIN LOGGING FUNCTION
   ============================================================ */

/**
 * Writes one structured security event.
 *
 * Existing 3-parameter calls remain supported:
 *
 * log_activity(
 *     LOG_LOGIN_SUCCESS,
 *     $userId,
 *     'User successfully authenticated.'
 * );
 *
 * New contextual logging:
 *
 * log_activity(
 *     LOG_LOGIN_SUCCESS,
 *     $userId,
 *     'Developer successfully authenticated.',
 *     [
 *         'module'   => 'Authentication',
 *         'severity' => 'INFO',
 *         'result'   => 'SUCCESS'
 *     ]
 * );
 */
function log_activity(
    string $eventType,
    ?int $userId,
    string $description,
    array $context = []
): bool {

    try {

        /* --------------------------------------------------------
           Ensure log directory exists
           -------------------------------------------------------- */

        if (!is_dir(LOG_DIR)) {

            if (!mkdir(LOG_DIR, 0750, true) && !is_dir(LOG_DIR)) {
                error_log(
                    'SecureLog: Unable to create audit log directory.'
                );

                return false;
            }
        }


        /* --------------------------------------------------------
           Protect log directory from direct web access
           -------------------------------------------------------- */

        $htaccessFile = LOG_DIR . '.htaccess';

        if (!file_exists($htaccessFile)) {

            $htaccessContent =
                "Require all denied\n"
                . "Deny from all\n";

            @file_put_contents(
                $htaccessFile,
                $htaccessContent,
                LOCK_EX
            );
        }


        /* --------------------------------------------------------
           Normalize supplied context
           -------------------------------------------------------- */

        $context = securelog_sanitize_context($context);


        /* --------------------------------------------------------
           Determine event attributes
           -------------------------------------------------------- */

        $module = $context['module'] ?? 'System';

        $severity = strtoupper(
            (string) ($context['severity'] ?? 'INFO')
        );

        $allowedSeverities = [
            'INFO',
            'WARNING',
            'ERROR',
            'CRITICAL'
        ];

        if (!in_array($severity, $allowedSeverities, true)) {
            $severity = 'INFO';
        }


        $result = strtoupper(
            (string) ($context['result'] ?? 'SUCCESS')
        );

        $allowedResults = [
            'SUCCESS',
            'FAILURE',
            'DENIED'
        ];

        if (!in_array($result, $allowedResults, true)) {
            $result = 'SUCCESS';
        }


        /* --------------------------------------------------------
           Build target
           -------------------------------------------------------- */

        $target = null;

        if (
            isset($context['target_type'])
            || isset($context['target_id'])
        ) {
            $target = [
                'type' => $context['target_type'] ?? null,
                'id'   => $context['target_id'] ?? null
            ];
        }


        /* --------------------------------------------------------
           Build structured event
           -------------------------------------------------------- */

        $event = [

            /*
             * Identification
             */
            'event_id' => securelog_generate_event_id(),

            /*
             * WHEN
             */
            'timestamp' => (new DateTimeImmutable(
                'now',
                new DateTimeZone('Asia/Kuala_Lumpur')
            ))->format(DATE_ATOM),

            /*
             * WHERE
             */
            'application' => 'SecureLog',
            'module' => securelog_sanitize_string(
                (string) $module
            ),

            /*
             * WHAT
             */
            'event' => securelog_sanitize_string(
                strtoupper($eventType)
            ),

            'severity' => $severity,

            /*
             * WHO
             */
            'actor' => securelog_get_actor(
                $userId,
                $context
            ),

            /*
             * REQUEST SOURCE
             */
            'source' => securelog_get_source(),

            /*
             * OBJECT AFFECTED
             */
            'target' => $target,

            /*
             * RESULT
             */
            'result' => $result,

            /*
             * HUMAN-READABLE EXPLANATION
             */
            'description' => securelog_sanitize_string(
                $description
            )
        ];


        /* --------------------------------------------------------
           Optional safe metadata
           -------------------------------------------------------- */

        if (
            isset($context['metadata'])
            && is_array($context['metadata'])
        ) {
            $event['metadata'] =
                securelog_sanitize_context(
                    $context['metadata']
                );
        }


        /* --------------------------------------------------------
           Convert to JSON
           -------------------------------------------------------- */

        $json = json_encode(
            $event,
            JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
        );

        if ($json === false) {

            error_log(
                'SecureLog: Failed to encode audit event.'
            );

            return false;
        }


        /* --------------------------------------------------------
           Append one JSON object per line
           -------------------------------------------------------- */

        $written = file_put_contents(
            LOG_FILE,
            $json . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );

        if ($written === false) {

            error_log(
                'SecureLog: Failed to write audit event.'
            );

            return false;
        }

        return true;

    } catch (Throwable $e) {

        /*
         * Security logging failure must not crash the main
         * SecureLog application.
         */

        error_log(
            'SecureLog Activity Logger Error: '
            . $e->getMessage()
        );

        return false;
    }
}


/* ============================================================
   READ ACTIVE LOG
   ============================================================ */

/**
 * Reads structured active audit events.
 *
 * Newest event will appear first.
 */
function read_logs(?int $limit = null): array
{
    if (!file_exists(LOG_FILE)) {
        return [];
    }

    $lines = file(
        LOG_FILE,
        FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
    );

    if ($lines === false) {
        return [];
    }

    $events = [];

    foreach (array_reverse($lines) as $line) {

        $event = parse_log_line($line);

        if ($event === null) {
            continue;
        }

        $events[] = $event;

        if (
            $limit !== null
            && count($events) >= $limit
        ) {
            break;
        }
    }

    return $events;
}


/* ============================================================
   PARSE STRUCTURED LOG LINE
   ============================================================ */

function parse_log_line(string $line): ?array
{
    $event = json_decode($line, true);

    if (!is_array($event)) {
        return null;
    }

    if (
        empty($event['event_id'])
        || empty($event['timestamp'])
        || empty($event['event'])
    ) {
        return null;
    }

    return $event;
}