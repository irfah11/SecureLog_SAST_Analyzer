<?php
declare(strict_types=1);

/**
 * SecureLog Vault - Verify, Decrypt & View
 *
 * Admin-only endpoint for viewing a sealed SecureLog archive.
 *
 * Security:
 * - POST only
 * - CSRF protected
 * - Prevents path traversal
 * - AES-256-GCM authentication before plaintext is shown
 * - Master key is never exposed
 * - Output is HTML escaped
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}


/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';
require_once __DIR__ . '/../Dashboard/ActivityLogger.php';
require_once __DIR__ . '/VaultCrypto.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}


/* ============================================================
   CONFIGURATION
   ============================================================ */

$vaultDirectory =
    __DIR__
    . DIRECTORY_SEPARATOR
    . 'encrypted_logs';

$errorMessage = '';
$archiveInfo = null;
$events = [];
$totalEvents = 0;


/* ============================================================
   HELPERS
   ============================================================ */

function decryptHtml(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}


function severityClass(string $severity): string
{
    return match (strtoupper($severity)) {
        'CRITICAL' => 'critical',
        'ERROR'    => 'error',
        'WARNING'  => 'warning',
        'INFO'     => 'info',
        default    => 'default'
    };
}


function formatVaultDate(string $date): string
{
    try {

        return (
            new DateTimeImmutable($date)
        )->format('d M Y, h:i:s A');

    } catch (Throwable $exception) {

        return $date;
    }
}


/* ============================================================
   REQUEST VALIDATION
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {

    http_response_code(405);

    $errorMessage =
        'This SecureLog Vault operation requires a valid POST request.';

} else {

    /* --------------------------------------------------------
       CSRF VALIDATION
       -------------------------------------------------------- */

    $submittedToken =
        $_POST['csrf_token']
        ?? '';

    $sessionToken =
        $_SESSION['securelog_vault_csrf']
        ?? '';

    if (
        !is_string($submittedToken)
        || !is_string($sessionToken)
        || $submittedToken === ''
        || $sessionToken === ''
        || !hash_equals(
            $sessionToken,
            $submittedToken
        )
    ) {

        http_response_code(403);

        $errorMessage =
            'Invalid security token. Please return to the Vault and try again.';

    } else {

        /* ----------------------------------------------------
           ARCHIVE NAME VALIDATION
           ---------------------------------------------------- */

        $requestedArchive =
            $_POST['archive']
            ?? '';

        if (!is_string($requestedArchive)) {

            $errorMessage =
                'Invalid SecureLog archive request.';

        } else {

            /*
             * basename() prevents directory traversal such as:
             *
             * ../../keys/master.key
             */
            $safeFileName =
                basename($requestedArchive);

            /*
             * The supplied name must already equal its basename.
             */
            if (
                $safeFileName !== $requestedArchive
                || !preg_match(
                    '/^securelog_[A-Za-z0-9_-]+\.slog$/',
                    $safeFileName
                )
            ) {

                http_response_code(400);

                $errorMessage =
                    'Invalid SecureLog archive filename.';

            } else {

                $archivePath =
                    $vaultDirectory
                    . DIRECTORY_SEPARATOR
                    . $safeFileName;


                /* =================================================
                   ARCHIVE MUST EXIST
                   ================================================= */

                if (!is_file($archivePath)) {

                    http_response_code(404);

                    $errorMessage =
                        'The requested SecureLog archive was not found.';

                } else {

                    /*
                     * Resolve real filesystem paths.
                     */
                    $realVaultDirectory =
                        realpath($vaultDirectory);

                    $realArchivePath =
                        realpath($archivePath);


                    /* =============================================
                       PATH CONTAINMENT CHECK
                       ============================================= */

                    if (
                        $realVaultDirectory === false
                        || $realArchivePath === false
                        || dirname($realArchivePath)
                            !== $realVaultDirectory
                    ) {

                        http_response_code(403);

                        $errorMessage =
                            'SecureLog blocked an invalid archive path.';

                    } else {

                        /* =========================================
                           LOAD + VERIFY + DECRYPT
                           ========================================= */

                        try {

                            $rawArchive =
                                file_get_contents(
                                    $realArchivePath
                                );

                            if ($rawArchive === false) {
                                throw new RuntimeException(
                                    'Unable to read encrypted archive.'
                                );
                            }


                            /* -------------------------------------
                               DECODE ARCHIVE ENVELOPE
                               ------------------------------------- */

                            $archive =
                                json_decode(
                                    $rawArchive,
                                    true,
                                    512,
                                    JSON_THROW_ON_ERROR
                                );

                            if (!is_array($archive)) {
                                throw new RuntimeException(
                                    'Invalid SecureLog archive structure.'
                                );
                            }


                            /* -------------------------------------
                               AES-256-GCM VERIFICATION + DECRYPTION
                               ------------------------------------- */

                            $crypto =
                                new VaultCrypto();

                            /*
                             * decrypt() verifies the AES-GCM
                             * authentication tag before returning
                             * plaintext.
                             */
                            $plaintext =
                                $crypto->decrypt(
                                    $archive
                                );


                            /* -------------------------------------
                               ARCHIVE VERIFIED
                               ------------------------------------- */

                            $archiveInfo = [

                                'filename' =>
                                    $safeFileName,

                                'archive_id' =>
                                    (string) (
                                        $archive['archive_id']
                                        ?? 'Unknown'
                                    ),

                                'algorithm' =>
                                    (string) (
                                        $archive['algorithm']
                                        ?? 'Unknown'
                                    ),

                                'created_at' =>
                                    (string) (
                                        $archive['created_at']
                                        ?? ''
                                    ),

                                'status' =>
                                    'VERIFIED',

                            ];


                            /* -------------------------------------
                               PARSE JSON-LINES AUDIT EVENTS
                               ------------------------------------- */

                            $lines =
                                preg_split(
                                    '/\R/',
                                    $plaintext
                                );

                            if ($lines === false) {
                                $lines = [];
                            }

                            foreach ($lines as $line) {

                                $line = trim($line);

                                if ($line === '') {
                                    continue;
                                }

                                try {

                                    $event =
                                        json_decode(
                                            $line,
                                            true,
                                            512,
                                            JSON_THROW_ON_ERROR
                                        );

                                    if (!is_array($event)) {
                                        continue;
                                    }

                                    $events[] =
                                        $event;

                                } catch (Throwable $exception) {

                                    /*
                                     * Archive itself passed AES-GCM
                                     * authentication, but an individual
                                     * historic line may not be valid JSON.
                                     *
                                     * Do not expose raw unparsed content.
                                     */
                                    $events[] = [

                                        'timestamp' =>
                                            '',

                                        'event' =>
                                            'UNPARSED_RECORD',

                                        'severity' =>
                                            'WARNING',

                                        'result' =>
                                            'UNKNOWN',

                                        'description' =>
                                            'An authenticated archived record could not be parsed as structured JSON.',

                                        'actor' => [
                                            'user_id'  => null,
                                            'username' => '',
                                            'role'     => '',
                                        ],

                                    ];
                                }
                            }


                            $totalEvents =
                                count($events);


                            /* -------------------------------------
                               LOG AUTHORIZED VAULT VIEW
                               ------------------------------------- */

                            $currentAdminId =
                                isset($_SESSION['UserID'])
                                    ? (int) $_SESSION['UserID']
                                    : (
                                        isset($_SESSION['user_id'])
                                            ? (int) $_SESSION['user_id']
                                            : null
                                    );

                            /*
                             * Use the standardized event name even
                             * if the constant has not yet been added
                             * to ActivityLogger.php.
                             */
                            $viewEvent =
                                defined('LOG_VIEWED')
                                    ? constant('LOG_VIEWED')
                                    : 'LOG_VIEWED';

                            log_activity(
                                $viewEvent,
                                $currentAdminId,
                                'Administrator verified and viewed a sealed SecureLog audit archive.',
                                [
                                    'module' =>
                                        'SecureLogVault',

                                    'severity' =>
                                        'INFO',

                                    'result' =>
                                        'SUCCESS',

                                    'target_type' =>
                                        'LOG_ARCHIVE',

                                    'target_id' =>
                                        (string) (
                                            $archive['archive_id']
                                            ?? $safeFileName
                                        ),

                                    'metadata' => [

                                        'archive_filename' =>
                                            $safeFileName,

                                        'algorithm' =>
                                            (string) (
                                                $archive['algorithm']
                                                ?? 'Unknown'
                                            ),

                                        'event_count' =>
                                            $totalEvents,

                                    ],
                                ]
                            );


                        } catch (Throwable $exception) {

                            /* =====================================
                               CRYPTOGRAPHIC VERIFICATION FAILURE
                               ===================================== */

                            http_response_code(422);

                            $errorMessage =
                                'SecureLog could not verify this archive. '
                                . 'The encrypted archive may have been '
                                . 'modified, corrupted, or protected using '
                                . 'a different master key.';


                            /*
                             * Record integrity verification failure.
                             *
                             * Never log ciphertext, tag, IV or key.
                             */
                            $currentAdminId =
                                isset($_SESSION['UserID'])
                                    ? (int) $_SESSION['UserID']
                                    : (
                                        isset($_SESSION['user_id'])
                                            ? (int) $_SESSION['user_id']
                                            : null
                                    );

                            $integrityEvent =
                                defined(
                                    'LOG_INTEGRITY_CHECK_FAILED'
                                )
                                    ? constant(
                                        'LOG_INTEGRITY_CHECK_FAILED'
                                    )
                                    : 'INTEGRITY_CHECK_FAILED';

                            log_activity(
                                $integrityEvent,
                                $currentAdminId,
                                'SecureLog Vault archive integrity verification failed.',
                                [
                                    'module' =>
                                        'SecureLogVault',

                                    'severity' =>
                                        'CRITICAL',

                                    'result' =>
                                        'FAILURE',

                                    'target_type' =>
                                        'LOG_ARCHIVE',

                                    'target_id' =>
                                        $safeFileName,

                                    'metadata' => [

                                        'archive_filename' =>
                                            $safeFileName,

                                    ],
                                ]
                            );
                        }
                    }
                }
            }
        }
    }
}


/* ============================================================
   NEWEST EVENTS FIRST
   ============================================================ */

if (!empty($events)) {

    usort(
        $events,
        static function (
            array $first,
            array $second
        ): int {

            $firstTime =
                strtotime(
                    (string) (
                        $first['timestamp']
                        ?? ''
                    )
                );

            $secondTime =
                strtotime(
                    (string) (
                        $second['timestamp']
                        ?? ''
                    )
                );

            return ($secondTime ?: 0)
                <=> ($firstTime ?: 0);
        }
    );
}

?>
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    Verify Archive | SecureLog
</title>

<link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    background: #07111f;

    color: #e7edf5;

    font-family:
        Inter,
        Arial,
        sans-serif;
}

.page {

    max-width: 1450px;

    margin: 0 auto;

    padding: 38px;
}

.back {

    display: inline-flex;

    align-items: center;

    gap: 8px;

    color: #8da4bb;

    text-decoration: none;

    margin-bottom: 25px;
}

.back:hover {
    color: #ffffff;
}

.header {

    display: flex;

    justify-content: space-between;

    gap: 20px;

    margin-bottom: 25px;
}

.eyebrow {

    color: #22d3ee;

    text-transform: uppercase;

    letter-spacing: 1.5px;

    font-size: 12px;

    font-weight: 800;

    margin-bottom: 8px;
}

h1 {

    margin: 0 0 8px;

    font-size: 30px;
}

.subtitle {

    color: #8da1b8;

    margin: 0;

    line-height: 1.6;
}


/* ============================================================
   VERIFIED BANNER
   ============================================================ */

.verified {

    padding: 17px 20px;

    border-radius: 12px;

    background:
        rgba(34, 197, 94, 0.10);

    border:
        1px solid
        rgba(34, 197, 94, 0.30);

    color: #86efac;

    margin-bottom: 22px;

    line-height: 1.6;
}

.failed {

    padding: 20px;

    border-radius: 12px;

    background:
        rgba(239, 68, 68, 0.10);

    border:
        1px solid
        rgba(239, 68, 68, 0.30);

    color: #fca5a5;

    margin-bottom: 22px;

    line-height: 1.7;
}


/* ============================================================
   ARCHIVE SUMMARY
   ============================================================ */

.summary {

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 15px;

    margin-bottom: 25px;
}

.card {

    background: #0d1b2a;

    border:
        1px solid #20344a;

    border-radius: 13px;

    padding: 18px;
}

.label {

    color: #8296ad;

    font-size: 12px;

    margin-bottom: 7px;
}

.value {

    font-weight: 800;

    word-break: break-word;
}

.green {
    color: #86efac;
}


/* ============================================================
   TABLE
   ============================================================ */

.panel {

    background: #0d1b2a;

    border:
        1px solid #20344a;

    border-radius: 15px;

    overflow: hidden;
}

.panel-header {

    padding: 20px;

    display: flex;

    justify-content: space-between;

    border-bottom:
        1px solid #20344a;
}

.panel-header h2 {

    margin: 0;

    font-size: 18px;
}

.panel-header span {

    color: #8296ad;

    font-size: 13px;
}

.table-wrapper {

    overflow-x: auto;
}

table {

    width: 100%;

    min-width: 1100px;

    border-collapse: collapse;
}

th {

    background: #091522;

    color: #8296ad;

    text-align: left;

    text-transform: uppercase;

    letter-spacing: .5px;

    font-size: 11px;

    padding: 13px 15px;
}

td {

    padding: 15px;

    border-top:
        1px solid #172a3d;

    vertical-align: top;

    font-size: 13px;
}

tbody tr:hover {
    background: #102034;
}

.event-name {

    font-family:
        Consolas,
        monospace;

    font-weight: 700;

    color: #dce8f5;
}

.actor {

    color: #b8c8d8;
}

.description {

    color: #9fb1c4;

    line-height: 1.5;

    max-width: 360px;
}


/* ============================================================
   BADGES
   ============================================================ */

.badge {

    display: inline-block;

    padding: 5px 9px;

    border-radius: 999px;

    font-size: 10px;

    font-weight: 800;
}

.info {

    color: #67e8f9;

    background:
        rgba(34, 211, 238, .10);
}

.warning {

    color: #fbbf24;

    background:
        rgba(245, 158, 11, .10);
}

.error {

    color: #fca5a5;

    background:
        rgba(239, 68, 68, .10);
}

.critical {

    color: #f87171;

    background:
        rgba(220, 38, 38, .15);
}

.default {

    color: #cbd5e1;

    background:
        rgba(148, 163, 184, .10);
}

.result {

    font-weight: 700;
}


/* ============================================================
   SECURITY NOTE
   ============================================================ */

.security-note {

    margin-top: 18px;

    padding: 16px;

    border:
        1px solid
        rgba(34, 211, 238, .15);

    background:
        rgba(34, 211, 238, .05);

    color: #9fb2c7;

    border-radius: 10px;

    font-size: 13px;

    line-height: 1.6;
}


@media (max-width: 850px) {

    .page {
        padding: 22px;
    }

    .summary {
        grid-template-columns:
            repeat(2, 1fr);
    }
}

</style>

</head>

<body>

<div class="page">

<a
    class="back"
    href="vault.php"
>
    <i class="fa-solid fa-arrow-left"></i>
    Back to Secure Log Vault
</a>


<?php if ($errorMessage !== ''): ?>

    <div class="failed">

        <strong>
            <i class="fa-solid fa-triangle-exclamation"></i>
            Verification Failed
        </strong>

        <br><br>

        <?= decryptHtml(
            $errorMessage
        ) ?>

    </div>

<?php elseif (
    is_array($archiveInfo)
): ?>


    <div class="header">

        <div>

            <div class="eyebrow">
                SecureLog Vault
            </div>

            <h1>
                Verified Audit Archive
            </h1>

            <p class="subtitle">
                Authenticated audit events recovered from
                the encrypted SecureLog archive.
            </p>

        </div>

    </div>


    <div class="verified">

        <strong>
            <i class="fa-solid fa-shield-check"></i>
            Cryptographic verification successful.
        </strong>

        AES-256-GCM authentication passed before
        the audit events were decrypted and displayed.

    </div>


    <div class="summary">


        <div class="card">

            <div class="label">
                Archive ID
            </div>

            <div class="value">

                <?= decryptHtml(
                    $archiveInfo['archive_id']
                ) ?>

            </div>

        </div>


        <div class="card">

            <div class="label">
                Algorithm
            </div>

            <div class="value">

                <?= decryptHtml(
                    $archiveInfo['algorithm']
                ) ?>

            </div>

        </div>


        <div class="card">

            <div class="label">
                Integrity
            </div>

            <div class="value green">
                VERIFIED ✓
            </div>

        </div>


        <div class="card">

            <div class="label">
                Archived Events
            </div>

            <div class="value">
                <?= $totalEvents ?>
            </div>

        </div>


    </div>


    <div class="panel">


        <div class="panel-header">

            <h2>
                Decrypted Audit Events
            </h2>

            <span>
                Sealed:
                <?= decryptHtml(
                    formatVaultDate(
                        $archiveInfo['created_at']
                    )
                ) ?>
            </span>

        </div>


        <div class="table-wrapper">

            <table>

                <thead>

                <tr>

                    <th>
                        Timestamp
                    </th>

                    <th>
                        Event
                    </th>

                    <th>
                        Severity
                    </th>

                    <th>
                        Actor
                    </th>

                    <th>
                        Role
                    </th>

                    <th>
                        Result
                    </th>

                    <th>
                        Description
                    </th>

                </tr>

                </thead>


                <tbody>

                <?php foreach (
                    $events as $event
                ): ?>

                    <?php

                    $actor =
                        isset($event['actor'])
                        && is_array($event['actor'])
                            ? $event['actor']
                            : [];

                    $severity =
                        strtoupper(
                            (string) (
                                $event['severity']
                                ?? 'INFO'
                            )
                        );

                    ?>

                    <tr>


                        <td>

                            <?= decryptHtml(
                                (string) (
                                    $event['timestamp']
                                    ?? ''
                                )
                            ) ?>

                        </td>


                        <td>

                            <span class="event-name">

                                <?= decryptHtml(
                                    (string) (
                                        $event['event']
                                        ?? 'UNKNOWN'
                                    )
                                ) ?>

                            </span>

                        </td>


                        <td>

                            <span
                                class="badge
                                <?= severityClass(
                                    $severity
                                ) ?>"
                            >

                                <?= decryptHtml(
                                    $severity
                                ) ?>

                            </span>

                        </td>


                        <td class="actor">

                            <?= decryptHtml(
                                (string) (
                                    $actor['username']
                                    ?? 'Unknown'
                                )
                            ) ?>

                            <?php if (
                                isset($actor['user_id'])
                                && $actor['user_id'] !== null
                            ): ?>

                                <br>

                                <small>
                                    User #
                                    <?= (int)
                                        $actor['user_id']
                                    ?>
                                </small>

                            <?php endif; ?>

                        </td>


                        <td>

                            <?= decryptHtml(
                                (string) (
                                    $actor['role']
                                    ?? ''
                                )
                            ) ?>

                        </td>


                        <td>

                            <span class="result">

                                <?= decryptHtml(
                                    (string) (
                                        $event['result']
                                        ?? ''
                                    )
                                ) ?>

                            </span>

                        </td>


                        <td class="description">

                            <?= decryptHtml(
                                (string) (
                                    $event['description']
                                    ?? ''
                                )
                            ) ?>

                        </td>


                    </tr>

                <?php endforeach; ?>

                </tbody>

            </table>

        </div>

    </div>


    <div class="security-note">

        <i class="fa-solid fa-lock"></i>

        The plaintext shown above exists only after successful
        server-side AES-256-GCM authentication and decryption.
        The SecureLog master encryption key is not exposed
        to the administrator interface.

    </div>


<?php endif; ?>

</div>

</body>

</html>