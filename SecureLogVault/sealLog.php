<?php
declare(strict_types=1);

/**
 * SecureLog Vault - Seal Audit Log
 *
 * Creates an encrypted snapshot of the current active audit log
 * using AES-256-GCM.
 *
 * IMPORTANT:
 * - The active audit log is NOT deleted or cleared.
 * - A .slog archive is only finalized after verification succeeds.
 * - Admin authentication is required.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}


/* ============================================================
   CRYPTOGRAPHY
   ============================================================ */

require_once __DIR__ . '/VaultCrypto.php';


/* ============================================================
   PATH CONFIGURATION
   ============================================================ */

/*
 * Active readable audit log.
 */
$activeLogFile =
    __DIR__
    . '/../Dashboard/logs/securelog_audit.txt';

/*
 * Encrypted SecureLog Vault directory.
 */
$vaultDirectory =
    __DIR__
    . '/encrypted_logs';


/* ============================================================
   CSRF TOKEN
   ============================================================ */

if (
    empty($_SESSION['securelog_vault_csrf'])
    || !is_string($_SESSION['securelog_vault_csrf'])
) {
    $_SESSION['securelog_vault_csrf'] =
        bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['securelog_vault_csrf'];


/* ============================================================
   PAGE STATE
   ============================================================ */

$successMessage = '';
$errorMessage   = '';
$archiveInfo    = null;


/* ============================================================
   HELPER
   ============================================================ */

function vaultEscape(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}


/**
 * Read the active audit log while obtaining a shared lock.
 *
 * ActivityLogger uses an exclusive lock when writing.
 * This reduces the possibility of taking a snapshot while
 * another process is in the middle of appending an event.
 */
function readLockedAuditLog(string $filePath): string
{
    if (!is_file($filePath)) {
        throw new RuntimeException(
            'Active SecureLog audit log was not found.'
        );
    }

    $handle = fopen($filePath, 'rb');

    if ($handle === false) {
        throw new RuntimeException(
            'Unable to open the active audit log.'
        );
    }

    try {

        if (!flock($handle, LOCK_SH)) {
            throw new RuntimeException(
                'Unable to obtain a read lock on the active audit log.'
            );
        }

        $contents = stream_get_contents($handle);

        flock($handle, LOCK_UN);

        if ($contents === false) {
            throw new RuntimeException(
                'Unable to read the active audit log.'
            );
        }

        if (trim($contents) === '') {
            throw new RuntimeException(
                'The active audit log is empty. Nothing can be sealed.'
            );
        }

        return $contents;

    } finally {

        /*
         * Ensure the file handle is always closed.
         */
        fclose($handle);
    }
}


/* ============================================================
   SEAL REQUEST
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    try {

        /* --------------------------------------------------------
           1. CSRF VALIDATION
           -------------------------------------------------------- */

        $submittedToken =
            $_POST['csrf_token']
            ?? '';

        if (
            !is_string($submittedToken)
            || !hash_equals(
                $_SESSION['securelog_vault_csrf'],
                $submittedToken
            )
        ) {
            throw new RuntimeException(
                'Invalid security token. Please refresh the page and try again.'
            );
        }


        /* --------------------------------------------------------
           2. ENSURE MASTER KEY EXISTS
           -------------------------------------------------------- */

        $crypto = new VaultCrypto();

        if (!$crypto->keyExists()) {
            throw new RuntimeException(
                'SecureLog Vault master key is not available.'
            );
        }


        /* --------------------------------------------------------
           3. READ ACTIVE LOG SNAPSHOT
           -------------------------------------------------------- */

        $plaintextLog =
            readLockedAuditLog($activeLogFile);

        $originalBytes =
            strlen($plaintextLog);


        /* --------------------------------------------------------
           4. ENCRYPT USING AES-256-GCM
           -------------------------------------------------------- */

        $encryptedArchive =
            $crypto->encrypt($plaintextLog);


        /* --------------------------------------------------------
           5. CREATE VAULT DIRECTORY IF REQUIRED
           -------------------------------------------------------- */

        if (!is_dir($vaultDirectory)) {

            $created = mkdir(
                $vaultDirectory,
                0750,
                true
            );

            if (
                !$created
                && !is_dir($vaultDirectory)
            ) {
                throw new RuntimeException(
                    'Unable to create SecureLog encrypted archive directory.'
                );
            }
        }


        /* --------------------------------------------------------
           6. GENERATE SAFE ARCHIVE FILE NAME
           -------------------------------------------------------- */

        $archiveId =
            (string) $encryptedArchive['archive_id'];

        /*
         * Only allow safe filename characters.
         */
        $safeArchiveId =
            preg_replace(
                '/[^A-Za-z0-9_-]/',
                '',
                $archiveId
            );

        if (
            $safeArchiveId === null
            || $safeArchiveId === ''
        ) {
            throw new RuntimeException(
                'Unable to generate a valid SecureLog archive filename.'
            );
        }

        $timestamp =
            (new DateTimeImmutable(
                'now',
                new DateTimeZone('Asia/Kuala_Lumpur')
            ))->format('Ymd_His');

        $archiveFileName =
            'securelog_'
            . $timestamp
            . '_'
            . $safeArchiveId
            . '.slog';

        $archivePath =
            $vaultDirectory
            . DIRECTORY_SEPARATOR
            . $archiveFileName;


        /* --------------------------------------------------------
           7. PREVENT ACCIDENTAL OVERWRITE
           -------------------------------------------------------- */

        if (file_exists($archivePath)) {
            throw new RuntimeException(
                'A SecureLog archive with this identifier already exists.'
            );
        }


        /* --------------------------------------------------------
           8. ENCODE VAULT ENVELOPE
           -------------------------------------------------------- */

        $archiveJson =
            json_encode(
                $encryptedArchive,
                JSON_PRETTY_PRINT
                | JSON_UNESCAPED_SLASHES
                | JSON_THROW_ON_ERROR
            );


        /* --------------------------------------------------------
           9. WRITE TO TEMPORARY FILE FIRST
           -------------------------------------------------------- */

        $temporaryPath =
            $archivePath
            . '.tmp';

        $written =
            file_put_contents(
                $temporaryPath,
                $archiveJson,
                LOCK_EX
            );

        if ($written === false) {
            throw new RuntimeException(
                'Unable to write temporary encrypted SecureLog archive.'
            );
        }

        /*
         * Best-effort restrictive permission.
         */
        @chmod(
            $temporaryPath,
            0600
        );


        /* --------------------------------------------------------
           10. READ TEMP FILE BACK
           -------------------------------------------------------- */

        $storedJson =
            file_get_contents(
                $temporaryPath
            );

        if ($storedJson === false) {

            @unlink($temporaryPath);

            throw new RuntimeException(
                'Unable to read the encrypted archive for verification.'
            );
        }

        $storedArchive =
            json_decode(
                $storedJson,
                true,
                512,
                JSON_THROW_ON_ERROR
            );

        if (!is_array($storedArchive)) {

            @unlink($temporaryPath);

            throw new RuntimeException(
                'Encrypted archive contains an invalid structure.'
            );
        }


        /* --------------------------------------------------------
           11. AUTHENTICATE + DECRYPT TEMP ARCHIVE
           -------------------------------------------------------- */

        /*
         * AES-GCM authentication is performed inside decrypt().
         *
         * If ciphertext, IV, authentication tag or authenticated
         * metadata has changed, decrypt() throws an exception.
         */
        $verificationPlaintext =
            $crypto->decrypt(
                $storedArchive
            );


        /* --------------------------------------------------------
           12. COMPARE ORIGINAL SNAPSHOT
           -------------------------------------------------------- */

        if (
            !hash_equals(
                $plaintextLog,
                $verificationPlaintext
            )
        ) {

            @unlink($temporaryPath);

            throw new RuntimeException(
                'SecureLog archive verification failed because '
                . 'the decrypted data does not match the original audit log.'
            );
        }


        /* --------------------------------------------------------
           13. FINALIZE ARCHIVE
           -------------------------------------------------------- */

        /*
         * Rename only after encryption + authentication +
         * decryption verification have all succeeded.
         */
        $renamed =
            rename(
                $temporaryPath,
                $archivePath
            );

        if (!$renamed) {

            @unlink($temporaryPath);

            throw new RuntimeException(
                'Unable to finalize the SecureLog encrypted archive.'
            );
        }

        @chmod(
            $archivePath,
            0600
        );


        /* --------------------------------------------------------
           14. SUCCESS
           -------------------------------------------------------- */

        $archiveInfo = [
            'filename'   => $archiveFileName,
            'archive_id' => $archiveId,
            'algorithm'  =>
                (string) $encryptedArchive['algorithm'],
            'created_at' =>
                (string) $encryptedArchive['created_at'],
            'bytes'      => $originalBytes,
        ];

        $successMessage =
            'Audit log sealed successfully. '
            . 'The original active log remains unchanged.';


        /*
         * Rotate CSRF token after successful sensitive operation.
         */
        $_SESSION['securelog_vault_csrf'] =
            bin2hex(random_bytes(32));

        $csrfToken =
            $_SESSION['securelog_vault_csrf'];


    } catch (Throwable $exception) {

        /*
         * Never expose cryptographic internals or key material.
         *
         * The exception messages generated by our own Vault classes
         * are safe enough for this local FYP administration page.
         */
        $errorMessage =
            $exception->getMessage();
    }
}


/* ============================================================
   SAFE STATUS INFORMATION
   ============================================================ */

$cryptoStatus = [];

try {

    $statusCrypto =
        new VaultCrypto();

    $cryptoStatus =
        $statusCrypto->getKeyStatus();

} catch (Throwable $exception) {

    $cryptoStatus = [
        'initialized' => false,
        'algorithm'   => 'AES-256-GCM',
        'key_bits'    => 256,
    ];
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

    <title>Seal Audit Log | SecureLog</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;

            font-family:
                Inter,
                Arial,
                sans-serif;

            background:
                #07111f;

            color:
                #e8eef7;

            display: flex;
            align-items: center;
            justify-content: center;

            padding: 30px;
        }

        .vault-card {

            width: 100%;
            max-width: 760px;

            background:
                #0d1b2a;

            border:
                1px solid #22354b;

            border-radius:
                18px;

            padding:
                32px;

            box-shadow:
                0 20px 60px
                rgba(0, 0, 0, 0.35);
        }

        .vault-label {

            color:
                #22d3ee;

            font-size:
                13px;

            font-weight:
                700;

            letter-spacing:
                1.5px;

            text-transform:
                uppercase;

            margin-bottom:
                8px;
        }

        h1 {

            margin:
                0 0 10px;

            font-size:
                30px;
        }

        .description {

            margin:
                0 0 28px;

            color:
                #9fb0c5;

            line-height:
                1.7;
        }

        .status-grid {

            display:
                grid;

            grid-template-columns:
                repeat(3, 1fr);

            gap:
                12px;

            margin-bottom:
                25px;
        }

        .status-box {

            background:
                #091522;

            border:
                1px solid #203247;

            border-radius:
                12px;

            padding:
                16px;
        }

        .status-title {

            color:
                #8194aa;

            font-size:
                12px;

            margin-bottom:
                7px;
        }

        .status-value {

            font-weight:
                700;

            color:
                #ffffff;
        }

        .success {

            background:
                rgba(34, 197, 94, 0.10);

            border:
                1px solid rgba(34, 197, 94, 0.35);

            color:
                #86efac;

            padding:
                15px;

            border-radius:
                10px;

            margin-bottom:
                20px;

            line-height:
                1.5;
        }

        .error {

            background:
                rgba(239, 68, 68, 0.10);

            border:
                1px solid rgba(239, 68, 68, 0.35);

            color:
                #fca5a5;

            padding:
                15px;

            border-radius:
                10px;

            margin-bottom:
                20px;

            line-height:
                1.5;
        }

        .archive-info {

            background:
                #091522;

            border:
                1px solid #28405a;

            border-radius:
                12px;

            padding:
                18px;

            margin-bottom:
                22px;
        }

        .archive-row {

            display:
                flex;

            justify-content:
                space-between;

            gap:
                20px;

            padding:
                8px 0;

            border-bottom:
                1px solid #182a3d;
        }

        .archive-row:last-child {

            border-bottom:
                none;
        }

        .archive-row span:first-child {

            color:
                #8194aa;
        }

        .archive-row span:last-child {

            text-align:
                right;

            word-break:
                break-all;
        }

        .warning {

            color:
                #fbbf24;

            font-size:
                14px;

            line-height:
                1.6;

            margin:
                20px 0;
        }

        button {

            width:
                100%;

            border:
                none;

            border-radius:
                10px;

            padding:
                15px 20px;

            font-size:
                15px;

            font-weight:
                700;

            cursor:
                pointer;

            background:
                #f59e0b;

            color:
                #08111d;
        }

        button:hover {

            background:
                #fbbf24;
        }

        button:disabled {

            opacity:
                0.5;

            cursor:
                not-allowed;
        }

        .small-note {

            color:
                #72859b;

            font-size:
                12px;

            margin-top:
                14px;

            text-align:
                center;

            line-height:
                1.5;
        }

        @media (
            max-width: 650px
        ) {

            .status-grid {

                grid-template-columns:
                    1fr;
            }

            .archive-row {

                flex-direction:
                    column;

                gap:
                    4px;
            }

            .archive-row span:last-child {

                text-align:
                    left;
            }
        }

    </style>

</head>

<body>

<div class="vault-card">

    <div class="vault-label">
        Secure Log Vault
    </div>

    <h1>
        Seal Audit Log
    </h1>

    <p class="description">
        Create an authenticated encrypted snapshot of the
        current SecureLog audit trail using AES-256-GCM.
        The active audit log will remain unchanged during
        this testing stage.
    </p>


    <div class="status-grid">

        <div class="status-box">

            <div class="status-title">
                Encryption
            </div>

            <div class="status-value">
                <?= vaultEscape(
                    (string) (
                        $cryptoStatus['algorithm']
                        ?? 'AES-256-GCM'
                    )
                ) ?>
            </div>

        </div>


        <div class="status-box">

            <div class="status-title">
                Key Size
            </div>

            <div class="status-value">
                <?= (int) (
                    $cryptoStatus['key_bits']
                    ?? 256
                ) ?> bits
            </div>

        </div>


        <div class="status-box">

            <div class="status-title">
                Master Key
            </div>

            <div class="status-value">

                <?php if (
                    !empty(
                        $cryptoStatus['initialized']
                    )
                ): ?>

                    Ready ✓

                <?php else: ?>

                    Missing ✕

                <?php endif; ?>

            </div>

        </div>

    </div>


    <?php if ($successMessage !== ''): ?>

        <div class="success">
            ✓ <?= vaultEscape(
                $successMessage
            ) ?>
        </div>

    <?php endif; ?>


    <?php if ($errorMessage !== ''): ?>

        <div class="error">
            ✕ <?= vaultEscape(
                $errorMessage
            ) ?>
        </div>

    <?php endif; ?>


    <?php if (
        is_array($archiveInfo)
    ): ?>

        <div class="archive-info">

            <div class="archive-row">

                <span>
                    Archive
                </span>

                <span>
                    <?= vaultEscape(
                        $archiveInfo['filename']
                    ) ?>
                </span>

            </div>


            <div class="archive-row">

                <span>
                    Archive ID
                </span>

                <span>
                    <?= vaultEscape(
                        $archiveInfo['archive_id']
                    ) ?>
                </span>

            </div>


            <div class="archive-row">

                <span>
                    Algorithm
                </span>

                <span>
                    <?= vaultEscape(
                        $archiveInfo['algorithm']
                    ) ?>
                </span>

            </div>


            <div class="archive-row">

                <span>
                    Created
                </span>

                <span>
                    <?= vaultEscape(
                        $archiveInfo['created_at']
                    ) ?>
                </span>

            </div>


            <div class="archive-row">

                <span>
                    Protected Data
                </span>

                <span>
                    <?= number_format(
                        (int) $archiveInfo['bytes']
                    ) ?> bytes
                </span>

            </div>

        </div>

    <?php endif; ?>


    <div class="warning">

        ⚠ During this stage, sealing creates an encrypted
        snapshot only. The active
        <strong>securelog_audit.txt</strong>
        file will NOT be deleted or cleared.

    </div>


    <form
        method="POST"
        action=""
    >

        <input
            type="hidden"
            name="csrf_token"
            value="<?= vaultEscape(
                $csrfToken
            ) ?>"
        >

        <button
            type="submit"
            <?= empty(
                $cryptoStatus['initialized']
            )
                ? 'disabled'
                : ''
            ?>
        >
            🔐 Seal Current Audit Log
        </button>

    </form>


    <div class="small-note">

        SecureLog will encrypt the current audit-log snapshot,
        verify the generated archive, and only then finalize
        the .slog file.

    </div>

</div>

</body>

</html>