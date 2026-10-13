<?php
declare(strict_types=1);

/**
 * SecureLog - Secure Log Vault
 *
 * Displays encrypted .slog archives stored by SecureLog.
 *
 * IMPORTANT:
 * - Admin only.
 * - Does NOT expose the master key.
 * - Does NOT decrypt archives on this page.
 * - Ciphertext is not displayed.
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
   VAULT CRYPTO
   ============================================================ */

require_once __DIR__ . '/VaultCrypto.php';
    if (
        empty($_SESSION['securelog_vault_csrf'])
        || !is_string($_SESSION['securelog_vault_csrf'])
    ) {
        $_SESSION['securelog_vault_csrf'] =
            bin2hex(random_bytes(32));
    }


/* ============================================================
   CONFIGURATION
   ============================================================ */

$vaultDirectory =
    __DIR__
    . DIRECTORY_SEPARATOR
    . 'encrypted_logs';


/* ============================================================
   HELPERS
   ============================================================ */

function vaultHtml(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}


function vaultFormatDate(string $date): string
{
    if ($date === '') {
        return 'Unknown';
    }

    try {

        $dateTime =
            new DateTimeImmutable($date);

        return $dateTime->format(
            'd M Y, h:i:s A'
        );

    } catch (Throwable $exception) {

        return 'Invalid date';
    }
}


function vaultFormatBytes(int $bytes): string
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }

    if ($bytes < 1024 * 1024) {
        return number_format(
            $bytes / 1024,
            2
        ) . ' KB';
    }

    return number_format(
        $bytes / (1024 * 1024),
        2
    ) . ' MB';
}


/* ============================================================
   READ VAULT ARCHIVES
   ============================================================ */

$archives = [];

if (is_dir($vaultDirectory)) {

    $files =
        glob(
            $vaultDirectory
            . DIRECTORY_SEPARATOR
            . '*.slog'
        );

    if ($files !== false) {

        foreach ($files as $filePath) {

            /*
             * Safety:
             * Only work with real files.
             */
            if (!is_file($filePath)) {
                continue;
            }

            $fileName =
                basename($filePath);

            $fileSize =
                filesize($filePath);

            if ($fileSize === false) {
                $fileSize = 0;
            }


            /* ----------------------------------------------------
               READ ARCHIVE ENVELOPE
               ---------------------------------------------------- */

            $rawArchive =
                file_get_contents($filePath);

            if ($rawArchive === false) {

                $archives[] = [
                    'filename'   => $fileName,
                    'archive_id' => 'Unknown',
                    'algorithm'  => 'Unknown',
                    'created_at' => '',
                    'size'       => $fileSize,
                    'status'     => 'UNREADABLE',
                ];

                continue;
            }


            /* ----------------------------------------------------
               PARSE JSON
               ---------------------------------------------------- */

            try {

                $archive =
                    json_decode(
                        $rawArchive,
                        true,
                        512,
                        JSON_THROW_ON_ERROR
                    );

                if (!is_array($archive)) {
                    throw new RuntimeException(
                        'Invalid archive structure.'
                    );
                }


                /*
                 * We intentionally read only safe archive metadata.
                 *
                 * Ciphertext, IV and authentication tag are NOT
                 * displayed on the Vault listing page.
                 */
                $archives[] = [

                    'filename' =>
                        $fileName,

                    'archive_id' =>
                        isset($archive['archive_id'])
                            ? (string) $archive['archive_id']
                            : 'Unknown',

                    'algorithm' =>
                        isset($archive['algorithm'])
                            ? (string) $archive['algorithm']
                            : 'Unknown',

                    'created_at' =>
                        isset($archive['created_at'])
                            ? (string) $archive['created_at']
                            : '',

                    'size' =>
                        $fileSize,

                    /*
                     * At this stage "SEALED" means the archive
                     * structure can be read.
                     *
                     * Cryptographic verification is performed
                     * separately in Step 4.5.
                     */
                    'status' =>
                        'SEALED',
                ];

            } catch (Throwable $exception) {

                /*
                 * A corrupted/non-JSON file must not crash
                 * the entire Vault.
                 */
                $archives[] = [

                    'filename' =>
                        $fileName,

                    'archive_id' =>
                        'Unknown',

                    'algorithm' =>
                        'Unknown',

                    'created_at' =>
                        '',

                    'size' =>
                        $fileSize,

                    'status' =>
                        'INVALID',

                ];
            }
        }
    }
}


/* ============================================================
   SORT NEWEST FIRST
   ============================================================ */

usort(
    $archives,
    static function (
        array $first,
        array $second
    ): int {

        $firstTime =
            strtotime(
                (string) (
                    $first['created_at']
                    ?? ''
                )
            );

        $secondTime =
            strtotime(
                (string) (
                    $second['created_at']
                    ?? ''
                )
            );

        return ($secondTime ?: 0)
            <=> ($firstTime ?: 0);
    }
);


/* ============================================================
   SUMMARY
   ============================================================ */

$totalArchives =
    count($archives);

$sealedArchives = 0;
$invalidArchives = 0;

foreach ($archives as $archive) {

    if (
        ($archive['status'] ?? '')
        === 'SEALED'
    ) {
        $sealedArchives++;
    } else {
        $invalidArchives++;
    }
}


/* ============================================================
   CRYPTO STATUS
   ============================================================ */

$keyReady = false;

try {

    $crypto =
        new VaultCrypto();

    $keyReady =
        $crypto->keyExists();

} catch (Throwable $exception) {

    $keyReady = false;
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
        Secure Log Vault | SecureLog
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

            font-family:
                Inter,
                Arial,
                sans-serif;

            background:
                #07111f;

            color:
                #e7edf5;
        }


        .vault-page {

            padding:
                38px;

            max-width:
                1450px;

            margin:
                0 auto;
        }


        /* ======================================================
           HEADER
           ====================================================== */

        .vault-header {

            display:
                flex;

            justify-content:
                space-between;

            align-items:
                center;

            gap:
                20px;

            margin-bottom:
                30px;
        }


        .eyebrow {

            color:
                #22d3ee;

            text-transform:
                uppercase;

            letter-spacing:
                1.5px;

            font-size:
                12px;

            font-weight:
                800;

            margin-bottom:
                7px;
        }


        .vault-header h1 {

            margin:
                0 0 7px;

            font-size:
                31px;
        }


        .vault-header p {

            margin:
                0;

            color:
                #8da1b8;

            line-height:
                1.6;
        }


        .seal-button {

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            gap:
                9px;

            text-decoration:
                none;

            background:
                #f59e0b;

            color:
                #07111f;

            font-weight:
                800;

            padding:
                13px 19px;

            border-radius:
                10px;

            white-space:
                nowrap;
        }


        .seal-button:hover {

            background:
                #fbbf24;
        }


        /* ======================================================
           SUMMARY CARDS
           ====================================================== */

        .summary-grid {

            display:
                grid;

            grid-template-columns:
                repeat(4, 1fr);

            gap:
                16px;

            margin-bottom:
                27px;
        }


        .summary-card {

            background:
                #0d1b2a;

            border:
                1px solid #20344a;

            border-radius:
                14px;

            padding:
                20px;
        }


        .summary-card .icon {

            width:
                40px;

            height:
                40px;

            display:
                flex;

            align-items:
                center;

            justify-content:
                center;

            border-radius:
                10px;

            background:
                #12283c;

            color:
                #22d3ee;

            margin-bottom:
                14px;
        }


        .summary-label {

            color:
                #8296ad;

            font-size:
                13px;

            margin-bottom:
                7px;
        }


        .summary-value {

            font-size:
                25px;

            font-weight:
                800;
        }


        .ready {

            color:
                #86efac;
        }


        .not-ready {

            color:
                #fca5a5;
        }


        /* ======================================================
           VAULT PANEL
           ====================================================== */

        .vault-panel {

            background:
                #0d1b2a;

            border:
                1px solid #20344a;

            border-radius:
                15px;

            overflow:
                hidden;
        }


        .panel-header {

            display:
                flex;

            align-items:
                center;

            justify-content:
                space-between;

            padding:
                20px 22px;

            border-bottom:
                1px solid #20344a;
        }


        .panel-header h2 {

            margin:
                0;

            font-size:
                18px;
        }


        .panel-header span {

            color:
                #8195ac;

            font-size:
                13px;
        }


        /* ======================================================
           TABLE
           ====================================================== */

        .table-wrapper {

            overflow-x:
                auto;
        }


        table {

            width:
                100%;

            border-collapse:
                collapse;

            min-width:
                980px;
        }


        th {

            text-align:
                left;

            padding:
                14px 18px;

            background:
                #091522;

            color:
                #8296ad;

            font-size:
                12px;

            text-transform:
                uppercase;

            letter-spacing:
                0.5px;
        }


        td {

            padding:
                17px 18px;

            border-top:
                1px solid #172a3d;

            vertical-align:
                middle;

            font-size:
                14px;
        }


        tbody tr:hover {

            background:
                #102034;
        }


        .archive-name {

            display:
                flex;

            align-items:
                center;

            gap:
                10px;

            font-weight:
                700;
        }


        .archive-name i {

            color:
                #f59e0b;
        }


        .archive-id {

            font-family:
                Consolas,
                monospace;

            color:
                #9eb1c6;

            font-size:
                12px;
        }


        /* ======================================================
           BADGES
           ====================================================== */

        .badge {

            display:
                inline-flex;

            align-items:
                center;

            gap:
                6px;

            border-radius:
                999px;

            padding:
                6px 10px;

            font-size:
                11px;

            font-weight:
                800;
        }


        .badge-sealed {

            background:
                rgba(
                    34,
                    197,
                    94,
                    0.12
                );

            color:
                #86efac;

            border:
                1px solid
                rgba(
                    34,
                    197,
                    94,
                    0.25
                );
        }


        .badge-invalid {

            background:
                rgba(
                    239,
                    68,
                    68,
                    0.12
                );

            color:
                #fca5a5;

            border:
                1px solid
                rgba(
                    239,
                    68,
                    68,
                    0.25
                );
        }


        .algorithm {

            color:
                #67e8f9;

            font-weight:
                700;
        }


        /* ======================================================
           ACTION
           ====================================================== */

        .verify-button {

            display:
                inline-flex;

            align-items:
                center;

            gap:
                7px;

            background:
                #15273a;

            border:
                1px solid #29435e;

            color:
                #dce8f5;

            border-radius:
                8px;

            padding:
                8px 11px;

            font-size:
                12px;

            cursor:
                not-allowed;

            opacity:
                0.65;
        }
        .active-verify {
                cursor: pointer;
                opacity: 1;
            }

            .active-verify:hover {
                background: #1d3851;
                border-color: #22d3ee;
                color: #ffffff;
            }


        /* ======================================================
           EMPTY STATE
           ====================================================== */

        .empty-state {

            padding:
                60px 20px;

            text-align:
                center;
        }


        .empty-state i {

            font-size:
                42px;

            color:
                #39536d;

            margin-bottom:
                17px;
        }


        .empty-state h3 {

            margin:
                0 0 8px;
        }


        .empty-state p {

            margin:
                0;

            color:
                #8195ac;
        }


        .security-note {

            margin-top:
                18px;

            padding:
                15px 18px;

            background:
                rgba(
                    34,
                    211,
                    238,
                    0.05
                );

            border:
                1px solid
                rgba(
                    34,
                    211,
                    238,
                    0.15
                );

            border-radius:
                10px;

            color:
                #9db1c7;

            font-size:
                13px;

            line-height:
                1.6;
        }


        @media (
            max-width: 900px
        ) {

            .vault-page {

                padding:
                    22px;
            }

            .vault-header {

                flex-direction:
                    column;

                align-items:
                    flex-start;
            }

            .summary-grid {

                grid-template-columns:
                    repeat(2, 1fr);
            }
        }


        @media (
            max-width: 520px
        ) {

            .summary-grid {

                grid-template-columns:
                    1fr;
            }
        }

    </style>

</head>


<body>

<div class="vault-page">


    <!-- ======================================================
         HEADER
         ====================================================== -->

    <div class="vault-header">

        <div>

            <div class="eyebrow">
                SecureLog Protection
            </div>

            <h1>
                <i class="fa-solid fa-vault"></i>
                Secure Log Vault
            </h1>

            <p>
                Protected AES-256-GCM audit log archives.
            </p>

        </div>


        <a
            class="seal-button"
            href="sealLog.php"
        >

            <i class="fa-solid fa-lock"></i>

            Seal Current Log

        </a>

    </div>



    <!-- ======================================================
         SUMMARY
         ====================================================== -->

    <div class="summary-grid">


        <div class="summary-card">

            <div class="icon">
                <i class="fa-solid fa-box-archive"></i>
            </div>

            <div class="summary-label">
                Total Archives
            </div>

            <div class="summary-value">
                <?= $totalArchives ?>
            </div>

        </div>



        <div class="summary-card">

            <div class="icon">
                <i class="fa-solid fa-lock"></i>
            </div>

            <div class="summary-label">
                Sealed Archives
            </div>

            <div class="summary-value">
                <?= $sealedArchives ?>
            </div>

        </div>



        <div class="summary-card">

            <div class="icon">
                <i class="fa-solid fa-triangle-exclamation"></i>
            </div>

            <div class="summary-label">
                Invalid Structure
            </div>

            <div class="summary-value">
                <?= $invalidArchives ?>
            </div>

        </div>



        <div class="summary-card">

            <div class="icon">
                <i class="fa-solid fa-key"></i>
            </div>

            <div class="summary-label">
                Vault Key
            </div>

            <div
                class="summary-value
                <?= $keyReady
                    ? 'ready'
                    : 'not-ready'
                ?>"
                style="font-size:18px;"
            >

                <?= $keyReady
                    ? 'READY'
                    : 'NOT READY'
                ?>

            </div>

        </div>

    </div>



    <!-- ======================================================
         ARCHIVE TABLE
         ====================================================== -->

    <div class="vault-panel">


        <div class="panel-header">

            <h2>
                Encrypted Archives
            </h2>

            <span>
                <?= $totalArchives ?>
                archive<?= $totalArchives === 1 ? '' : 's' ?>
            </span>

        </div>


        <?php if (
            empty($archives)
        ): ?>


            <div class="empty-state">

                <i class="fa-solid fa-box-open"></i>

                <h3>
                    No encrypted archives
                </h3>

                <p>
                    Seal the current audit log to create
                    your first protected archive.
                </p>

            </div>


        <?php else: ?>


            <div class="table-wrapper">

                <table>

                    <thead>

                    <tr>

                        <th>
                            Archive
                        </th>

                        <th>
                            Archive ID
                        </th>

                        <th>
                            Algorithm
                        </th>

                        <th>
                            Sealed At
                        </th>

                        <th>
                            Size
                        </th>

                        <th>
                            Status
                        </th>

                        <th>
                            Action
                        </th>

                    </tr>

                    </thead>


                    <tbody>

                    <?php foreach (
                        $archives as $archive
                    ): ?>

                        <?php

                        $archiveStatus =
                            (string) (
                                $archive['status']
                                ?? 'INVALID'
                            );

                        ?>

                        <tr>


                            <td>

                                <div class="archive-name">

                                    <i class="fa-solid fa-file-shield"></i>

                                    <?= vaultHtml(
                                        (string) $archive['filename']
                                    ) ?>

                                </div>

                            </td>


                            <td>

                                <span class="archive-id">

                                    <?= vaultHtml(
                                        (string) $archive['archive_id']
                                    ) ?>

                                </span>

                            </td>


                            <td>

                                <span class="algorithm">

                                    <?= vaultHtml(
                                        (string) $archive['algorithm']
                                    ) ?>

                                </span>

                            </td>


                            <td>

                                <?= vaultHtml(
                                    vaultFormatDate(
                                        (string) $archive['created_at']
                                    )
                                ) ?>

                            </td>


                            <td>

                                <?= vaultHtml(
                                    vaultFormatBytes(
                                        (int) $archive['size']
                                    )
                                ) ?>

                            </td>


                            <td>

                                <?php if (
                                    $archiveStatus === 'SEALED'
                                ): ?>

                                    <span
                                        class="badge badge-sealed"
                                    >

                                        <i class="fa-solid fa-lock"></i>

                                        SEALED

                                    </span>

                                <?php else: ?>

                                    <span
                                        class="badge badge-invalid"
                                    >

                                        <i class="fa-solid fa-circle-exclamation"></i>

                                        <?= vaultHtml(
                                            $archiveStatus
                                        ) ?>

                                    </span>

                                <?php endif; ?>

                            </td>


                            <td>

                                <?php if (
                                    $archiveStatus === 'SEALED'
                                ): ?>

                                    <!--
                                        Activated in Step 4.5.
                                    -->

                                    <form
                                        method="POST"
                                        action="decryptLog.php"
                                        style="margin:0;"
                                    >

                                        <input
                                            type="hidden"
                                            name="csrf_token"
                                            value="<?= vaultHtml(
                                                $_SESSION['securelog_vault_csrf']
                                                ?? ''
                                            ) ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="archive"
                                            value="<?= vaultHtml(
                                                (string) $archive['filename']
                                            ) ?>"
                                        >

                                        <button
                                            class="verify-button active-verify"
                                            type="submit"
                                        >

                                            <i class="fa-solid fa-shield-halved"></i>

                                            Verify & View

                                        </button>

                                    </form>

                                <?php else: ?>

                                    <span
                                        style="
                                            color:#fca5a5;
                                            font-size:12px;
                                        "
                                    >

                                        Cannot open

                                    </span>

                                <?php endif; ?>

                            </td>


                        </tr>

                    <?php endforeach; ?>

                    </tbody>

                </table>

            </div>


        <?php endif; ?>


    </div>



    <div class="security-note">

        <i class="fa-solid fa-circle-info"></i>

        <strong>Vault security:</strong>

        This page displays only non-sensitive archive metadata.
        Ciphertext and cryptographic key material are not exposed.
        A <strong>SEALED</strong> status currently indicates that
        the archive envelope is structurally readable; cryptographic
        authenticity will be checked before decryption in the next
        stage.

    </div>


</div>

</body>

</html>