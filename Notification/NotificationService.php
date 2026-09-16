<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../vendor/autoload.php';

$config = require __DIR__ . '/email_config.php';

/**
 * Send SecureLog developer approval email.
 */
function sendApprovalNotification(
    string $recipientEmail,
    string $recipientName
): bool {
    global $config;

    $mail = new PHPMailer(true);

    try {

        /*
        |--------------------------------------------------------------------------
        | SMTP CONFIGURATION
        |--------------------------------------------------------------------------
        */

        $mail->isSMTP();

        $mail->Host = $config['smtp_host'];
        $mail->SMTPAuth = true;

        $mail->Username = $config['smtp_username'];
        $mail->Password = $config['smtp_password'];

        $mail->SMTPSecure =
            PHPMailer::ENCRYPTION_STARTTLS;

        $mail->Port = $config['smtp_port'];

        /*
        |--------------------------------------------------------------------------
        | EMAIL SENDER
        |--------------------------------------------------------------------------
        */

        $mail->setFrom(
            $config['from_email'],
            $config['from_name']
        );

        /*
        |--------------------------------------------------------------------------
        | EMAIL RECIPIENT
        |--------------------------------------------------------------------------
        */

        $mail->addAddress(
            $recipientEmail,
            $recipientName
        );

        /*
        |--------------------------------------------------------------------------
        | EMAIL FORMAT
        |--------------------------------------------------------------------------
        */

        $mail->isHTML(true);
        $mail->CharSet = 'UTF-8';

        $mail->Subject =
            'SecureLog Account Approved';

        /*
        |--------------------------------------------------------------------------
        | SAFE OUTPUT
        |--------------------------------------------------------------------------
        */

        $safeName = htmlspecialchars(
            $recipientName,
            ENT_QUOTES,
            'UTF-8'
        );

        /*
        |--------------------------------------------------------------------------
        | EMBED SECURELOG LOGO
        |--------------------------------------------------------------------------
        |
        | Change this filename if your actual logo is different.
        |
        */

        $logoPath =
            __DIR__ . '/../Asset/securelog.png';

        $logoAvailable = false;

        if (file_exists($logoPath)) {

            $mail->addEmbeddedImage(
                $logoPath,
                'securelog_logo',
                'securelog.png'
            );

            $logoAvailable = true;
        }

        /*
        |--------------------------------------------------------------------------
        | LOGO HTML
        |--------------------------------------------------------------------------
        */

        if ($logoAvailable) {

            $logoHtml = "
                <img
                    src='cid:securelog_logo'
                    alt='SecureLog'
                    style='
                        max-width:220px;
                        width:100%;
                        height:auto;
                        display:block;
                    '
                >
            ";

        } else {

            /*
             * Fallback if logo image cannot be found.
             */

            $logoHtml = "
                <div style='
                    font-size:30px;
                    font-weight:800;
                    letter-spacing:1px;
                    color:#ffffff;
                '>
                    SECURE<span style='color:#ff6500;'>LOG</span>
                </div>

                <div style='
                    margin-top:5px;
                    font-size:13px;
                    letter-spacing:4px;
                    color:#8eb5d1;
                '>
                    SAST ANALYZER
                </div>
            ";
        }

        /*
        |--------------------------------------------------------------------------
        | HTML EMAIL BODY
        |--------------------------------------------------------------------------
        */

        $mail->Body = "
        <!DOCTYPE html>
        <html>
        <head>

            <meta charset='UTF-8'>

            <meta
                name='viewport'
                content='width=device-width, initial-scale=1.0'
            >

            <title>SecureLog Account Approved</title>

        </head>

        <body style='
            margin:0;
            padding:0;
            background:#07111d;
            font-family:
                Arial,
                Helvetica,
                sans-serif;
        '>

            <table
                role='presentation'
                width='100%'
                cellspacing='0'
                cellpadding='0'
                border='0'
                style='
                    width:100%;
                    background:#07111d;
                    padding:30px 12px;
                '
            >

                <tr>

                    <td align='center'>

                        <table
                            role='presentation'
                            width='100%'
                            cellspacing='0'
                            cellpadding='0'
                            border='0'
                            style='
                                width:100%;
                                max-width:680px;
                                background:#ffffff;
                                border-radius:18px;
                                overflow:hidden;
                                border:
                                    1px solid #18334a;
                                box-shadow:
                                    0 20px 60px
                                    rgba(0,0,0,0.35);
                            '
                        >

                            <!-- =================================================
                                 HEADER
                            ================================================== -->

                            <tr>

                                <td
                                    style='
                                        padding:30px 38px;
                                        background:
                                            linear-gradient(
                                                135deg,
                                                #041525,
                                                #071c2e
                                            );
                                        border-bottom:
                                            4px solid #ff6500;
                                    '
                                >

                                    <table
                                        role='presentation'
                                        width='100%'
                                        cellspacing='0'
                                        cellpadding='0'
                                        border='0'
                                    >

                                        <tr>

                                            <td
                                                style='
                                                    width:65%;
                                                    vertical-align:middle;
                                                '
                                            >

                                                {$logoHtml}

                                            </td>

                                            <td
                                                align='right'
                                                style='
                                                    color:#8eb5d1;
                                                    font-size:11px;
                                                    line-height:1.8;
                                                    letter-spacing:3px;
                                                    text-transform:uppercase;
                                                    vertical-align:middle;
                                                '
                                            >

                                                Scan<br>
                                                Detect<br>
                                                Analyze<br>
                                                Secure

                                            </td>

                                        </tr>

                                    </table>

                                </td>

                            </tr>


                            <!-- =================================================
                                 MAIN CONTENT
                            ================================================== -->

                            <tr>

                                <td
                                    style='
                                        padding:
                                            42px 42px 20px;
                                        background:#ffffff;
                                    '
                                >

                                    <table
                                        role='presentation'
                                        width='100%'
                                        cellspacing='0'
                                        cellpadding='0'
                                        border='0'
                                    >

                                        <tr>

                                            <td>

                                                <div
                                                    style='
                                                        font-size:36px;
                                                        line-height:1.15;
                                                        font-weight:800;
                                                        color:#071827;
                                                    '
                                                >
                                                    Account
                                                    <span
                                                        style='
                                                            color:#00a865;
                                                        '
                                                    >
                                                        Approved
                                                    </span>
                                                </div>

                                            </td>

                                            <td
                                                align='right'
                                                style='
                                                    width:90px;
                                                '
                                            >

                                                <div
                                                    style='
                                                        width:72px;
                                                        height:72px;
                                                        line-height:72px;
                                                        border-radius:50%;
                                                        text-align:center;
                                                        background:#dcf8eb;
                                                        color:#00a865;
                                                        font-size:38px;
                                                        font-weight:700;
                                                    '
                                                >
                                                    ✓
                                                </div>

                                            </td>

                                        </tr>

                                    </table>


                                    <p
                                        style='
                                            margin:
                                                32px 0 0;
                                            font-size:19px;
                                            line-height:1.6;
                                            color:#26384a;
                                        '
                                    >
                                        Hello
                                        <strong
                                            style='
                                                color:#071827;
                                            '
                                        >
                                            {$safeName}
                                        </strong>,
                                    </p>


                                    <p
                                        style='
                                            margin:
                                                25px 0 0;
                                            font-size:17px;
                                            line-height:1.75;
                                            color:#4b5d6d;
                                        '
                                    >
                                        Your SecureLog developer
                                        account has been approved
                                        by the administrator.
                                    </p>


                                    <p
                                        style='
                                            margin:
                                                18px 0 0;
                                            font-size:17px;
                                            line-height:1.75;
                                            color:#4b5d6d;
                                        '
                                    >
                                        You can now log in and
                                        access SecureLog's source
                                        code scanning and security
                                        analysis features.
                                    </p>

                                </td>

                            </tr>


                            <!-- =================================================
                                 APPROVAL STATUS
                            ================================================== -->

                            <tr>

                                <td
                                    style='
                                        padding:
                                            20px 42px 10px;
                                        background:#ffffff;
                                    '
                                >

                                    <table
                                        role='presentation'
                                        width='100%'
                                        cellspacing='0'
                                        cellpadding='0'
                                        border='0'
                                        style='
                                            background:#e9fbf3;
                                            border-radius:12px;
                                            overflow:hidden;
                                            border-left:
                                                5px solid #00a865;
                                        '
                                    >

                                        <tr>

                                            <td
                                                style='
                                                    padding:
                                                        22px 24px;
                                                '
                                            >

                                                <div
                                                    style='
                                                        font-size:12px;
                                                        font-weight:700;
                                                        color:#456272;
                                                        letter-spacing:1px;
                                                        text-transform:uppercase;
                                                    '
                                                >
                                                    Account Status
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:6px;
                                                        font-size:25px;
                                                        font-weight:800;
                                                        color:#00a865;
                                                    '
                                                >
                                                    APPROVED
                                                </div>

                                            </td>

                                            <td
                                                align='right'
                                                style='
                                                    padding:
                                                        22px 24px;
                                                    color:#31566b;
                                                    font-size:14px;
                                                    font-weight:600;
                                                '
                                            >
                                                Welcome to
                                                SecureLog
                                            </td>

                                        </tr>

                                    </table>

                                </td>

                            </tr>


                            <!-- =================================================
                                 FEATURE HIGHLIGHTS
                            ================================================== -->

                            <tr>

                                <td
                                    style='
                                        padding:
                                            28px 32px 10px;
                                        background:#ffffff;
                                    '
                                >

                                    <table
                                        role='presentation'
                                        width='100%'
                                        cellspacing='0'
                                        cellpadding='0'
                                        border='0'
                                    >

                                        <tr>

                                            <td
                                                align='center'
                                                style='
                                                    width:25%;
                                                    padding:10px;
                                                '
                                            >

                                                <div
                                                    style='
                                                        width:52px;
                                                        height:52px;
                                                        line-height:52px;
                                                        margin:auto;
                                                        border-radius:12px;
                                                        background:#fff1e8;
                                                        color:#ff6500;
                                                        font-size:25px;
                                                        font-weight:bold;
                                                    '
                                                >
                                                    &lt;/&gt;
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:10px;
                                                        font-size:14px;
                                                        font-weight:800;
                                                        color:#122438;
                                                    '
                                                >
                                                    Scan
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:5px;
                                                        font-size:11px;
                                                        color:#758596;
                                                    '
                                                >
                                                    Analyze code
                                                </div>

                                            </td>


                                            <td
                                                align='center'
                                                style='
                                                    width:25%;
                                                    padding:10px;
                                                '
                                            >

                                                <div
                                                    style='
                                                        width:52px;
                                                        height:52px;
                                                        line-height:52px;
                                                        margin:auto;
                                                        border-radius:12px;
                                                        background:#fff1e8;
                                                        color:#ff6500;
                                                        font-size:22px;
                                                    '
                                                >
                                                    🔎
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:10px;
                                                        font-size:14px;
                                                        font-weight:800;
                                                        color:#122438;
                                                    '
                                                >
                                                    Detect
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:5px;
                                                        font-size:11px;
                                                        color:#758596;
                                                    '
                                                >
                                                    Find issues
                                                </div>

                                            </td>


                                            <td
                                                align='center'
                                                style='
                                                    width:25%;
                                                    padding:10px;
                                                '
                                            >

                                                <div
                                                    style='
                                                        width:52px;
                                                        height:52px;
                                                        line-height:52px;
                                                        margin:auto;
                                                        border-radius:12px;
                                                        background:#fff1e8;
                                                        color:#ff6500;
                                                        font-size:23px;
                                                    '
                                                >
                                                    ▥
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:10px;
                                                        font-size:14px;
                                                        font-weight:800;
                                                        color:#122438;
                                                    '
                                                >
                                                    Analyze
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:5px;
                                                        font-size:11px;
                                                        color:#758596;
                                                    '
                                                >
                                                    Review reports
                                                </div>

                                            </td>


                                            <td
                                                align='center'
                                                style='
                                                    width:25%;
                                                    padding:10px;
                                                '
                                            >

                                                <div
                                                    style='
                                                        width:52px;
                                                        height:52px;
                                                        line-height:52px;
                                                        margin:auto;
                                                        border-radius:12px;
                                                        background:#fff1e8;
                                                        color:#ff6500;
                                                        font-size:23px;
                                                    '
                                                >
                                                    🛡
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:10px;
                                                        font-size:14px;
                                                        font-weight:800;
                                                        color:#122438;
                                                    '
                                                >
                                                    Secure
                                                </div>

                                                <div
                                                    style='
                                                        margin-top:5px;
                                                        font-size:11px;
                                                        color:#758596;
                                                    '
                                                >
                                                    Build safely
                                                </div>

                                            </td>

                                        </tr>

                                    </table>

                                </td>

                            </tr>


                            <!-- =================================================
                                 INFORMATION MESSAGE
                            ================================================== -->

                            <tr>

                                <td
                                    style='
                                        padding:
                                            25px 42px 38px;
                                        background:#ffffff;
                                    '
                                >

                                    <table
                                        role='presentation'
                                        width='100%'
                                        cellspacing='0'
                                        cellpadding='0'
                                        border='0'
                                        style='
                                            background:#fff3ec;
                                            border-radius:10px;
                                        '
                                    >

                                        <tr>

                                            <td
                                                style='
                                                    width:48px;
                                                    padding:
                                                        17px 0 17px 20px;
                                                    color:#ff6500;
                                                    font-size:23px;
                                                    font-weight:bold;
                                                '
                                            >
                                                ⓘ
                                            </td>

                                            <td
                                                style='
                                                    padding:
                                                        17px 20px 17px 10px;
                                                    color:#526474;
                                                    font-size:13px;
                                                    line-height:1.6;
                                                '
                                            >
                                                If you did not
                                                register for a
                                                SecureLog account,
                                                please contact the
                                                administrator.
                                            </td>

                                        </tr>

                                    </table>

                                </td>

                            </tr>


                            <!-- =================================================
                                 FOOTER
                            ================================================== -->

                            <tr>

                                <td
                                    style='
                                        padding:
                                            25px 38px;
                                        background:#041525;
                                    '
                                >

                                    <table
                                        role='presentation'
                                        width='100%'
                                        cellspacing='0'
                                        cellpadding='0'
                                        border='0'
                                    >

                                        <tr>

                                            <td
                                                style='
                                                    width:45%;
                                                    vertical-align:middle;
                                                '
                                            >

                                                {$logoHtml}

                                            </td>

                                            <td
                                                align='right'
                                                style='
                                                    color:#8eb5d1;
                                                    font-size:12px;
                                                    line-height:1.7;
                                                    vertical-align:middle;
                                                '
                                            >
                                                SecureLog Security
                                                Notification
                                                <br>

                                                <span
                                                    style='
                                                        color:#5f8098;
                                                    '
                                                >
                                                    Safer Code.
                                                    A More Secure
                                                    Tomorrow.
                                                </span>

                                            </td>

                                        </tr>

                                    </table>

                                </td>

                            </tr>

                        </table>

                    </td>

                </tr>

            </table>

        </body>
        </html>
        ";

        /*
        |--------------------------------------------------------------------------
        | PLAIN TEXT FALLBACK
        |--------------------------------------------------------------------------
        */

        $mail->AltBody =
            "SECURELOG - SAST ANALYZER\n\n"
            . "ACCOUNT APPROVED\n\n"
            . "Hello {$recipientName},\n\n"
            . "Your SecureLog developer account "
            . "has been approved by the administrator.\n\n"
            . "You can now log in and access SecureLog's "
            . "source code scanning and security analysis "
            . "features.\n\n"
            . "Account Status: APPROVED\n\n"
            . "If you did not register for a SecureLog "
            . "account, please contact the administrator.\n\n"
            . "SecureLog Security Notification";

        /*
        |--------------------------------------------------------------------------
        | SEND EMAIL
        |--------------------------------------------------------------------------
        */

        $mail->send();

        return true;

    } catch (Exception $exception) {

        /*
        |--------------------------------------------------------------------------
        | EMAIL ERROR
        |--------------------------------------------------------------------------
        |
        | Do NOT show SMTP credentials or detailed errors
        | to the normal user.
        |
        */

        error_log(
            'SecureLog Email Error: '
            . $mail->ErrorInfo
        );

        return false;
    }
    
}
function sendNewDeveloperAccountNotification(
    string $recipientEmail,
    string $recipientName,
    string $username,
    string $temporaryPassword
): bool {
    global $config;

    $mail = new PHPMailer(true);

    try {

        /* ============================
           SMTP CONFIGURATION
           ============================ */

        $mail->isSMTP();

        $mail->Host = $config['smtp_host'];
        $mail->SMTPAuth = true;

        $mail->Username =
            trim($config['smtp_username']);

        /*
         * Gmail normally displays App Password
         * grouped with spaces.
         */
        $mail->Password =
            str_replace(
                ' ',
                '',
                $config['smtp_password']
            );

        $mail->SMTPSecure =
            PHPMailer::ENCRYPTION_STARTTLS;

        $mail->Port =
            (int) $config['smtp_port'];

        $mail->CharSet = 'UTF-8';

        /* ============================
           SENDER / RECIPIENT
           ============================ */

        $mail->setFrom(
            trim($config['from_email']),
            $config['from_name']
        );

        $mail->addAddress(
            $recipientEmail,
            $recipientName
        );

        /* ============================
           LOGO
           ============================ */

        $logoPath =
            __DIR__ . '/../Asset/securelog.png';

        $logoAvailable = false;

        if (file_exists($logoPath)) {

            $mail->addEmbeddedImage(
                $logoPath,
                'securelog_logo',
                'securelog.png'
            );

            $logoAvailable = true;
        }

        if ($logoAvailable) {

            $logoHtml = "
                <img
                    src='cid:securelog_logo'
                    alt='SecureLog'
                    style='
                        max-width:220px;
                        width:100%;
                        height:auto;
                        display:block;
                    '
                >
            ";

        } else {

            $logoHtml = "
                <div style='
                    font-size:30px;
                    font-weight:800;
                    color:#ffffff;
                '>
                    SECURE<span style='color:#ff6500;'>LOG</span>
                </div>
            ";
        }

        /* ============================
           SAFE VALUES
           ============================ */

        $safeName =
            htmlspecialchars(
                $recipientName,
                ENT_QUOTES,
                'UTF-8'
            );

        $safeUsername =
            htmlspecialchars(
                $username,
                ENT_QUOTES,
                'UTF-8'
            );

        $safeTemporaryPassword =
            htmlspecialchars(
                $temporaryPassword,
                ENT_QUOTES,
                'UTF-8'
            );

        /* ============================
           EMAIL
           ============================ */

        $mail->isHTML(true);

        $mail->Subject =
            'Your SecureLog Developer Account';

        $mail->Body = "
        <!DOCTYPE html>

        <html>

        <body style='
            margin:0;
            padding:0;
            background:#07111d;
            font-family:
                Arial,
                Helvetica,
                sans-serif;
        '>

        <table
            role='presentation'
            width='100%'
            cellspacing='0'
            cellpadding='0'
            border='0'
            style='
                width:100%;
                background:#07111d;
                padding:30px 12px;
            '
        >

            <tr>

                <td align='center'>

                    <table
                        role='presentation'
                        width='100%'
                        cellspacing='0'
                        cellpadding='0'
                        border='0'
                        style='
                            width:100%;
                            max-width:680px;
                            background:#ffffff;
                            border-radius:18px;
                            overflow:hidden;
                            border:1px solid #18334a;
                        '
                    >

                        <!-- HEADER -->

                        <tr>

                            <td
                                style='
                                    padding:30px 38px;
                                    background:#041525;
                                    border-bottom:
                                        4px solid #ff6500;
                                '
                            >

                                {$logoHtml}

                            </td>

                        </tr>

                        <!-- CONTENT -->

                        <tr>

                            <td
                                style='
                                    padding:42px;
                                    background:#ffffff;
                                '
                            >

                                <div
                                    style='
                                        font-size:32px;
                                        font-weight:800;
                                        color:#071827;
                                    '
                                >
                                    Welcome to

                                    <span
                                        style='color:#ff6500;'
                                    >
                                        SecureLog
                                    </span>
                                </div>

                                <p
                                    style='
                                        margin-top:28px;
                                        font-size:17px;
                                        line-height:1.7;
                                        color:#4b5d6d;
                                    '
                                >

                                    Hello
                                    <strong>
                                        {$safeName}
                                    </strong>,

                                </p>

                                <p
                                    style='
                                        font-size:16px;
                                        line-height:1.7;
                                        color:#4b5d6d;
                                    '
                                >
                                    A SecureLog administrator
                                    has created a Developer
                                    account for you.
                                </p>

                                <!-- CREDENTIAL BOX -->

                                <table
                                    role='presentation'
                                    width='100%'
                                    cellspacing='0'
                                    cellpadding='0'
                                    style='
                                        margin-top:25px;
                                        background:#071827;
                                        border-radius:12px;
                                    '
                                >

                                    <tr>

                                        <td
                                            style='
                                                padding:25px;
                                            '
                                        >

                                            <div
                                                style='
                                                    color:#8eb5d1;
                                                    font-size:12px;
                                                    text-transform:uppercase;
                                                    letter-spacing:1px;
                                                '
                                            >
                                                Username
                                            </div>

                                            <div
                                                style='
                                                    margin-top:6px;
                                                    color:#ffffff;
                                                    font-size:19px;
                                                    font-weight:700;
                                                '
                                            >
                                                {$safeUsername}
                                            </div>

                                            <div
                                                style='
                                                    margin-top:22px;
                                                    color:#8eb5d1;
                                                    font-size:12px;
                                                    text-transform:uppercase;
                                                    letter-spacing:1px;
                                                '
                                            >
                                                Temporary Password
                                            </div>

                                            <div
                                                style='
                                                    margin-top:6px;
                                                    color:#ff7a18;
                                                    font-size:19px;
                                                    font-weight:800;
                                                '
                                            >
                                                {$safeTemporaryPassword}
                                            </div>

                                        </td>

                                    </tr>

                                </table>

                                <!-- PASSWORD NOTICE -->

                                <div
                                    style='
                                        margin-top:25px;
                                        padding:18px 20px;
                                        background:#fff3ec;
                                        border-left:
                                            5px solid #ff6500;
                                        border-radius:8px;
                                        color:#526474;
                                        font-size:14px;
                                        line-height:1.6;
                                    '
                                >

                                    <strong>
                                        Password Change Required
                                    </strong>

                                    <br>

                                    This is a temporary password.
                                    You will be required to create
                                    a new password when you first
                                    sign in to SecureLog.

                                </div>

                                <p
                                    style='
                                        margin-top:28px;
                                        color:#758596;
                                        font-size:13px;
                                        line-height:1.6;
                                    '
                                >
                                    Do not share your temporary
                                    password with anyone.
                                </p>

                            </td>

                        </tr>

                        <!-- FOOTER -->

                        <tr>

                            <td
                                style='
                                    padding:24px 38px;
                                    background:#041525;
                                    color:#8eb5d1;
                                    font-size:12px;
                                '
                            >

                                SecureLog Security Notification

                                <br>

                                <span
                                    style='color:#5f8098;'
                                >
                                    Safer Code.
                                    A More Secure Tomorrow.
                                </span>

                            </td>

                        </tr>

                    </table>

                </td>

            </tr>

        </table>

        </body>

        </html>
        ";

        $mail->AltBody =
            "SECURELOG - DEVELOPER ACCOUNT\n\n"
            . "Hello {$recipientName},\n\n"
            . "A SecureLog administrator has "
            . "created a Developer account for you.\n\n"
            . "Username: {$username}\n"
            . "Temporary Password: {$temporaryPassword}\n\n"
            . "You must change this temporary password "
            . "when you first log in.\n\n"
            . "SecureLog Security Notification";

        $mail->send();

        return true;

    } catch (Exception $exception) {

        error_log(
            'SecureLog New Account Email Error: '
            . $mail->ErrorInfo
        );

        return false;
    }
}