<?php
/**
 * SecureLog - Add Developer
 * File: ManageUser/addUser.php
 */
require_once __DIR__
    . '/../Notification/NotificationService.php';

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
   DATABASE / LOGGER
   ============================================================ */

require_once __DIR__ . '/../Engine_Process/connection.php';
require_once __DIR__ . '/../Dashboard/ActivityLogger.php';

/*
|--------------------------------------------------------------------------
| PHPMailer
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/*
|--------------------------------------------------------------------------
| Email configuration
|--------------------------------------------------------------------------
*/

$emailConfigPath =
    __DIR__ . '/../Notification/email_config.php';

if (is_file($emailConfigPath)) {
    require_once $emailConfigPath;
}

/* ============================================================
   CURRENT ADMIN
   ============================================================ */

$currentUserId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

if ($currentUserId <= 0) {
    header(
        'Location: ../Registration/login.php'
    );
    exit;
}

/* ============================================================
   CSRF
   ============================================================ */

if (
    empty($_SESSION['csrf_token'])
) {
    $_SESSION['csrf_token'] =
        bin2hex(
            random_bytes(32)
        );
}

$csrfToken =
    $_SESSION['csrf_token'];

/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */

function e(
    mixed $value
): string {
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}

function oldInput(
    string $field,
    string $default = ''
): string {
    return e(
        $_POST[$field]
        ?? $default
    );
}

/*
|--------------------------------------------------------------------------
| Check database column
|--------------------------------------------------------------------------
*/

function userColumnExists(
    mysqli $conn,
    string $columnName
): bool {

    $statement =
        $conn->prepare(
            "
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'users'
              AND column_name = ?
            "
        );

    if (!$statement) {
        return false;
    }

    $statement->bind_param(
        's',
        $columnName
    );

    $statement->execute();

    $statement->bind_result(
        $exists
    );

    $statement->fetch();
    $statement->close();

    return (int) $exists > 0;
}

/*
|--------------------------------------------------------------------------
| Generate temporary password
|--------------------------------------------------------------------------
|
| No temporary password is stored in plaintext in the database.
|--------------------------------------------------------------------------
*/

function generateTemporaryPassword(
    int $length = 14
): string {

    $uppercase =
        'ABCDEFGHJKLMNPQRSTUVWXYZ';

    $lowercase =
        'abcdefghijkmnopqrstuvwxyz';

    $numbers =
        '23456789';

    $symbols =
        '!@#$%&*?';

    /*
     * Guarantee at least one character
     * from every required category.
     */

    $password =
        $uppercase[
            random_int(
                0,
                strlen($uppercase) - 1
            )
        ]
        .
        $lowercase[
            random_int(
                0,
                strlen($lowercase) - 1
            )
        ]
        .
        $numbers[
            random_int(
                0,
                strlen($numbers) - 1
            )
        ]
        .
        $symbols[
            random_int(
                0,
                strlen($symbols) - 1
            )
        ];

    $allCharacters =
        $uppercase
        . $lowercase
        . $numbers
        . $symbols;

    while (
        strlen($password) < $length
    ) {

        $password .=
            $allCharacters[
                random_int(
                    0,
                    strlen($allCharacters) - 1
                )
            ];
    }

    /*
     * Cryptographically safe shuffle
     */

    $characters =
        str_split($password);

    for (
        $i = count($characters) - 1;
        $i > 0;
        $i--
    ) {

        $j =
            random_int(
                0,
                $i
            );

        [
            $characters[$i],
            $characters[$j]
        ] = [
            $characters[$j],
            $characters[$i]
        ];
    }

    return implode(
        '',
        $characters
    );
}

/*
|--------------------------------------------------------------------------
| Send developer account email
|--------------------------------------------------------------------------
|
| IMPORTANT:
| Adjust the configuration variable names below ONLY if your
| email_config.php uses different names.
|--------------------------------------------------------------------------
*/



/* ============================================================
   DATABASE REQUIREMENTS
   ============================================================ */

$hasMustChangePassword =
    userColumnExists(
        $conn,
        'must_change_password'
    );

if (!$hasMustChangePassword) {

    http_response_code(500);

    exit(
        'Database configuration error: '
        . 'users.must_change_password column is missing.'
    );
}

/* ============================================================
   FORM VARIABLES
   ============================================================ */

$errors = [];

$successMessage =
    trim(
        $_GET['success']
        ?? ''
    );

$warningMessage =
    trim(
        $_GET['warning']
        ?? ''
    );

$fullname =
    trim(
        $_POST['fullname']
        ?? ''
    );

$email =
    trim(
        $_POST['email']
        ?? ''
    );

$username =
    trim(
        $_POST['username']
        ?? ''
    );

$department =
    trim(
        $_POST['department']
        ?? ''
    );

/*
|--------------------------------------------------------------------------
| Fixed values
|--------------------------------------------------------------------------
|
| Admin CANNOT create another Admin.
|--------------------------------------------------------------------------
*/

$role =
    'developer';

$isActive =
    1;

$mustChangePassword =
    1;

$registrationStatus =
    'Approved';

/* ============================================================
   HANDLE FORM
   ============================================================ */

if (
    $_SERVER['REQUEST_METHOD']
    === 'POST'
) {

    /*
    |--------------------------------------------------------------------------
    | CSRF verification
    |--------------------------------------------------------------------------
    */

    $submittedToken =
        $_POST['csrf_token']
        ?? '';

    if (
        !hash_equals(
            $_SESSION['csrf_token'],
            $submittedToken
        )
    ) {

        $errors[] =
            'Invalid request token. Please refresh the page and try again.';
    }

    /*
    |--------------------------------------------------------------------------
    | Full name
    |--------------------------------------------------------------------------
    */

    if ($fullname === '') {

        $errors[] =
            'Full name is required.';

    } elseif (
        mb_strlen($fullname) > 150
    ) {

        $errors[] =
            'Full name is too long.';
    }

    /*
    |--------------------------------------------------------------------------
    | Email
    |--------------------------------------------------------------------------
    */

    if ($email === '') {

        $errors[] =
            'Email address is required.';

    } elseif (
        !filter_var(
            $email,
            FILTER_VALIDATE_EMAIL
        )
    ) {

        $errors[] =
            'Please enter a valid email address.';
    }

    /*
    |--------------------------------------------------------------------------
    | Username
    |--------------------------------------------------------------------------
    */

    if ($username === '') {

        $errors[] =
            'Username is required.';

    } elseif (
        !preg_match(
            '/^[a-zA-Z0-9_]{3,50}$/',
            $username
        )
    ) {

        $errors[] =
            'Username must contain 3-50 letters, numbers or underscores only.';
    }

    /*
    |--------------------------------------------------------------------------
    | Department
    |--------------------------------------------------------------------------
    */

    $allowedDepartments = [
        '',
        'Software Development',
        'Cyber Security',
        'DevOps',
        'Quality Assurance',
        'IT Support',
        'Other'
    ];

    if (
        !in_array(
            $department,
            $allowedDepartments,
            true
        )
    ) {

        $errors[] =
            'Please select a valid department.';
    }

    /*
    |--------------------------------------------------------------------------
    | Duplicate username/email
    |--------------------------------------------------------------------------
    */

    if (empty($errors)) {

        $duplicateStatement =
            $conn->prepare(
                "
                SELECT
                    UserID,
                    username,
                    email
                FROM users
                WHERE username = ?
                   OR email = ?
                LIMIT 1
                "
            );

        if (!$duplicateStatement) {

            $errors[] =
                'Unable to validate username and email.';

        } else {

            $duplicateStatement->bind_param(
                'ss',
                $username,
                $email
            );

            $duplicateStatement->execute();

            $duplicateResult =
                $duplicateStatement->get_result();

            if (
                $duplicateResult->num_rows > 0
            ) {

                $existingUser =
                    $duplicateResult->fetch_assoc();

                if (
                    strcasecmp(
                        $existingUser['username'],
                        $username
                    ) === 0
                ) {

                    $errors[] =
                        'Username is already registered.';
                }

                if (
                    strcasecmp(
                        $existingUser['email'],
                        $email
                    ) === 0
                ) {

                    $errors[] =
                        'Email address is already registered.';
                }
            }

            $duplicateStatement->close();
        }
    }

    /* ============================================================
       CREATE ACCOUNT
       ============================================================ */

    if (empty($errors)) {

        /*
        |--------------------------------------------------------------------------
        | Generate temporary password
        |--------------------------------------------------------------------------
        */

        $temporaryPassword =
            generateTemporaryPassword();

        $hashedPassword =
            password_hash(
                $temporaryPassword,
                PASSWORD_BCRYPT,
                [
                    'cost' => 12
                ]
            );

        if ($hashedPassword === false) {

            $errors[] =
                'Unable to securely generate the account password.';

        } else {

            try {

                /*
                |--------------------------------------------------------------------------
                | Transaction begins
                |--------------------------------------------------------------------------
                */

                $conn->begin_transaction();

                /*
                |--------------------------------------------------------------------------
                | Create users record
                |--------------------------------------------------------------------------
                |
                | Role is hardcoded as developer.
                |--------------------------------------------------------------------------
                */

                $userStatement =
                    $conn->prepare(
                        "
                        INSERT INTO users
                        (
                            fullname,
                            email,
                            username,
                            password,
                            role,
                            is_active,
                            must_change_password,
                            created_at
                        )
                        VALUES
                        (
                            ?,
                            ?,
                            ?,
                            ?,
                            'developer',
                            1,
                            1,
                            NOW()
                        )
                        "
                    );

                if (!$userStatement) {
                    throw new RuntimeException(
                        'Unable to prepare user account query.'
                    );
                }

                $userStatement->bind_param(
                    'ssss',
                    $fullname,
                    $email,
                    $username,
                    $hashedPassword
                );

                if (
                    !$userStatement->execute()
                ) {

                    throw new RuntimeException(
                        'Unable to create user account.'
                    );
                }

                $newUserId =
                    (int) $conn->insert_id;

                $userStatement->close();

                /*
                |--------------------------------------------------------------------------
                | Create developer record
                |--------------------------------------------------------------------------
                */

                $developerStatement =
                    $conn->prepare(
                        "
                        INSERT INTO developer
                        (
                            UserID,
                            registration_status,
                            department
                        )
                        VALUES
                        (
                            ?,
                            ?,
                            ?
                        )
                        "
                    );

                if (!$developerStatement) {

                    throw new RuntimeException(
                        'Unable to prepare developer account query.'
                    );
                }

                $developerStatement->bind_param(
                    'iss',
                    $newUserId,
                    $registrationStatus,
                    $department
                );

                if (
                    !$developerStatement->execute()
                ) {

                    throw new RuntimeException(
                        'Unable to create developer profile.'
                    );
                }

                $developerStatement->close();

                /*
                |--------------------------------------------------------------------------
                | Commit BOTH records
                |--------------------------------------------------------------------------
                */

                $conn->commit();

                /*
                |--------------------------------------------------------------------------
                | Activity Log - USER_CREATED
                |--------------------------------------------------------------------------
                |
                | The database transaction has already been committed.
                | Therefore the account definitely exists before we record SUCCESS.
                |
                | IMPORTANT:
                | Never store the temporary password in the activity log.
                |--------------------------------------------------------------------------
                */

                if (
                    $currentUserId > 0
                    && function_exists('log_activity')
                ) {
                    log_activity(
                        LOG_USER_CREATED,
                        $currentUserId,
                        'Administrator created a new developer account.',
                        [
                            'module' => 'UserManagement',
                            'severity' => 'INFO',
                            'result' => 'SUCCESS',

                            'target_type' => 'USER_ACCOUNT',
                            'target_id' => $newUserId,

                            'metadata' => [
                                'created_role' => 'developer',
                                'account_status' => 'APPROVED',
                                'must_change_password' => true
                            ]
                        ]
                    );
                }


                /*
                |--------------------------------------------------------------------------
                | Email AFTER database commit
                |--------------------------------------------------------------------------
                |
                | Email failure does NOT remove the developer account.
                |--------------------------------------------------------------------------
                */

                $emailSent =
                    sendNewDeveloperAccountNotification(
                        $email,
                        $fullname,
                        $username,
                        $temporaryPassword
                    );
                /*
                 * Remove our reference to the plaintext password
                 * as soon as it is no longer required.
                 */

                $temporaryPassword =
                    null;

                /*
                |--------------------------------------------------------------------------
                | Regenerate CSRF after successful privileged action
                |--------------------------------------------------------------------------
                */

                $_SESSION['csrf_token'] =
                    bin2hex(
                        random_bytes(32)
                    );

                if ($emailSent) {

                    header(
                        'Location: addUser.php?success='
                        . urlencode(
                            'Developer account created successfully. Temporary login credentials were sent by email.'
                        )
                    );

                } else {

                    header(
                        'Location: addUser.php?success='
                        . urlencode(
                            'Developer account created successfully.'
                        )
                        . '&warning='
                        . urlencode(
                            'The account was created, but SecureLog could not send the temporary credential email. Check the SMTP configuration.'
                        )
                    );
                }

                exit;

            } catch (Throwable $exception) {

    try {
        $conn->rollback();
    } catch (Throwable $ignored) {
    }

    error_log(
        'SecureLog Add Developer error: '
        . $exception->getMessage()
    );

    $errors[] =
        'DEBUG: ' . $exception->getMessage();
}
        }
    }
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
        Add Developer | SecureLog
    </title>

    <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
    >

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <style>

        :root {
            --bg: #020c17;
            --panel: #061729;
            --input: #071521;
            --border: #183247;

            --orange: #ff6500;
            --orange-light: #ff8500;

            --red: #ff3547;
            --green: #00d89f;
            --yellow: #f59e0b;

            --text: #f8fafc;
            --muted: #a7b2bf;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
            background: var(--bg);
            color: var(--text);

            font-family:
                "Inter",
                "Segoe UI",
                sans-serif;
        }

        body {
            overflow-x: hidden;
        }

        .add-user-page {
            min-height: 100vh;

            padding:
                8px
                10px
                12px;

            background:
                radial-gradient(
                    circle at 72% 12%,
                    rgba(56, 189, 248, 0.035),
                    transparent 28%
                ),
                var(--bg);
        }

        .add-user-container {
            width: 100%;
            max-width: 1500px;

            min-height:
                calc(100vh - 20px);

            margin: 0 auto;

            background:
                linear-gradient(
                    145deg,
                    rgba(5, 24, 40, 0.98),
                    rgba(2, 14, 26, 0.98)
                );

            border:
                1px solid
                var(--border);

            border-radius: 13px;

            overflow: hidden;
        }

        /* HEADER */

        .add-user-header {
            min-height: 118px;

            padding:
                30px
                32px
                25px;

            display: flex;
            align-items: flex-start;

            gap: 19px;

            border-bottom:
                1px solid
                var(--border);
        }

        .add-user-header-icon {
            width: 50px;
            height: 50px;

            display: flex;
            align-items: center;
            justify-content: center;

            flex-shrink: 0;

            color: var(--orange);

            background:
                rgba(255, 101, 0, 0.13);

            border-radius: 50%;

            font-size: 25px;
        }

        .add-user-header-text h1 {
            margin:
                2px
                0
                8px;

            font-size: 26px;
            font-weight: 800;
        }

        .add-user-header-text p {
            margin: 0;

            color: #c3ccd6;

            font-size: 14px;
        }

        /* MESSAGE */

        .message-area {
            padding:
                22px
                32px
                0;
        }

        .alert-message {
            padding:
                14px
                17px;

            margin-bottom: 10px;

            border-radius: 7px;

            font-size: 13px;
            font-weight: 500;
        }

        .alert-success {
            color: #4ff0b6;

            background:
                rgba(0, 216, 159, 0.1);

            border:
                1px solid
                rgba(0, 216, 159, 0.35);
        }

        .alert-warning {
            color: #fbbf24;

            background:
                rgba(245, 158, 11, 0.1);

            border:
                1px solid
                rgba(245, 158, 11, 0.35);
        }

        .alert-error {
            color: #ff8792;

            background:
                rgba(255, 53, 71, 0.1);

            border:
                1px solid
                rgba(255, 53, 71, 0.35);
        }

        .alert-error ul {
            margin: 0;
            padding-left: 20px;
        }

        /* INFO */

        .account-info {
            margin:
                22px
                32px
                0;

            padding: 16px 18px;

            display: flex;
            align-items: flex-start;

            gap: 12px;

            color: #cbd5e1;

            background:
                rgba(56, 189, 248, 0.05);

            border:
                1px solid
                rgba(56, 189, 248, 0.18);

            border-radius: 8px;

            font-size: 13px;
            line-height: 1.6;
        }

        .account-info i {
            margin-top: 3px;

            color: #38bdf8;
        }

        /* FORM */

        .add-user-form {
            padding:
                24px
                32px
                0;
        }

        .form-group {
            margin-bottom: 21px;
        }

        .form-label {
            display: block;

            margin-bottom: 9px;

            color: #f2f5f8;

            font-size: 13px;
            font-weight: 700;

            text-transform: uppercase;
        }

        .required-mark {
            color: var(--red);
        }

        .form-control {
            width: 100%;
            height: 51px;

            padding:
                0
                17px;

            color: #ffffff;

            background:
                rgba(4, 18, 31, 0.82);

            border:
                1px solid
                var(--border);

            border-radius: 7px;

            outline: none;

            font-family: inherit;
            font-size: 14px;
        }

        .form-control:focus {
            background: #051827;

            border-color:
                var(--orange);

            box-shadow:
                0 0 0 3px
                rgba(255, 101, 0, 0.1);
        }

        .form-control::placeholder {
            color: #8997a6;
        }

        select.form-control {
            cursor: pointer;
        }

        select.form-control option {
            color: #ffffff;
            background: #071521;
        }

        .field-help {
            margin-top: 7px;

            color: #788898;

            font-size: 12px;
        }

        /* ACTION */

        .form-actions {
            margin:
                12px
                -32px
                0;

            padding:
                19px
                32px
                22px;

            display: flex;
            align-items: center;

            gap: 17px;

            background:
                rgba(7, 24, 39, 0.7);

            border-top:
                1px solid
                var(--border);
        }

        .create-user-button {
            width: 295px;

            min-height: 50px;

            display: inline-flex;

            align-items: center;
            justify-content: center;

            gap: 11px;

            color: #ffffff;

            background:
                linear-gradient(
                    90deg,
                    #ff6500,
                    #ff7900
                );

            border: none;

            border-radius: 6px;

            font-family: inherit;

            font-size: 14px;
            font-weight: 700;

            cursor: pointer;
        }

        .create-user-button:hover {
            filter: brightness(1.08);
        }

        .cancel-button {
            width: 190px;

            min-height: 50px;

            display: inline-flex;

            align-items: center;
            justify-content: center;

            color: #ffffff;

            background: transparent;

            border:
                1px solid
                var(--border);

            border-radius: 6px;

            text-decoration: none;

            font-size: 14px;
            font-weight: 600;
        }

        .cancel-button:hover {
            background:
                rgba(255, 255, 255, 0.04);
        }

        @media (
            max-width: 600px
        ) {

            .add-user-header,
            .add-user-form {
                padding-left: 20px;
                padding-right: 20px;
            }

            .message-area {
                padding-left: 20px;
                padding-right: 20px;
            }

            .account-info {
                margin-left: 20px;
                margin-right: 20px;
            }

            .form-actions {
                margin-left: -20px;
                margin-right: -20px;

                padding-left: 20px;
                padding-right: 20px;

                flex-direction: column;
            }

            .create-user-button,
            .cancel-button {
                width: 100%;
            }
        }

    </style>

</head>

<body>

<?php
require __DIR__
    . '/../Sidebar/sidebaradmin.php';
?>

<main
    class="
        admin-page-content
        add-user-page
    "
>

    <div
        class="add-user-container"
    >

        <!-- HEADER -->

        <header
            class="add-user-header"
        >

            <div
                class="add-user-header-icon"
            >
                <i
                    class="fa-solid fa-user-plus"
                ></i>
            </div>

            <div
                class="add-user-header-text"
            >

                <h1>
                    Add New Developer
                </h1>

                <p>
                    Create a SecureLog Developer account.
                </p>

            </div>

        </header>

        <!-- SUCCESS -->

        <?php
        if (
            $successMessage !== ''
        ):
        ?>

            <div
                class="message-area"
            >

                <div
                    class="
                        alert-message
                        alert-success
                    "
                >

                    <i
                        class="fa-solid fa-circle-check"
                    ></i>

                    <?= e(
                        $successMessage
                    ); ?>

                </div>

            </div>

        <?php endif; ?>

        <!-- WARNING -->

        <?php
        if (
            $warningMessage !== ''
        ):
        ?>

            <div
                class="message-area"
            >

                <div
                    class="
                        alert-message
                        alert-warning
                    "
                >

                    <i
                        class="fa-solid fa-triangle-exclamation"
                    ></i>

                    <?= e(
                        $warningMessage
                    ); ?>

                </div>

            </div>

        <?php endif; ?>

        <!-- ERRORS -->

        <?php
        if (
            !empty($errors)
        ):
        ?>

            <div
                class="message-area"
            >

                <div
                    class="
                        alert-message
                        alert-error
                    "
                >

                    <ul>

                        <?php
                        foreach (
                            $errors
                            as $error
                        ):
                        ?>

                            <li>
                                <?= e(
                                    $error
                                ); ?>
                            </li>

                        <?php
                        endforeach;
                        ?>

                    </ul>

                </div>

            </div>

        <?php endif; ?>

        <!-- ACCOUNT INFO -->

        <div
            class="account-info"
        >

            <i
                class="fa-solid fa-shield-halved"
            ></i>

            <div>

                SecureLog will automatically
                create an active
                <strong>
                    Developer
                </strong>
                account.

                A temporary password will
                be generated and sent to the
                developer's email address.

                The developer must change
                the password on first login.

            </div>

        </div>

        <!-- FORM -->

        <form
            method="POST"
            action="addUser.php"
            class="add-user-form"
            autocomplete="off"
        >

            <input
                type="hidden"
                name="csrf_token"
                value="<?= e(
                    $csrfToken
                ); ?>"
            >

            <!-- FULL NAME -->

            <div
                class="form-group"
            >

                <label
                    for="fullname"
                    class="form-label"
                >
                    Full Name
                    <span
                        class="required-mark"
                    >*</span>
                </label>

                <input
                    type="text"
                    id="fullname"
                    name="fullname"
                    class="form-control"
                    placeholder="e.g. Ahmad Razif"
                    maxlength="150"
                    value="<?= oldInput(
                        'fullname'
                    ); ?>"
                    required
                >

            </div>

            <!-- EMAIL -->

            <div
                class="form-group"
            >

                <label
                    for="email"
                    class="form-label"
                >
                    Email Address
                    <span
                        class="required-mark"
                    >*</span>
                </label>

                <input
                    type="email"
                    id="email"
                    name="email"
                    class="form-control"
                    placeholder="developer@example.com"
                    value="<?= oldInput(
                        'email'
                    ); ?>"
                    required
                >

                <div
                    class="field-help"
                >
                    Temporary login credentials
                    will be sent to this email.
                </div>

            </div>

            <!-- USERNAME -->

            <div
                class="form-group"
            >

                <label
                    for="username"
                    class="form-label"
                >
                    Username
                    <span
                        class="required-mark"
                    >*</span>
                </label>

                <input
                    type="text"
                    id="username"
                    name="username"
                    class="form-control"
                    placeholder="Letters, numbers and underscore"
                    minlength="3"
                    maxlength="50"
                    pattern="[a-zA-Z0-9_]+"
                    value="<?= oldInput(
                        'username'
                    ); ?>"
                    required
                >

            </div>

            <!-- DEPARTMENT -->

            <div
                class="form-group"
            >

                <label
                    for="department"
                    class="form-label"
                >
                    Department
                </label>

                <select
                    id="department"
                    name="department"
                    class="form-control"
                >

                    <?php

                    $departments = [
                        '',
                        'Software Development',
                        'Cyber Security',
                        'DevOps',
                        'Quality Assurance',
                        'IT Support',
                        'Other'
                    ];

                    foreach (
                        $departments
                        as $item
                    ):

                        $label =
                            $item === ''
                            ? 'Select department (optional)'
                            : $item;

                    ?>

                        <option
                            value="<?= e(
                                $item
                            ); ?>"
                            <?= $department === $item
                                ? 'selected'
                                : ''; ?>
                        >
                            <?= e(
                                $label
                            ); ?>
                        </option>

                    <?php
                    endforeach;
                    ?>

                </select>

            </div>

            <!-- ACTION -->

            <div
                class="form-actions"
            >

                <button
                    type="submit"
                    class="create-user-button"
                >

                    <i
                        class="fa-solid fa-user-plus"
                    ></i>

                    Create Developer

                </button>

                <a
                    href="user.php"
                    class="cancel-button"
                >
                    Cancel
                </a>

            </div>

        </form>

    </div>

</main>

</body>
</html>