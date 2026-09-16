```php
<?php
/**
 * SecureLog Developer Profile
 * File: ProfileDeveloper/profile.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';

if (function_exists('require_role')) {
    require_role(['developer']);
}

/* ============================================================
   DATABASE CONNECTION
   ============================================================ */

require_once __DIR__ . '/../Engine_Process/connection.php';

if (!isset($conn) || !($conn instanceof mysqli)) {
    die('Database connection is not available.');
}

/* ============================================================
   CURRENT USER
   ============================================================ */

$currentUserId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

if ($currentUserId <= 0) {
    header('Location: ../Registration/login.php');
    exit();
}

/* ============================================================
   CSRF TOKEN
   ============================================================ */

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(
        random_bytes(32)
    );
}

$csrfToken = $_SESSION['csrf_token'];

/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */

function profileColumnExists(
    mysqli $conn,
    string $columnName
): bool {
    $statement = $conn->prepare(
        "SELECT COUNT(*)
         FROM information_schema.columns
         WHERE table_schema = DATABASE()
         AND table_name = 'users'
         AND column_name = ?"
    );

    if (!$statement) {
        return false;
    }

    $statement->bind_param(
        's',
        $columnName
    );

    $statement->execute();
    $statement->bind_result($exists);
    $statement->fetch();
    $statement->close();

    return (int) $exists > 0;
}

function formatProfileDate(
    ?string $date,
    string $format = 'F j, Y'
): string {
    if (
        $date === null
        || trim($date) === ''
        || $date === '0000-00-00 00:00:00'
    ) {
        return 'Not available';
    }

    $timestamp = strtotime($date);

    if ($timestamp === false) {
        return $date;
    }

    return date(
        $format,
        $timestamp
    );
}

function redirectProfile(
    string $type,
    string $message
): void {
    $query = http_build_query([
        'type' => $type,
        'message' => $message
    ]);

    header(
        "Location: profile.php?{$query}"
    );

    exit();
}

function getProfileUser(
    mysqli $conn,
    int $userId,
    bool $hasDepartmentColumn
): ?array {
    $departmentField = $hasDepartmentColumn
        ? ', department'
        : '';

    $statement = $conn->prepare(
        "SELECT
            UserID,
            fullname,
            username,
            email,
            password,
            role,
            is_active,
            created_at,
            last_login
            {$departmentField}
         FROM users
         WHERE UserID = ?
         LIMIT 1"
    );

    if (!$statement) {
        return null;
    }

    $statement->bind_param(
        'i',
        $userId
    );

    $statement->execute();

    $result = $statement->get_result();

    $user = $result->fetch_assoc();

    $statement->close();

    return $user ?: null;
}

/* ============================================================
   OPTIONAL DATABASE COLUMNS
   ============================================================ */

$hasDepartmentColumn = profileColumnExists(
    $conn,
    'department'
);

/* ============================================================
   LOAD PROFILE
   ============================================================ */

$profileUser = getProfileUser(
    $conn,
    $currentUserId,
    $hasDepartmentColumn
);

if (!$profileUser) {
    session_destroy();

    header(
        'Location: ../Registration/login.php'
    );

    exit();
}

/* ============================================================
   PROCESS PROFILE UPDATE
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $submittedToken =
        $_POST['csrf_token'] ?? '';

    if (
        !hash_equals(
            $_SESSION['csrf_token'],
            $submittedToken
        )
    ) {
        redirectProfile(
            'error',
            'Invalid request token. Please try again.'
        );
    }

    $fullname = trim(
        $_POST['fullname'] ?? ''
    );

    $email = trim(
        $_POST['email'] ?? ''
    );

    $department = trim(
        $_POST['department'] ?? ''
    );

    $currentPassword =
        $_POST['current_password'] ?? '';

    $newPassword =
        $_POST['new_password'] ?? '';

    $confirmNewPassword =
        $_POST['confirm_new_password'] ?? '';

    $errors = [];

    /* -------------------------------
       Validate personal information
       ------------------------------- */

    if ($fullname === '') {
        $errors[] =
            'Full name is required.';
    }

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

    /* -------------------------------
       Check duplicate email
       ------------------------------- */

    if (empty($errors)) {
        $emailStatement = $conn->prepare(
            'SELECT UserID
             FROM users
             WHERE email = ?
             AND UserID != ?
             LIMIT 1'
        );

        if (!$emailStatement) {
            $errors[] =
                'Unable to validate the email address.';
        } else {
            $emailStatement->bind_param(
                'si',
                $email,
                $currentUserId
            );

            $emailStatement->execute();

            $emailResult =
                $emailStatement->get_result();

            if ($emailResult->num_rows > 0) {
                $errors[] =
                    'This email address is already used by another account.';
            }

            $emailStatement->close();
        }
    }

    /* -------------------------------
       Password validation
       ------------------------------- */

    $changingPassword =
        $currentPassword !== ''
        || $newPassword !== ''
        || $confirmNewPassword !== '';

    if ($changingPassword) {

        if ($currentPassword === '') {
            $errors[] =
                'Current password is required to change your password.';
        } elseif (
            !password_verify(
                $currentPassword,
                $profileUser['password']
            )
        ) {
            $errors[] =
                'Current password is incorrect.';
        }

        if (strlen($newPassword) < 8) {
            $errors[] =
                'New password must contain at least 8 characters.';
        }

        if (
            $newPassword
            !== $confirmNewPassword
        ) {
            $errors[] =
                'New password and confirmation do not match.';
        }

        if (
            $currentPassword !== ''
            && $newPassword !== ''
            && $currentPassword === $newPassword
        ) {
            $errors[] =
                'New password must be different from the current password.';
        }
    }

    /* -------------------------------
       Update profile
       ------------------------------- */

    if (empty($errors)) {

        $conn->begin_transaction();

        try {

            if ($hasDepartmentColumn) {
                $profileStatement = $conn->prepare(
                    'UPDATE users
                     SET fullname = ?,
                         email = ?,
                         department = ?
                     WHERE UserID = ?'
                );

                if (!$profileStatement) {
                    throw new Exception(
                        'Unable to prepare profile update.'
                    );
                }

                $profileStatement->bind_param(
                    'sssi',
                    $fullname,
                    $email,
                    $department,
                    $currentUserId
                );
            } else {
                $profileStatement = $conn->prepare(
                    'UPDATE users
                     SET fullname = ?,
                         email = ?
                     WHERE UserID = ?'
                );

                if (!$profileStatement) {
                    throw new Exception(
                        'Unable to prepare profile update.'
                    );
                }

                $profileStatement->bind_param(
                    'ssi',
                    $fullname,
                    $email,
                    $currentUserId
                );
            }

            if (!$profileStatement->execute()) {
                throw new Exception(
                    $profileStatement->error
                );
            }

            $profileStatement->close();

            /* Update password only when entered */
            if ($changingPassword) {
                $hashedPassword = password_hash(
                    $newPassword,
                    PASSWORD_BCRYPT,
                    [
                        'cost' => 12
                    ]
                );

                $passwordStatement = $conn->prepare(
                    'UPDATE users
                     SET password = ?
                     WHERE UserID = ?'
                );

                if (!$passwordStatement) {
                    throw new Exception(
                        'Unable to prepare password update.'
                    );
                }

                $passwordStatement->bind_param(
                    'si',
                    $hashedPassword,
                    $currentUserId
                );

                if (!$passwordStatement->execute()) {
                    throw new Exception(
                        $passwordStatement->error
                    );
                }

                $passwordStatement->close();
            }

            $conn->commit();

            /* Update session display values */
            $_SESSION['fullname'] = $fullname;
            $_SESSION['email'] = $email;

            redirectProfile(
                'success',
                $changingPassword
                    ? 'Profile and password updated successfully.'
                    : 'Profile updated successfully.'
            );

        } catch (Throwable $exception) {
            $conn->rollback();

            redirectProfile(
                'error',
                'Unable to update profile: '
                . $exception->getMessage()
            );
        }
    }

    redirectProfile(
        'error',
        implode(' ', $errors)
    );
}

/* ============================================================
   REFRESH PROFILE DATA
   ============================================================ */

$profileUser = getProfileUser(
    $conn,
    $currentUserId,
    $hasDepartmentColumn
);

if (!$profileUser) {
    header(
        'Location: ../Registration/login.php'
    );

    exit();
}

/* ============================================================
   DISPLAY VALUES
   ============================================================ */

$profileName = trim(
    $profileUser['fullname']
    ?? $profileUser['username']
    ?? 'Developer'
);

$profileEmail = trim(
    $profileUser['email']
    ?? ''
);

$profileDepartment = $hasDepartmentColumn
    ? trim(
        $profileUser['department']
        ?? ''
    )
    : '';

$memberSince = formatProfileDate(
    $profileUser['created_at']
    ?? null,
    'F j, Y'
);

$lastLogin = formatProfileDate(
    $profileUser['last_login']
    ?? null,
    'F j, Y, h:i A'
);

$messageType =
    $_GET['type'] ?? '';

$messageText =
    $_GET['message'] ?? '';

if (
    !in_array(
        $messageType,
        ['success', 'error'],
        true
    )
) {
    $messageType = '';
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

    <title>Developer Profile | SecureLog</title>

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
            --profile-bg: #020d1b;
            --profile-panel: #06182b;
            --profile-panel-dark: #041321;
            --profile-input: #061522;
            --profile-border: #17334c;

            --profile-blue: #1168f4;
            --profile-blue-light: #2f87ff;
            --profile-cyan: #00c8c8;
            --profile-red: #ff4c5f;
            --profile-green: #23d5a5;

            --profile-text: #f8fafc;
            --profile-muted: #9caabd;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;

            color: var(--profile-text);
            background: var(--profile-bg);

            font-family:
                "Inter",
                "Segoe UI",
                sans-serif;
        }

        body {
            overflow-x: hidden;
        }

        /* =====================================================
           PAGE
           ===================================================== */

        .profile-page {
            min-height: 100vh;
            padding: 38px 30px 30px;

            background:
                radial-gradient(
                    circle at 72% 10%,
                    rgba(47, 135, 255, 0.045),
                    transparent 32%
                ),
                var(--profile-bg);
        }

        .profile-container {
            width: 100%;
            max-width: 1450px;

            margin: 0 auto;
        }

        /* =====================================================
           HEADER
           ===================================================== */

        .profile-header {
            margin-bottom: 24px;
        }

        .profile-header h1 {
            margin: 0 0 8px;

            color: #ffffff;

            font-size: 28px;
            font-weight: 800;
        }

        .profile-header p {
            margin: 0;

            color: #d3dbe4;

            font-size: 14px;
        }

        /* =====================================================
           MESSAGE
           ===================================================== */

        .profile-message {
            margin-bottom: 20px;
            padding: 14px 17px;

            border-radius: 8px;

            font-size: 13px;
            font-weight: 500;
        }

        .profile-message.success {
            color: #5cf1be;
            background: rgba(35, 213, 165, 0.1);

            border: 1px solid rgba(35, 213, 165, 0.32);
        }

        .profile-message.error {
            color: #ff8b97;
            background: rgba(255, 76, 95, 0.1);

            border: 1px solid rgba(255, 76, 95, 0.32);
        }

        /* =====================================================
           TOP GRID
           ===================================================== */

        .profile-grid {
            display: grid;
            grid-template-columns:
                minmax(330px, 0.78fr)
                minmax(0, 1.22fr);

            gap: 18px;

            margin-bottom: 18px;
        }

        .profile-panel {
            padding: 28px;

            background:
                linear-gradient(
                    145deg,
                    rgba(7, 28, 48, 0.98),
                    rgba(3, 17, 31, 0.98)
                );

            border: 1px solid var(--profile-border);
            border-radius: 13px;
        }

        .profile-panel-title {
            margin-bottom: 18px;

            display: flex;
            align-items: center;
            gap: 12px;

            color: #ffffff;

            font-size: 17px;
            font-weight: 800;
        }

        .profile-panel-title i {
            color: var(--profile-blue-light);
            font-size: 19px;
        }

        .profile-panel-subtitle {
            margin: -8px 0 23px;

            color: #bec8d2;

            font-size: 13px;
        }

        /* =====================================================
           PROFILE OVERVIEW
           ===================================================== */

        .profile-overview {
            min-height: 695px;
        }

        .profile-avatar {
            width: 116px;
            height: 116px;

            margin: 20px auto 17px;

            display: flex;
            align-items: center;
            justify-content: center;

            color: #8ec2ff;
            background:
                radial-gradient(
                    circle at 50% 40%,
                    #1b4e93,
                    #0d2e5f
                );

            border: 1px solid rgba(47, 135, 255, 0.35);
            border-radius: 50%;

            font-size: 63px;

            box-shadow:
                0 15px 35px rgba(0, 55, 130, 0.2);
        }

        .profile-overview-name {
            margin-bottom: 10px;

            color: #ffffff;

            font-size: 26px;
            font-weight: 800;
            text-align: center;
        }

        .profile-overview-role {
            margin-bottom: 26px;

            color: var(--profile-blue-light);

            font-size: 15px;
            text-align: center;
        }

        .profile-divider {
            height: 1px;
            margin-bottom: 12px;

            background: var(--profile-border);
        }

        .profile-info-row {
            min-height: 48px;

            display: grid;
            grid-template-columns: 26px 1fr;
            align-items: center;
            gap: 12px;

            color: #ffffff;

            font-size: 14px;
        }

        .profile-info-row i {
            color: #b9c8d9;
            font-size: 18px;
            text-align: center;
        }

        .profile-info-row.muted {
            color: #b8c2ce;
        }

        /* =====================================================
           PROFILE FORM
           ===================================================== */

        .profile-form-group {
            margin-bottom: 19px;
        }

        .profile-form-label {
            display: block;
            margin-bottom: 9px;

            color: #ffffff;

            font-size: 13px;
            font-weight: 700;
        }

        .profile-control {
            width: 100%;
            height: 43px;
            padding: 0 14px;

            color: #ffffff;
            background: rgba(4, 18, 31, 0.9);

            border: 1px solid var(--profile-border);
            border-radius: 7px;

            outline: none;

            font-family: inherit;
            font-size: 13px;

            transition:
                border-color 0.2s ease,
                box-shadow 0.2s ease;
        }

        .profile-control:focus {
            border-color: var(--profile-blue-light);

            box-shadow:
                0 0 0 3px rgba(47, 135, 255, 0.1);
        }

        select.profile-control {
            cursor: pointer;
        }

        select.profile-control option {
            color: #ffffff;
            background: #061522;
        }

        .password-heading {
            margin: 25px 0 18px;

            color: #ffffff;

            font-size: 14px;
            font-weight: 800;
        }

        .password-input-wrapper {
            position: relative;
        }

        .password-input-wrapper .profile-control {
            padding-right: 45px;
        }

        .password-toggle {
            position: absolute;
            top: 50%;
            right: 11px;

            width: 30px;
            height: 30px;

            display: flex;
            align-items: center;
            justify-content: center;

            color: #b7c3cf;
            background: transparent;

            border: none;

            cursor: pointer;

            transform: translateY(-50%);
        }

        .password-toggle:hover {
            color: var(--profile-blue-light);
        }

        /* =====================================================
           FORM ACTIONS
           ===================================================== */

        .profile-actions {
            margin-top: 23px;

            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
        }

        .profile-cancel,
        .profile-save {
            height: 47px;

            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 9px;

            border-radius: 7px;

            font-family: inherit;
            font-size: 13px;
            font-weight: 700;

            cursor: pointer;
        }

        .profile-cancel {
            color: #ffffff;
            background: #101f31;

            border: 1px solid #13283d;
        }

        .profile-cancel:hover {
            border-color: var(--profile-blue-light);
        }

        .profile-save {
            color: #ffffff;
            background:
                linear-gradient(
                    90deg,
                    #1168f4,
                    #0874ff
                );

            border: 1px solid #2582ff;

            box-shadow:
                0 0 18px rgba(17, 104, 244, 0.18);
        }

        .profile-save:hover {
            filter: brightness(1.08);
        }

        /* =====================================================
           SECURITY TIPS
           ===================================================== */

        .security-panel {
            padding: 26px;
        }

        .security-header {
            margin-bottom: 22px;

            display: flex;
            align-items: flex-start;
            gap: 14px;
        }

        .security-header i {
            margin-top: 3px;

            color: var(--profile-blue-light);
            font-size: 20px;
        }

        .security-header h2 {
            margin: 0 0 6px;

            color: #ffffff;

            font-size: 17px;
        }

        .security-header p {
            margin: 0;

            color: #c2ccd6;
            font-size: 12px;
        }

        .security-tips-grid {
            display: grid;
            grid-template-columns:
                repeat(3, minmax(0, 1fr));

            gap: 32px;
        }

        .security-tip {
            display: grid;
            grid-template-columns: 51px 1fr;
            gap: 16px;
            align-items: center;
        }

        .security-tip-icon {
            width: 51px;
            height: 51px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 12px;

            font-size: 21px;
        }

        .security-tip:nth-child(1)
        .security-tip-icon {
            color: #c6ceff;
            background: rgba(86, 100, 180, 0.18);
        }

        .security-tip:nth-child(2)
        .security-tip-icon {
            color: #5eead4;
            background: rgba(0, 190, 170, 0.12);
        }

        .security-tip:nth-child(3)
        .security-tip-icon {
            color: #c4b5fd;
            background: rgba(139, 92, 246, 0.13);
        }

        .security-tip-title {
            margin-bottom: 5px;

            color: #ffffff;

            font-size: 13px;
            font-weight: 700;
        }

        .security-tip-text {
            color: #aeb9c6;

            font-size: 11px;
            line-height: 1.5;
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 1050px) {
            .profile-grid {
                grid-template-columns: 1fr;
            }

            .profile-overview {
                min-height: auto;
            }
        }

        @media (max-width: 800px) {
            .profile-page {
                padding: 25px 16px;
            }

            .security-tips-grid {
                grid-template-columns: 1fr;
                gap: 22px;
            }
        }

        @media (max-width: 550px) {
            .profile-panel {
                padding: 20px;
            }

            .profile-actions {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>

    <!-- Existing developer sidebar -->
    <?php
    require __DIR__ . '/../Sidebar/sidebaruser.php';
    ?>

    <main class="developer-page-content profile-page">

        <div class="profile-container">

            <!-- Header -->
            <header class="profile-header">
                <h1>Developer Profile</h1>

                <p>
                    View and manage your personal information.
                </p>
            </header>

            <!-- Message -->
            <?php if (
                $messageType !== ''
                && $messageText !== ''
            ): ?>

                <div
                    class="profile-message <?= htmlspecialchars(
                        $messageType
                    ); ?>"
                >
                    <?= htmlspecialchars(
                        $messageText,
                        ENT_QUOTES,
                        'UTF-8'
                    ); ?>
                </div>

            <?php endif; ?>

            <div class="profile-grid">

                <!-- =================================================
                     PROFILE OVERVIEW
                     ================================================= -->

                <section class="profile-panel profile-overview">

                    <div class="profile-panel-title">
                        <i class="fa-regular fa-user"></i>
                        Profile Overview
                    </div>

                    <div class="profile-avatar">
                        <i class="fa-solid fa-user"></i>
                    </div>

                    <div class="profile-overview-name">
                        <?= htmlspecialchars(
                            $profileName,
                            ENT_QUOTES,
                            'UTF-8'
                        ); ?>
                    </div>

                    <div class="profile-overview-role">
                        <?= htmlspecialchars(
                            ucfirst(
                                strtolower(
                                    $profileUser['role']
                                    ?? 'developer'
                                )
                            )
                        ); ?>
                    </div>

                    <div class="profile-divider"></div>

                    <div class="profile-info-row">
                        <i class="fa-regular fa-envelope"></i>

                        <span>
                            <?= htmlspecialchars(
                                $profileEmail,
                                ENT_QUOTES,
                                'UTF-8'
                            ); ?>
                        </span>
                    </div>

                    <?php if ($hasDepartmentColumn): ?>
                        <div class="profile-info-row">
                            <i class="fa-regular fa-building"></i>

                            <span>
                                <?= htmlspecialchars(
                                    $profileDepartment !== ''
                                        ? $profileDepartment
                                        : 'Not specified',
                                    ENT_QUOTES,
                                    'UTF-8'
                                ); ?>
                            </span>
                        </div>
                    <?php endif; ?>

                    <div class="profile-info-row muted">
                        <i class="fa-regular fa-calendar"></i>

                        <span>
                            Member since
                            <?= htmlspecialchars(
                                $memberSince,
                                ENT_QUOTES,
                                'UTF-8'
                            ); ?>
                        </span>
                    </div>

                    <div class="profile-info-row muted">
                        <i class="fa-regular fa-clock"></i>

                        <span>
                            Last login:
                            <?= htmlspecialchars(
                                $lastLogin,
                                ENT_QUOTES,
                                'UTF-8'
                            ); ?>
                        </span>
                    </div>

                </section>

                <!-- =================================================
                     EDIT PROFILE
                     ================================================= -->

                <section class="profile-panel">

                    <div class="profile-panel-title">
                        <i class="fa-solid fa-pen-ruler"></i>
                        Edit Profile
                    </div>

                    <p class="profile-panel-subtitle">
                        Update your personal information.
                    </p>

                    <form
                        method="POST"
                        action="profile.php"
                        autocomplete="off"
                    >
                        <input
                            type="hidden"
                            name="csrf_token"
                            value="<?= htmlspecialchars(
                                $csrfToken,
                                ENT_QUOTES,
                                'UTF-8'
                            ); ?>"
                        >

                        <!-- Full name -->
                        <div class="profile-form-group">

                            <label
                                for="fullname"
                                class="profile-form-label"
                            >
                                Full Name
                            </label>

                            <input
                                type="text"
                                id="fullname"
                                name="fullname"
                                class="profile-control"
                                value="<?= htmlspecialchars(
                                    $profileName,
                                    ENT_QUOTES,
                                    'UTF-8'
                                ); ?>"
                                required
                            >

                        </div>

                        <!-- Email -->
                        <div class="profile-form-group">

                            <label
                                for="email"
                                class="profile-form-label"
                            >
                                Email Address
                            </label>

                            <input
                                type="email"
                                id="email"
                                name="email"
                                class="profile-control"
                                value="<?= htmlspecialchars(
                                    $profileEmail,
                                    ENT_QUOTES,
                                    'UTF-8'
                                ); ?>"
                                required
                            >

                        </div>

                        <!-- Department -->
                        <?php if ($hasDepartmentColumn): ?>

                            <div class="profile-form-group">

                                <label
                                    for="department"
                                    class="profile-form-label"
                                >
                                    Department
                                </label>

                                <select
                                    id="department"
                                    name="department"
                                    class="profile-control"
                                >
                                    <?php
                                    $departments = [
                                        'Security Engineering',
                                        'Software Development',
                                        'Cyber Security',
                                        'DevOps',
                                        'Quality Assurance',
                                        'IT Support',
                                        'Other'
                                    ];
                                    ?>

                                    <option value="">
                                        Select department
                                    </option>

                                    <?php foreach (
                                        $departments
                                        as $departmentOption
                                    ): ?>

                                        <option
                                            value="<?= htmlspecialchars(
                                                $departmentOption,
                                                ENT_QUOTES,
                                                'UTF-8'
                                            ); ?>"
                                            <?= $profileDepartment
                                                === $departmentOption
                                                    ? 'selected'
                                                    : ''; ?>
                                        >
                                            <?= htmlspecialchars(
                                                $departmentOption,
                                                ENT_QUOTES,
                                                'UTF-8'
                                            ); ?>
                                        </option>

                                    <?php endforeach; ?>

                                </select>

                            </div>

                        <?php endif; ?>

                        <div class="password-heading">
                            Change Password
                        </div>

                        <!-- Current password -->
                        <div class="profile-form-group">

                            <label
                                for="current_password"
                                class="profile-form-label"
                            >
                                Current Password
                            </label>

                            <div class="password-input-wrapper">

                                <input
                                    type="password"
                                    id="current_password"
                                    name="current_password"
                                    class="profile-control"
                                    placeholder="Enter current password"
                                >

                                <button
                                    type="button"
                                    class="password-toggle"
                                    data-target="current_password"
                                    aria-label="Show current password"
                                >
                                    <i class="fa-regular fa-eye"></i>
                                </button>

                            </div>

                        </div>

                        <!-- New password -->
                        <div class="profile-form-group">

                            <label
                                for="new_password"
                                class="profile-form-label"
                            >
                                New Password
                            </label>

                            <div class="password-input-wrapper">

                                <input
                                    type="password"
                                    id="new_password"
                                    name="new_password"
                                    class="profile-control"
                                    placeholder="Minimum 8 characters"
                                    minlength="8"
                                >

                                <button
                                    type="button"
                                    class="password-toggle"
                                    data-target="new_password"
                                    aria-label="Show new password"
                                >
                                    <i class="fa-regular fa-eye"></i>
                                </button>

                            </div>

                        </div>

                        <!-- Confirm password -->
                        <div class="profile-form-group">

                            <label
                                for="confirm_new_password"
                                class="profile-form-label"
                            >
                                Confirm New Password
                            </label>

                            <div class="password-input-wrapper">

                                <input
                                    type="password"
                                    id="confirm_new_password"
                                    name="confirm_new_password"
                                    class="profile-control"
                                    placeholder="Confirm new password"
                                    minlength="8"
                                >

                                <button
                                    type="button"
                                    class="password-toggle"
                                    data-target="confirm_new_password"
                                    aria-label="Show confirm password"
                                >
                                    <i class="fa-regular fa-eye"></i>
                                </button>

                            </div>

                        </div>

                        <!-- Buttons -->
                        <div class="profile-actions">

                            <button
                                type="reset"
                                class="profile-cancel"
                            >
                                Cancel
                            </button>

                            <button
                                type="submit"
                                class="profile-save"
                            >
                                <i class="fa-regular fa-floppy-disk"></i>
                                Save Changes
                            </button>

                        </div>

                    </form>

                </section>

            </div>

            <!-- =================================================
                 SECURITY TIPS
                 ================================================= -->

            <section class="profile-panel security-panel">

                <div class="security-header">

                    <i class="fa-solid fa-shield-halved"></i>

                    <div>
                        <h2>Security Tips</h2>

                        <p>
                            Keep your account secure with
                            these recommendations.
                        </p>
                    </div>

                </div>

                <div class="security-tips-grid">

                    <div class="security-tip">

                        <div class="security-tip-icon">
                            <i class="fa-solid fa-lock"></i>
                        </div>

                        <div>
                            <div class="security-tip-title">
                                Use a strong password
                            </div>

                            <div class="security-tip-text">
                                Use at least 8 characters with
                                a mix of letters, numbers,
                                and symbols.
                            </div>
                        </div>

                    </div>

                    <div class="security-tip">

                        <div class="security-tip-icon">
                            <i class="fa-solid fa-rotate"></i>
                        </div>

                        <div>
                            <div class="security-tip-title">
                                Update your password regularly
                            </div>

                            <div class="security-tip-text">
                                Change your password periodically
                                to keep your account secure.
                            </div>
                        </div>

                    </div>

                    <div class="security-tip">

                        <div class="security-tip-icon">
                            <i class="fa-solid fa-user-shield"></i>
                        </div>

                        <div>
                            <div class="security-tip-title">
                                Do not share your credentials
                            </div>

                            <div class="security-tip-text">
                                Never share your login information
                                with anyone.
                            </div>
                        </div>

                    </div>

                </div>

            </section>

        </div>

    </main>

    <script>
        /*
        |--------------------------------------------------------------------------
        | Show and hide password fields
        |--------------------------------------------------------------------------
        */

        document
            .querySelectorAll('.password-toggle')
            .forEach(button => {
                button.addEventListener(
                    'click',
                    function () {
                        const targetId =
                            this.dataset.target;

                        const input =
                            document.getElementById(targetId);

                        const icon =
                            this.querySelector('i');

                        if (!input) {
                            return;
                        }

                        if (input.type === 'password') {
                            input.type = 'text';

                            icon.classList.remove(
                                'fa-eye'
                            );

                            icon.classList.add(
                                'fa-eye-slash'
                            );
                        } else {
                            input.type = 'password';

                            icon.classList.remove(
                                'fa-eye-slash'
                            );

                            icon.classList.add(
                                'fa-eye'
                            );
                        }
                    }
                );
            });

        /*
        |--------------------------------------------------------------------------
        | Confirm new password in the browser
        |--------------------------------------------------------------------------
        */

        const newPasswordInput =
            document.getElementById(
                'new_password'
            );

        const confirmPasswordInput =
            document.getElementById(
                'confirm_new_password'
            );

        function validateNewPasswords() {
            if (
                confirmPasswordInput.value !== ''
                && newPasswordInput.value
                    !== confirmPasswordInput.value
            ) {
                confirmPasswordInput.setCustomValidity(
                    'New passwords do not match.'
                );
            } else {
                confirmPasswordInput.setCustomValidity('');
            }
        }

        newPasswordInput.addEventListener(
            'input',
            validateNewPasswords
        );

        confirmPasswordInput.addEventListener(
            'input',
            validateNewPasswords
        );
    </script>

</body>
</html>
```
