<?php
/**
 * SecureLog User Management
 * File: Dashboard/ManageUser/user.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';
require_once __DIR__ . '/../Notification/NotificationService.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}

/* ============================================================
   DATABASE AND ACTIVITY LOGGER
   ============================================================ */

require_once __DIR__ . '/../Engine_Process/connection.php';
require_once __DIR__ . '/../Dashboard/ActivityLogger.php';
require_once __DIR__. '/../Notification/NotificationService.php';


/* Support both session key formats */
$currentAdminId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

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

function redirectWithMessage(
    string $type,
    string $message,
    int $page = 1
): void {
    $query = http_build_query([
        'page' => $page,
        'type' => $type,
        'message' => $message
    ]);

    header("Location: user.php?{$query}");
    exit();
}

function roleClass(string $role): string
{
    return match (strtolower($role)) {
        'admin' => 'role-admin',
        'developer' => 'role-developer',
        'guest' => 'role-guest',
        default => 'role-default'
    };
}

function displayRole(string $role): string
{
    return ucfirst(strtolower($role));
}

function displayDate(?string $date): string
{
    if (
        $date === null
        || trim($date) === ''
        || $date === '0000-00-00 00:00:00'
    ) {
        return 'Never';
    }

    $timestamp = strtotime($date);

    if ($timestamp === false) {
        return htmlspecialchars($date);
    }

    return date('Y-m-d H:i:s', $timestamp);
}

/* ============================================================
   PROCESS USER ACTIONS
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';

    $returnPage = max(
        1,
        (int) ($_POST['return_page'] ?? 1)
    );

    if (
        !hash_equals(
            $_SESSION['csrf_token'],
            $submittedToken
        )
    ) {
        redirectWithMessage(
            'error',
            'Invalid request token. Please try again.',
            $returnPage
        );
    }

    $action = $_POST['action'] ?? '';
    $targetUserId = (int) (
        $_POST['target_user_id'] ?? 0
    );

    if ($targetUserId <= 0) {
        redirectWithMessage(
            'error',
            'Invalid user account selected.',
            $returnPage
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Prevent administrator from disabling their own account
    |--------------------------------------------------------------------------
    */

    if (
        $action === 'toggle_status'
        && $targetUserId === $currentAdminId
    ) {
        redirectWithMessage(
            'error',
            'You cannot deactivate your own account.',
            $returnPage
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Approve or deactivate user
    |--------------------------------------------------------------------------
    */

   if ($action === 'toggle_status') 
    {

        $newStatus = isset($_POST['new_status'])
            ? (int) $_POST['new_status']
            : 0;

        $newStatus = $newStatus === 1 ? 1 : 0;

        /*
        |--------------------------------------------------------------------------
        | Get target user information
        |--------------------------------------------------------------------------
        */

        $userStatement = $conn->prepare(
            "SELECT UserID, fullname, email, role
            FROM users
            WHERE UserID = ?"
        );

        if (!$userStatement) {
            redirectWithMessage(
                'error',
                'Unable to prepare user lookup.',
                $returnPage
            );
        }

        $userStatement->bind_param(
            'i',
            $targetUserId
        );

        $userStatement->execute();

        $targetUser = $userStatement
            ->get_result()
            ->fetch_assoc();

        $userStatement->close();

        if (!$targetUser) {
            redirectWithMessage(
                'error',
                'User account not found.',
                $returnPage
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Database Transaction
        |--------------------------------------------------------------------------
        |
        | Both users.is_active and developer.registration_status
        | must stay synchronized.
        |
        */

        $conn->begin_transaction();

        try {

            /*
            |--------------------------------------------------------------------------
            | Update main user account
            |--------------------------------------------------------------------------
            */

            $statement = $conn->prepare(
                "UPDATE users
                SET is_active = ?
                WHERE UserID = ?"
            );

            if (!$statement) {
                throw new Exception(
                    'Unable to prepare user status update.'
                );
            }

            $statement->bind_param(
                'ii',
                $newStatus,
                $targetUserId
            );

            if (!$statement->execute()) {
                throw new Exception(
                    $statement->error
                );
            }

            $statement->close();


            /*
            |--------------------------------------------------------------------------
            | Update developer registration status
            |--------------------------------------------------------------------------
            */

            if (
                strtolower($targetUser['role'])
                === 'developer'
            ) {

                $registrationStatus =
                    $newStatus === 1
                        ? 'Approved'
                        : 'Pending';

                $developerStatement = $conn->prepare(
                    "UPDATE developer
                    SET registration_status = ?
                    WHERE UserID = ?"
                );

                if (!$developerStatement) {
                    throw new Exception(
                        'Unable to prepare developer status update.'
                    );
                }

                $developerStatement->bind_param(
                    'si',
                    $registrationStatus,
                    $targetUserId
                );

                if (!$developerStatement->execute()) {
                    throw new Exception(
                        $developerStatement->error
                    );
                }

                $developerStatement->close();
            }


            /*
            |--------------------------------------------------------------------------
            | Everything successful
            |--------------------------------------------------------------------------
            */

            $conn->commit();

            /*
            |--------------------------------------------------------------------------
            | Send Approval Email
            |--------------------------------------------------------------------------
            */

            $emailSent = null;

            if (
                $newStatus === 1
                && strtolower($targetUser['role']) === 'developer'
            ) {

                $emailSent = sendApprovalNotification(
                    $targetUser['email'],
                    $targetUser['fullname']
                );
            }

            if (
                $newStatus === 1
                && strtolower($targetUser['role']) === 'developer'
            ) {

                $emailSent = sendApprovalNotification(
                    $targetUser['email'],
                    $targetUser['fullname']
                );

                if (
                    $currentAdminId > 0
                    && function_exists('log_activity')
                ) {

                    if ($emailSent) {

                        log_activity(
                            'EMAIL_NOTIFICATION_SENT',
                            $currentAdminId,
                            "Approval email sent to User ID {$targetUserId}"
                        );

                    } else {

                        log_activity(
                            'EMAIL_NOTIFICATION_FAILED',
                            $currentAdminId,
                            "Approval email failed for User ID {$targetUserId}"
                        );
                    }
                }
            }


            /*
            |--------------------------------------------------------------------------
            | Activity Log
            |--------------------------------------------------------------------------
            */

            $statusLabel =
                $newStatus === 1
                    ? 'approved'
                    : 'set to pending';

            if (
                $currentAdminId > 0
                && function_exists('log_activity')
            ) {

                /*
                * For now we keep your existing logger.
                *
                * Later I recommend creating:
                * LOG_USER_APPROVED
                * LOG_USER_PENDING
                */

                if (defined('LOG_USER_DEACTIVATED')) {

                    log_activity(
                        LOG_USER_DEACTIVATED,
                        $currentAdminId,
                        "User ID {$targetUserId} was {$statusLabel}"
                    );
                }
            }


            /*
            |--------------------------------------------------------------------------
            | EMAIL NOTIFICATION WILL GO HERE LATER
            |--------------------------------------------------------------------------
            |
            | IMPORTANT:
            | Email runs AFTER database commit.
            |
            | Example later:
            |
            | if ($newStatus === 1) {
            |     sendApprovalNotification(
            |         $targetUser['email'],
            |         $targetUser['fullname']
            |     );
            | }
            |
            */


            if ($newStatus === 1) {

                if ($emailSent === true) {

                    $message =
                        'Developer account approved and '
                        . 'notification email sent successfully.';

                } else {

                    $message =
                        'Developer account approved successfully, '
                        . 'but the notification email could not be sent.';
                }

            } else {

                $message =
                    'User account successfully set to pending.';
            }

            redirectWithMessage(
                'success',
                $message,
                $returnPage
            );

        } catch (Throwable $exception) {

            $conn->rollback();

            redirectWithMessage(
                'error',
                'Failed to update user status: '
                . $exception->getMessage(),
                $returnPage
            );
        }
    }
}

/* ============================================================
   PAGINATION
   ============================================================ */

$usersPerPage = 8;

$currentPageNumber = max(
    1,
    (int) ($_GET['page'] ?? 1)
);

$totalUsers = 0;

$countResult = $conn->query(
    'SELECT COUNT(*) AS total
     FROM users'
);

if ($countResult) {
    $countRow = $countResult->fetch_assoc();

    $totalUsers = (int) (
        $countRow['total'] ?? 0
    );
}

$totalPages = max(
    1,
    (int) ceil($totalUsers / $usersPerPage)
);

if ($currentPageNumber > $totalPages) {
    $currentPageNumber = $totalPages;
}

$offset = (
    $currentPageNumber - 1
) * $usersPerPage;

/* ============================================================
   GET USERS
   ============================================================ */

$users = [];

$userQuery = "
    SELECT
        UserID,
        fullname,
        username,
        email,
        role,
        is_active,
        created_at,
        last_login
    FROM users
    ORDER BY UserID DESC
    LIMIT {$usersPerPage}
    OFFSET {$offset}
";

$userResult = $conn->query($userQuery);

$queryError = '';

if ($userResult) {
    while ($user = $userResult->fetch_assoc()) {
        $users[] = $user;
    }
} else {
    $queryError = $conn->error;
}

/* ============================================================
   RECORD SUMMARY
   ============================================================ */

$startingRecord = $totalUsers > 0
    ? $offset + 1
    : 0;

$endingRecord = min(
    $offset + $usersPerPage,
    $totalUsers
);

/* ============================================================
   FLASH MESSAGE
   ============================================================ */

$messageType = $_GET['type'] ?? '';
$messageText = $_GET['message'] ?? '';

$allowedMessageTypes = [
    'success',
    'error'
];

if (
    !in_array(
        $messageType,
        $allowedMessageTypes,
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

    <title>User Management | SecureLog</title>

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
            --users-bg: #020c17;
            --users-panel: #061729;
            --users-panel-dark: #03111f;
            --users-border: #173247;

            --users-orange: #ff6500;
            --users-orange-light: #ff8100;

            --users-green: #00d98b;
            --users-yellow: #ff9d00;
            --users-red: #ff4355;
            --users-blue: #38bdf8;

            --users-text: #f8fafc;
            --users-muted: #9eabb8;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
            background: var(--users-bg);
            color: var(--users-text);
            font-family: "Inter", "Segoe UI", sans-serif;
        }

        body {
            overflow-x: hidden;
        }

        /* =====================================================
           PAGE BESIDE SIDEBAR
           ===================================================== */

        .users-page {
            min-height: 100vh;
            padding: 15px 13px;

            background:
                radial-gradient(
                    circle at 72% 10%,
                    rgba(56, 189, 248, 0.035),
                    transparent 30%
                ),
                var(--users-bg);
        }

        .users-container {
            width: 100%;
            max-width: 1500px;
            min-height: calc(100vh - 30px);

            margin: 0 auto;

            background:
                linear-gradient(
                    145deg,
                    rgba(5, 24, 40, 0.98),
                    rgba(2, 14, 26, 0.98)
                );

            border: 1px solid var(--users-border);
            border-radius: 14px;

            overflow: hidden;
        }

        /* =====================================================
           HEADER
           ===================================================== */

        .users-header {
            min-height: 140px;
            padding: 30px 31px;

            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 25px;
        }

        .users-heading {
            display: flex;
            align-items: flex-start;
            gap: 18px;
        }

        .users-heading-icon {
            width: 54px;
            height: 54px;

            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;

            color: var(--users-orange);
            background: rgba(255, 101, 0, 0.13);

            border-radius: 50%;

            font-size: 26px;
        }

        .users-heading-text h1 {
            margin: 3px 0 8px;

            color: #ffffff;

            font-size: 25px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .users-heading-text p {
            margin: 0;

            color: #aeb9c4;

            font-size: 14px;
        }

        .add-user-button {
            min-width: 145px;
            min-height: 52px;
            padding: 0 20px;

            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 11px;

            color: #ffffff;
            background:
                linear-gradient(
                    90deg,
                    var(--users-orange),
                    var(--users-orange-light)
                );

            border: none;
            border-radius: 8px;

            text-decoration: none;

            font-size: 14px;
            font-weight: 700;

            box-shadow:
                0 0 20px rgba(255, 101, 0, 0.15);

            transition:
                filter 0.2s ease,
                transform 0.2s ease;
        }

        .add-user-button:hover {
            color: #ffffff;
            filter: brightness(1.08);
            transform: translateY(-1px);
        }

        /* =====================================================
           FLASH MESSAGES
           ===================================================== */

        .message-area {
            padding: 0 25px 16px;
        }

        .flash-message {
            padding: 13px 16px;

            border-radius: 7px;

            font-size: 13px;
            font-weight: 500;
        }

        .flash-message.success {
            color: #52ecb2;
            background: rgba(0, 217, 139, 0.1);
            border: 1px solid rgba(0, 217, 139, 0.3);
        }

        .flash-message.error {
            color: #ff8490;
            background: rgba(255, 67, 85, 0.1);
            border: 1px solid rgba(255, 67, 85, 0.3);
        }

        /* =====================================================
           TABLE PANEL
           ===================================================== */

        .users-panel {
            margin: 0 25px 24px;
            padding: 0 20px 20px;

            background:
                linear-gradient(
                    145deg,
                    rgba(7, 27, 45, 0.98),
                    rgba(3, 17, 31, 0.98)
                );

            border: 1px solid rgba(23, 50, 71, 0.7);
            border-radius: 13px;
        }

        .users-table-wrapper {
            width: 100%;
            overflow-x: auto;
        }

        .users-table {
            width: 100%;
            min-width: 950px;

            border-collapse: collapse;
        }

        .users-table thead {
            background: rgba(2, 14, 26, 0.88);
        }

        .users-table th {
            padding: 17px 14px;

            color: #aab6c2;

            border: 1px solid rgba(23, 50, 71, 0.75);

            font-size: 12px;
            font-weight: 600;
            text-align: left;
            text-transform: uppercase;
        }

        .users-table td {
            padding: 18px 14px;

            color: #ffffff;

            border-bottom: 1px solid rgba(23, 50, 71, 0.62);

            font-size: 14px;
            vertical-align: middle;
        }

        .users-table tbody tr {
            transition: background-color 0.2s ease;
        }

        .users-table tbody tr:hover {
            background: rgba(255, 101, 0, 0.03);
        }

        .user-id {
            color: #ffffff;
            font-weight: 700;
        }

        .user-fullname {
            color: #ffffff;
            font-weight: 500;
        }

        .user-email {
            color: #ffffff;
        }

        /* =====================================================
           ROLE BADGES
           ===================================================== */

        .role-badge {
            padding: 5px 10px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            border-radius: 5px;

            font-size: 12px;
            font-weight: 600;
        }

        .role-admin {
            color: #ff9755;
            background: rgba(255, 101, 0, 0.12);
        }

        .role-developer {
            color: #8edcff;
            background: rgba(56, 189, 248, 0.12);
        }

        .role-guest {
            color: #c1cad4;
            background: rgba(158, 171, 184, 0.12);
        }

        .role-default {
            color: #ffffff;
            background: rgba(255, 255, 255, 0.08);
        }

        /* =====================================================
           STATUS BADGES
           ===================================================== */

        .status-badge {
            min-width: 84px;
            padding: 6px 11px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            background: transparent;

            border-radius: 5px;

            font-size: 12px;
            font-weight: 600;
        }

        .status-approved {
            color: var(--users-green);
            border: 1px solid rgba(0, 217, 139, 0.7);
        }

        .status-pending {
            color: var(--users-yellow);
            border: 1px solid rgba(255, 157, 0, 0.8);
        }

        .last-login {
            color: #ffffff;
            white-space: nowrap;
        }

        /* =====================================================
           ACTION BUTTONS
           ===================================================== */

        .actions-cell {
            position: relative;

            display: flex;
            align-items: center;
            gap: 12px;
        }

        .action-icon-button {
            width: 39px;
            height: 39px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            color: #ffffff;
            background: #101f2d;

            border: 1px solid rgba(255, 255, 255, 0.02);
            border-radius: 7px;

            text-decoration: none;
            cursor: pointer;

            font-size: 14px;

            transition:
                color 0.2s ease,
                background-color 0.2s ease,
                border-color 0.2s ease;
        }

        .action-icon-button:hover {
            color: var(--users-orange);
            background: rgba(255, 101, 0, 0.1);
            border-color: rgba(255, 101, 0, 0.35);
        }

        .action-menu-container {
            position: relative;
        }

        .action-dropdown {
            position: absolute;
            top: 45px;
            right: 0;
            z-index: 50;

            width: 180px;
            padding: 7px;

            display: none;

            background: #071827;

            border: 1px solid var(--users-border);
            border-radius: 8px;

            box-shadow:
                0 14px 30px rgba(0, 0, 0, 0.4);
        }

        .action-dropdown.open {
            display: block;
        }

        .dropdown-form {
            margin: 0;
        }

        .dropdown-action {
            width: 100%;
            min-height: 39px;
            padding: 0 10px;

            display: flex;
            align-items: center;
            gap: 10px;

            color: #ffffff;
            background: transparent;

            border: none;
            border-radius: 5px;

            font-family: inherit;
            font-size: 12px;
            text-align: left;

            cursor: pointer;
        }

        .dropdown-action:hover {
            background: rgba(255, 101, 0, 0.1);
        }

        .dropdown-action.approve {
            color: var(--users-green);
        }

        .dropdown-action.deactivate {
            color: var(--users-red);
        }

        .dropdown-note {
            padding: 9px 10px;

            color: var(--users-muted);

            font-size: 11px;
        }

        /* =====================================================
           EMPTY AND ERROR
           ===================================================== */

        .table-message {
            padding: 45px 20px;

            color: var(--users-muted);

            text-align: center;
        }

        .table-message i {
            display: block;
            margin-bottom: 12px;

            color: var(--users-orange);

            font-size: 28px;
        }

        /* =====================================================
           TABLE FOOTER
           ===================================================== */

        .users-table-footer {
            padding: 24px 7px 7px;

            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }

        .records-summary {
            color: #bdc7d1;

            font-size: 13px;
        }

        .pagination {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .page-link {
            width: 44px;
            height: 44px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            color: #a9b5c0;
            background: #041321;

            border: 1px solid var(--users-border);
            border-radius: 7px;

            text-decoration: none;

            transition:
                color 0.2s ease,
                background-color 0.2s ease,
                border-color 0.2s ease;
        }

        .page-link:hover {
            color: #ffffff;
            border-color: var(--users-orange);
            background: rgba(255, 101, 0, 0.1);
        }

        .page-link.active {
            color: #ffffff;
            background: var(--users-orange);
            border-color: var(--users-orange);

            box-shadow:
                0 0 17px rgba(255, 101, 0, 0.25);
        }

        .page-link.disabled {
            color: #50606e;

            pointer-events: none;
            opacity: 0.55;
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 800px) {
            .users-page {
                padding: 10px;
            }

            .users-header {
                padding: 25px 20px;
            }

            .users-panel {
                margin-left: 12px;
                margin-right: 12px;
            }
        }

        @media (max-width: 600px) {
            .users-header {
                flex-direction: column;
            }

            .add-user-button {
                width: 100%;
            }

            .users-table-footer {
                flex-direction: column;
                align-items: flex-start;
            }

            .pagination {
                align-self: center;
            }
        }
    </style>
</head>

<body>

    <!-- Existing admin sidebar -->
    <?php
    require __DIR__ . '/../Sidebar/sidebaradmin.php';
    ?>

    <main class="admin-page-content users-page">

        <div class="users-container">

            <!-- Header -->
            <header class="users-header">

                <div class="users-heading">

                    <div class="users-heading-icon">
                        <i class="fa-solid fa-users"></i>
                    </div>

                    <div class="users-heading-text">
                        <h1>User Management</h1>

                        <p>
                            View and manage all user accounts
                            in the system.
                        </p>
                    </div>

                </div>

                <a
                    href="addUser.php"
                    class="add-user-button"
                >
                    <i class="fa-solid fa-plus"></i>
                    Add User
                </a>

            </header>

            <!-- Message -->
            <?php if (
                $messageType !== ''
                && $messageText !== ''
            ): ?>

                <div class="message-area">

                    <div
                        class="flash-message <?= htmlspecialchars(
                            $messageType
                        ); ?>"
                    >
                        <?= htmlspecialchars(
                            $messageText,
                            ENT_QUOTES,
                            'UTF-8'
                        ); ?>
                    </div>

                </div>

            <?php endif; ?>

            <!-- Query error -->
            <?php if ($queryError !== ''): ?>

                <div class="message-area">

                    <div class="flash-message error">
                        Database error:
                        <?= htmlspecialchars(
                            $queryError,
                            ENT_QUOTES,
                            'UTF-8'
                        ); ?>
                    </div>

                </div>

            <?php endif; ?>

            <!-- Users table -->
            <section class="users-panel">

                <div class="users-table-wrapper">

                    <table class="users-table">

                        <thead>
                            <tr>
                                <th>User ID</th>
                                <th>Full Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Status</th>
                                <th>Last Login</th>
                                <th>Actions</th>
                            </tr>
                        </thead>

                        <tbody>

                            <?php if (!empty($users)): ?>

                                <?php foreach ($users as $user): ?>

                                    <?php
                                    $userId = (int) (
                                        $user['UserID'] ?? 0
                                    );

                                    $isActive = (int) (
                                        $user['is_active'] ?? 0
                                    ) === 1;

                                    $userRole = trim(
                                        $user['role'] ?? 'guest'
                                    );
                                    ?>

                                    <tr>

                                        <td class="user-id">
                                            #<?= $userId; ?>
                                        </td>

                                        <td class="user-fullname">
                                            <?= htmlspecialchars(
                                                $user['fullname']
                                                    ?? 'Unknown User',
                                                ENT_QUOTES,
                                                'UTF-8'
                                            ); ?>
                                        </td>

                                        <td class="user-email">
                                            <?= htmlspecialchars(
                                                $user['email'] ?? '-',
                                                ENT_QUOTES,
                                                'UTF-8'
                                            ); ?>
                                        </td>

                                        <td>
                                            <span
                                                class="role-badge <?= roleClass(
                                                    $userRole
                                                ); ?>"
                                            >
                                                <?= htmlspecialchars(
                                                    displayRole(
                                                        $userRole
                                                    )
                                                ); ?>
                                            </span>
                                        </td>

                                        <td>
                                            <span
                                                class="status-badge <?= $isActive
                                                    ? 'status-approved'
                                                    : 'status-pending'; ?>"
                                            >
                                                <?= $isActive
                                                    ? 'Approved'
                                                    : 'Pending'; ?>
                                            </span>
                                        </td>

                                        <td class="last-login">
                                            <?= htmlspecialchars(
                                                displayDate(
                                                    $user['last_login']
                                                        ?? null
                                                )
                                            ); ?>
                                        </td>

                                      <td>
                                            <div class="actions-cell">

                                                <!-- Edit user -->
                                                <a
                                                    href="editUser.php?user_id=<?= urlencode((string) $userId); ?>"
                                                    class="action-icon-button"
                                                    title="Edit user"
                                                >
                                                    <i class="fa-solid fa-pen"></i>
                                                </a>

                                                <!-- More actions -->
                                                <div class="action-menu-container">

                                                    <button
                                                        type="button"
                                                        class="action-icon-button menu-toggle"
                                                        title="More actions"
                                                        data-menu="menu-<?= $userId; ?>"
                                                    >
                                                        <i class="fa-solid fa-ellipsis-vertical"></i>
                                                    </button>

                                                    <div
                                                        class="action-dropdown"
                                                        id="menu-<?= $userId; ?>"
                                                    >
                                                        <?php if ($userId === $currentAdminId): ?>

                                                            <div class="dropdown-note">
                                                                This is your account.
                                                            </div>

                                                        <?php else: ?>

                                                            <form
                                                                method="POST"
                                                                action="user.php"
                                                                class="dropdown-form"
                                                            >
                                                                <input
                                                                    type="hidden"
                                                                    name="csrf_token"
                                                                    value="<?= htmlspecialchars($csrfToken); ?>"
                                                                >

                                                                <input
                                                                    type="hidden"
                                                                    name="return_page"
                                                                    value="<?= $currentPageNumber; ?>"
                                                                >

                                                                <input
                                                                    type="hidden"
                                                                    name="action"
                                                                    value="toggle_status"
                                                                >

                                                                <input
                                                                    type="hidden"
                                                                    name="target_user_id"
                                                                    value="<?= $userId; ?>"
                                                                >

                                                                <input
                                                                    type="hidden"
                                                                    name="new_status"
                                                                    value="<?= $isActive ? 0 : 1; ?>"
                                                                >

                                                                <button
                                                                    type="submit"
                                                                    class="dropdown-action <?= $isActive
                                                                        ? 'deactivate'
                                                                        : 'approve'; ?>"
                                                                >
                                                                    <i class="fa-solid <?= $isActive
                                                                        ? 'fa-user-slash'
                                                                        : 'fa-user-check'; ?>"></i>

                                                                    <?= $isActive
                                                                        ? 'Set as Pending'
                                                                        : 'Approve User'; ?>
                                                                </button>
                                                            </form>

                                                        <?php endif; ?>
                                                    </div>

                                                </div>
                                            </div>
                                        </td>

                                    </tr>

                                <?php endforeach; ?>

                            <?php else: ?>

                                <tr>
                                    <td colspan="7">

                                        <div class="table-message">
                                            <i class="fa-solid fa-users-slash"></i>
                                            No user accounts found.
                                        </div>

                                    </td>
                                </tr>

                            <?php endif; ?>

                        </tbody>

                    </table>

                </div>

                <!-- Footer -->
                <div class="users-table-footer">

                    <div class="records-summary">
                        Showing
                        <?= $startingRecord; ?>
                        to
                        <?= $endingRecord; ?>
                        of
                        <?= $totalUsers; ?>
                        users
                    </div>

                    <nav
                        class="pagination"
                        aria-label="User pagination"
                    >

                        <!-- Previous -->
                        <a
                            href="?page=<?= max(
                                1,
                                $currentPageNumber - 1
                            ); ?>"
                            class="page-link <?= $currentPageNumber <= 1
                                ? 'disabled'
                                : ''; ?>"
                            aria-label="Previous page"
                        >
                            <i class="fa-solid fa-chevron-left"></i>
                        </a>

                        <?php
                        $startPage = max(
                            1,
                            $currentPageNumber - 2
                        );

                        $endPage = min(
                            $totalPages,
                            $currentPageNumber + 2
                        );
                        ?>

                        <?php for (
                            $pageNumber = $startPage;
                            $pageNumber <= $endPage;
                            $pageNumber++
                        ): ?>

                            <a
                                href="?page=<?= $pageNumber; ?>"
                                class="page-link <?= $pageNumber
                                    === $currentPageNumber
                                        ? 'active'
                                        : ''; ?>"
                            >
                                <?= $pageNumber; ?>
                            </a>

                        <?php endfor; ?>

                        <!-- Next -->
                        <a
                            href="?page=<?= min(
                                $totalPages,
                                $currentPageNumber + 1
                            ); ?>"
                            class="page-link <?= $currentPageNumber
                                >= $totalPages
                                    ? 'disabled'
                                    : ''; ?>"
                            aria-label="Next page"
                        >
                            <i class="fa-solid fa-chevron-right"></i>
                        </a>

                    </nav>

                </div>

            </section>

        </div>

    </main>

    <script>
        /*
        |--------------------------------------------------------------------------
        | User action dropdowns
        |--------------------------------------------------------------------------
        */

        const menuButtons =
            document.querySelectorAll('.menu-toggle');

        const dropdownMenus =
            document.querySelectorAll('.action-dropdown');

        function closeAllMenus() {
            dropdownMenus.forEach(menu => {
                menu.classList.remove('open');
            });
        }

        menuButtons.forEach(button => {
            button.addEventListener(
                'click',
                function (event) {
                    event.stopPropagation();

                    const menuId =
                        this.dataset.menu;

                    const selectedMenu =
                        document.getElementById(menuId);

                    const alreadyOpen =
                        selectedMenu.classList.contains(
                            'open'
                        );

                    closeAllMenus();

                    if (!alreadyOpen) {
                        selectedMenu.classList.add(
                            'open'
                        );
                    }
                }
            );
        });

        document.addEventListener(
            'click',
            function () {
                closeAllMenus();
            }
        );

        dropdownMenus.forEach(menu => {
            menu.addEventListener(
                'click',
                function (event) {
                    event.stopPropagation();
                }
            );
        });
    </script>

</body>
</html>