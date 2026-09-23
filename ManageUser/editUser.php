<?php
/**
 * SecureLog Edit User
 * File: Dashboard/ManageUser/editUser.php
 */


/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';

/*
 * authCheck.php already starts the session when required
 * and loads ActivityLogger.php.
 */
require_role(['admin']);


/* ============================================================
   DATABASE
   ============================================================ */

require_once __DIR__ . '/../Engine_Process/connection.php';

if (!isset($conn) || !($conn instanceof mysqli)) {
    die('Database connection is not available.');
}


/* ============================================================
   CURRENT ADMIN
   ============================================================ */

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
   GET SELECTED USER ID
   ============================================================ */

$selectedUserId = (int) (
    $_GET['user_id']
    ?? $_POST['user_id']
    ?? 0
);

if ($selectedUserId <= 0) {
    header('Location: user.php');
    exit();
}

/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */

function redirectEditUser(
    int $userId,
    string $type,
    string $message
): void {
    $query = http_build_query([
        'user_id' => $userId,
        'type' => $type,
        'message' => $message
    ]);

    header("Location: editUser.php?{$query}");
    exit();
}

function formatUserDate(?string $date): string
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
        return $date;
    }

    return date('Y-m-d H:i:s', $timestamp);
}

function getRoleLabel(string $role): string
{
    return match (strtolower($role)) {
        'admin' => 'Administrator',
        'developer' => 'Developer',
        'guest' => 'Guest',
        default => ucfirst($role)
    };
}

function getUserInitials(string $fullname): string
{
    $fullname = trim($fullname);

    if ($fullname === '') {
        return 'U';
    }

    $words = preg_split('/\s+/', $fullname);

    $initials = '';

    foreach (array_slice($words, 0, 2) as $word) {
        $initials .= strtoupper(
            mb_substr($word, 0, 1)
        );
    }

    return $initials !== ''
        ? $initials
        : 'U';
}

/* ============================================================
   LOAD SELECTED USER
   ============================================================ */

function getSelectedUser(
    mysqli $conn,
    int $selectedUserId
): ?array {
    $statement = $conn->prepare(
        'SELECT
            UserID,
            fullname,
            username,
            email,
            role,
            is_active,
            created_at,
            last_login
         FROM users
         WHERE UserID = ?
         LIMIT 1'
    );

    if (!$statement) {
        return null;
    }

    $statement->bind_param(
        'i',
        $selectedUserId
    );

    $statement->execute();

    $result = $statement->get_result();

    $user = $result->fetch_assoc();

    $statement->close();

    return $user ?: null;
}

$selectedUser = getSelectedUser(
    $conn,
    $selectedUserId
);

if (!$selectedUser) {
    $query = http_build_query([
        'type' => 'error',
        'message' => 'User account was not found.'
    ]);

    header("Location: user.php?{$query}");
    exit();
}

/* ============================================================
   PROCESS FORM ACTIONS
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !hash_equals(
            $_SESSION['csrf_token'],
            $submittedToken
        )
    ) {
        redirectEditUser(
            $selectedUserId,
            'error',
            'Invalid request token. Please try again.'
        );
    }

    $action = $_POST['action'] ?? '';

    /* ========================================================
       UPDATE USER STATUS
       ======================================================== */

    if ($action === 'update_status') {

        $newStatus = (int) (
            $_POST['new_status'] ?? 0
        );

        $newStatus = $newStatus === 1 ? 1 : 0;

        /*
         * Prevent admin from disabling their own account.
         */
        if (
            $selectedUserId === $currentAdminId
            && $newStatus === 0
        ) {
            redirectEditUser(
                $selectedUserId,
                'error',
                'You cannot set your own administrator account as pending.'
            );
        }

        $statusStatement = $conn->prepare(
            'UPDATE users
             SET is_active = ?
             WHERE UserID = ?'
        );

        if (!$statusStatement) {
            redirectEditUser(
                $selectedUserId,
                'error',
                'Unable to prepare the status update.'
            );
        }

        $statusStatement->bind_param(
            'ii',
            $newStatus,
            $selectedUserId
        );

        if ($statusStatement->execute()) {

            $statusLabel = $newStatus === 1
                ? 'approved'
                : 'set as pending';

            if (
                $currentAdminId > 0
                && function_exists('log_activity')
            ) {

                if ($newStatus === 1) {

                    log_activity(
                        LOG_USER_APPROVED,
                        $currentAdminId,
                        'Administrator approved a developer account.',
                        [
                            'module' => 'UserManagement',
                            'severity' => 'INFO',
                            'result' => 'SUCCESS',

                            'target_type' => 'USER_ACCOUNT',
                            'target_id' => $selectedUserId,

                            'metadata' => [
                                'new_status' => 'APPROVED'
                            ]
                        ]
                    );

                } else {

                    log_activity(
                        LOG_USER_DEACTIVATED,
                        $currentAdminId,
                        'Administrator set a user account as pending.',
                        [
                            'module' => 'UserManagement',
                            'severity' => 'WARNING',
                            'result' => 'SUCCESS',

                            'target_type' => 'USER_ACCOUNT',
                            'target_id' => $selectedUserId,

                            'metadata' => [
                                'new_status' => 'PENDING'
                            ]
                        ]
                    );
                }
            }

    $statusStatement->close();

    redirectEditUser(
        $selectedUserId,
        'success',
        "User account successfully {$statusLabel}."
    );
}

        $databaseError = $statusStatement->error;

        $statusStatement->close();

        redirectEditUser(
            $selectedUserId,
            'error',
            'Failed to update user status: '
            . $databaseError
        );
    }

    /* ========================================================
       SEND EMAIL NOTIFICATION
       ======================================================== */

    if ($action === 'send_email') {

        $selectedUser = getSelectedUser(
            $conn,
            $selectedUserId
        );

        if (!$selectedUser) {
            redirectEditUser(
                $selectedUserId,
                'error',
                'Selected user was not found.'
            );
        }

        $recipientEmail = trim(
            $selectedUser['email'] ?? ''
        );

        if (
            !filter_var(
                $recipientEmail,
                FILTER_VALIDATE_EMAIL
            )
        ) {
            redirectEditUser(
                $selectedUserId,
                'error',
                'The registered email address is invalid.'
            );
        }

        $recipientName = trim(
            $selectedUser['fullname']
            ?? $selectedUser['username']
            ?? 'User'
        );

        $isApproved = (int) (
            $selectedUser['is_active'] ?? 0
        ) === 1;

        if ($isApproved) {
            $emailSubject =
                'SecureLog Account Approved';

            $emailBody =
                "Dear {$recipientName},\n\n"
                . "Your SecureLog registration has been approved.\n"
                . "You may now log in and access the SecureLog system.\n\n"
                . "Regards,\n"
                . "SecureLog Administrator";
        } else {
            $emailSubject =
                'SecureLog Registration Status';

            $emailBody =
                "Dear {$recipientName},\n\n"
                . "Your SecureLog registration is currently pending administrator approval.\n"
                . "You will receive another notification after your account is approved.\n\n"
                . "Regards,\n"
                . "SecureLog Administrator";
        }

        $emailHeaders = [
            'From: SecureLog Administrator <noreply@securelog.local>',
            'Reply-To: noreply@securelog.local',
            'Content-Type: text/plain; charset=UTF-8'
        ];

        $emailSent = mail(
            $recipientEmail,
            $emailSubject,
            $emailBody,
            implode("\r\n", $emailHeaders)
        );

        if ($emailSent) {

            if (
                $currentAdminId > 0
                && function_exists('log_activity')
                && defined('LOG_ADMIN_VIEW')
            ) {
                log_activity(
                    LOG_ADMIN_VIEW,
                    $currentAdminId,
                    "Sent notification email to user ID {$selectedUserId}"
                );
            }

            redirectEditUser(
                $selectedUserId,
                'success',
                "Notification email was sent to {$recipientEmail}."
            );
        }

        redirectEditUser(
            $selectedUserId,
            'error',
            'The email could not be sent. Configure SMTP or PHP mail settings first.'
        );
    }

    /* ========================================================
       REMOVE USER ACCOUNT
       ======================================================== */

    if ($action === 'remove_account') {

        if ($selectedUserId === $currentAdminId) {
            redirectEditUser(
                $selectedUserId,
                'error',
                'You cannot remove your own administrator account.'
            );
        }

        /*
         * Check whether the user has scan records.
         * This prevents foreign key errors.
         */
        $scanCount = 0;

        $scanStatement = $conn->prepare(
            'SELECT COUNT(*)
             FROM scans
             WHERE UserID = ?'
        );

        if ($scanStatement) {
            $scanStatement->bind_param(
                'i',
                $selectedUserId
            );

            $scanStatement->execute();

            $scanStatement->bind_result(
                $scanCount
            );

            $scanStatement->fetch();

            $scanStatement->close();
        }

        if ((int) $scanCount > 0) {
            redirectEditUser(
                $selectedUserId,
                'error',
                "This account cannot be removed because it has {$scanCount} related scan record(s). Set the account as pending instead."
            );
        }
                    /*
            * Preserve minimal identity information before deletion.
            * After DELETE succeeds, this user will no longer exist
            * in the users table.
            */
            $deletedUsername = $selectedUser['username'] ?? 'Unknown';

        $deleteStatement = $conn->prepare(
            'DELETE FROM users
             WHERE UserID = ?
             LIMIT 1'
        );

        if (!$deleteStatement) {
            redirectEditUser(
                $selectedUserId,
                'error',
                'Unable to prepare the account removal.'
            );
        }

        $deleteStatement->bind_param(
            'i',
            $selectedUserId
        );
            if ($deleteStatement->execute()) {

                if (
                    $currentAdminId > 0
                    && function_exists('log_activity')
                ) {
                    log_activity(
                        LOG_USER_DELETED,
                        $currentAdminId,
                        'Administrator permanently removed a user account.',
                        [
                            'module' => 'UserManagement',
                            'severity' => 'WARNING',
                            'result' => 'SUCCESS',

                            'target_type' => 'USER_ACCOUNT',
                            'target_id' => $selectedUserId,

                            'metadata' => [
                                'deleted_username' => $deletedUsername
                            ]
                        ]
                    );
                }

                $deleteStatement->close();

                $query = http_build_query([
                    'type' => 'success',
                    'message' => 'User account permanently removed.'
                ]);

                header("Location: user.php?{$query}");
                exit();
            }

        $deleteError = $deleteStatement->error;

        $deleteStatement->close();

        redirectEditUser(
            $selectedUserId,
            'error',
            'Failed to remove the account: '
            . $deleteError
        );
    }
}

/* ============================================================
   REFRESH USER DATA AFTER ACTIONS
   ============================================================ */

$selectedUser = getSelectedUser(
    $conn,
    $selectedUserId
);

if (!$selectedUser) {
    header('Location: user.php');
    exit();
}

/* ============================================================
   DISPLAY VALUES
   ============================================================ */

$isApproved = (int) (
    $selectedUser['is_active'] ?? 0
) === 1;

$initials = getUserInitials(
    $selectedUser['fullname'] ?? ''
);

$messageType = $_GET['type'] ?? '';
$messageText = $_GET['message'] ?? '';

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

    <title>Edit User | SecureLog</title>

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
            --edit-bg: #020c17;
            --edit-panel: #061729;
            --edit-panel-dark: #03111f;
            --edit-border: #173247;

            --edit-orange: #ff6500;
            --edit-green: #00d995;
            --edit-yellow: #ffae00;
            --edit-blue: #38bdf8;
            --edit-red: #ff4355;

            --edit-text: #f8fafc;
            --edit-muted: #a3afbb;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;

            background: var(--edit-bg);
            color: var(--edit-text);

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

        .edit-user-page {
            min-height: 100vh;
            padding: 12px;

            background:
                radial-gradient(
                    circle at 72% 10%,
                    rgba(56, 189, 248, 0.035),
                    transparent 30%
                ),
                var(--edit-bg);
        }

        .edit-user-container {
            width: 100%;
            max-width: 1500px;
            min-height: calc(100vh - 24px);

            margin: 0 auto;

            background:
                linear-gradient(
                    145deg,
                    rgba(5, 24, 40, 0.98),
                    rgba(2, 14, 26, 0.98)
                );

            border: 1px solid var(--edit-border);
            border-radius: 14px;

            overflow: hidden;
        }

        /* =====================================================
           HEADER
           ===================================================== */

        .edit-header {
            min-height: 116px;
            padding: 27px 30px;

            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 20px;

            border-bottom: 1px solid var(--edit-border);
        }

        .edit-heading {
            display: flex;
            align-items: center;
            gap: 18px;
        }

        .back-button {
            width: 50px;
            height: 50px;

            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;

            color: #ffffff;
            background: #0b1b2a;

            border: 1px solid var(--edit-border);
            border-radius: 50%;

            text-decoration: none;

            transition:
                color 0.2s ease,
                border-color 0.2s ease;
        }

        .back-button:hover {
            color: var(--edit-orange);
            border-color: var(--edit-orange);
        }

        .edit-heading-icon {
            color: var(--edit-orange);
            font-size: 30px;
        }

        .edit-heading-text h1 {
            margin: 0 0 7px;

            color: #ffffff;

            font-size: 25px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .edit-heading-text p {
            margin: 0;

            color: var(--edit-muted);
            font-size: 14px;
        }

        .edit-date {
            padding-top: 10px;

            display: flex;
            align-items: center;
            gap: 9px;

            color: #bec8d2;

            font-size: 13px;
            white-space: nowrap;
        }

        /* =====================================================
           MESSAGE
           ===================================================== */

        .message-area {
            padding: 20px 25px 0;
        }

        .message {
            padding: 13px 16px;

            border-radius: 7px;

            font-size: 13px;
            font-weight: 500;
        }

        .message.success {
            color: #53edb5;
            background: rgba(0, 217, 149, 0.1);
            border: 1px solid rgba(0, 217, 149, 0.32);
        }

        .message.error {
            color: #ff8b96;
            background: rgba(255, 67, 85, 0.1);
            border: 1px solid rgba(255, 67, 85, 0.32);
        }

        /* =====================================================
           CONTENT LAYOUT
           ===================================================== */

        .edit-content {
            padding: 25px;

            display: grid;
            grid-template-columns:
                minmax(0, 1.2fr)
                minmax(350px, 0.8fr);

            gap: 18px;
        }

        .edit-panel {
            padding: 27px;

            background:
                linear-gradient(
                    145deg,
                    rgba(7, 27, 45, 0.98),
                    rgba(3, 17, 31, 0.98)
                );

            border: 1px solid var(--edit-border);
            border-radius: 13px;
        }

        .section-title {
            margin: 0 0 20px;

            color: var(--edit-orange);

            font-size: 15px;
            font-weight: 800;
            text-transform: uppercase;
        }

        /* =====================================================
           STATUS
           ===================================================== */

        .current-status-label {
            margin-bottom: 10px;

            color: #c8d1da;
            font-size: 14px;
        }

        .current-status-badge {
            margin-bottom: 28px;
            padding: 8px 14px;

            display: inline-flex;
            align-items: center;
            gap: 9px;

            border-radius: 6px;

            font-size: 13px;
            font-weight: 700;
        }

        .current-status-badge.approved {
            color: var(--edit-green);
            background: rgba(0, 217, 149, 0.11);
            border: 1px solid rgba(0, 217, 149, 0.28);
        }

        .current-status-badge.pending {
            color: var(--edit-yellow);
            background: rgba(255, 174, 0, 0.1);
            border: 1px solid rgba(255, 174, 0, 0.28);
        }

        .status-dot {
            width: 10px;
            height: 10px;

            border-radius: 50%;
            background: currentColor;
        }

        .change-status-title {
            margin-bottom: 8px;

            color: #ffffff;

            font-size: 15px;
            font-weight: 600;
        }

        .change-status-description {
            margin-bottom: 22px;

            color: var(--edit-muted);
            font-size: 13px;
        }

        .status-choice {
            margin-bottom: 20px;
            padding: 23px 21px;

            display: grid;
            grid-template-columns: 24px 48px 1fr;
            gap: 16px;
            align-items: flex-start;

            border-radius: 9px;

            cursor: pointer;
        }

        .approve-choice {
            border: 1px solid rgba(0, 217, 149, 0.5);
        }

        .pending-choice {
            border: 1px solid rgba(255, 174, 0, 0.55);
        }

        .status-choice input {
            margin-top: 9px;
            accent-color: var(--edit-orange);
        }

        .status-choice-icon {
            width: 47px;
            height: 47px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 50%;

            font-size: 21px;
        }

        .approve-choice .status-choice-icon {
            color: #ffffff;
            background: rgba(0, 217, 149, 0.55);
        }

        .pending-choice .status-choice-icon {
            color: var(--edit-yellow);
            background: rgba(255, 174, 0, 0.08);
            border: 2px solid var(--edit-yellow);
        }

        .status-choice-title {
            margin: 1px 0 9px;

            display: block;

            font-size: 15px;
            font-weight: 700;
        }

        .approve-choice .status-choice-title {
            color: var(--edit-green);
        }

        .pending-choice .status-choice-title {
            color: var(--edit-yellow);
        }

        .status-choice-text {
            color: #b6c0ca;
            font-size: 13px;
            line-height: 1.55;
        }

        .update-status-button {
            min-width: 255px;
            height: 51px;
            margin-top: 10px;

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
            border-radius: 7px;

            font-family: inherit;
            font-size: 14px;
            font-weight: 700;

            cursor: pointer;
        }

        .update-status-button:hover {
            filter: brightness(1.08);
        }

        /* =====================================================
           USER OVERVIEW
           ===================================================== */

        .overview-panel {
            margin-bottom: 18px;
        }

        .overview-title {
            color: var(--edit-blue);
        }

        .user-profile-summary {
            margin-bottom: 24px;

            display: flex;
            align-items: center;
            gap: 18px;
        }

        .user-avatar {
            width: 84px;
            height: 84px;

            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;

            color: #d9e2eb;
            background: #0a1b2b;

            border: 1px solid var(--edit-border);
            border-radius: 50%;

            font-size: 31px;
            font-weight: 500;
        }

        .user-summary-name {
            margin-bottom: 9px;

            color: #ffffff;

            font-size: 18px;
            font-weight: 700;
        }

        .user-role-badge {
            padding: 6px 11px;

            display: inline-flex;

            color: #70cfff;
            background: rgba(56, 189, 248, 0.08);

            border: 1px solid rgba(56, 189, 248, 0.45);
            border-radius: 5px;

            font-size: 12px;
        }

        .overview-row {
            min-height: 41px;

            display: grid;
            grid-template-columns: 27px 110px 1fr;
            align-items: center;
            gap: 8px;

            color: #ffffff;

            font-size: 13px;
        }

        .overview-row i {
            color: #a9b5c0;
            font-size: 16px;
        }

        .overview-row-label {
            color: #9eabb7;
        }

        .overview-row-value {
            text-align: right;
            word-break: break-word;
        }

        .approved-text {
            color: var(--edit-green);
        }

        .pending-text {
            color: var(--edit-yellow);
        }

        /* =====================================================
           ACCOUNT ACTIONS
           ===================================================== */

        .action-card {
            margin-bottom: 14px;
            padding: 20px;

            display: grid;
            grid-template-columns: 46px 1fr;
            gap: 14px;

            border-radius: 9px;
        }

        .email-action-card {
            border: 1px solid rgba(56, 189, 248, 0.48);
        }

        .remove-action-card {
            border: 1px solid rgba(255, 67, 85, 0.52);
        }

        .action-card-icon {
            width: 44px;
            height: 44px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 50%;

            font-size: 19px;
        }

        .email-action-card .action-card-icon {
            color: #ffffff;
            background: #1475b7;
        }

        .remove-action-card .action-card-icon {
            color: #ffffff;
            background: #d52d42;
        }

        .action-card-title {
            margin: 0 0 7px;

            font-size: 14px;
            font-weight: 700;
        }

        .email-action-card .action-card-title {
            color: var(--edit-blue);
        }

        .remove-action-card .action-card-title {
            color: var(--edit-red);
        }

        .action-card-description {
            margin: 0 0 12px;

            color: #aeb9c4;
            font-size: 12px;
            line-height: 1.5;
        }

        .action-button {
            min-height: 36px;
            padding: 0 13px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            background: transparent;

            border-radius: 5px;

            font-family: inherit;
            font-size: 12px;
            font-weight: 600;

            cursor: pointer;
        }

        .email-button {
            color: var(--edit-blue);
            border: 1px solid rgba(56, 189, 248, 0.58);
        }

        .email-button:hover {
            color: #ffffff;
            background: rgba(56, 189, 248, 0.13);
        }

        .remove-button {
            color: var(--edit-red);
            border: 1px solid rgba(255, 67, 85, 0.58);
        }

        .remove-button:hover {
            color: #ffffff;
            background: rgba(255, 67, 85, 0.13);
        }

        .remove-warning {
            padding: 10px 12px;

            color: #ff747f;
            background: rgba(255, 67, 85, 0.05);

            border: 1px solid rgba(255, 67, 85, 0.62);
            border-radius: 6px;

            font-size: 11px;
            line-height: 1.4;
            text-align: center;
        }

        /* =====================================================
           MODAL
           ===================================================== */

        .confirmation-modal {
            position: fixed;
            inset: 0;
            z-index: 5000;

            padding: 20px;

            display: none;
            align-items: center;
            justify-content: center;

            background: rgba(0, 0, 0, 0.75);
        }

        .confirmation-modal.open {
            display: flex;
        }

        .confirmation-box {
            width: 100%;
            max-width: 440px;
            padding: 27px;

            background: #071827;

            border: 1px solid rgba(255, 67, 85, 0.5);
            border-radius: 12px;
        }

        .confirmation-box h2 {
            margin: 0 0 13px;

            color: var(--edit-red);
            font-size: 19px;
        }

        .confirmation-box p {
            margin: 0 0 22px;

            color: #c0cad4;
            font-size: 13px;
            line-height: 1.55;
        }

        .confirmation-actions {
            display: flex;
            justify-content: flex-end;
            gap: 11px;
        }

        .modal-cancel,
        .modal-remove {
            min-height: 40px;
            padding: 0 16px;

            border-radius: 6px;

            font-family: inherit;
            font-weight: 600;

            cursor: pointer;
        }

        .modal-cancel {
            color: #ffffff;
            background: transparent;
            border: 1px solid var(--edit-border);
        }

        .modal-remove {
            color: #ffffff;
            background: var(--edit-red);
            border: 1px solid var(--edit-red);
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 1050px) {
            .edit-content {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 800px) {
            .edit-user-page {
                padding: 10px;
            }

            .edit-header {
                padding: 23px 20px;
            }

            .edit-content {
                padding-left: 15px;
                padding-right: 15px;
            }
        }

        @media (max-width: 600px) {
            .edit-header {
                flex-direction: column;
            }

            .edit-panel {
                padding: 20px;
            }

            .update-status-button {
                width: 100%;
                min-width: 0;
            }

            .overview-row {
                grid-template-columns: 24px 95px 1fr;
            }
        }
    </style>
</head>

<body>

    <!-- Existing admin sidebar -->
    <?php
    require __DIR__ . '/../Sidebar/sidebaradmin.php';
    ?>

    <main class="admin-page-content edit-user-page">

        <div class="edit-user-container">

            <!-- Header -->
            <header class="edit-header">

                <div class="edit-heading">

                    <a
                        href="user.php"
                        class="back-button"
                        title="Back to Manage Users"
                    >
                        <i class="fa-solid fa-arrow-left"></i>
                    </a>

                    <i
                        class="fa-solid fa-user-pen edit-heading-icon"
                    ></i>

                    <div class="edit-heading-text">
                        <h1>Edit User</h1>

                        <p>
                            Manage user account status and actions
                        </p>
                    </div>

                </div>

                <div class="edit-date">
                    <i class="fa-regular fa-calendar"></i>

                    <?= htmlspecialchars(
                        date('D, d M Y H:i:s')
                    ); ?>
                </div>

            </header>

            <!-- Flash message -->
            <?php if (
                $messageType !== ''
                && $messageText !== ''
            ): ?>

                <div class="message-area">

                    <div
                        class="message <?= htmlspecialchars(
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

            <div class="edit-content">

                <!-- =================================================
                     LEFT SIDE: STATUS
                     ================================================= -->

                <section class="edit-panel">

                    <h2 class="section-title">
                        Account Status
                    </h2>

                    <div class="current-status-label">
                        Current Status
                    </div>

                    <div
                        class="current-status-badge <?= $isApproved
                            ? 'approved'
                            : 'pending'; ?>"
                    >
                        <span class="status-dot"></span>

                        <?= $isApproved
                            ? 'Approved'
                            : 'Pending'; ?>
                    </div>

                    <div class="change-status-title">
                        Change Status
                    </div>

                    <div class="change-status-description">
                        Approve or set this user account as pending.
                    </div>

                    <form
                        method="POST"
                        action="editUser.php?user_id=<?= $selectedUserId; ?>"
                    >
                        <input
                            type="hidden"
                            name="csrf_token"
                            value="<?= htmlspecialchars(
                                $csrfToken
                            ); ?>"
                        >

                        <input
                            type="hidden"
                            name="user_id"
                            value="<?= $selectedUserId; ?>"
                        >

                        <input
                            type="hidden"
                            name="action"
                            value="update_status"
                        >

                        <!-- Approve -->
                        <label class="status-choice approve-choice">

                            <input
                                type="radio"
                                name="new_status"
                                value="1"
                                <?= $isApproved
                                    ? 'checked'
                                    : ''; ?>
                            >

                            <span class="status-choice-icon">
                                <i class="fa-solid fa-check"></i>
                            </span>

                            <span>
                                <span class="status-choice-title">
                                    Approve User
                                </span>

                                <span class="status-choice-text">
                                    Approve this user's registration
                                    and allow access to the SecureLog system.
                                </span>
                            </span>

                        </label>

                        <!-- Pending -->
                        <label class="status-choice pending-choice">

                            <input
                                type="radio"
                                name="new_status"
                                value="0"
                                <?= !$isApproved
                                    ? 'checked'
                                    : ''; ?>
                            >

                            <span class="status-choice-icon">
                                <i class="fa-regular fa-clock"></i>
                            </span>

                            <span>
                                <span class="status-choice-title">
                                    Set as Pending
                                </span>

                                <span class="status-choice-text">
                                    Set this account as pending.
                                    The user will not be able to log in.
                                </span>
                            </span>

                        </label>

                        <button
                            type="submit"
                            class="update-status-button"
                        >
                            <i class="fa-solid fa-user-check"></i>
                            Update Status
                        </button>

                    </form>

                </section>

                <!-- =================================================
                     RIGHT SIDE
                     ================================================= -->

                <div>

                    <!-- User overview -->
                    <section class="edit-panel overview-panel">

                        <h2 class="section-title overview-title">
                            User Overview
                        </h2>

                        <div class="user-profile-summary">

                            <div class="user-avatar">
                                <?= htmlspecialchars(
                                    $initials
                                ); ?>
                            </div>

                            <div>
                                <div class="user-summary-name">
                                    <?= htmlspecialchars(
                                        $selectedUser['fullname']
                                        ?? 'Unknown User'
                                    ); ?>
                                </div>

                                <span class="user-role-badge">
                                    <?= htmlspecialchars(
                                        getRoleLabel(
                                            $selectedUser['role']
                                            ?? 'guest'
                                        )
                                    ); ?>
                                </span>
                            </div>

                        </div>

                        <div class="overview-row">
                            <i class="fa-solid fa-id-card"></i>

                            <span class="overview-row-label">
                                User ID
                            </span>

                            <span class="overview-row-value">
                                #<?= $selectedUserId; ?>
                            </span>
                        </div>

                        <div class="overview-row">
                            <i class="fa-regular fa-user"></i>

                            <span class="overview-row-label">
                                Username
                            </span>

                            <span class="overview-row-value">
                                <?= htmlspecialchars(
                                    $selectedUser['username']
                                    ?? '-'
                                ); ?>
                            </span>
                        </div>

                        <div class="overview-row">
                            <i class="fa-regular fa-envelope"></i>

                            <span class="overview-row-label">
                                Email
                            </span>

                            <span class="overview-row-value">
                                <?= htmlspecialchars(
                                    $selectedUser['email']
                                    ?? '-'
                                ); ?>
                            </span>
                        </div>

                        <div class="overview-row">
                            <i class="fa-solid fa-user-shield"></i>

                            <span class="overview-row-label">
                                Role
                            </span>

                            <span class="overview-row-value">
                                <?= htmlspecialchars(
                                    getRoleLabel(
                                        $selectedUser['role']
                                        ?? 'guest'
                                    )
                                ); ?>
                            </span>
                        </div>

                        <div class="overview-row">
                            <i class="fa-regular fa-calendar"></i>

                            <span class="overview-row-label">
                                Member Since
                            </span>

                            <span class="overview-row-value">
                                <?= htmlspecialchars(
                                    formatUserDate(
                                        $selectedUser['created_at']
                                        ?? null
                                    )
                                ); ?>
                            </span>
                        </div>

                        <div class="overview-row">
                            <i class="fa-regular fa-clock"></i>

                            <span class="overview-row-label">
                                Last Login
                            </span>

                            <span class="overview-row-value">
                                <?= htmlspecialchars(
                                    formatUserDate(
                                        $selectedUser['last_login']
                                        ?? null
                                    )
                                ); ?>
                            </span>
                        </div>

                        <div class="overview-row">
                            <i class="fa-regular fa-circle-check"></i>

                            <span class="overview-row-label">
                                Status
                            </span>

                            <span
                                class="overview-row-value <?= $isApproved
                                    ? 'approved-text'
                                    : 'pending-text'; ?>"
                            >
                                <?= $isApproved
                                    ? 'Approved'
                                    : 'Pending'; ?>
                            </span>
                        </div>

                    </section>

                    <!-- Account actions -->
                    <section class="edit-panel">

                        <h2 class="section-title">
                            Account Actions
                        </h2>

                        <!-- Email action -->
                        <div class="action-card email-action-card">

                            <div class="action-card-icon">
                                <i class="fa-solid fa-envelope"></i>
                            </div>

                            <div>
                                <h3 class="action-card-title">
                                    Notify User via Email
                                </h3>

                                <p class="action-card-description">
                                    Send the account status notification
                                    to the user's registered email address.
                                </p>

                                <form
                                    method="POST"
                                    action="editUser.php?user_id=<?= $selectedUserId; ?>"
                                >
                                    <input
                                        type="hidden"
                                        name="csrf_token"
                                        value="<?= htmlspecialchars(
                                            $csrfToken
                                        ); ?>"
                                    >

                                    <input
                                        type="hidden"
                                        name="user_id"
                                        value="<?= $selectedUserId; ?>"
                                    >

                                    <input
                                        type="hidden"
                                        name="action"
                                        value="send_email"
                                    >

                                    <button
                                        type="submit"
                                        class="action-button email-button"
                                    >
                                        Send Email
                                    </button>
                                </form>
                            </div>

                        </div>

                        <!-- Remove account -->
                        <div class="action-card remove-action-card">

                            <div class="action-card-icon">
                                <i class="fa-solid fa-trash-can"></i>
                            </div>

                            <div>
                                <h3 class="action-card-title">
                                    Remove Account
                                </h3>

                                <p class="action-card-description">
                                    Permanently remove this user account
                                    from the SecureLog system.
                                </p>

                                <button
                                    type="button"
                                    class="action-button remove-button"
                                    id="openRemoveModal"
                                >
                                    Remove Account
                                </button>
                            </div>

                        </div>

                        <div class="remove-warning">
                            <i class="fa-solid fa-triangle-exclamation"></i>

                            Removing an account is permanent
                            and cannot be undone.
                        </div>

                    </section>

                </div>

            </div>

        </div>

    </main>

    <!-- =====================================================
         REMOVE ACCOUNT CONFIRMATION MODAL
         ===================================================== -->

    <div
        class="confirmation-modal"
        id="removeConfirmationModal"
    >

        <div class="confirmation-box">

            <h2>
                <i class="fa-solid fa-triangle-exclamation"></i>
                Remove Account?
            </h2>

            <p>
                This will permanently remove

                <strong>
                    <?= htmlspecialchars(
                        $selectedUser['fullname']
                        ?? 'this user'
                    ); ?>
                </strong>

                from SecureLog. This action cannot be undone.
            </p>

            <div class="confirmation-actions">

                <button
                    type="button"
                    class="modal-cancel"
                    id="closeRemoveModal"
                >
                    Cancel
                </button>

                <form
                    method="POST"
                    action="editUser.php?user_id=<?= $selectedUserId; ?>"
                >
                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?= htmlspecialchars(
                            $csrfToken
                        ); ?>"
                    >

                    <input
                        type="hidden"
                        name="user_id"
                        value="<?= $selectedUserId; ?>"
                    >

                    <input
                        type="hidden"
                        name="action"
                        value="remove_account"
                    >

                    <button
                        type="submit"
                        class="modal-remove"
                    >
                        Permanently Remove
                    </button>
                </form>

            </div>

        </div>

    </div>

    <script>
        const removeModal =
            document.getElementById(
                'removeConfirmationModal'
            );

        const openRemoveModalButton =
            document.getElementById(
                'openRemoveModal'
            );

        const closeRemoveModalButton =
            document.getElementById(
                'closeRemoveModal'
            );

        if (openRemoveModalButton) {
            openRemoveModalButton.addEventListener(
                'click',
                function () {
                    removeModal.classList.add('open');
                }
            );
        }

        if (closeRemoveModalButton) {
            closeRemoveModalButton.addEventListener(
                'click',
                function () {
                    removeModal.classList.remove('open');
                }
            );
        }

        removeModal.addEventListener(
            'click',
            function (event) {
                if (event.target === removeModal) {
                    removeModal.classList.remove('open');
                }
            }
        );

        document.addEventListener(
            'keydown',
            function (event) {
                if (event.key === 'Escape') {
                    removeModal.classList.remove('open');
                }
            }
        );
    </script>

</body>
</html>