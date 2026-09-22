<?php
/**
 * SecureLog — Logout.php
 */

session_start();

require_once __DIR__ . '/../Dashboard/ActivityLogger.php';


/* ============================================================
   CAPTURE AUTHENTICATED USER BEFORE DESTROYING SESSION
   ============================================================ */

$userId = isset($_SESSION['UserID'])
    ? (int) $_SESSION['UserID']
    : (
        isset($_SESSION['user_id'])
            ? (int) $_SESSION['user_id']
            : null
    );

$username = $_SESSION['username'] ?? null;
$role = $_SESSION['role'] ?? null;


/* ============================================================
   RECORD LOGOUT EVENT
   ============================================================ */

if ($userId !== null && $userId > 0) {

    log_activity(
        LOG_LOGOUT,
        $userId,
        'User logged out of SecureLog.',
        [
            'module' => 'Authentication',
            'severity' => 'INFO',
            'result' => 'SUCCESS',

            'actor_username' => $username,
            'actor_role' => $role,

            'target_type' => 'USER_SESSION',
            'target_id' => $userId
        ]
    );
}


/* ============================================================
   DESTROY SESSION
   ============================================================ */

$_SESSION = [];


/*
 * Remove session cookie as well.
 */
if (ini_get('session.use_cookies')) {

    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}


session_destroy();


/* ============================================================
   RETURN TO LOGIN
   ============================================================ */

header(
    "Location: login.php?msg=logged_out"
);

exit();