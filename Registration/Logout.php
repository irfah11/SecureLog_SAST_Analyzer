<?php
/**
 * SecureLog — logout.php
 */
session_start();
require_once '../Dashboard/ActivityLogger.php';

if (isset($_SESSION['user_id'])) {
    log_activity(LOG_LOGOUT, $_SESSION['user_id'], "User '{$_SESSION['username']}' logged out");
}

$_SESSION = [];
session_destroy();
header("Location: login.php?msg=logged_out");
exit();