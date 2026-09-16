<?php
/**
 * SecureLog — auth_check.php
 * Include at the TOP of every protected page.
 *
*  Usage:
*   require_once 'auth_check.php';
 *   require_role(['admin']);           // admin only
 *   require_role(['developer','guest']); // both scanner users
 */


if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Redirects to login if user is not authenticated.
 */
function require_login(): void
{
    if (empty($_SESSION['user_id'])) {
        header("Location: ../Registration/login.php?error=session_expired");
        exit();
    }
}

/**
 * Checks role after require_login().
 * @param string[] $allowed Array of allowed roles, e.g. ['admin'], ['developer','guest']
 */
function require_role(array $allowed): void
{
    require_login();

    if (!in_array($_SESSION['role'] ?? '', $allowed, true)) {

    http_response_code(403);

    die("
    <h1>403 - Access Denied</h1>
    <p>You do not have permission to access this page.</p>
    ");

}
}

/**
 * Helper: returns current user role.
 */
function current_role(): string
{
    return $_SESSION['role'] ?? 'guest';
}

/**
 * Helper: returns true if user is admin.
 */
function is_admin(): bool
{
    return ($_SESSION['role'] ?? '') === 'admin';
}