<?php
/**
 * SecureLog — authCheck.php
 *
 * Centralized authentication and authorization guard.
 *
 * Usage:
 *
 * require_once __DIR__ . '/authCheck.php';
 * require_role(['admin']);
 *
 * or:
 *
 * require_role(['developer']);
 */


/* ============================================================
   SESSION
   ============================================================ */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}


/* ============================================================
   ACTIVITY LOGGER
   ============================================================ */

require_once __DIR__ . '/ActivityLogger.php';


/* ============================================================
   REQUIRE AUTHENTICATED USER
   ============================================================ */

/**
 * Redirect user to login page when no authenticated
 * SecureLog session exists.
 */
function require_login(): void
{
    /*
     * Support both session keys temporarily while the project
     * is being standardized.
     */
    $userId =
        $_SESSION['UserID']
        ?? $_SESSION['user_id']
        ?? null;

    if (empty($userId)) {

        header(
            "Location: /FinalYearProject/Registration/login.php"
            . "?error=session_expired"
        );

        exit();
    }
}


/* ============================================================
   REQUIRE AUTHORIZED ROLE
   ============================================================ */

/**
 * Check whether the authenticated user's role is allowed
 * to access the current resource.
 *
 * Example:
 *
 * require_role(['admin']);
 *
 * require_role(['developer']);
 *
 * @param string[] $allowed
 */
function require_role(array $allowed): void
{
    /*
     * Authentication must happen first.
     */
    require_login();


    /* --------------------------------------------------------
       Current authenticated identity
       -------------------------------------------------------- */

    $userId = isset($_SESSION['UserID'])
        ? (int) $_SESSION['UserID']
        : (int) ($_SESSION['user_id'] ?? 0);

    $username =
        $_SESSION['username']
        ?? null;

    $currentRole =
        $_SESSION['role']
        ?? '';


    /* --------------------------------------------------------
       Authorization check
       -------------------------------------------------------- */

    if (!in_array($currentRole, $allowed, true)) {

        /*
         * IMPORTANT:
         *
         * This user is already authenticated.
         * Therefore UserID, username and role represent the
         * verified actor.
         */

        log_activity(
            LOG_ACCESS_DENIED,
            $userId > 0 ? $userId : null,
            'Authenticated user attempted to access a resource without the required role.',
            [
                'module' => 'AccessControl',

                'severity' => 'WARNING',

                'result' => 'DENIED',

                'actor_username' => $username,

                'actor_role' => $currentRole,

                'target_type' => 'PROTECTED_RESOURCE',

                /*
                 * The requested resource is useful for
                 * security investigation.
                 */
                'target_id' =>
                    $_SERVER['REQUEST_URI']
                    ?? null,

                'metadata' => [
                    'required_roles' =>
                        array_values($allowed)
                ]
            ]
        );


        /* ----------------------------------------------------
           Return HTTP 403
           ---------------------------------------------------- */

        http_response_code(403);

        die("
            <h1>403 - Access Denied</h1>
            <p>You do not have permission to access this page.</p>
        ");
    }
}


/* ============================================================
   CURRENT ROLE
   ============================================================ */

function current_role(): string
{
    return $_SESSION['role'] ?? '';
}


/* ============================================================
   ADMIN CHECK
   ============================================================ */

function is_admin(): bool
{
    return ($_SESSION['role'] ?? '') === 'admin';
}