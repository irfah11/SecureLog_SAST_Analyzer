<?php
/**
 * SecureLog — login.php
 * Authentication + Security Activity Logging
 */

session_start();

require_once __DIR__ . '/../Engine_Process/connection.php';
require_once __DIR__ . '/../Dashboard/ActivityLogger.php';

$error_msg = null;


/* ============================================================
   LOGIN PROCESSING
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* --------------------------------------------------------
       Initialize brute-force protection
       -------------------------------------------------------- */

    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }

    if (!isset($_SESSION['login_lockout_until'])) {
        $_SESSION['login_lockout_until'] = 0;
    }


    /* --------------------------------------------------------
       Collect login input
       --------------------------------------------------------

       Password is intentionally NEVER passed to ActivityLogger.
       -------------------------------------------------------- */

    $identifier = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $selected_role = trim($_POST['role'] ?? '');


    /* --------------------------------------------------------
       Temporary login lockout
       -------------------------------------------------------- */

    if (time() < $_SESSION['login_lockout_until']) {

        $wait = (int) ceil(
            ($_SESSION['login_lockout_until'] - time()) / 60
        );

        $error_msg =
            "Terlalu banyak percubaan gagal. "
            . "Sila tunggu {$wait} minit.";


        /*
         * Record blocked authentication attempt.
         *
         * User ID is null because authentication has not
         * succeeded and we should not trust the supplied identity.
         */

        if ($identifier !== '') {

           log_activity(
                LOG_LOGIN_FAILED,
                null,
                'Authentication failed due to invalid credentials or role.',
                [
                    'module' => 'Authentication',
                    'severity' => 'WARNING',
                    'result' => 'FAILURE',

                    // Identity belum berjaya disahkan
                    'actor_username' => $auditUsername,
                    'actor_role' => null,

                    'target_type' => 'USER_ACCOUNT',

                    'metadata' => [
                        'reason' => 'INVALID_CREDENTIALS',
                        'attempted_role' => $selected_role,
                        'lockout_triggered' => true
                    ]
                ]
            );
        }

    } else {

        /* --------------------------------------------------------
           Basic validation
           -------------------------------------------------------- */

        if (
            $identifier === ''
            || $password === ''
            || $selected_role === ''
        ) {

            $error_msg =
                "Sila masukkan username, password dan pilih Role.";

        } else {

            /* ----------------------------------------------------
               Find account
               ---------------------------------------------------- */

            $stmt = $conn->prepare(
                "SELECT
                    UserID,
                    username,
                    fullname,
                    password,
                    role,
                    is_active
                 FROM users
                 WHERE (username = ? OR email = ?)
                 AND role = ?
                 LIMIT 1"
            );

            if (!$stmt) {

                /*
                 * Internal database error is NOT presented
                 * as authentication information to the user.
                 */

                error_log(
                    'SecureLog Login Prepare Error: '
                    . $conn->error
                );

                $error_msg =
                    "Login tidak dapat diproses. "
                    . "Sila cuba lagi.";

            } else {

                $stmt->bind_param(
                    "sss",
                    $identifier,
                    $identifier,
                    $selected_role
                );

                $stmt->execute();

                $result = $stmt->get_result();
                $user = $result->fetch_assoc();

                $stmt->close();


                /* =================================================
                   INVALID CREDENTIALS
                   ================================================= */

                if (
                    !$user
                    || !password_verify(
                        $password,
                        $user['password']
                    )
                ) {

                    $_SESSION['login_attempts']++;


                    /*
                     * If account exists, use the canonical username.
                     *
                     * Otherwise retain the attempted identifier
                     * because it can be useful during security
                     * investigation.
                     *
                     * Password is NEVER logged.
                     */

                    $auditUsername = $user
                        ? $user['username']
                        : $identifier;


                    /*
                     * Fifth failed attempt triggers temporary
                     * session-based lockout.
                     */

                    if ($_SESSION['login_attempts'] >= 5) {

                        $_SESSION['login_lockout_until'] =
                            time() + 600;

                        $_SESSION['login_attempts'] = 0;

                        $error_msg =
                            "Akaun dikunci sementara (10 minit).";


                        log_activity(
                            LOG_LOGIN_FAILED,
                            null,
                            'Authentication failed and temporary login lockout was activated.',
                            [
                                'module' => 'Authentication',
                                'severity' => 'WARNING',
                                'result' => 'FAILURE',

                                'actor_username' =>
                                    $auditUsername,

                                'actor_role' =>
                                    $selected_role,

                                'target_type' =>
                                    'USER_ACCOUNT',

                                'metadata' => [
                                    'reason' =>
                                        'INVALID_CREDENTIALS',

                                    'lockout_triggered' =>
                                        true
                                ]
                            ]
                        );

                    } else {

                        $remaining =
                            5 - $_SESSION['login_attempts'];

                        $error_msg =
                            "Kredensial atau Role salah. "
                            . "Baki percubaan: {$remaining}.";


                        log_activity(
                            LOG_LOGIN_FAILED,
                            null,
                            'Authentication failed due to invalid credentials or role.',
                            [
                                'module' =>
                                    'Authentication',

                                'severity' =>
                                    'WARNING',

                                'result' =>
                                    'FAILURE',

                                'actor_username' =>
                                    $auditUsername,

                                'actor_role' =>
                                    $selected_role,

                                'target_type' =>
                                    'USER_ACCOUNT',

                                'metadata' => [
                                    'reason' =>
                                        'INVALID_CREDENTIALS',

                                    'remaining_attempts' =>
                                        $remaining
                                ]
                            ]
                        );
                    }


                /* =================================================
                   ACCOUNT INACTIVE
                   ================================================= */

                } elseif (
                    isset($user['is_active'])
                    && (int) $user['is_active'] === 0
                ) {

                    $error_msg =
                        "Akaun anda tidak aktif. "
                        . "Sila hubungi admin.";


                    log_activity(
                        LOG_LOGIN_FAILED,
                        (int) $user['UserID'],
                        'Authentication denied because the account is inactive.',
                        [
                            'module' =>
                                'Authentication',

                            'severity' =>
                                'WARNING',

                            'result' =>
                                'DENIED',

                            'actor_username' =>
                                $user['username'],

                            'actor_role' =>
                                $user['role'],

                            'target_type' =>
                                'USER_ACCOUNT',

                            'target_id' =>
                                (int) $user['UserID'],

                            'metadata' => [
                                'reason' =>
                                    'ACCOUNT_INACTIVE'
                            ]
                        ]
                    );


                /* =================================================
                   LOGIN SUCCESS
                   ================================================= */

                } else {

                    /*
                     * Prevent session fixation.
                     */
                    session_regenerate_id(true);


                    /*
                     * Reset login protection.
                     */
                    $_SESSION['login_attempts'] = 0;
                    $_SESSION['login_lockout_until'] = 0;


                    /*
                     * Store authenticated identity.
                     *
                     * UserID is the preferred standard.
                     * user_id is temporarily retained for compatibility
                     * with existing SecureLog modules.
                     */
                    $_SESSION['UserID'] =
                        (int) $user['UserID'];

                    $_SESSION['user_id'] =
                        (int) $user['UserID'];

                    $_SESSION['username'] =
                        $user['username'];

                    $_SESSION['role'] =
                        $user['role'];


                    /* ---------------------------------------------
                       Update last login
                       --------------------------------------------- */

                    $upd = $conn->prepare(
                        "UPDATE users
                         SET last_login = NOW()
                         WHERE UserID = ?"
                    );

                    if ($upd) {

                        $userId =
                            (int) $user['UserID'];

                        $upd->bind_param(
                            "i",
                            $userId
                        );

                        $upd->execute();
                        $upd->close();
                    }


                    /* ---------------------------------------------
                       SECURITY AUDIT EVENT

                       Important:
                       Log AFTER authentication succeeded and
                       AFTER session identity has been established.
                       --------------------------------------------- */

                    log_activity(
                        LOG_LOGIN_SUCCESS,
                        (int) $user['UserID'],
                        'User successfully authenticated.',
                        [
                            'module' =>
                                'Authentication',

                            'severity' =>
                                'INFO',

                            'result' =>
                                'SUCCESS',

                            'actor_username' =>
                                $user['username'],

                            'actor_role' =>
                                $user['role'],

                            'target_type' =>
                                'USER_ACCOUNT',

                            'target_id' =>
                                (int) $user['UserID']
                        ]
                    );


                    /* ---------------------------------------------
                       Redirect according to role
                       --------------------------------------------- */

                    switch ($user['role']) {

                        case 'admin':

                            header(
                                "Location: "
                                . "../Dashboard/dashboard_Admin.php"
                            );

                            break;


                        case 'developer':

                            header(
                                "Location: "
                                . "../Engine_Process/index.php"
                            );

                            break;


                        default:

                            /*
                             * Defensive fallback.
                             *
                             * Current SecureLog design only uses
                             * Admin and Developer.
                             */

                            $_SESSION = [];

                            session_destroy();

                            header(
                                "Location: login.php"
                            );

                            break;
                    }

                    exit();
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ms">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Analyzer - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="styleLogin.css">
</head>
<body>

<div class="login-wrapper">
    <div class="login-box shadow-lg">
        <h2 class="text-center fw-bold mb-4 text-white">
            Login
        </h2>

        <?php if ($error_msg): ?>
            <div class="alert alert-danger small py-2"><?php echo $error_msg; ?></div>
        <?php endif; ?>

        <form action="login.php" method="POST">
            <!-- Input Username -->
            <div class="mb-4">
                <label class="form-label small fw-bold">Username / Email</label>
                <div class="input-group-custom">
                    <i class="fas fa-user"></i>
                    <input type="text" name="username" placeholder="Type your username" required>
                </div>
            </div>

            <!-- Input Role Selection (TAMBAHAN BARU) -->
            <div class="mb-4">
                <label class="form-label small fw-bold">Login As</label>
                <div class="input-group-custom">
                    <i class="fas fa-user-tag"></i>
                    <select name="role" class="form-select border-0 bg-transparent shadow-none" required>
                        <option value="" disabled selected>Select your role</option>
                        <option value="developer">Developer</option>
                        <option value="admin">Admin</option>
                        <!-- <option value="guest">Guest</option> -->
                    </select>
                </div>
            </div>

            <!-- Input Password -->
            <div class="mb-3">
                <label class="form-label small fw-bold">Password</label>
                <div class="input-group-custom">
                    <i class="fas fa-lock"></i>
                    <input type="password" name="password" placeholder="Type your password" required>
                </div>
            </div>

            <div class="text-end mb-4">
                <a href="#" class="text-muted small text-decoration-none">Forgot password?</a>
            </div>

            <button type="submit" class="btn-login w-100 fw-bold">LOGIN</button>


            <div class="register-link">
                <p> Don't have an account? <a href="registration.php">Register now</a>
                </p>
            </div>
        </form>
    </div>
</div>

</body>
</html>