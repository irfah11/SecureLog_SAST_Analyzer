<?php
/**
 * SecureLog — login.php
 * Digabungkan: Logik Verifikasi + Paparan UI + Role Selection
 */

session_start();
include '../Engine_Process/connection.php'; 

$error_msg = null;

// ── 1. LOGIK PEMPROSESAN LOGIN ────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Brute-force protection setup
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts']  = 0;
        $_SESSION['login_lockout_until'] = 0;
    }

    if (time() < $_SESSION['login_lockout_until']) {
        $wait = ceil(($_SESSION['login_lockout_until'] - time()) / 60);
        $error_msg = "Terlalu banyak percubaan gagal. Sila tunggu {$wait} minit.";
    } else {
        // Collect inputs
        $identifier = trim($_POST['username'] ?? ''); 
        $password   = $_POST['password']   ?? '';
        $selected_role = $_POST['role']    ?? ''; // Role yang dipilih dari dropdown

        if (empty($identifier) || empty($password) || empty($selected_role)) {
            $error_msg = "Sila masukkan username, password dan pilih Role.";
        } else {
            // Lookup user berdasarkan username DAN role yang dipilih
            $stmt = $conn->prepare(
                "SELECT UserID, username, fullname, password, role, is_active
                FROM users
                WHERE (username = ? OR email = ?)
                AND role = ?"
            );

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

            // Verify password & user existence
            if (!$user || !password_verify($password, $user['password'])) {
                $_SESSION['login_attempts']++;
                if ($_SESSION['login_attempts'] >= 5) {
                    $_SESSION['login_lockout_until'] = time() + 600;
                    $_SESSION['login_attempts'] = 0;
                    $error_msg = "Akaun dikunci sementara (10 minit).";
                } else {
                    $remaining = 5 - $_SESSION['login_attempts'];
                    $error_msg = "Kredensial atau Role salah. Baki percubaan: {$remaining}.";
                }
            } elseif (isset($user['is_active']) && $user['is_active'] == 0) {
                $error_msg = "Akaun anda tidak aktif. Sila hubungi admin.";
            } else {
                // SUCCESS!
                session_regenerate_id(true);
                $_SESSION['login_attempts'] = 0;
                
                $_SESSION['user_id']  = $user['UserID']; 
                $_SESSION['username'] = $user['username'];
                $_SESSION['role']     = $user['role'];

                // Update last login guna UserID
                $upd = $conn->prepare("UPDATE users SET last_login = NOW() WHERE UserID = ?");
                $upd->bind_param("i", $user['UserID']);
                $upd->execute();
                $upd->close();

                // Redirect mengikut role
                switch ($user['role']) {
                    case 'admin':
                        header("Location: ../Dashboard/dashboard_Admin.php");
                        break;
                    case 'developer':
                    case 'guest':
                        header("Location: ../Engine_Process/index.php");
                        break;
                    default:
                        header("Location: index.php");
                }
                exit();
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