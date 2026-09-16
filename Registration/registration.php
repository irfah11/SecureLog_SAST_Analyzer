<?php

session_start();
include '../Engine_Process/connection.php';


// ── 1. LOGIK PEMPROSESAN PENDAFTARAN ─────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $fullname = trim($_POST['fullname'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $department = trim($_POST['department'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    $role = 'developer';
    $errors = [];

    // Full Name Validation
    if (empty($fullname) || strlen($fullname) < 2) {
        $errors[] = "Full Name must be at least 2 characters.";
    }

    // Email Validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please enter a valid email address.";
    }

    // Department Validation
    if (empty($department)) {
        $errors[] = "Please select a department.";
    }

    
    // Username Validation
    if (empty($username) || !preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        $errors[] = "Username must be between 3 and 30 characters.";
    }

    // Password Strength Validation
    if (
        strlen($password) < 8 ||
        !preg_match('/[A-Z]/', $password) ||
        !preg_match('/[a-z]/', $password) ||
        !preg_match('/[0-9]/', $password) ||
        !preg_match('/[\W_]/', $password)
    ) {
        $errors[] = "Password must contain uppercase, lowercase, number and symbol.";
    }

    // Confirm Password Validation
    if ($password !== $confirm_password) {
        $errors[] = "Password and Confirm Password do not match.";
    }

    // Continue only if no validation errors
    if (empty($errors)) {

        // Check duplicate username/email
        $stmt = $conn->prepare(
            "SELECT UserID FROM users WHERE username = ? OR email = ?"
        );

        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {

            $errors[] = "Username or Email already exists.";

        } else {

            $hashed_password = password_hash(
                $password,
                PASSWORD_BCRYPT,
                ['cost' => 12]
            );

            // Insert User
            $stmt_insert = $conn->prepare(
                "INSERT INTO users
                (fullname,email,username,password,role,is_active,created_at)
                VALUES
                (?,?,?,?,?,0,NOW())"
            );

            $stmt_insert->bind_param(
                "sssss",
                $fullname,
                $email,
                $username,
                $hashed_password,
                $role
            );

            if ($stmt_insert->execute()) {

                $new_user_id = $conn->insert_id;

                // Insert Developer Profile
                $registration_status = 'Pending';

                $stmt_dev = $conn->prepare(
                    "INSERT INTO developer
                    (UserID, registration_status, department)
                    VALUES
                    (?, ?, ?)"
                );

                $stmt_dev->bind_param(
                    "iss",
                    $new_user_id,
                    $registration_status,
                    $department
                );

                if ($stmt_dev->execute()) {

                    echo "
                    <script>
                        alert('Registration submitted successfully. Please wait for administrator approval.');
                        window.location='login.php';
                    </script>
                    ";
                    exit();

                } else {

                    $errors[] = "Failed to create developer profile.";

                }

            } else {

                $errors[] = "Registration failed.";

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
    <title>SecureLog - Developer Registration</title>

    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Font Awesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

    <!-- Custom CSS -->
    <link rel="stylesheet" href="styleRegister.css?v=11">
</head>

<body>

<div class="container-fluid min-vh-100 d-flex align-items-center justify-content-center">

    <div class="registration-card shadow-lg d-flex overflow-hidden">

        <!-- LEFT PANEL -->
        <div class="info-panel d-none d-md-flex">
            <div class="info-content">

                <h1 class="brand-title">SECURELOG</h1>
                <h2 class="brand-subtitle">SAST ANALYZER</h2>

                <p class="brand-description">
                    Secure your code with AI-powered static analysis.<br>
                    Build Trust. Ship Safely.
                </p>

                <div class="feature-list">
                    <div class="feature-item">
                        <i class="fas fa-shield-alt"></i>
                        <span>Accurate Scanning</span>
                    </div>

                    <div class="feature-item">
                        <i class="fas fa-search"></i>
                        <span>Intelligent Mitigation</span>
                    </div>

                    <div class="feature-item">
                        <i class="fas fa-chart-line"></i>
                        <span>Role-Based Reports</span>
                    </div>
                </div>

            </div>
        </div>

        <!-- RIGHT PANEL -->
        <div class="form-panel">

            <h2>Developer Registration</h2>

            <p class="form-subtitle">
                Create your developer account to start using SecureLog.
            </p>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger p-2 small">
                    <ul class="mb-0">
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <form action="registration.php" method="POST">

                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-user"></i>
                    </span>
                    <input 
                        type="text" 
                        class="form-control" 
                        name="fullname" 
                        placeholder="Full Name" 
                        value="<?php echo htmlspecialchars($fullname ?? ''); ?>" 
                        required>
                </div>

                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-id-badge"></i>
                    </span>
                    <input 
                        type="text" 
                        class="form-control" 
                        name="username" 
                        placeholder="Username" 
                        value="<?php echo htmlspecialchars($username ?? ''); ?>" 
                        required>
                </div>

                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-envelope"></i>
                    </span>
                    <input 
                        type="email" 
                        class="form-control" 
                        name="email" 
                        placeholder="Work Email" 
                        value="<?php echo htmlspecialchars($email ?? ''); ?>" 
                        required>
                </div>

                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-building"></i>
                    </span>

                    <select class="form-control" name="department" required>
                        <option value="">Select Department</option>
                        <option value="Software Development">Software Development</option>
                        <option value="Cyber Security">Cyber Security</option>
                        <option value="DevOps">DevOps</option>
                        <option value="Quality Assurance">Quality Assurance</option>
                        <option value="IT Support">IT Support</option>
                        <option value="Other">Other</option>
                    </select>
                </div>

                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-lock"></i>
                    </span>
                    <input 
                        type="password" 
                        class="form-control" 
                        name="password" 
                        placeholder="Password" 
                        required>
                </div>

                <div class="input-group">
                    <span class="input-group-text">
                        <i class="fas fa-lock"></i>
                    </span>
                    <input 
                        type="password" 
                        class="form-control" 
                        name="confirm_password" 
                        placeholder="Confirm Password" 
                        required>
                </div>

                <p class="password-note">
                    Password must be 8+ chars with Uppercase, Number & Symbol.
                </p>

                <div class="alert alert-info custom-note">
                    <i class="fas fa-info-circle me-2"></i>
                    <strong>Note:</strong>
                    Developer accounts require administrator approval before access is granted.
                </div>

                <button type="submit" class="btn btn-primary w-100 register-btn">
                    REGISTER NOW
                </button>

                <p class="login-text">
                    Already have an account?
                    <a href="login.php">Login here</a>
                </p>

            </form>
        </div>

    </div>
</div>

</body>
</html>