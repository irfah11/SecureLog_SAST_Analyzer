<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureLog - SAST Tool</title>

    <link rel="stylesheet" href="stylehome.css">

    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>

<!-- NAVIGATION BAR -->
<nav class="navbar">

    <div class="logo">
        SECURELOG
    </div>

    <div class="nav-buttons">

        <a href="../Registration/login.php" class="btn-login">
            Login
        </a>

        <a href="../Engine_Process/index.php" class="btn-start">
            Get Started
        </a>

    </div>

</nav>

<!-- HERO SECTION -->
<section class="hero">

    <div class="hero-content">

        <h1>
            Secure Your Code.
            <br>
            Build with
            <span>Confidence.</span>
        </h1>

        <p>
            SecureLog is a Static Application Security Testing (SAST) tool
            designed to identify OWASP Top 10 2025 A09 Security Logging and
            Alerting Failures before deployment. The system helps developers
            discover vulnerabilities related to improper logging, missing
            security alerts, and insecure log handling practices.
        </p>

        <div class="hero-buttons">

            <a href="../Engine_Process/index.php" class="scan-btn">
                🚀 Start Scanning Now
            </a>

            <a href="https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/"
               target="_blank"
               class="learn-btn">
                Learn More
            </a>

        </div>

    </div>

    <div class="hero-image">

        <img src="../Asset/homepage.png" alt="SecureLog Preview">

    </div>

</section>

<!-- FEATURES -->
<section class="features" id="features">

    <h2>Why Choose SecureLog?</h2>

    <div class="feature-grid">

        <div class="card">
            <h3>OWASP Top 10 2025</h3>
            <p>
                Detects Security Logging and Alerting Failures based on
                OWASP A09 guidelines.
            </p>
        </div>

        <div class="card">
            <h3>CWE Detection</h3>
            <p>
                Identifies CWE-117 and CWE-778 vulnerabilities using
                automated analysis rules.
            </p>
        </div>

        <div class="card">
            <h3>Fast Analysis</h3>
            <p>
                Performs rapid source code scanning through a regex-based
                SAST engine.
            </p>
        </div>

        <div class="card">
            <h3>Detailed Reports</h3>
            <p>
                Generates detailed vulnerability reports with severity
                classifications and recommendations.
            </p>
        </div>

    </div>

</section>

<!-- STATISTICS -->
<section class="statistics">

    <div class="stat-box">
        <h3>OWASP A09</h3>
        <p>Security Logging & Alerting Failures</p>
    </div>

    <div class="stat-box">
        <h3>CWE-117</h3>
        <p>Improper Output Neutralization for Logs</p>
    </div>

    <div class="stat-box">
        <h3>CWE-778</h3>
        <p>Insufficient Logging</p>
    </div>

    <div class="stat-box">
        <h3>SAST</h3>
        <p>Static Application Security Testing</p>
    </div>

</section>

<!-- HOW IT WORKS -->
<section class="how-it-works">

    <h2>How SecureLog Works</h2>

    <div class="steps">

        <div class="step">
            <h3>1. Upload Source Code</h3>
            <p>
                Developers upload PHP source code files into the SecureLog
                scanning engine.
            </p>
        </div>

        <div class="step">
            <h3>2. Analyze Code</h3>
            <p>
                The regex scanning engine evaluates source code against
                predefined OWASP A09 security rules.
            </p>
        </div>

        <div class="step">
            <h3>3. Detect Vulnerabilities</h3>
            <p>
                Missing logging controls and insecure logging practices are
                identified automatically.
            </p>
        </div>

        <div class="step">
            <h3>4. Generate Reports</h3>
            <p>
                Detailed scan reports are generated and stored for future
                reference and auditing.
            </p>
        </div>

    </div>

</section>

<!-- FOOTER -->
<footer>

    <h3>SecureLog</h3>

    <p>
        Static Application Security Testing (SAST) Tool for detecting
        OWASP Top 10 2025 A09 Security Logging and Alerting Failures.
    </p>

    <p>
        Bachelor of Computer Science (Software Engineering)
    </p>

    <p>
        Universiti Malaysia Pahang Al-Sultan Abdullah (UMPSA)
    </p>

    <p>
        © 2026 SecureLog. All Rights Reserved.
    </p>

</footer>

</body>
</html>