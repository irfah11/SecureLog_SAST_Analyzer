<?php
/**
 * SecureLog - Add Scanner Rule
 * File: ScannerRule/addRule.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}

/* ============================================================
   DATABASE
   ============================================================ */

require_once __DIR__ . '/../Engine_Process/connection.php';

if (!isset($conn) || !($conn instanceof mysqli)) {
    die('Database connection is not available.');
}

/* ============================================================
   ACTIVITY LOGGER
   ============================================================ */

$activityLoggerPath =
    __DIR__ . '/../Dashboard/ActivityLogger.php';

if (file_exists($activityLoggerPath)) {
    require_once $activityLoggerPath;
}

$currentAdminId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

/* ============================================================
   CSRF
   ============================================================ */

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] =
        bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['csrf_token'];

/* ============================================================
   HELPERS
   ============================================================ */

function e(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES,
        'UTF-8'
    );
}

function oldInput(
    string $field,
    string $default = ''
): string {
    return e(
        (string) (
            $_POST[$field]
            ?? $default
        )
    );
}

/**
 * Validate a PHP PCRE regular expression.
 */
function isValidRegex(string $pattern): bool
{
    if ($pattern === '') {
        return false;
    }

    set_error_handler(
        static function (): bool {
            return true;
        }
    );

    $result = preg_match(
        $pattern,
        ''
    );

    restore_error_handler();

    return $result !== false;
}

/* ============================================================
   OPTIONS
   ============================================================ */

$languageOptions = [
    'PHP'        => 'PHP',
    'JAVA'       => 'Java',
    'JAVASCRIPT' => 'JavaScript',
    'C'          => 'C'
];

$detectionTypeOptions = [
    'LOGGING'           => 'Logging',
    'TXT_FORMAT'        => 'TXT Log Format',
    'ENCRYPTION'        => 'Encryption / Protection',
    'SENSITIVE_LOGGING' => 'Sensitive Information in Log',
    'CUSTOM'            => 'Custom Detection'
];

$matchTypeOptions = [
    'SIMPLE_PATTERN'  => 'Simple Pattern',
    'CONTEXT_PATTERN' => 'Context Pattern'
];

$severityOptions = [
    'HIGH'   => 'High',
    'MEDIUM' => 'Medium',
    'LOW'    => 'Low',
    'INFO'   => 'Info'
];

$owaspOptions = [
    'A01: Broken Access Control',
    'A02: Cryptographic Failures',
    'A03: Injection',
    'A04: Insecure Design',
    'A05: Security Misconfiguration',
    'A06: Vulnerable and Outdated Components',
    'A07: Identification and Authentication Failures',
    'A08: Software and Data Integrity Failures',
    'A09: Security Logging and Monitoring Failures',
    'A10: Server-Side Request Forgery'
];

/* ============================================================
   FORM VALUES
   ============================================================ */

$errors = [];

$ruleCode = strtoupper(
    trim($_POST['rule_code'] ?? '')
);

$ruleName = trim(
    $_POST['rule_name'] ?? ''
);

$language = strtoupper(
    trim($_POST['language'] ?? '')
);

$detectionType = strtoupper(
    trim($_POST['detection_type'] ?? '')
);

$weaknessCategory = trim(
    $_POST['weakness_category'] ?? ''
);

$matchType = strtoupper(
    trim(
        $_POST['match_type']
        ?? 'SIMPLE_PATTERN'
    )
);

$cweId = strtoupper(
    trim($_POST['cwe_id'] ?? '')
);

$owaspCategory = trim(
    $_POST['owasp_category'] ?? ''
);

$severity = strtoupper(
    trim($_POST['severity'] ?? '')
);

$description = trim(
    $_POST['description'] ?? ''
);

$pattern = trim(
    $_POST['pattern'] ?? ''
);

$secondaryPattern = trim(
    $_POST['secondary_pattern'] ?? ''
);

$recommendation = trim(
    $_POST['recommendation'] ?? ''
);

/* ============================================================
   PROCESS ADD RULE
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* --------------------------------------------------------
       CSRF
       -------------------------------------------------------- */

    $submittedToken =
        $_POST['csrf_token']
        ?? '';

    if (
        !hash_equals(
            $_SESSION['csrf_token'],
            $submittedToken
        )
    ) {
        $errors[] =
            'Invalid request token. Please refresh the page.';
    }

    /* --------------------------------------------------------
       RULE CODE
       -------------------------------------------------------- */

    if ($ruleCode === '') {

        $errors[] =
            'Rule Code is required.';

    } elseif (
        !preg_match(
            '/^[A-Z0-9_-]+$/',
            $ruleCode
        )
    ) {

        $errors[] =
            'Rule Code may only contain letters, numbers, hyphens and underscores.';

    } elseif (strlen($ruleCode) > 100) {

        $errors[] =
            'Rule Code must not exceed 100 characters.';
    }

    /* --------------------------------------------------------
       RULE NAME
       -------------------------------------------------------- */

    if ($ruleName === '') {

        $errors[] =
            'Rule Name is required.';

    } elseif (strlen($ruleName) > 255) {

        $errors[] =
            'Rule Name must not exceed 255 characters.';
    }

    /* --------------------------------------------------------
       LANGUAGE
       -------------------------------------------------------- */

    if (
        !array_key_exists(
            $language,
            $languageOptions
        )
    ) {
        $errors[] =
            'Please select a valid programming language.';
    }

    /* --------------------------------------------------------
       DETECTION TYPE
       -------------------------------------------------------- */

    if (
        !array_key_exists(
            $detectionType,
            $detectionTypeOptions
        )
    ) {
        $errors[] =
            'Please select a valid detection type.';
    }

    /* --------------------------------------------------------
       WEAKNESS CATEGORY
       -------------------------------------------------------- */

    if ($weaknessCategory === '') {

        $errors[] =
            'Weakness Category is required.';

    } elseif (
        strlen($weaknessCategory) > 150
    ) {

        $errors[] =
            'Weakness Category must not exceed 150 characters.';
    }

    /* --------------------------------------------------------
       MATCH TYPE
       -------------------------------------------------------- */

    if (
        !array_key_exists(
            $matchType,
            $matchTypeOptions
        )
    ) {
        $errors[] =
            'Please select a valid match type.';
    }

    /* --------------------------------------------------------
       CWE - OPTIONAL
       -------------------------------------------------------- */

    if (
        $cweId !== ''
        && !preg_match(
            '/^CWE-\d+$/',
            $cweId
        )
    ) {
        $errors[] =
            'CWE ID must use a format such as CWE-532, or leave it blank.';
    }

    /* --------------------------------------------------------
       OWASP - OPTIONAL
       -------------------------------------------------------- */

    if (
        $owaspCategory !== ''
        && !in_array(
            $owaspCategory,
            $owaspOptions,
            true
        )
    ) {
        $errors[] =
            'Please select a valid OWASP category or leave it unmapped.';
    }

    /* --------------------------------------------------------
       SEVERITY
       -------------------------------------------------------- */

    if (
        !array_key_exists(
            $severity,
            $severityOptions
        )
    ) {
        $errors[] =
            'Please select a valid severity.';
    }

    /* --------------------------------------------------------
       DESCRIPTION
       -------------------------------------------------------- */

    if ($description === '') {
        $errors[] =
            'Description is required.';
    }

    /* --------------------------------------------------------
       PRIMARY PATTERN
       -------------------------------------------------------- */

    if ($pattern === '') {

        $errors[] =
            'Primary Pattern is required.';

    } elseif (!isValidRegex($pattern)) {

        $errors[] =
            'Primary Pattern is not a valid regular expression.';
    }

    /* --------------------------------------------------------
       SECONDARY PATTERN
       -------------------------------------------------------- */

    if ($matchType === 'CONTEXT_PATTERN') {

        if ($secondaryPattern === '') {

            $errors[] =
                'Secondary Pattern is required for a Context Pattern rule.';

        } elseif (
            !isValidRegex(
                $secondaryPattern
            )
        ) {

            $errors[] =
                'Secondary Pattern is not a valid regular expression.';
        }

    } else {

        /*
         * SIMPLE_PATTERN must not retain an old
         * secondary condition.
         */
        $secondaryPattern = '';
    }

    /* --------------------------------------------------------
       RECOMMENDATION
       -------------------------------------------------------- */

    if ($recommendation === '') {
        $errors[] =
            'Recommendation is required.';
    }

    /* --------------------------------------------------------
       DUPLICATE RULE CODE
       -------------------------------------------------------- */

    if (empty($errors)) {

        $duplicateStatement =
            $conn->prepare(
                "
                SELECT RuleID
                FROM scanner_rules
                WHERE RuleCode = ?
                LIMIT 1
                "
            );

        if (!$duplicateStatement) {

            $errors[] =
                'Unable to validate Rule Code.';

        } else {

            $duplicateStatement->bind_param(
                's',
                $ruleCode
            );

            $duplicateStatement->execute();

            $duplicateResult =
                $duplicateStatement->get_result();

            if (
                $duplicateResult->num_rows > 0
            ) {
                $errors[] =
                    'This Rule Code already exists.';
            }

            $duplicateStatement->close();
        }
    }

/* --------------------------------------------------------
   INSERT DRAFT RULE
   -------------------------------------------------------- */

if (empty($errors)) {

    $status = 'DRAFT';

    $nullableCwe =
        $cweId !== ''
            ? $cweId
            : null;

    $nullableOwasp =
        $owaspCategory !== ''
            ? $owaspCategory
            : null;

    $nullableSecondary =
        $secondaryPattern !== ''
            ? $secondaryPattern
            : null;

    $insertStatement =
        $conn->prepare(
            "
            INSERT INTO scanner_rules
            (
                RuleCode,
                RuleName,
                Language,
                DetectionType,
                WeaknessCategory,
                MatchType,
                CWEID,
                OWASPCategory,
                Severity,
                Status,
                Description,
                Pattern,
                SecondaryPattern,
                Recommendation,
                CreatedBy,
                CreatedAt
            )
            VALUES
            (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, NOW()
            )
            "
        );

    if (!$insertStatement) {

        $errors[] =
            'Unable to prepare scanner rule query: '
            . $conn->error;

    } else {

        $insertStatement->bind_param(
            'ssssssssssssssi',
            $ruleCode,
            $ruleName,
            $language,
            $detectionType,
            $weaknessCategory,
            $matchType,
            $nullableCwe,
            $nullableOwasp,
            $severity,
            $status,
            $description,
            $pattern,
            $nullableSecondary,
            $recommendation,
            $currentAdminId
        );

        if (
            $insertStatement->execute()
        ) {

            $newRuleId =
                $insertStatement->insert_id;

            $insertStatement->close();

           /* ========================================================
                ACTIVITY LOG - RULE CREATED
                ======================================================== */

                if (
                    $currentAdminId > 0
                    && function_exists('log_activity')
                ) {

                    log_activity(
                        LOG_RULE_CREATED,
                        $currentAdminId,
                        'Administrator created a new scanner rule.',
                        [
                            'module' => 'ScannerRule',
                            'severity' => 'INFO',
                            'result' => 'SUCCESS',

                            'target_type' => 'SCANNER_RULE',
                            'target_id' => $newRuleId,

                            'metadata' => [
                                'rule_code' => $ruleCode,
                                'rule_name' => $ruleName,
                                'language' => $language,
                                'detection_type' => $detectionType,
                                'match_type' => $matchType,
                                'severity' => $severity,
                                'status' => 'DRAFT'
                            ]
                        ]
                    );
                }

            /*
             * For now go back to scanner rule list.
             * Later when testRule.php exists,
             * we change this redirect to testRule.php.
             */

            header(
                'Location: scannerRule.php?'
                . http_build_query([
                    'type' => 'success',
                    'message' =>
                        'Scanner rule saved successfully as DRAFT.'
                ])
            );

            exit();
        }

        $errors[] =
            'Failed to save scanner rule: '
            . $insertStatement->error;

        $insertStatement->close();
    }
}
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

    <title>
        Add Scanner Rule | SecureLog
    </title>

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
            --bg: #020c17;
            --panel: #061729;
            --input: #061523;
            --border: #183247;

            --orange: #ff6500;
            --orange-light: #ff8100;

            --blue: #38bdf8;
            --green: #00d995;
            --red: #ff4355;
            --yellow: #fbbf24;

            --text: #f8fafc;
            --muted: #aab5c0;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;

            color: var(--text);
            background: var(--bg);

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

        .scanner-rule-page {
            min-height: 100vh;

            padding:
                14px
                18px;

            background:
                radial-gradient(
                    circle at 72% 7%,
                    rgba(56, 189, 248, 0.04),
                    transparent 30%
                ),
                var(--bg);
        }

        .scanner-rule-container {
            width: 100%;
            max-width: 1550px;

            margin: 0 auto;

            padding:
                27px
                27px
                35px;

            background:
                linear-gradient(
                    145deg,
                    rgba(5, 24, 40, 0.98),
                    rgba(2, 14, 26, 0.98)
                );

            border:
                1px solid
                var(--border);

            border-radius: 14px;
        }

        /* =====================================================
           HEADER
           ===================================================== */

        .page-header {
            margin-bottom: 25px;

            display: flex;

            align-items:
                flex-start;

            justify-content:
                space-between;

            gap: 20px;
        }

        .page-title h1 {
            margin:
                0
                0
                9px;

            font-size: 27px;
            font-weight: 800;

            text-transform:
                uppercase;
        }

        .page-title p {
            margin: 0;

            max-width: 760px;

            color: #bdc8d3;

            font-size: 13px;
            line-height: 1.65;
        }

        .back-button {
            height: 43px;

            padding:
                0
                15px;

            display:
                inline-flex;

            align-items: center;

            gap: 8px;

            color: #fff;
            background: #102334;

            border:
                1px solid
                var(--border);

            border-radius: 7px;

            text-decoration: none;

            font-size: 12px;
            font-weight: 600;
        }

        .back-button:hover {
            color: var(--orange);
            border-color: var(--orange);
        }

        /* =====================================================
           BREADCRUMB
           ===================================================== */

        .breadcrumb {
            margin-bottom: 24px;

            display: flex;
            align-items: center;
            flex-wrap: wrap;

            gap: 10px;

            color: var(--muted);

            font-size: 12px;
        }

        .breadcrumb a {
            color: var(--muted);
            text-decoration: none;
        }

        .breadcrumb a:hover {
            color: var(--orange);
        }

        .breadcrumb-current {
            color: var(--orange);
            font-weight: 600;
        }

        /* =====================================================
           MESSAGE
           ===================================================== */

        .message {
            margin-bottom: 20px;

            padding:
                15px
                18px;

            border-radius: 8px;

            font-size: 12px;
            line-height: 1.6;
        }

        .message.error {
            color: #ff8c97;

            background:
                rgba(255, 67, 85, 0.09);

            border:
                1px solid
                rgba(255, 67, 85, 0.30);
        }

        .message ul {
            margin: 0;
            padding-left: 20px;
        }

        /* =====================================================
           LAYOUT
           ===================================================== */

        .rule-layout {
            display: grid;

            grid-template-columns:
                minmax(0, 1fr)
                310px;

            gap: 25px;
        }

        .form-panel,
        .help-panel {
            background:
                linear-gradient(
                    145deg,
                    rgba(7, 27, 45, 0.98),
                    rgba(3, 17, 31, 0.98)
                );

            border:
                1px solid
                var(--border);

            border-radius: 12px;
        }

        .form-panel {
            padding:
                27px
                25px;
        }

        .form-header {
            margin-bottom: 25px;
        }

        .form-header h2 {
            margin:
                0
                0
                8px;

            color: var(--orange);

            font-size: 18px;
            font-weight: 800;

            text-transform:
                uppercase;
        }

        .form-header p {
            margin: 0;

            color: var(--muted);

            font-size: 12px;
            line-height: 1.6;
        }

        /* =====================================================
           DRAFT NOTICE
           ===================================================== */

        .draft-notice {
            margin-bottom: 25px;

            padding:
                15px
                17px;

            display: flex;

            align-items:
                flex-start;

            gap: 12px;

            color: #f6d373;

            background:
                rgba(251, 191, 36, 0.07);

            border:
                1px solid
                rgba(251, 191, 36, 0.24);

            border-radius: 8px;

            font-size: 12px;
            line-height: 1.6;
        }

        .draft-notice i {
            margin-top: 2px;

            color: var(--yellow);

            font-size: 16px;
        }

        /* =====================================================
           FORM
           ===================================================== */

        .form-grid {
            display: grid;

            grid-template-columns:
                repeat(
                    2,
                    minmax(0, 1fr)
                );

            gap:
                22px
                25px;
        }

        .form-group {
            min-width: 0;
        }

        .full-width {
            grid-column:
                1 / -1;
        }

        .form-label {
            display: block;

            margin-bottom: 9px;

            color: #fff;

            font-size: 12px;
            font-weight: 700;
        }

        .required {
            color: var(--orange);
        }

        .optional {
            margin-left: 5px;

            color: #718497;

            font-size: 10px;
            font-weight: 500;
        }

        .form-control {
            width: 100%;
            height: 47px;

            padding:
                0
                14px;

            color: #fff;

            background:
                rgba(4, 18, 31, 0.9);

            border:
                1px solid
                var(--border);

            border-radius: 7px;

            outline: none;

            font-family: inherit;
            font-size: 12px;

            transition:
                border-color 0.2s ease,
                box-shadow 0.2s ease;
        }

        .form-control::placeholder {
            color: #738495;
        }

        .form-control:focus {
            border-color: var(--orange);

            box-shadow:
                0 0 0 3px
                rgba(255, 101, 0, 0.08);
        }

        select.form-control {
            cursor: pointer;
        }

        select.form-control option {
            color: #fff;
            background: #071521;
        }

        textarea.form-control {
            min-height: 105px;
            height: 105px;

            padding:
                13px
                14px;

            resize: vertical;

            line-height: 1.55;
        }

        textarea.pattern {
            min-height: 110px;

            font-family:
                Consolas,
                Monaco,
                monospace;

            color: #ff9c5c;
        }

        .field-note {
            margin-top: 7px;

            color: #8191a0;

            font-size: 10px;
            line-height: 1.6;
        }

        /* =====================================================
           MATCH TYPE INFO
           ===================================================== */

        .match-info {
            grid-column:
                1 / -1;

            padding:
                14px
                16px;

            color: #b6d9ec;

            background:
                rgba(56, 189, 248, 0.04);

            border:
                1px solid
                rgba(56, 189, 248, 0.20);

            border-radius: 7px;

            font-size: 11px;
            line-height: 1.65;
        }

        .match-info strong {
            color: var(--blue);
        }

        /* =====================================================
           SECONDARY PATTERN
           ===================================================== */

        #secondaryPatternGroup {
            display: none;
        }

        /* =====================================================
           BUTTONS
           ===================================================== */

        .form-actions {
            margin-top: 5px;

            display: flex;
            align-items: center;

            gap: 12px;
        }

        .save-button,
        .cancel-button {
            min-height: 46px;

            padding:
                0
                18px;

            display:
                inline-flex;

            align-items: center;
            justify-content: center;

            gap: 8px;

            border-radius: 7px;

            font-family: inherit;

            font-size: 12px;
            font-weight: 700;
        }

        .save-button {
            color: #fff;

            background:
                linear-gradient(
                    90deg,
                    var(--orange),
                    var(--orange-light)
                );

            border: 0;

            cursor: pointer;
        }

        .save-button:hover {
            filter: brightness(1.08);
        }

        .cancel-button {
            color: #fff;
            background: #102334;

            border:
                1px solid
                var(--border);

            text-decoration: none;
        }

        .cancel-button:hover {
            border-color: var(--orange);
        }

        /* =====================================================
           HELP PANEL
           ===================================================== */

        .help-panel {
            align-self: start;

            padding:
                24px
                20px;
        }

        .help-panel h2 {
            margin:
                0
                0
                8px;

            color: var(--orange);

            font-size: 16px;

            text-transform:
                uppercase;
        }

        .help-panel > p {
            margin:
                0
                0
                22px;

            color: var(--muted);

            font-size: 11px;
            line-height: 1.6;
        }

        .help-heading {
            margin:
                22px
                0
                10px;

            color: #fff;

            font-size: 11px;
            font-weight: 700;

            text-transform:
                uppercase;
        }

        .example {
            margin-bottom: 12px;

            padding: 14px;

            background:
                rgba(4, 18, 31, 0.85);

            border:
                1px solid
                var(--border);

            border-radius: 7px;
        }

        .example-title {
            margin-bottom: 7px;

            color: var(--blue);

            font-size: 10px;
            font-weight: 700;
        }

        .example code {
            display: block;

            color: #ff9854;

            font-family:
                Consolas,
                Monaco,
                monospace;

            font-size: 10px;
            line-height: 1.6;

            word-break: break-word;
        }

        .security-note {
            margin-top: 20px;

            padding: 14px;

            color: #a6cce2;

            background:
                rgba(56, 189, 248, 0.05);

            border:
                1px solid
                rgba(56, 189, 248, 0.22);

            border-radius: 7px;

            font-size: 10px;
            line-height: 1.6;
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 1050px) {

            .rule-layout {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 750px) {

            .page-header {
                flex-direction: column;
            }

            .form-grid {
                grid-template-columns: 1fr;
            }

            .full-width,
            .match-info {
                grid-column: auto;
            }
        }

        @media (max-width: 500px) {

            .scanner-rule-page {
                padding: 8px;
            }

            .scanner-rule-container {
                padding:
                    20px
                    13px;
            }

            .form-panel {
                padding:
                    20px
                    15px;
            }

            .form-actions {
                flex-direction: column;
            }

            .save-button,
            .cancel-button {
                width: 100%;
            }
        }

    </style>

</head>

<body>

<?php
require __DIR__
    . '/../Sidebar/sidebaradmin.php';
?>

<main
    class="
        admin-page-content
        scanner-rule-page
    "
>

<div class="scanner-rule-container">

    <!-- =======================================================
         HEADER
         ======================================================= -->

    <header class="page-header">

        <div class="page-title">

            <h1>
                Add Scanner Rule
            </h1>

            <p>
                Create a SecureLog detection rule using
                configurable source-code patterns. CWE and
                OWASP mappings are optional because custom
                weaknesses may not always map directly to
                those classifications.
            </p>

        </div>

        <a
            href="scannerRule.php"
            class="back-button"
        >
            <i
                class="
                    fa-solid
                    fa-arrow-left
                "
            ></i>

            Back to Rules
        </a>

    </header>

    <!-- =======================================================
         BREADCRUMB
         ======================================================= -->

    <nav class="breadcrumb">

        <a
            href="../Dashboard/dashboard_Admin.php"
        >
            Dashboard
        </a>

        <i
            class="
                fa-solid
                fa-chevron-right
            "
        ></i>

        <a href="scannerRule.php">
            Scanner Rules
        </a>

        <i
            class="
                fa-solid
                fa-chevron-right
            "
        ></i>

        <span class="breadcrumb-current">
            Add Rule
        </span>

    </nav>

    <!-- =======================================================
         ERROR
         ======================================================= -->

    <?php if (!empty($errors)): ?>

        <div class="message error">

            <ul>

                <?php foreach (
                    $errors
                    as $error
                ): ?>

                    <li>
                        <?= e($error); ?>
                    </li>

                <?php endforeach; ?>

            </ul>

        </div>

    <?php endif; ?>

    <!-- =======================================================
         MAIN
         ======================================================= -->

    <section class="rule-layout">

        <div class="form-panel">

            <div class="form-header">

                <h2>
                    Rule Configuration
                </h2>

                <p>
                    Define how SecureLog should recognise
                    a source-code weakness.
                </p>

            </div>

            <div class="draft-notice">

                <i
                    class="
                        fa-solid
                        fa-circle-info
                    "
                ></i>

                <div>

                    <strong>
                        New rules are saved as DRAFT.
                    </strong>

                    <br>

                    The rule must be tested before it
                    can be activated and used by the
                    scanner engine.

                </div>

            </div>

            <form
                method="POST"
                action="addRule.php"
                autocomplete="off"
            >

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= e(
                        $csrfToken
                    ); ?>"
                >

                <div class="form-grid">

                    <!-- =======================================
                         RULE CODE
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="rule_code"
                            class="form-label"
                        >
                            Rule Code

                            <span class="required">
                                *
                            </span>
                        </label>

                        <input
                            type="text"
                            id="rule_code"
                            name="rule_code"
                            class="form-control"
                            maxlength="100"
                            placeholder="e.g. PHP-LOG-002"
                            value="<?= oldInput(
                                'rule_code'
                            ); ?>"
                            required
                        >

                        <div class="field-note">
                            Unique identifier for the rule.
                        </div>

                    </div>

                    <!-- =======================================
                         RULE NAME
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="rule_name"
                            class="form-label"
                        >
                            Rule Name

                            <span class="required">
                                *
                            </span>
                        </label>

                        <input
                            type="text"
                            id="rule_name"
                            name="rule_name"
                            class="form-control"
                            maxlength="255"
                            placeholder="e.g. Sensitive Information Written to Log"
                            value="<?= oldInput(
                                'rule_name'
                            ); ?>"
                            required
                        >

                    </div>

                    <!-- =======================================
                         LANGUAGE
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="language"
                            class="form-label"
                        >
                            Programming Language

                            <span class="required">
                                *
                            </span>
                        </label>

                        <select
                            id="language"
                            name="language"
                            class="form-control"
                            required
                        >

                            <option value="">
                                Select Language
                            </option>

                            <?php foreach (
                                $languageOptions
                                as $value => $label
                            ): ?>

                                <option
                                    value="<?= e($value); ?>"
                                    <?= $language === $value
                                        ? 'selected'
                                        : ''; ?>
                                >
                                    <?= e($label); ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <!-- =======================================
                         DETECTION TYPE
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="detection_type"
                            class="form-label"
                        >
                            Detection Type

                            <span class="required">
                                *
                            </span>
                        </label>

                        <select
                            id="detection_type"
                            name="detection_type"
                            class="form-control"
                            required
                        >

                            <option value="">
                                Select Detection Type
                            </option>

                            <?php foreach (
                                $detectionTypeOptions
                                as $value => $label
                            ): ?>

                                <option
                                    value="<?= e($value); ?>"
                                    <?= $detectionType === $value
                                        ? 'selected'
                                        : ''; ?>
                                >
                                    <?= e($label); ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <!-- =======================================
                         WEAKNESS CATEGORY
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="weakness_category"
                            class="form-label"
                        >
                            Weakness Category

                            <span class="required">
                                *
                            </span>
                        </label>

                        <input
                            type="text"
                            id="weakness_category"
                            name="weakness_category"
                            class="form-control"
                            maxlength="150"
                            placeholder="e.g. Sensitive Logging"
                            value="<?= oldInput(
                                'weakness_category'
                            ); ?>"
                            required
                        >

                        <div class="field-note">
                            SecureLog's own classification.
                            Custom categories are allowed.
                        </div>

                    </div>

                    <!-- =======================================
                         MATCH TYPE
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="match_type"
                            class="form-label"
                        >
                            Match Type

                            <span class="required">
                                *
                            </span>
                        </label>

                        <select
                            id="match_type"
                            name="match_type"
                            class="form-control"
                            required
                        >

                            <?php foreach (
                                $matchTypeOptions
                                as $value => $label
                            ): ?>

                                <option
                                    value="<?= e($value); ?>"
                                    <?= $matchType === $value
                                        ? 'selected'
                                        : ''; ?>
                                >
                                    <?= e($label); ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <!-- =======================================
                         MATCH EXPLANATION
                         ======================================= -->

                    <div class="match-info">

                        <strong>
                            Simple Pattern
                        </strong>

                        — SecureLog checks one regular
                        expression.

                        <br>

                        <strong>
                            Context Pattern
                        </strong>

                        — both Primary Pattern AND
                        Secondary Pattern must match the
                        same source-code statement.

                    </div>

                    <!-- =======================================
                         CWE
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="cwe_id"
                            class="form-label"
                        >
                            CWE ID

                            <span class="optional">
                                Optional
                            </span>
                        </label>

                        <input
                            type="text"
                            id="cwe_id"
                            name="cwe_id"
                            class="form-control"
                            placeholder="e.g. CWE-532"
                            value="<?= oldInput(
                                'cwe_id'
                            ); ?>"
                        >

                        <div class="field-note">
                            Leave blank when no suitable
                            CWE mapping exists.
                        </div>

                    </div>

                    <!-- =======================================
                         OWASP
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="owasp_category"
                            class="form-label"
                        >
                            OWASP Category

                            <span class="optional">
                                Optional
                            </span>
                        </label>

                        <select
                            id="owasp_category"
                            name="owasp_category"
                            class="form-control"
                        >

                            <option value="">
                                Not Mapped / Not Applicable
                            </option>

                            <?php foreach (
                                $owaspOptions
                                as $option
                            ): ?>

                                <option
                                    value="<?= e(
                                        $option
                                    ); ?>"
                                    <?= $owaspCategory ===
                                        $option
                                            ? 'selected'
                                            : ''; ?>
                                >
                                    <?= e($option); ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <!-- =======================================
                         SEVERITY
                         ======================================= -->

                    <div class="form-group">

                        <label
                            for="severity"
                            class="form-label"
                        >
                            Severity

                            <span class="required">
                                *
                            </span>
                        </label>

                        <select
                            id="severity"
                            name="severity"
                            class="form-control"
                            required
                        >

                            <option value="">
                                Select Severity
                            </option>

                            <?php foreach (
                                $severityOptions
                                as $value => $label
                            ): ?>

                                <option
                                    value="<?= e($value); ?>"
                                    <?= $severity === $value
                                        ? 'selected'
                                        : ''; ?>
                                >
                                    <?= e($label); ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <!-- =======================================
                         STATUS
                         ======================================= -->

                    <div class="form-group">

                        <label class="form-label">
                            Initial Status
                        </label>

                        <input
                            type="text"
                            class="form-control"
                            value="DRAFT"
                            disabled
                        >

                        <div class="field-note">
                            Activation is only available
                            after rule testing.
                        </div>

                    </div>

                    <!-- =======================================
                         DESCRIPTION
                         ======================================= -->

                    <div
                        class="
                            form-group
                            full-width
                        "
                    >

                        <label
                            for="description"
                            class="form-label"
                        >
                            Description

                            <span class="required">
                                *
                            </span>
                        </label>

                        <textarea
                            id="description"
                            name="description"
                            class="form-control"
                            placeholder="Describe the weakness this rule detects..."
                            required
                        ><?= oldInput(
                            'description'
                        ); ?></textarea>

                    </div>

                    <!-- =======================================
                         PRIMARY PATTERN
                         ======================================= -->

                    <div
                        class="
                            form-group
                            full-width
                        "
                    >

                        <label
                            for="pattern"
                            class="form-label"
                        >
                            Primary Pattern

                            <span class="required">
                                *
                            </span>
                        </label>

                        <textarea
                            id="pattern"
                            name="pattern"
                            class="
                                form-control
                                pattern
                            "
                            placeholder="/error_log\s*\(/i"
                            required
                        ><?= oldInput(
                            'pattern'
                        ); ?></textarea>

                        <div
                            class="field-note"
                            id="primaryPatternNote"
                        >
                            Main regular expression used
                            by the rule.
                        </div>

                    </div>

                    <!-- =======================================
                         SECONDARY PATTERN
                         ======================================= -->

                    <div
                        class="
                            form-group
                            full-width
                        "
                        id="secondaryPatternGroup"
                    >

                        <label
                            for="secondary_pattern"
                            class="form-label"
                        >
                            Secondary Pattern

                            <span class="required">
                                *
                            </span>
                        </label>

                        <textarea
                            id="secondary_pattern"
                            name="secondary_pattern"
                            class="
                                form-control
                                pattern
                            "
                            placeholder="/(password|token|api[_-]?key|secret)/i"
                        ><?= oldInput(
                            'secondary_pattern'
                        ); ?></textarea>

                        <div class="field-note">
                            Required for Context Pattern.
                            Both patterns must match the
                            same source-code statement.
                        </div>

                    </div>

                    <!-- =======================================
                         RECOMMENDATION
                         ======================================= -->

                    <div
                        class="
                            form-group
                            full-width
                        "
                    >

                        <label
                            for="recommendation"
                            class="form-label"
                        >
                            Recommendation

                            <span class="required">
                                *
                            </span>
                        </label>

                        <textarea
                            id="recommendation"
                            name="recommendation"
                            class="form-control"
                            placeholder="Explain how the developer should remediate this weakness..."
                            required
                        ><?= oldInput(
                            'recommendation'
                        ); ?></textarea>

                    </div>

                    <!-- =======================================
                         BUTTONS
                         ======================================= -->

                    <div
                        class="
                            form-group
                            full-width
                        "
                    >

                        <div class="form-actions">

                            <button
                                type="submit"
                                class="save-button"
                            >
                                <i
                                    class="
                                        fa-regular
                                        fa-floppy-disk
                                    "
                                ></i>

                                Save as Draft
                            </button>

                            <a
                                href="scannerRule.php"
                                class="cancel-button"
                            >
                                Cancel
                            </a>

                        </div>

                    </div>

                </div>

            </form>

        </div>

        <!-- ===================================================
             HELP
             =================================================== -->

        <aside class="help-panel">

            <h2>
                Rule Guide
            </h2>

            <p>
                Rules define patterns that SecureLog can
                evaluate against source code. Classification
                references do not control scanner behaviour.
            </p>

            <div class="help-heading">
                Simple Rule
            </div>

            <div class="example">

                <div class="example-title">
                    PHP Encryption
                </div>

                <code>
                    /openssl_encrypt\s*\(/i
                </code>

            </div>

            <div class="help-heading">
                Context Rule Example
            </div>

            <div class="example">

                <div class="example-title">
                    Primary — Logging
                </div>

                <code>
                    /(error_log|syslog|log_activity)\s*\(/i
                </code>

            </div>

            <div class="example">

                <div class="example-title">
                    Secondary — Sensitive Data
                </div>

                <code>
                    /(password|passwd|token|api[_-]?key|secret|session[_-]?id)/i
                </code>

            </div>

            <div class="security-note">

                <strong>
                    Context condition
                </strong>

                <br><br>

                Primary Match
                <strong>AND</strong>
                Secondary Match

                <br><br>

                Example:

                <br><br>

                <code>
                    error_log("Password: " . $password);
                </code>

                <br><br>

                Both conditions match, therefore
                SecureLog can report the finding.

            </div>

            <div class="security-note">

                <strong>
                    Classification
                </strong>

                <br><br>

                Weakness Category is SecureLog's
                internal classification.

                <br><br>

                CWE and OWASP mappings are optional
                references and do not determine whether
                the rule executes.

            </div>

        </aside>

    </section>

</div>

</main>

<script>

/* ============================================================
   MATCH TYPE UI
   ============================================================ */

const matchType =
    document.getElementById(
        'match_type'
    );

const secondaryPatternGroup =
    document.getElementById(
        'secondaryPatternGroup'
    );

const secondaryPattern =
    document.getElementById(
        'secondary_pattern'
    );

const primaryPatternNote =
    document.getElementById(
        'primaryPatternNote'
    );

function updateMatchTypeUI() {

    const isContext =
        matchType.value ===
        'CONTEXT_PATTERN';

    if (isContext) {

        secondaryPatternGroup.style.display =
            'block';

        secondaryPattern.required =
            true;

        primaryPatternNote.textContent =
            'Primary condition. For example, detect a logging statement.';

    } else {

        secondaryPatternGroup.style.display =
            'none';

        secondaryPattern.required =
            false;

        primaryPatternNote.textContent =
            'Single regular expression used to detect this weakness.';
    }
}

matchType.addEventListener(
    'change',
    updateMatchTypeUI
);

updateMatchTypeUI();

</script>

</body>
</html>