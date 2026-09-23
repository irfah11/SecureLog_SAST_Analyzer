<?php
/**
 * SecureLog - Edit Scanner Rule
 * File: ScannerRule/editRule.php
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

$csrfToken =
    $_SESSION['csrf_token'];

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

    $result =
        preg_match(
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
   RULE ID
   ============================================================ */

$ruleId = (int) (
    $_GET['rule_id']
    ?? $_POST['rule_id']
    ?? 0
);

if ($ruleId <= 0) {

    header(
        'Location: scannerRule.php?'
        . http_build_query([
            'type' => 'error',
            'message' => 'Invalid scanner rule.'
        ])
    );

    exit();
}

/* ============================================================
   LOAD RULE
   ============================================================ */

$loadStatement =
    $conn->prepare(
        "
        SELECT
            RuleID,
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
            CreatedAt,
            UpdatedAt
        FROM scanner_rules
        WHERE RuleID = ?
        LIMIT 1
        "
    );

if (!$loadStatement) {
    die('Unable to prepare scanner rule query.');
}

$loadStatement->bind_param(
    'i',
    $ruleId
);

$loadStatement->execute();

$result =
    $loadStatement->get_result();

$rule =
    $result->fetch_assoc();

$loadStatement->close();

if (!$rule) {

    header(
        'Location: scannerRule.php?'
        . http_build_query([
            'type' => 'error',
            'message' => 'Scanner rule was not found.'
        ])
    );

    exit();
}

/* ============================================================
   ORIGINAL VALUES
   ============================================================ */

$originalRuleCode =
    (string) $rule['RuleCode'];

$originalLanguage =
    (string) $rule['Language'];

$originalDetectionType =
    (string) $rule['DetectionType'];

$originalMatchType =
    (string) $rule['MatchType'];

$originalPattern =
    (string) $rule['Pattern'];

$originalSecondaryPattern =
    (string) (
        $rule['SecondaryPattern']
        ?? ''
    );

$originalStatus =
    strtoupper(
        (string) $rule['Status']
    );

/* ============================================================
   FORM VALUES
   ============================================================ */

$errors = [];

$ruleCode =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? strtoupper(
            trim($_POST['rule_code'] ?? '')
        )
        : $originalRuleCode;

$ruleName =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim($_POST['rule_name'] ?? '')
        : (string) $rule['RuleName'];

$language =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? strtoupper(
            trim($_POST['language'] ?? '')
        )
        : $originalLanguage;

$detectionType =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? strtoupper(
            trim($_POST['detection_type'] ?? '')
        )
        : $originalDetectionType;

$weaknessCategory =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim(
            $_POST['weakness_category']
            ?? ''
        )
        : (string) (
            $rule['WeaknessCategory']
            ?? ''
        );

$matchType =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? strtoupper(
            trim(
                $_POST['match_type']
                ?? ''
            )
        )
        : $originalMatchType;

$cweId =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? strtoupper(
            trim($_POST['cwe_id'] ?? '')
        )
        : (string) (
            $rule['CWEID']
            ?? ''
        );

$owaspCategory =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim(
            $_POST['owasp_category']
            ?? ''
        )
        : (string) (
            $rule['OWASPCategory']
            ?? ''
        );

$severity =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? strtoupper(
            trim($_POST['severity'] ?? '')
        )
        : strtoupper(
            (string) $rule['Severity']
        );

$description =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim(
            $_POST['description']
            ?? ''
        )
        : (string) $rule['Description'];

$pattern =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim(
            $_POST['pattern']
            ?? ''
        )
        : $originalPattern;

$secondaryPattern =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim(
            $_POST['secondary_pattern']
            ?? ''
        )
        : $originalSecondaryPattern;

$recommendation =
    $_SERVER['REQUEST_METHOD'] === 'POST'
        ? trim(
            $_POST['recommendation']
            ?? ''
        )
        : (string) (
            $rule['Recommendation']
            ?? ''
        );

/* ============================================================
   PROCESS UPDATE
   ============================================================ */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    /* CSRF */

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

    /* Rule Code */

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
    }

    /* Rule Name */

    if ($ruleName === '') {
        $errors[] =
            'Rule Name is required.';
    }

    /* Language */

    if (
        !array_key_exists(
            $language,
            $languageOptions
        )
    ) {
        $errors[] =
            'Please select a valid programming language.';
    }

    /* Detection Type */

    if (
        !array_key_exists(
            $detectionType,
            $detectionTypeOptions
        )
    ) {
        $errors[] =
            'Please select a valid detection type.';
    }

    /* Weakness Category */

    if ($weaknessCategory === '') {
        $errors[] =
            'Weakness Category is required.';
    }

    /* Match Type */

    if (
        !array_key_exists(
            $matchType,
            $matchTypeOptions
        )
    ) {
        $errors[] =
            'Please select a valid match type.';
    }

    /* CWE optional */

    if (
        $cweId !== ''
        && !preg_match(
            '/^CWE-\d+$/',
            $cweId
        )
    ) {
        $errors[] =
            'CWE ID must use a format such as CWE-532 or be left blank.';
    }

    /* OWASP optional */

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

    /* Severity */

    if (
        !array_key_exists(
            $severity,
            $severityOptions
        )
    ) {
        $errors[] =
            'Please select a valid severity.';
    }

    /* Description */

    if ($description === '') {
        $errors[] =
            'Description is required.';
    }

    /* Primary Pattern */

    if ($pattern === '') {

        $errors[] =
            'Primary Pattern is required.';

    } elseif (
        !isValidRegex($pattern)
    ) {

        $errors[] =
            'Primary Pattern is not a valid regular expression.';
    }

    /* Secondary Pattern */

    if (
        $matchType ===
        'CONTEXT_PATTERN'
    ) {

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

        $secondaryPattern = '';
    }

    /* Recommendation */

    if ($recommendation === '') {
        $errors[] =
            'Recommendation is required.';
    }

    /* Duplicate Rule Code */

    if (empty($errors)) {

        $duplicateStatement =
            $conn->prepare(
                "
                SELECT RuleID
                FROM scanner_rules
                WHERE RuleCode = ?
                AND RuleID <> ?
                LIMIT 1
                "
            );

        if (!$duplicateStatement) {

            $errors[] =
                'Unable to validate Rule Code.';

        } else {

            $duplicateStatement->bind_param(
                'si',
                $ruleCode,
                $ruleId
            );

            $duplicateStatement->execute();

            $duplicateResult =
                $duplicateStatement
                    ->get_result();

            if (
                $duplicateResult->num_rows > 0
            ) {
                $errors[] =
                    'This Rule Code already exists.';
            }

            $duplicateStatement->close();
        }
    }

    /* ========================================================
       DETERMINE WHETHER RETEST IS REQUIRED
       ======================================================== */

    if (empty($errors)) {

        $logicChanged =
            $language !==
                $originalLanguage
            || $detectionType !==
                $originalDetectionType
            || $matchType !==
                $originalMatchType
            || $pattern !==
                $originalPattern
            || $secondaryPattern !==
                $originalSecondaryPattern;

        /*
         * If detection logic changes, invalidate
         * previous activation and require testing again.
         */
        $newStatus =
            $logicChanged
                ? 'DRAFT'
                : $originalStatus;

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

        /* ====================================================
           UPDATE
           ==================================================== */

        $updateStatement =
            $conn->prepare(
                "
                UPDATE scanner_rules
                SET
                    RuleCode = ?,
                    RuleName = ?,
                    Language = ?,
                    DetectionType = ?,
                    WeaknessCategory = ?,
                    MatchType = ?,
                    CWEID = ?,
                    OWASPCategory = ?,
                    Severity = ?,
                    Status = ?,
                    Description = ?,
                    Pattern = ?,
                    SecondaryPattern = ?,
                    Recommendation = ?,
                    UpdatedAt = NOW()
                WHERE RuleID = ?
                LIMIT 1
                "
            );

        if (!$updateStatement) {

            $errors[] =
                'Unable to prepare scanner rule update: '
                . $conn->error;

        } else {

            $updateStatement->bind_param(
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
                $newStatus,
                $description,
                $pattern,
                $nullableSecondary,
                $recommendation,
                $ruleId
            );

            if (
                $updateStatement->execute()
            ) {

                $updateStatement->close();

             /* ========================================================
                ACTIVITY LOG - RULE UPDATED
                ======================================================== */

                if (
                    $currentAdminId > 0
                    && function_exists('log_activity')
                ) {

                    log_activity(
                        LOG_RULE_UPDATED,
                        $currentAdminId,
                        'Administrator updated a scanner rule.',
                        [
                            'module' => 'ScannerRule',
                            'severity' => 'INFO',
                            'result' => 'SUCCESS',

                            'target_type' => 'SCANNER_RULE',
                            'target_id' => $ruleId,

                            'metadata' => [
                                'rule_code' => $ruleCode,
                                'rule_name' => $ruleName,
                                'language' => $language,
                                'detection_type' => $detectionType,
                                'match_type' => $matchType,
                                'severity' => $severity,

                                'logic_changed' => $logicChanged,

                                'previous_status' => $originalStatus,
                                'new_status' => $newStatus,

                                'retest_required' => $logicChanged
                            ]
                        ]
                    );
                }

                /* Redirect */

                if ($logicChanged) {

                    header(
                        'Location: testRule.php?'
                        . http_build_query([
                            'rule_id' => $ruleId,
                            'type' => 'warning',
                            'message' =>
                                'Rule updated. Detection logic changed, so the rule was reset to DRAFT and must be tested again.'
                        ])
                    );

                } else {

                    header(
                        'Location: scannerRule.php?'
                        . http_build_query([
                            'type' => 'success',
                            'message' =>
                                'Scanner rule updated successfully.'
                        ])
                    );
                }

                exit();
            }

            $errors[] =
                'Failed to update scanner rule: '
                . $updateStatement->error;

            $updateStatement->close();
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
    Edit Scanner Rule | SecureLog
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

.page-header {
    margin-bottom: 25px;

    display: flex;
    justify-content: space-between;
    align-items: flex-start;

    gap: 20px;
}

.page-title h1 {
    margin:
        0
        0
        9px;

    font-size: 27px;
    font-weight: 800;

    text-transform: uppercase;
}

.page-title p {
    margin: 0;

    max-width: 760px;

    color: #bdc8d3;

    font-size: 13px;
    line-height: 1.65;
}

.back-button {
    min-height: 43px;

    padding:
        0
        15px;

    display: inline-flex;
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

    text-transform: uppercase;
}

.form-header p {
    margin: 0;

    color: var(--muted);

    font-size: 12px;
    line-height: 1.6;
}

.status-notice {
    margin-bottom: 25px;

    padding:
        15px
        17px;

    display: flex;
    gap: 12px;

    color: #b6d9ec;

    background:
        rgba(56, 189, 248, 0.05);

    border:
        1px solid
        rgba(56, 189, 248, 0.22);

    border-radius: 8px;

    font-size: 12px;
    line-height: 1.6;
}

.status-notice strong {
    color: var(--orange);
}

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
}

.form-control:focus {
    border-color: var(--orange);

    box-shadow:
        0 0 0 3px
        rgba(255, 101, 0, 0.08);
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

    color: #ff9c5c;

    font-family:
        Consolas,
        Monaco,
        monospace;
}

.field-note {
    margin-top: 7px;

    color: #8191a0;

    font-size: 10px;
    line-height: 1.6;
}

#secondaryPatternGroup {
    display: none;
}

.form-actions {
    margin-top: 5px;

    display: flex;
    align-items: center;
    flex-wrap: wrap;

    gap: 12px;
}

.save-button,
.cancel-button {
    min-height: 46px;

    padding:
        0
        18px;

    display: inline-flex;
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

.cancel-button {
    color: #fff;
    background: #102334;

    border:
        1px solid
        var(--border);

    text-decoration: none;
}

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

    text-transform: uppercase;
}

.help-panel p {
    color: var(--muted);

    font-size: 11px;
    line-height: 1.7;
}

.help-card {
    margin-top: 15px;

    padding: 14px;

    color: #b6d9ec;

    background:
        rgba(56, 189, 248, 0.04);

    border:
        1px solid
        rgba(56, 189, 248, 0.2);

    border-radius: 7px;

    font-size: 10px;
    line-height: 1.7;
}

@media (max-width: 1050px) {

    .rule-layout {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 750px) {

    .form-grid {
        grid-template-columns: 1fr;
    }

    .full-width {
        grid-column: auto;
    }

    .page-header {
        flex-direction: column;
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

    <header class="page-header">

        <div class="page-title">

            <h1>
                Edit Scanner Rule
            </h1>

            <p>
                Update scanner rule configuration,
                classification and detection logic.
            </p>

        </div>

        <a
            href="scannerRule.php"
            class="back-button"
        >
            <i class="fa-solid fa-arrow-left"></i>

            Back to Rules
        </a>

    </header>

    <nav class="breadcrumb">

        <a href="../Dashboard/dashboard_Admin.php">
            Dashboard
        </a>

        <i class="fa-solid fa-chevron-right"></i>

        <a href="scannerRule.php">
            Scanner Rules
        </a>

        <i class="fa-solid fa-chevron-right"></i>

        <span class="breadcrumb-current">
            Edit Rule
        </span>

    </nav>

    <?php if (!empty($errors)): ?>

        <div class="message error">

            <ul>

                <?php foreach ($errors as $error): ?>

                    <li>
                        <?= e($error); ?>
                    </li>

                <?php endforeach; ?>

            </ul>

        </div>

    <?php endif; ?>

    <section class="rule-layout">

        <div class="form-panel">

            <div class="form-header">

                <h2>
                    Rule Configuration
                </h2>

                <p>
                    Editing detection logic requires
                    the rule to be tested again.
                </p>

            </div>

            <div class="status-notice">

                <i class="fa-solid fa-shield-halved"></i>

                <div>

                    Current Status:

                    <strong>
                        <?= e($originalStatus); ?>
                    </strong>

                    <br>

                    If Language, Detection Type,
                    Match Type or Pattern changes,
                    SecureLog automatically resets
                    this rule to DRAFT.

                </div>

            </div>

            <form
                method="POST"
                action="editRule.php"
                autocomplete="off"
            >

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= e($csrfToken); ?>"
                >

                <input
                    type="hidden"
                    name="rule_id"
                    value="<?= $ruleId; ?>"
                >

                <div class="form-grid">

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="rule_code"
                        >
                            Rule Code
                            <span class="required">*</span>
                        </label>

                        <input
                            type="text"
                            id="rule_code"
                            name="rule_code"
                            class="form-control"
                            value="<?= e($ruleCode); ?>"
                            required
                        >

                    </div>

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="rule_name"
                        >
                            Rule Name
                            <span class="required">*</span>
                        </label>

                        <input
                            type="text"
                            id="rule_name"
                            name="rule_name"
                            class="form-control"
                            value="<?= e($ruleName); ?>"
                            required
                        >

                    </div>

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="language"
                        >
                            Programming Language
                            <span class="required">*</span>
                        </label>

                        <select
                            id="language"
                            name="language"
                            class="form-control"
                            required
                        >

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

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="detection_type"
                        >
                            Detection Type
                            <span class="required">*</span>
                        </label>

                        <select
                            id="detection_type"
                            name="detection_type"
                            class="form-control"
                            required
                        >

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

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="weakness_category"
                        >
                            Weakness Category
                            <span class="required">*</span>
                        </label>

                        <input
                            type="text"
                            id="weakness_category"
                            name="weakness_category"
                            class="form-control"
                            value="<?= e($weaknessCategory); ?>"
                            required
                        >

                    </div>

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="match_type"
                        >
                            Match Type
                            <span class="required">*</span>
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

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="cwe_id"
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
                            value="<?= e($cweId); ?>"
                            placeholder="e.g. CWE-532"
                        >

                    </div>

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="owasp_category"
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
                                    value="<?= e($option); ?>"
                                    <?= $owaspCategory === $option
                                        ? 'selected'
                                        : ''; ?>
                                >
                                    <?= e($option); ?>
                                </option>

                            <?php endforeach; ?>

                        </select>

                    </div>

                    <div class="form-group">

                        <label
                            class="form-label"
                            for="severity"
                        >
                            Severity
                            <span class="required">*</span>
                        </label>

                        <select
                            id="severity"
                            name="severity"
                            class="form-control"
                            required
                        >

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

                    <div class="form-group">

                        <label class="form-label">
                            Current Status
                        </label>

                        <input
                            type="text"
                            class="form-control"
                            value="<?= e($originalStatus); ?>"
                            disabled
                        >

                        <div class="field-note">
                            Status is managed through
                            testing and rule actions.
                        </div>

                    </div>

                    <div class="form-group full-width">

                        <label
                            class="form-label"
                            for="description"
                        >
                            Description
                            <span class="required">*</span>
                        </label>

                        <textarea
                            id="description"
                            name="description"
                            class="form-control"
                            required
                        ><?= e($description); ?></textarea>

                    </div>

                    <div class="form-group full-width">

                        <label
                            class="form-label"
                            for="pattern"
                        >
                            Primary Pattern
                            <span class="required">*</span>
                        </label>

                        <textarea
                            id="pattern"
                            name="pattern"
                            class="form-control pattern"
                            required
                        ><?= e($pattern); ?></textarea>

                    </div>

                    <div
                        class="form-group full-width"
                        id="secondaryPatternGroup"
                    >

                        <label
                            class="form-label"
                            for="secondary_pattern"
                        >
                            Secondary Pattern
                            <span class="required">*</span>
                        </label>

                        <textarea
                            id="secondary_pattern"
                            name="secondary_pattern"
                            class="form-control pattern"
                        ><?= e($secondaryPattern); ?></textarea>

                        <div class="field-note">
                            Required for Context Pattern.
                        </div>

                    </div>

                    <div class="form-group full-width">

                        <label
                            class="form-label"
                            for="recommendation"
                        >
                            Recommendation
                            <span class="required">*</span>
                        </label>

                        <textarea
                            id="recommendation"
                            name="recommendation"
                            class="form-control"
                            required
                        ><?= e($recommendation); ?></textarea>

                    </div>

                    <div class="form-group full-width">

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

                                Update Rule
                            </button>

                            <a
                                href="testRule.php?rule_id=<?= $ruleId; ?>"
                                class="cancel-button"
                            >
                                Test Rule
                            </a>

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

        <aside class="help-panel">

            <h2>
                Editing Rules
            </h2>

            <p>
                Metadata such as description,
                CWE mapping or recommendation may
                be updated without changing the
                scanner behaviour.
            </p>

            <div class="help-card">

                <strong>
                    Re-test required
                </strong>

                <br><br>

                Changing Language, Detection Type,
                Match Type, Primary Pattern or
                Secondary Pattern changes the
                detection logic.

                <br><br>

                SecureLog will therefore reset the
                rule to DRAFT.

            </div>

            <div class="help-card">

                <strong>
                    Example
                </strong>

                <br><br>

                ACTIVE

                <br>
                ↓

                Admin changes regex

                <br>
                ↓

                DRAFT

                <br>
                ↓

                Test again

                <br>
                ↓

                Activate

            </div>

        </aside>

    </section>

</div>

</main>

<script>

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

function updateMatchTypeUI() {

    const isContext =
        matchType.value ===
        'CONTEXT_PATTERN';

    secondaryPatternGroup.style.display =
        isContext
            ? 'block'
            : 'none';

    secondaryPattern.required =
        isContext;
}

matchType.addEventListener(
    'change',
    updateMatchTypeUI
);

updateMatchTypeUI();

</script>

</body>
</html>