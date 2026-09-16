<?php
/**
 * SecureLog - Test Scanner Rule
 * File: ScannerRule/testRule.php
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

/* ============================================================
   CURRENT ADMIN
   ============================================================ */

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

function validateRegex(
    string $pattern
): bool {

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

/**
 * Test SIMPLE_PATTERN rule.
 */
function testSimplePattern(
    string $pattern,
    string $sourceCode
): array {

    $matchedLines = [];

    $lines =
        preg_split(
            "/\r\n|\n|\r/",
            $sourceCode
        );

    if (!is_array($lines)) {
        $lines = [];
    }

    foreach (
        $lines as
        $index => $line
    ) {

        $matched =
            preg_match(
                $pattern,
                $line
            );

        if ($matched === 1) {

            $matchedLines[] = [
                'line_number' =>
                    $index + 1,

                'line_content' =>
                    $line,

                'primary_match' =>
                    true,

                'secondary_match' =>
                    null
            ];
        }
    }

    return [
        'matched' =>
            !empty($matchedLines),

        'matches' =>
            $matchedLines
    ];
}

/**
 * Test CONTEXT_PATTERN rule.
 *
 * Both patterns must match the same source-code line.
 */
function testContextPattern(
    string $primaryPattern,
    string $secondaryPattern,
    string $sourceCode
): array {

    $matchedLines = [];

    $lines =
        preg_split(
            "/\r\n|\n|\r/",
            $sourceCode
        );

    if (!is_array($lines)) {
        $lines = [];
    }

    foreach (
        $lines as
        $index => $line
    ) {

        $primaryMatched =
            preg_match(
                $primaryPattern,
                $line
            ) === 1;

        $secondaryMatched =
            preg_match(
                $secondaryPattern,
                $line
            ) === 1;

        if (
            $primaryMatched
            && $secondaryMatched
        ) {

            $matchedLines[] = [
                'line_number' =>
                    $index + 1,

                'line_content' =>
                    $line,

                'primary_match' =>
                    true,

                'secondary_match' =>
                    true
            ];
        }
    }

    return [
        'matched' =>
            !empty($matchedLines),

        'matches' =>
            $matchedLines
    ];
}

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
            'message' =>
                'Invalid scanner rule.'
        ])
    );

    exit();
}

/* ============================================================
   LOAD RULE
   ============================================================ */

$ruleStatement =
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

if (!$ruleStatement) {
    die(
        'Unable to prepare scanner rule query.'
    );
}

$ruleStatement->bind_param(
    'i',
    $ruleId
);

$ruleStatement->execute();

$ruleResult =
    $ruleStatement->get_result();

$rule =
    $ruleResult->fetch_assoc();

$ruleStatement->close();

if (!$rule) {

    header(
        'Location: scannerRule.php?'
        . http_build_query([
            'type' => 'error',
            'message' =>
                'Scanner rule was not found.'
        ])
    );

    exit();
}

/* ============================================================
   RULE VALUES
   ============================================================ */

$ruleCode =
    (string) $rule['RuleCode'];

$ruleName =
    (string) $rule['RuleName'];

$language =
    (string) $rule['Language'];

$detectionType =
    (string) $rule['DetectionType'];

$weaknessCategory =
    (string) (
        $rule['WeaknessCategory']
        ?? ''
    );

$matchType =
    strtoupper(
        (string) $rule['MatchType']
    );

$severity =
    strtoupper(
        (string) $rule['Severity']
    );

$status =
    strtoupper(
        (string) $rule['Status']
    );

$primaryPattern =
    (string) $rule['Pattern'];

$secondaryPattern =
    (string) (
        $rule['SecondaryPattern']
        ?? ''
    );

/* ============================================================
   TEST STATE
   ============================================================ */

$errors = [];

$sourceCode = '';

$testPerformed = false;

$testPassed = false;

$testResult = [
    'matched' => false,
    'matches' => []
];

/* ============================================================
   FLASH MESSAGE
   ============================================================ */

$messageType =
    $_GET['type']
    ?? '';

$messageText =
    $_GET['message']
    ?? '';

if (
    !in_array(
        $messageType,
        [
            'success',
            'error',
            'warning'
        ],
        true
    )
) {
    $messageType = '';
}

/* ============================================================
   PROCESS TEST
   ============================================================ */

if (
    $_SERVER['REQUEST_METHOD']
    === 'POST'
) {

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

    $sourceCode =
        trim(
            $_POST['source_code']
            ?? ''
        );

    if ($sourceCode === '') {

        $errors[] =
            'Please enter sample source code.';
    }

    /* Validate stored primary regex */
    if (
        !validateRegex(
            $primaryPattern
        )
    ) {
        $errors[] =
            'The stored Primary Pattern is invalid. Edit the rule before testing.';
    }

    /* Validate context rule */
    if (
        $matchType ===
        'CONTEXT_PATTERN'
    ) {

        if (
            $secondaryPattern === ''
        ) {

            $errors[] =
                'This Context Pattern rule does not contain a Secondary Pattern.';

        } elseif (
            !validateRegex(
                $secondaryPattern
            )
        ) {

            $errors[] =
                'The stored Secondary Pattern is invalid. Edit the rule before testing.';
        }
    }

    if (empty($errors)) {

        $testPerformed = true;

        /* ================================================
           SIMPLE PATTERN
           ================================================ */

        if (
            $matchType ===
            'SIMPLE_PATTERN'
        ) {

            $testResult =
                testSimplePattern(
                    $primaryPattern,
                    $sourceCode
                );

        }

        /* ================================================
           CONTEXT PATTERN
           ================================================ */

        elseif (
            $matchType ===
            'CONTEXT_PATTERN'
        ) {

            $testResult =
                testContextPattern(
                    $primaryPattern,
                    $secondaryPattern,
                    $sourceCode
                );

        }

        /* ================================================
           UNKNOWN MATCH TYPE
           ================================================ */

        else {

            $errors[] =
                'Unsupported scanner rule match type.';

            $testPerformed =
                false;
        }

        if ($testPerformed) {

            $testPassed =
                (bool) $testResult[
                    'matched'
                ];
                                /* ============================================================
                SAVE TEST RESULT TO DATABASE
                ============================================================ */

                $testPassedValue = $testPassed ? 1 : 0;

                $testUpdateStatement = $conn->prepare(
                    "
                    UPDATE scanner_rules
                    SET
                        LastTestPassed = ?,
                        LastTestedAt = NOW(),
                        UpdatedAt = NOW()
                    WHERE RuleID = ?
                    LIMIT 1
                    "
                );

                if (!$testUpdateStatement) {

                    $errors[] =
                        'Unable to save rule test result: '
                        . $conn->error;

                } else {

                    $testUpdateStatement->bind_param(
                        'ii',
                        $testPassedValue,
                        $ruleId
                    );

                    if (!$testUpdateStatement->execute()) {

                        $errors[] =
                            'Failed to save rule test result: '
                            . $testUpdateStatement->error;

                    }

                    $testUpdateStatement->close();
                }

            /* ============================================
               ACTIVITY LOG
               ============================================ */

            if (
                $currentAdminId > 0
                && function_exists(
                    'log_activity'
                )
            ) {

                $logType =
                    defined(
                        'LOG_SCANNER_RULE_TESTED'
                    )
                        ? LOG_SCANNER_RULE_TESTED
                        : 'SCANNER_RULE_TESTED';

                $testStatus =
                    $testPassed
                        ? 'MATCH'
                        : 'NO_MATCH';

                log_activity(
                    $logType,
                    $currentAdminId,
                    "Tested scanner rule {$ruleCode}; result={$testStatus}"
                );
            }
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
    Test Scanner Rule | SecureLog
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
    --panel-light: #081d31;
    --input: #061523;
    --border: #183247;

    --orange: #ff6500;
    --orange-light: #ff8100;

    --blue: #38bdf8;
    --green: #00d995;
    --red: #ff4355;
    --yellow: #fbbf24;
    --purple: #a78bfa;

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

/* =========================================================
   PAGE
   ========================================================= */

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

/* =========================================================
   HEADER
   ========================================================= */

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
    min-height: 43px;

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

/* =========================================================
   BREADCRUMB
   ========================================================= */

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

/* =========================================================
   MESSAGES
   ========================================================= */

.message {
    margin-bottom: 20px;

    padding:
        14px
        17px;

    border-radius: 8px;

    font-size: 12px;
    line-height: 1.65;
}

.message.success {
    color: #5ef0b9;

    background:
        rgba(0, 217, 149, 0.08);

    border:
        1px solid
        rgba(0, 217, 149, 0.28);
}

.message.error {
    color: #ff8c97;

    background:
        rgba(255, 67, 85, 0.08);

    border:
        1px solid
        rgba(255, 67, 85, 0.28);
}

.message.warning {
    color: #fbd56d;

    background:
        rgba(251, 191, 36, 0.08);

    border:
        1px solid
        rgba(251, 191, 36, 0.28);
}

.message ul {
    margin: 0;

    padding-left: 20px;
}

/* =========================================================
   RULE INFO
   ========================================================= */

.rule-summary {
    margin-bottom: 25px;

    padding:
        22px
        23px;

    background:
        linear-gradient(
            145deg,
            rgba(7, 27, 45, 0.98),
            rgba(3, 17, 31, 0.98)
        );

    border:
        1px solid
        var(--border);

    border-radius: 11px;
}

.rule-summary-header {
    margin-bottom: 18px;

    display: flex;

    align-items:
        flex-start;

    justify-content:
        space-between;

    gap: 20px;
}

.rule-code {
    color: var(--orange);

    font-family:
        Consolas,
        Monaco,
        monospace;

    font-size: 12px;
    font-weight: 700;
}

.rule-name {
    margin-top: 5px;

    color: #fff;

    font-size: 20px;
    font-weight: 800;
}

.status-badge {
    padding:
        7px
        10px;

    border-radius: 6px;

    font-size: 10px;
    font-weight: 800;
}

.status-draft {
    color: #fbd56d;

    background:
        rgba(251, 191, 36, 0.1);

    border:
        1px solid
        rgba(251, 191, 36, 0.25);
}

.status-active {
    color: #5ef0b9;

    background:
        rgba(0, 217, 149, 0.1);

    border:
        1px solid
        rgba(0, 217, 149, 0.25);
}

.status-disabled {
    color: #ff8c97;

    background:
        rgba(255, 67, 85, 0.1);

    border:
        1px solid
        rgba(255, 67, 85, 0.25);
}

.rule-meta-grid {
    display: grid;

    grid-template-columns:
        repeat(
            4,
            minmax(0, 1fr)
        );

    gap: 12px;
}

.meta-card {
    padding:
        13px
        14px;

    background:
        rgba(4, 18, 31, 0.7);

    border:
        1px solid
        var(--border);

    border-radius: 7px;
}

.meta-label {
    margin-bottom: 5px;

    color: #7f91a2;

    font-size: 9px;
    font-weight: 700;

    text-transform:
        uppercase;
}

.meta-value {
    color: #dce5ec;

    font-size: 11px;
    font-weight: 600;

    word-break:
        break-word;
}

/* =========================================================
   TEST LAYOUT
   ========================================================= */

.test-layout {
    display: grid;

    grid-template-columns:
        minmax(0, 1fr)
        350px;

    gap: 25px;
}

.test-panel,
.pattern-panel {
    background:
        linear-gradient(
            145deg,
            rgba(7, 27, 45, 0.98),
            rgba(3, 17, 31, 0.98)
        );

    border:
        1px solid
        var(--border);

    border-radius: 11px;
}

.test-panel {
    padding:
        24px
        23px;
}

.pattern-panel {
    align-self: start;

    padding:
        22px
        19px;
}

.section-title {
    margin:
        0
        0
        8px;

    color: var(--orange);

    font-size: 16px;
    font-weight: 800;

    text-transform:
        uppercase;
}

.section-description {
    margin:
        0
        0
        20px;

    color: var(--muted);

    font-size: 11px;
    line-height: 1.6;
}

/* =========================================================
   CODE INPUT
   ========================================================= */

.form-label {
    display: block;

    margin-bottom: 9px;

    color: #fff;

    font-size: 12px;
    font-weight: 700;
}

.code-input {
    width: 100%;

    min-height: 330px;

    padding:
        16px
        17px;

    color: #dce5ec;

    background:
        #020d18;

    border:
        1px solid
        var(--border);

    border-radius: 8px;

    outline: none;

    resize: vertical;

    font-family:
        Consolas,
        Monaco,
        monospace;

    font-size: 12px;
    line-height: 1.65;
}

.code-input:focus {
    border-color: var(--orange);

    box-shadow:
        0 0 0 3px
        rgba(255, 101, 0, 0.08);
}

.field-note {
    margin-top: 8px;

    color: #8191a0;

    font-size: 10px;
    line-height: 1.6;
}

/* =========================================================
   BUTTON
   ========================================================= */

.form-actions {
    margin-top: 18px;

    display: flex;

    align-items: center;

    flex-wrap: wrap;

    gap: 10px;
}

.test-button,
.activate-button,
.edit-button {
    min-height: 44px;

    padding:
        0
        17px;

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

.test-button {
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

.activate-button {
    color: #5ef0b9;

    background:
        rgba(0, 217, 149, 0.08);

    border:
        1px solid
        rgba(0, 217, 149, 0.28);

    text-decoration: none;
}

.edit-button {
    color: #9edfff;

    background:
        rgba(56, 189, 248, 0.08);

    border:
        1px solid
        rgba(56, 189, 248, 0.25);

    text-decoration: none;
}

/* =========================================================
   PATTERNS
   ========================================================= */

.pattern-title {
    margin-bottom: 8px;

    color: #fff;

    font-size: 11px;
    font-weight: 700;
}

.pattern-box {
    margin-bottom: 17px;

    padding:
        14px;

    color: #ff9c5c;

    background:
        #020d18;

    border:
        1px solid
        var(--border);

    border-radius: 7px;

    font-family:
        Consolas,
        Monaco,
        monospace;

    font-size: 10px;
    line-height: 1.65;

    word-break:
        break-word;
}

.condition-box {
    margin-top: 18px;

    padding: 14px;

    color: #b6d9ec;

    background:
        rgba(56, 189, 248, 0.04);

    border:
        1px solid
        rgba(56, 189, 248, 0.20);

    border-radius: 7px;

    font-size: 10px;
    line-height: 1.6;
}

/* =========================================================
   RESULT
   ========================================================= */

.test-result {
    margin-top: 25px;

    padding:
        20px;

    border-radius: 10px;
}

.result-pass {
    background:
        rgba(0, 217, 149, 0.07);

    border:
        1px solid
        rgba(0, 217, 149, 0.28);
}

.result-fail {
    background:
        rgba(255, 67, 85, 0.07);

    border:
        1px solid
        rgba(255, 67, 85, 0.28);
}

.result-heading {
    margin-bottom: 8px;

    display: flex;

    align-items: center;

    gap: 9px;

    font-size: 17px;
    font-weight: 800;
}

.result-pass .result-heading {
    color: #5ef0b9;
}

.result-fail .result-heading {
    color: #ff8c97;
}

.result-description {
    margin-bottom: 16px;

    color: #b7c3ce;

    font-size: 11px;
    line-height: 1.65;
}

/* =========================================================
   MATCH LINES
   ========================================================= */

.match-list {
    display: grid;

    gap: 9px;
}

.match-item {
    padding:
        12px
        13px;

    background:
        rgba(2, 13, 24, 0.78);

    border:
        1px solid
        rgba(24, 50, 71, 0.85);

    border-radius: 7px;
}

.match-line-number {
    margin-bottom: 6px;

    color: var(--orange);

    font-size: 9px;
    font-weight: 800;

    text-transform:
        uppercase;
}

.match-code {
    color: #dce5ec;

    font-family:
        Consolas,
        Monaco,
        monospace;

    font-size: 10px;

    word-break:
        break-word;
}

/* =========================================================
   RESPONSIVE
   ========================================================= */

@media (max-width: 1100px) {

    .test-layout {
        grid-template-columns: 1fr;
    }

    .rule-meta-grid {
        grid-template-columns:
            repeat(
                2,
                minmax(0, 1fr)
            );
    }
}

@media (max-width: 650px) {

    .scanner-rule-page {
        padding: 8px;
    }

    .scanner-rule-container {
        padding:
            20px
            13px;
    }

    .page-header {
        flex-direction: column;
    }

    .rule-meta-grid {
        grid-template-columns: 1fr;
    }

    .code-input {
        min-height: 260px;
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

    <!-- =====================================================
         HEADER
         ===================================================== -->

    <header class="page-header">

        <div class="page-title">

            <h1>
                Test Scanner Rule
            </h1>

            <p>
                Validate the rule against sample source
                code before activating it for scanner use.
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

    <!-- =====================================================
         BREADCRUMB
         ===================================================== -->

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
            Test Rule
        </span>

    </nav>

    <!-- =====================================================
         FLASH
         ===================================================== -->

    <?php if (
        $messageType !== ''
        && $messageText !== ''
    ): ?>

        <div
            class="
                message
                <?= e(
                    $messageType
                ); ?>
            "
        >
            <?= e(
                $messageText
            ); ?>
        </div>

    <?php endif; ?>

    <!-- =====================================================
         ERRORS
         ===================================================== -->

    <?php if (
        !empty($errors)
    ): ?>

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

    <!-- =====================================================
         RULE SUMMARY
         ===================================================== -->

    <section class="rule-summary">

        <div class="rule-summary-header">

            <div>

                <div class="rule-code">
                    <?= e($ruleCode); ?>
                </div>

                <div class="rule-name">
                    <?= e($ruleName); ?>
                </div>

            </div>

            <span
                class="
                    status-badge
                    status-<?= e(
                        strtolower(
                            $status
                        )
                    ); ?>
                "
            >
                <?= e($status); ?>
            </span>

        </div>

        <div class="rule-meta-grid">

            <div class="meta-card">

                <div class="meta-label">
                    Language
                </div>

                <div class="meta-value">
                    <?= e($language); ?>
                </div>

            </div>

            <div class="meta-card">

                <div class="meta-label">
                    Detection Type
                </div>

                <div class="meta-value">
                    <?= e(
                        str_replace(
                            '_',
                            ' ',
                            $detectionType
                        )
                    ); ?>
                </div>

            </div>

            <div class="meta-card">

                <div class="meta-label">
                    Match Type
                </div>

                <div class="meta-value">
                    <?= e(
                        str_replace(
                            '_',
                            ' ',
                            $matchType
                        )
                    ); ?>
                </div>

            </div>

            <div class="meta-card">

                <div class="meta-label">
                    Severity
                </div>

                <div class="meta-value">
                    <?= e($severity); ?>
                </div>

            </div>

            <?php if (
                $weaknessCategory !== ''
            ): ?>

                <div class="meta-card">

                    <div class="meta-label">
                        Weakness Category
                    </div>

                    <div class="meta-value">
                        <?= e(
                            $weaknessCategory
                        ); ?>
                    </div>

                </div>

            <?php endif; ?>

            <?php if (
                !empty(
                    $rule['CWEID']
                )
            ): ?>

                <div class="meta-card">

                    <div class="meta-label">
                        CWE
                    </div>

                    <div class="meta-value">
                        <?= e(
                            $rule['CWEID']
                        ); ?>
                    </div>

                </div>

            <?php endif; ?>

        </div>

    </section>

    <!-- =====================================================
         TEST AREA
         ===================================================== -->

    <section class="test-layout">

        <!-- =================================================
             SOURCE CODE
             ================================================= -->

        <div class="test-panel">

            <h2 class="section-title">
                Sample Source Code
            </h2>

            <p class="section-description">

                Paste a small source-code sample.
                SecureLog will evaluate each line against
                the stored scanner rule.

            </p>

            <form
                method="POST"
                action="testRule.php"
            >

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= e(
                        $csrfToken
                    ); ?>"
                >

                <input
                    type="hidden"
                    name="rule_id"
                    value="<?= $ruleId; ?>"
                >

                <label
                    for="source_code"
                    class="form-label"
                >
                    Source Code
                </label>

                <textarea
                    id="source_code"
                    name="source_code"
                    class="code-input"
                    spellcheck="false"
                    placeholder="Paste sample code here..."
                    required
                ><?= e(
                    $sourceCode
                ); ?></textarea>

                <div class="field-note">

                    Context Pattern currently requires
                    Primary and Secondary patterns to match
                    the same source-code line.

                </div>

                <div class="form-actions">

                    <button
                        type="submit"
                        class="test-button"
                    >
                        <i
                            class="
                                fa-solid
                                fa-flask
                            "
                        ></i>

                        Test Rule
                    </button>

                    <a
                        href="editRule.php?rule_id=<?= $ruleId; ?>"
                        class="edit-button"
                    >
                        <i
                            class="
                                fa-solid
                                fa-pen
                            "
                        ></i>

                        Edit Rule
                    </a>

                </div>

            </form>

            <!-- =============================================
                 TEST RESULT
                 ============================================= -->

            <?php if (
                $testPerformed
            ): ?>

                <div
                    class="
                        test-result
                        <?= $testPassed
                            ? 'result-pass'
                            : 'result-fail'; ?>
                    "
                >

                    <div class="result-heading">

                        <?php if (
                            $testPassed
                        ): ?>

                            <i
                                class="
                                    fa-solid
                                    fa-circle-check
                                "
                            ></i>

                            MATCH FOUND

                        <?php else: ?>

                            <i
                                class="
                                    fa-solid
                                    fa-circle-xmark
                                "
                            ></i>

                            NO MATCH

                        <?php endif; ?>

                    </div>

                    <div class="result-description">

                        <?php if (
                            $testPassed
                        ): ?>

                            The scanner rule matched
                            <?= count(
                                $testResult[
                                    'matches'
                                ]
                            ); ?>
                            source-code
                            line<?= count(
                                $testResult[
                                    'matches'
                                ]
                            ) === 1
                                ? ''
                                : 's'; ?>.

                        <?php else: ?>

                            The supplied sample did not
                            satisfy this scanner rule.

                        <?php endif; ?>

                    </div>

                    <?php if (
                        $testPassed
                    ): ?>

                        <div class="match-list">

                            <?php foreach (
                                $testResult[
                                    'matches'
                                ]
                                as $match
                            ): ?>

                                <div class="match-item">

                                    <div
                                        class="
                                            match-line-number
                                        "
                                    >
                                        Line
                                        <?= (int) (
                                            $match[
                                                'line_number'
                                            ]
                                        ); ?>
                                    </div>

                                    <div class="match-code">
                                        <?= e(
                                            $match[
                                                'line_content'
                                            ]
                                        ); ?>
                                    </div>

                                </div>

                            <?php endforeach; ?>

                        </div>

                        <?php if (
                            $status !==
                            'ACTIVE'
                        ): ?>

                            <div class="form-actions">

                                <form
                                    method="POST"
                                    action="ruleAction.php"
                                    onsubmit="
                                        return confirm(
                                            'Activate this scanner rule?'
                                        );
                                    "
                                >

                                    <input
                                        type="hidden"
                                        name="csrf_token"
                                        value="<?= e(
                                            $csrfToken
                                        ); ?>"
                                    >

                                    <input
                                        type="hidden"
                                        name="rule_id"
                                        value="<?= $ruleId; ?>"
                                    >

                                    <input
                                        type="hidden"
                                        name="action"
                                        value="activate"
                                    >

                                    <button
                                        type="submit"
                                        class="activate-button"
                                    >
                                        <i
                                            class="
                                                fa-solid
                                                fa-circle-play
                                            "
                                        ></i>

                                        Activate Rule
                                    </button>

                                </form>

                            </div>

                        <?php endif; ?>

                    <?php endif; ?>

                </div>

            <?php endif; ?>

        </div>

        <!-- =================================================
             PATTERN INFORMATION
             ================================================= -->

        <aside class="pattern-panel">

            <h2 class="section-title">
                Detection Logic
            </h2>

            <p class="section-description">

                These are the stored expressions
                evaluated by SecureLog.

            </p>

            <div class="pattern-title">
                Primary Pattern
            </div>

            <div class="pattern-box">
                <?= e(
                    $primaryPattern
                ); ?>
            </div>

            <?php if (
                $matchType ===
                'CONTEXT_PATTERN'
            ): ?>

                <div class="pattern-title">
                    Secondary Pattern
                </div>

                <div class="pattern-box">
                    <?= e(
                        $secondaryPattern
                    ); ?>
                </div>

                <div class="condition-box">

                    <strong>
                        CONTEXT RULE
                    </strong>

                    <br><br>

                    Primary Pattern

                    <strong>
                        AND
                    </strong>

                    Secondary Pattern

                    <br><br>

                    must match the same source-code
                    line.

                </div>

            <?php else: ?>

                <div class="condition-box">

                    <strong>
                        SIMPLE RULE
                    </strong>

                    <br><br>

                    A finding is matched when the
                    Primary Pattern matches a
                    source-code line.

                </div>

            <?php endif; ?>

        </aside>

    </section>

</div>

</main>

</body>
</html>