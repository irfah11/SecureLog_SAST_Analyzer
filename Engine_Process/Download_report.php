<?php

/*
|--------------------------------------------------------------------------
| SecureLog - View / Download Scan Report
|--------------------------------------------------------------------------
*/

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/connection.php';


/*
|--------------------------------------------------------------------------
| 1. AUTHENTICATION
|--------------------------------------------------------------------------
*/

$currentUserId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

$userRole = strtolower(
    trim((string) ($_SESSION['role'] ?? ''))
);

if ($currentUserId <= 0) {
    header('Location: ../Registration/login.php');
    exit;
}


/*
|--------------------------------------------------------------------------
| 2. ROLE AUTHORIZATION
|--------------------------------------------------------------------------
*/

$allowedRoles = ['admin', 'developer'];

if (!in_array($userRole, $allowedRoles, true)) {
    http_response_code(403);
    exit('Access denied.');
}


/*
|--------------------------------------------------------------------------
| 3. VALIDATE SCAN ID
|--------------------------------------------------------------------------
*/

$scanId = filter_input(
    INPUT_GET,
    'scan_id',
    FILTER_VALIDATE_INT,
    [
        'options' => [
            'min_range' => 1
        ]
    ]
);

if ($scanId === false || $scanId === null) {
    http_response_code(400);
    exit('Invalid scan ID.');
}


/*
|--------------------------------------------------------------------------
| 4. GET SCAN + VERIFY OWNERSHIP
|--------------------------------------------------------------------------
*/

if ($userRole === 'admin') {

    $scanStmt = $conn->prepare(
        "SELECT *
         FROM scans
         WHERE ScanID = ?
         LIMIT 1"
    );

    if (!$scanStmt) {
        http_response_code(500);
        exit('Unable to prepare report query.');
    }

    $scanStmt->bind_param('i', $scanId);

} else {

    $scanStmt = $conn->prepare(
        "SELECT *
         FROM scans
         WHERE ScanID = ?
           AND UserID = ?
         LIMIT 1"
    );

    if (!$scanStmt) {
        http_response_code(500);
        exit('Unable to prepare report query.');
    }

    $scanStmt->bind_param(
        'ii',
        $scanId,
        $currentUserId
    );
}

if (!$scanStmt->execute()) {
    $scanStmt->close();

    http_response_code(500);
    exit('Unable to retrieve scan report.');
}

$scanResult = $scanStmt->get_result();
$scan = $scanResult->fetch_assoc();

$scanStmt->close();

if (!$scan) {
    http_response_code(404);
    exit('Scan report not found.');
}


/*
|--------------------------------------------------------------------------
| 5. GET SCAN RESULTS
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| Status is now important:
|
| FAIL = actual failed security/policy check
| PASS = successful check
| N/A  = dependent check could not be evaluated
|
|--------------------------------------------------------------------------
*/

$findingStmt = $conn->prepare(
    "SELECT
        ResultID,
        RuleID,
        Status,
        Standard,
        VulnerabilityName,
        Severity,
        FilePath,
        LineNumber,
        MatchedCode,
        Description,
        Remediation
     FROM scan_results
     WHERE ScanID = ?
     ORDER BY
        FIELD(Status, 'FAIL', 'PASS', 'N/A'),
        FIELD(
            UPPER(Severity),
            'CRITICAL',
            'HIGH',
            'MEDIUM',
            'LOW',
            'INFO'
        ),
        FilePath ASC,
        LineNumber ASC"
);

if (!$findingStmt) {
    http_response_code(500);
    exit('Unable to prepare findings query.');
}

$findingStmt->bind_param('i', $scanId);

if (!$findingStmt->execute()) {
    $findingStmt->close();

    http_response_code(500);
    exit('Unable to retrieve scan findings.');
}

$findingResult = $findingStmt->get_result();


/*
|--------------------------------------------------------------------------
| 6. SEPARATE FAIL / PASS / N/A
|--------------------------------------------------------------------------
*/

$allResults = [];
$failedFindings = [];
$passedChecks = [];
$notEvaluatedChecks = [];

$statusCounts = [
    'FAIL' => 0,
    'PASS' => 0,
    'N/A'  => 0
];

$severityCounts = [
    'CRITICAL' => 0,
    'HIGH'     => 0,
    'MEDIUM'   => 0,
    'LOW'      => 0
];

while ($row = $findingResult->fetch_assoc()) {

    /*
    |--------------------------------------------------------------------------
    | Normalize Status
    |--------------------------------------------------------------------------
    */

    $status = strtoupper(
        trim((string) ($row['Status'] ?? 'N/A'))
    );

    if (!array_key_exists($status, $statusCounts)) {
        $status = 'N/A';
    }

    $row['Status'] = $status;


    /*
    |--------------------------------------------------------------------------
    | Normalize Severity
    |--------------------------------------------------------------------------
    */

    $severity = strtoupper(
        trim((string) ($row['Severity'] ?? 'INFO'))
    );

    $allowedSeverities = [
        'CRITICAL',
        'HIGH',
        'MEDIUM',
        'LOW',
        'INFO'
    ];

    if (!in_array($severity, $allowedSeverities, true)) {
        $severity = 'INFO';
    }

    $row['Severity'] = $severity;

    $statusCounts[$status]++;

    $allResults[] = $row;


    /*
    |--------------------------------------------------------------------------
    | FAIL
    |--------------------------------------------------------------------------
    |
    | Only FAIL rows are security/policy findings.
    |
    */

    if ($status === 'FAIL') {

        $failedFindings[] = $row;

        if (array_key_exists($severity, $severityCounts)) {
            $severityCounts[$severity]++;
        }
    }


    /*
    |--------------------------------------------------------------------------
    | PASS
    |--------------------------------------------------------------------------
    */

    elseif ($status === 'PASS') {
        $passedChecks[] = $row;
    }


    /*
    |--------------------------------------------------------------------------
    | N/A
    |--------------------------------------------------------------------------
    */

    else {
        $notEvaluatedChecks[] = $row;
    }
}

$findingStmt->close();


/*
|--------------------------------------------------------------------------
| 7. FINAL COUNTS
|--------------------------------------------------------------------------
*/

$totalChecks = count($allResults);

$totalFailed = count($failedFindings);

$totalPassed = count($passedChecks);

$totalNotEvaluated = count($notEvaluatedChecks);


/*
|--------------------------------------------------------------------------
| 8. CALCULATE OVERALL RISK
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| PASS and N/A must NOT increase risk.
|
|--------------------------------------------------------------------------
*/

if ($severityCounts['CRITICAL'] > 0) {

    $overallRisk = 'CRITICAL';

} elseif ($severityCounts['HIGH'] > 0) {

    $overallRisk = 'HIGH';

} elseif ($severityCounts['MEDIUM'] > 0) {

    $overallRisk = 'MEDIUM';

} elseif ($severityCounts['LOW'] > 0) {

    $overallRisk = 'LOW';

} else {

    $overallRisk = 'NONE';
}


/*
|--------------------------------------------------------------------------
| 9. OUTPUT ESCAPING
|--------------------------------------------------------------------------
*/

function e(mixed $value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}


/*
|--------------------------------------------------------------------------
| 10. FRIENDLY STANDARD
|--------------------------------------------------------------------------
*/

function getStandardLabel(array $finding): string
{
    $standard = trim(
        (string) ($finding['Standard'] ?? '')
    );

    if ($standard !== '') {
        return $standard;
    }

    $ruleId = (int) ($finding['RuleID'] ?? 0);

    /*
    |--------------------------------------------------------------------------
    | SecureLog internal mapping
    |--------------------------------------------------------------------------
    */

    if (in_array($ruleId, [77801, 77802, 77803], true)) {
        return 'CWE-778';
    }

    if ($ruleId >= 11700 && $ruleId < 11800) {
        return 'CWE-117';
    }

    return 'SecureLog Policy';
}


/*
|--------------------------------------------------------------------------
| 11. FRIENDLY CHECK NAME
|--------------------------------------------------------------------------
*/

function getCheckName(array $finding): string
{
    $name = trim(
        (string) ($finding['VulnerabilityName'] ?? '')
    );

    if ($name !== '') {
        return $name;
    }

    return 'Security Check';
}


/*
|--------------------------------------------------------------------------
| 12. RECOMMENDATION
|--------------------------------------------------------------------------
*/

function getRecommendation(array $finding): string
{
    /*
    |--------------------------------------------------------------------------
    | Prefer scanner-generated remediation
    |--------------------------------------------------------------------------
    */

    $remediation = trim(
        (string) ($finding['Remediation'] ?? '')
    );

    if ($remediation !== '') {
        return $remediation;
    }

    $name = strtolower(
        (string) ($finding['VulnerabilityName'] ?? '')
    );

    $description = strtolower(
        (string) ($finding['Description'] ?? '')
    );

    $text = $name . ' ' . $description;


    /*
    |--------------------------------------------------------------------------
    | CWE-778
    |--------------------------------------------------------------------------
    */

    if (
        str_contains($text, 'security logging') ||
        str_contains($text, 'without an associated logging') ||
        str_contains($text, 'without logging')
    ) {
        return
            'Add an appropriate security logging operation for this security-relevant event.';
    }


    /*
    |--------------------------------------------------------------------------
    | CWE-117
    |--------------------------------------------------------------------------
    */

    if (
        str_contains($text, 'neutraliz') ||
        str_contains($text, 'log injection') ||
        str_contains($text, 'external input')
    ) {
        return
            'Neutralize untrusted external input before it is written to the security log.';
    }


    /*
    |--------------------------------------------------------------------------
    | TXT Storage Policy
    |--------------------------------------------------------------------------
    */

    if (
        str_contains($text, '.txt') ||
        str_contains($text, 'log storage')
    ) {
        return
            'Store security logs using the approved SecureLog .txt storage policy.';
    }


    /*
    |--------------------------------------------------------------------------
    | Log Protection
    |--------------------------------------------------------------------------
    */

    if (
        str_contains($text, 'protection') ||
        str_contains($text, 'encrypt')
    ) {
        return
            'Protect stored log data using the approved SecureLog log protection mechanism.';
    }

    return
        'Review this failed security check and apply the recommended SecureLog control.';
}


/*
|--------------------------------------------------------------------------
| 13. NORMALIZE SCAN INFORMATION
|--------------------------------------------------------------------------
*/

$projectName =
    $scan['ProjectName']
    ?? $scan['projectName']
    ?? $scan['project_name']
    ?? 'Unknown Project';

$scanDate =
    $scan['ScanDate']
    ?? $scan['scan_date']
    ?? '-';

$status =
    $scan['Status']
    ?? $scan['status']
    ?? 'COMPLETED';

$language =
    $scan['ProgrammingLanguage']
    ?? $scan['Language']
    ?? '-';

$totalFiles =
    $scan['TotalFiles']
    ?? $scan['total_files']
    ?? 0;


/*
|--------------------------------------------------------------------------
| Fix display if old scan record still says Pending
|--------------------------------------------------------------------------
*/

if (strtolower((string) $status) === 'pending') {
    $status = 'COMPLETED';
}


/*
|--------------------------------------------------------------------------
| Friendly language
|--------------------------------------------------------------------------
*/

switch (strtolower((string) $language)) {

    case 'php':
        $language = 'PHP';
        break;

    case 'java':
        $language = 'Java';
        break;

    case 'javascript':
        $language = 'JavaScript';
        break;

    case 'c':
        $language = 'C';
        break;
}

?>
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<title>
    SecureLog Report - Scan <?= e($scanId); ?>
</title>

<link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
>

<style>

:root {

    --bg: #020817;
    --card: #07162b;
    --card2: #0f1f35;

    --border: rgba(59,130,246,.22);

    --blue: #3b82f6;
    --green: #10b981;
    --orange: #f59e0b;
    --red: #ef4444;
    --purple: #8b5cf6;
    --gray: #64748b;

    --text: #f8fafc;
    --muted: #94a3b8;
}

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    background: var(--bg);

    color: var(--text);

    font-family: Arial, sans-serif;
}

.page {

    width: 100%;

    max-width: 1100px;

    margin: 0 auto;

    padding: 36px 24px 50px;
}


/*
|--------------------------------------------------------------------------
| TOP ACTIONS
|--------------------------------------------------------------------------
*/

.top-actions {

    margin-bottom: 24px;

    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 14px;
}

.back-link,
.print-btn {

    padding: 11px 16px;

    display: inline-flex;

    align-items: center;

    gap: 8px;

    color: #fff;

    text-decoration: none;

    font-weight: 700;

    font-size: 13px;

    border-radius: 9px;

    border: 1px solid var(--border);

    background: var(--card);
}

.print-btn {

    border: none;

    background: var(--green);

    cursor: pointer;
}


/*
|--------------------------------------------------------------------------
| HEADER
|--------------------------------------------------------------------------
*/

.report-header {

    margin-bottom: 24px;

    padding: 28px;

    background:
        linear-gradient(
            145deg,
            rgba(8,27,51,.98),
            rgba(5,19,38,.98)
        );

    border: 1px solid var(--border);

    border-radius: 16px;
}

.brand {

    color: var(--blue);

    font-size: 22px;

    font-weight: 900;

    letter-spacing: 1px;
}

h1 {

    margin: 18px 0 8px;

    font-size: 30px;
}

.subtitle {

    color: var(--muted);

    font-size: 14px;
}

.risk-badge {

    margin-top: 18px;

    padding: 8px 14px;

    display: inline-flex;

    align-items: center;

    gap: 8px;

    border-radius: 999px;

    font-size: 13px;

    font-weight: 800;
}

.risk-critical,
.risk-high {

    color: #fff;

    background: var(--red);
}

.risk-medium {

    color: #111827;

    background: var(--orange);
}

.risk-low {

    color: #fff;

    background: var(--blue);
}

.risk-none {

    color: #fff;

    background: var(--green);
}


/*
|--------------------------------------------------------------------------
| SUMMARY
|--------------------------------------------------------------------------
*/

.summary-grid {

    margin-bottom: 24px;

    display: grid;

    grid-template-columns: repeat(4,1fr);

    gap: 14px;
}

.summary-card {

    padding: 18px;

    background: var(--card);

    border: 1px solid var(--border);

    border-radius: 14px;
}

.summary-label {

    color: var(--muted);

    font-size: 12px;

    text-transform: uppercase;

    font-weight: 800;
}

.summary-value {

    margin-top: 10px;

    color: #fff;

    font-size: 24px;

    font-weight: 900;
}

.text-red {
    color: var(--red);
}

.text-orange {
    color: var(--orange);
}

.text-blue {
    color: var(--blue);
}

.text-green {
    color: var(--green);
}

.text-gray {
    color: var(--gray);
}


/*
|--------------------------------------------------------------------------
| SECTIONS
|--------------------------------------------------------------------------
*/

.section {

    margin-bottom: 24px;

    padding: 24px;

    background: var(--card);

    border: 1px solid var(--border);

    border-radius: 14px;
}

.section h2 {

    margin: 0 0 18px;

    display: flex;

    align-items: center;

    gap: 10px;

    font-size: 18px;
}


/*
|--------------------------------------------------------------------------
| SCAN INFORMATION
|--------------------------------------------------------------------------
*/

.scan-info {

    width: 100%;

    border-collapse: collapse;
}

.scan-info td {

    padding: 10px 12px;

    border-bottom:
        1px solid rgba(148,163,184,.12);

    font-size: 13px;
}

.scan-info td:first-child {

    color: var(--muted);

    width: 190px;

    font-weight: 700;
}


/*
|--------------------------------------------------------------------------
| CHECK STATUS SUMMARY
|--------------------------------------------------------------------------
*/

.check-grid {

    display: grid;

    grid-template-columns: repeat(3,1fr);

    gap: 14px;
}

.check-card {

    padding: 20px;

    background: var(--card2);

    border: 1px solid rgba(148,163,184,.18);

    border-radius: 12px;
}

.check-card span {

    display: block;

    color: var(--muted);

    font-size: 12px;

    font-weight: 800;

    text-transform: uppercase;
}

.check-card strong {

    display: block;

    margin-top: 8px;

    font-size: 28px;
}


/*
|--------------------------------------------------------------------------
| SEVERITY
|--------------------------------------------------------------------------
*/

.severity-row {

    display: grid;

    grid-template-columns: repeat(4,1fr);

    gap: 12px;
}

.severity-card {

    padding: 16px;

    border-radius: 12px;

    background: var(--card2);

    border:
        1px solid rgba(148,163,184,.18);
}

.severity-card span {

    display: block;

    color: var(--muted);

    font-size: 12px;

    font-weight: 800;
}

.severity-card strong {

    display: block;

    margin-top: 8px;

    font-size: 25px;
}


/*
|--------------------------------------------------------------------------
| FINDINGS
|--------------------------------------------------------------------------
*/

.finding {

    margin-bottom: 16px;

    padding: 18px;

    background: var(--card2);

    border:
        1px solid rgba(148,163,184,.18);

    border-radius: 12px;

    page-break-inside: avoid;
}

.finding-title {

    margin-bottom: 12px;

    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 14px;

    font-weight: 900;
}

.finding-meta {

    display: grid;

    grid-template-columns: 1fr 1fr;

    gap: 8px 16px;

    color: #dbeafe;

    font-size: 13px;
}

.finding-meta strong {
    color: var(--muted);
}

.description,
.recommendation {

    margin-top: 14px;

    color: #d1d5db;

    font-size: 13px;

    line-height: 1.6;
}

.severity-pill,
.status-pill {

    padding: 5px 10px;

    border-radius: 999px;

    font-size: 11px;

    font-weight: 900;
}

.pill-critical,
.pill-high {

    color: #fff;

    background: var(--red);
}

.pill-medium {

    color: #111827;

    background: var(--orange);
}

.pill-low {

    color: #fff;

    background: var(--blue);
}

.status-fail {

    color: #fff;

    background: var(--red);
}

.status-pass {

    color: #fff;

    background: var(--green);
}

.status-na {

    color: #fff;

    background: var(--gray);
}


/*
|--------------------------------------------------------------------------
| SUMMARY MESSAGE
|--------------------------------------------------------------------------
*/

.summary-message {

    padding: 15px 17px;

    background: var(--card2);

    border:
        1px solid rgba(148,163,184,.18);

    border-radius: 10px;

    color: #dbeafe;

    font-size: 13px;

    line-height: 1.6;
}

.footer {

    color: var(--muted);

    text-align: center;

    font-size: 12px;

    margin-top: 30px;
}


/*
|--------------------------------------------------------------------------
| PRINT / PDF
|--------------------------------------------------------------------------
*/

@media print {

    body {

        background: #fff;

        color: #111827;
    }

    .top-actions {
        display: none;
    }

    .report-header,
    .section,
    .summary-card,
    .finding,
    .severity-card,
    .check-card,
    .summary-message {

        background: #fff;

        color: #111827;

        border: 1px solid #d1d5db;

        box-shadow: none;
    }

    .brand,
    h1,
    h2,
    .summary-value,
    .finding-title {

        color: #111827;
    }

    .subtitle,
    .summary-label,
    .scan-info td:first-child,
    .finding-meta strong,
    .footer {

        color: #4b5563;
    }

    .description,
    .recommendation,
    .finding-meta,
    .summary-message {

        color: #111827;
    }

    .page {

        max-width: none;

        padding: 20px;
    }
}


/*
|--------------------------------------------------------------------------
| MOBILE
|--------------------------------------------------------------------------
*/

@media (max-width: 800px) {

    .summary-grid,
    .severity-row {

        grid-template-columns: repeat(2,1fr);
    }

    .check-grid {

        grid-template-columns: 1fr;
    }

    .finding-meta {

        grid-template-columns: 1fr;
    }
}

</style>

</head>


<body>

<div class="page">


<!-- =========================================================
     TOP ACTIONS
========================================================= -->

<div class="top-actions">

    <a
        href="index.php"
        class="back-link"
    >
        <i class="fa-solid fa-arrow-left"></i>

        Back to Scanner
    </a>


    <button
        type="button"
        class="print-btn"
        onclick="window.print()"
    >
        <i class="fa-solid fa-file-pdf"></i>

        Download / Print PDF
    </button>

</div>


<!-- =========================================================
     HEADER
========================================================= -->

<header class="report-header">

    <div class="brand">
        SECURELOG
    </div>

    <h1>
        Scan Security Report
    </h1>

    <div class="subtitle">
        Static Application Security Testing report generated by SecureLog.
    </div>

    <div class="risk-badge risk-<?= strtolower(e($overallRisk)); ?>">

        <i class="fa-solid fa-shield-halved"></i>

        Overall Risk:
        <?= e($overallRisk); ?>

    </div>

</header>


<!-- =========================================================
     MAIN SUMMARY
========================================================= -->

<section class="summary-grid">

    <div class="summary-card">

        <div class="summary-label">
            Files Scanned
        </div>

        <div class="summary-value">
            <?= (int) $totalFiles; ?>
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-label">
            Failed Checks
        </div>

        <div class="summary-value text-red">
            <?= (int) $totalFailed; ?>
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-label">
            Passed Checks
        </div>

        <div class="summary-value text-green">
            <?= (int) $totalPassed; ?>
        </div>

    </div>


    <div class="summary-card">

        <div class="summary-label">
            Not Evaluated
        </div>

        <div class="summary-value text-gray">
            <?= (int) $totalNotEvaluated; ?>
        </div>

    </div>

</section>


<!-- =========================================================
     SCAN INFORMATION
========================================================= -->

<section class="section">

    <h2>

        <i class="fa-solid fa-circle-info"></i>

        Scan Information

    </h2>


    <table class="scan-info">

        <tr>
            <td>Scan ID</td>

            <td>
                <?= e($scanId); ?>
            </td>
        </tr>


        <tr>
            <td>Project Name</td>

            <td>
                <?= e($projectName); ?>
            </td>
        </tr>


        <tr>
            <td>Programming Language</td>

            <td>
                <?= e($language); ?>
            </td>
        </tr>


        <tr>
            <td>Total Files Uploaded</td>

            <td>
                <?= e($totalFiles); ?>
            </td>
        </tr>


        <tr>
            <td>Scan Date</td>

            <td>
                <?= e($scanDate); ?>
            </td>
        </tr>


        <tr>
            <td>Status</td>

            <td>
                <?= e($status); ?>
            </td>
        </tr>

    </table>

</section>


<!-- =========================================================
     CHECK STATUS SUMMARY
========================================================= -->

<section class="section">

    <h2>

        <i class="fa-solid fa-list-check"></i>

        Check Status Summary

    </h2>


    <div class="check-grid">


        <div class="check-card">

            <span>
                ❌ Failed
            </span>

            <strong class="text-red">
                <?= (int) $totalFailed; ?>
            </strong>

        </div>


        <div class="check-card">

            <span>
                ✅ Passed
            </span>

            <strong class="text-green">
                <?= (int) $totalPassed; ?>
            </strong>

        </div>


        <div class="check-card">

            <span>
                ➖ Not Evaluated
            </span>

            <strong class="text-gray">
                <?= (int) $totalNotEvaluated; ?>
            </strong>

        </div>


    </div>

</section>


<!-- =========================================================
     SECURITY FINDINGS BY SEVERITY
========================================================= -->

<section class="section">

    <h2>

        <i class="fa-solid fa-chart-pie"></i>

        Failed Security Findings by Severity

    </h2>


    <div class="severity-row">


        <div class="severity-card">

            <span>
                Critical
            </span>

            <strong class="text-red">
                <?= (int) $severityCounts['CRITICAL']; ?>
            </strong>

        </div>


        <div class="severity-card">

            <span>
                High
            </span>

            <strong class="text-red">
                <?= (int) $severityCounts['HIGH']; ?>
            </strong>

        </div>


        <div class="severity-card">

            <span>
                Medium
            </span>

            <strong class="text-orange">
                <?= (int) $severityCounts['MEDIUM']; ?>
            </strong>

        </div>


        <div class="severity-card">

            <span>
                Low
            </span>

            <strong class="text-blue">
                <?= (int) $severityCounts['LOW']; ?>
            </strong>

        </div>


    </div>

</section>


<!-- =========================================================
     FAILED FINDINGS
========================================================= -->

<section class="section">

    <h2>

        <i class="fa-solid fa-triangle-exclamation"></i>

        Failed Security Findings

    </h2>


    <?php if (empty($failedFindings)): ?>


        <div class="summary-message">

            <strong>
                ✅ No failed security checks detected.
            </strong>

            <br><br>

            SecureLog did not identify a failed
            security or logging policy check
            during this scan.

        </div>


    <?php else: ?>


        <?php foreach ($failedFindings as $index => $finding): ?>


            <?php

            $severity = strtoupper(
                (string) ($finding['Severity'] ?? 'INFO')
            );

            $severityClass =
                strtolower($severity);

            $name =
                getCheckName($finding);

            $standard =
                getStandardLabel($finding);

            $description =
                $finding['Description']
                ?? '-';

            $lineNumber =
                (int) ($finding['LineNumber'] ?? 0);

            $lineDisplay =
                $lineNumber > 0
                    ? (string) $lineNumber
                    : 'Not recorded';

            $recommendation =
                getRecommendation($finding);

            ?>


            <div class="finding">


                <div class="finding-title">


                    <span>

                        <?= $index + 1; ?>.

                        <?= e($name); ?>

                    </span>


                    <span class="status-pill status-fail">

                        ❌ FAIL

                    </span>


                </div>


                <div class="finding-meta">


                    <div>

                        <strong>
                            File:
                        </strong>

                        <?= e(
                            $finding['FilePath']
                            ?? '-'
                        ); ?>

                    </div>


                    <div>

                        <strong>
                            Line:
                        </strong>

                        <?= e($lineDisplay); ?>

                    </div>


                    <div>

                        <strong>
                            Standard:
                        </strong>

                        <?= e($standard); ?>

                    </div>


                    <div>

                        <strong>
                            Severity:
                        </strong>

                        <span class="severity-pill pill-<?= e($severityClass); ?>">

                            <?= e($severity); ?>

                        </span>

                    </div>


                </div>


                <div class="description">

                    <strong>
                        Description:
                    </strong>

                    <br>

                    <?= e($description); ?>

                </div>


                <div class="recommendation">

                    <strong>
                        Recommendation:
                    </strong>

                    <br>

                    <?= e($recommendation); ?>

                </div>


            </div>


        <?php endforeach; ?>


    <?php endif; ?>


</section>


<!-- =========================================================
     PASSED CHECKS SUMMARY
========================================================= -->

<section class="section">

    <h2>

        <i class="fa-solid fa-circle-check"></i>

        Passed Checks

    </h2>


    <?php if ($totalPassed === 0): ?>


        <div class="summary-message">

            No PASS results were recorded
            for this scan.

        </div>


    <?php else: ?>


        <div class="summary-message">

            <strong class="text-green">

                <?= (int) $totalPassed; ?>
                check(s) passed.

            </strong>

            <br><br>

            These checks satisfied the
            SecureLog detection criteria.

        </div>


    <?php endif; ?>


</section>


<!-- =========================================================
     NOT EVALUATED SUMMARY
========================================================= -->

<section class="section">

    <h2>

        <i class="fa-solid fa-circle-minus"></i>

        Not Evaluated

    </h2>


    <?php if ($totalNotEvaluated === 0): ?>


        <div class="summary-message">

            All applicable checks were evaluated.

        </div>


    <?php else: ?>


        <div class="summary-message">

            <strong>

                <?= (int) $totalNotEvaluated; ?>
                dependent check(s) were not evaluated.

            </strong>

            <br><br>

            A dependent SecureLog check may be marked
            N/A when its prerequisite is not satisfied.

            For example, log neutralization,
            log storage and log protection cannot be
            meaningfully evaluated for a security event
            when no associated logging operation exists.

            <br><br>

            <strong>
                N/A results are not counted as security findings
                and do not increase the overall risk level.
            </strong>

        </div>


    <?php endif; ?>


</section>


<!-- =========================================================
     FOOTER
========================================================= -->

<div class="footer">

    Generated by SecureLog SAST Tool.

    <br>

    Scan #<?= e($scanId); ?>

</div>


</div>

</body>

</html>