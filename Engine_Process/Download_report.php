<?php

/*
|--------------------------------------------------------------------------
| SecureLog - View / Download Scan Report
|--------------------------------------------------------------------------
|
| SECURITY:
| - User must be authenticated
| - Only admin or developer roles are accepted
| - Developer may access ONLY their own scan
| - Admin may access all scans
| - Scan ownership is verified BEFORE findings are retrieved
|
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
    trim(
        (string) (
            $_SESSION['role']
            ?? ''
        )
    )
);


if ($currentUserId <= 0) {

    header(
        'Location: ../Registration/login.php'
    );

    exit;
}


/*
|--------------------------------------------------------------------------
| 2. ROLE AUTHORIZATION
|--------------------------------------------------------------------------
*/

$allowedRoles = [
    'admin',
    'developer'
];

if (
    !in_array(
        $userRole,
        $allowedRoles,
        true
    )
) {

    http_response_code(403);

    exit(
        'Access denied.'
    );
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

    exit(
        'Invalid scan ID.'
    );
}


/*
|--------------------------------------------------------------------------
| 4. GET SCAN + VERIFY OWNERSHIP
|--------------------------------------------------------------------------
|
| ADMIN:
|
|   ScanID = ?
|
| DEVELOPER:
|
|   ScanID = ?
|   AND UserID = current session UserID
|
| This prevents IDOR / Broken Object Level Authorization.
|--------------------------------------------------------------------------
*/

if ($userRole === 'admin') {

    $scanStmt = $conn->prepare(
        "
        SELECT *
        FROM scans
        WHERE ScanID = ?
        LIMIT 1
        "
    );


    if (!$scanStmt) {

        http_response_code(500);

        exit(
            'Unable to prepare report query.'
        );
    }


    $scanStmt->bind_param(
        'i',
        $scanId
    );

} else {

    /*
    |--------------------------------------------------------------------------
    | DEVELOPER OWNERSHIP CHECK
    |--------------------------------------------------------------------------
    */

    $scanStmt = $conn->prepare(
        "
        SELECT *
        FROM scans
        WHERE ScanID = ?
          AND UserID = ?
        LIMIT 1
        "
    );


    if (!$scanStmt) {

        http_response_code(500);

        exit(
            'Unable to prepare report query.'
        );
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

    exit(
        'Unable to retrieve scan report.'
    );
}


$scanResult =
    $scanStmt->get_result();


$scan =
    $scanResult->fetch_assoc();


$scanStmt->close();


/*
|--------------------------------------------------------------------------
| IMPORTANT
|--------------------------------------------------------------------------
|
| We intentionally return the same response for:
|
| - Scan does not exist
| - Scan belongs to another developer
|
| This avoids revealing whether another user's ScanID exists.
|--------------------------------------------------------------------------
*/

if (!$scan) {

    http_response_code(404);

    exit(
        'Scan report not found.'
    );
}


/*
|--------------------------------------------------------------------------
| 5. GET FINDINGS
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| We only reach this section AFTER authorization / ownership verification.
|--------------------------------------------------------------------------
*/

$findingStmt = $conn->prepare(
    "
    SELECT
        ResultID,
        RuleID,
        VulnerabilityName,
        Severity,
        FilePath,
        LineNumber,
        Description
    FROM scan_results
    WHERE ScanID = ?
    ORDER BY
        FIELD(
            UPPER(Severity),
            'HIGH',
            'MEDIUM',
            'LOW',
            'INFO'
        ),
        FilePath ASC,
        LineNumber ASC
    "
);


if (!$findingStmt) {

    http_response_code(500);

    exit(
        'Unable to prepare findings query.'
    );
}


$findingStmt->bind_param(
    'i',
    $scanId
);


if (!$findingStmt->execute()) {

    $findingStmt->close();

    http_response_code(500);

    exit(
        'Unable to retrieve scan findings.'
    );
}


$findingResult =
    $findingStmt->get_result();


$findings = [];


$severityCounts = [

    'HIGH' => 0,

    'MEDIUM' => 0,

    'LOW' => 0,

    'INFO' => 0
];


while (
    $row =
        $findingResult->fetch_assoc()
) {

    $severity = strtoupper(
        trim(
            (string) (
                $row['Severity']
                ?? 'INFO'
            )
        )
    );


    /*
    |--------------------------------------------------------------------------
    | Only known severity values are accepted
    |--------------------------------------------------------------------------
    */

    if (
        !array_key_exists(
            $severity,
            $severityCounts
        )
    ) {

        $severity = 'INFO';
    }


    $severityCounts[$severity]++;


    $row['Severity'] =
        $severity;


    $findings[] =
        $row;
}


$findingStmt->close();


$totalIssues =
    count($findings);


/*
|--------------------------------------------------------------------------
| 6. CALCULATE OVERALL RISK
|--------------------------------------------------------------------------
*/

if (
    $severityCounts['HIGH'] > 0
) {

    $overallRisk =
        'HIGH';

} elseif (
    $severityCounts['MEDIUM'] > 0
) {

    $overallRisk =
        'MEDIUM';

} elseif (
    $severityCounts['LOW'] > 0
) {

    $overallRisk =
        'LOW';

} else {

    $overallRisk =
        'INFO';
}


/*
|--------------------------------------------------------------------------
| 7. OUTPUT ESCAPING
|--------------------------------------------------------------------------
*/

function e(
    mixed $value
): string {

    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}


/*
|--------------------------------------------------------------------------
| 8. RECOMMENDATION
|--------------------------------------------------------------------------
|
| Temporary recommendation logic.
|
| Later this should ideally come from scanner_rules so the scanner,
| database and report share the same rule definition.
|--------------------------------------------------------------------------
*/

function getRecommendation(
    string $severity,
    string $vulnerabilityName,
    string $description
): string {

    $text = strtolower(
        $vulnerabilityName
        . ' '
        . $description
    );


    /*
    |--------------------------------------------------------------------------
    | Missing logging
    |--------------------------------------------------------------------------
    */

    if (
        str_contains(
            $text,
            'missing security logging'
        )
        ||
        str_contains(
            $text,
            'no security logging'
        )
        ||
        str_contains(
            $text,
            'logging mechanism was detected'
        )
    ) {

        return
            'Implement security logging for important application and security events using an appropriate logging mechanism for the selected programming language.';
    }


    /*
    |--------------------------------------------------------------------------
    | Improper log format
    |--------------------------------------------------------------------------
    */

    if (
        str_contains(
            $text,
            'improper log file format'
        )
        ||
        str_contains(
            $text,
            '.txt'
        )
    ) {

        return
            'Store application security logs using the approved SecureLog .txt log format and ensure the logging destination is configured correctly.';
    }


    /*
    |--------------------------------------------------------------------------
    | Unprotected log
    |--------------------------------------------------------------------------
    */

    if (
        str_contains(
            $text,
            'unprotected'
        )
        ||
        str_contains(
            $text,
            'encryption'
        )
    ) {

        return
            'Protect sensitive log data using appropriate encryption before persistent storage and keep cryptographic keys separate from the stored log files.';
    }


    /*
    |--------------------------------------------------------------------------
    | Secure configuration / informational
    |--------------------------------------------------------------------------
    */

    if ($severity === 'INFO') {

        return
            'Maintain the current secure logging implementation and continue protecting log confidentiality and access.';
    }


    /*
    |--------------------------------------------------------------------------
    | Generic fallback
    |--------------------------------------------------------------------------
    */

    return
        'Review the detected logging implementation and apply the recommended secure logging controls.';
}


/*
|--------------------------------------------------------------------------
| 9. NORMALIZE SCAN INFORMATION
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
| Friendly language display
|--------------------------------------------------------------------------
*/

switch (
    strtolower(
        (string) $language
    )
) {

    case 'php':

        $language =
            'PHP';

        break;


    case 'java':

        $language =
            'Java';

        break;


    case 'javascript':

        $language =
            'JavaScript';

        break;


    case 'c':

        $language =
            'C';

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
            --border: rgba(59, 130, 246, 0.22);

            --blue: #3b82f6;
            --green: #10b981;
            --orange: #f59e0b;
            --red: #ef4444;
            --purple: #8b5cf6;

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

            font-family:
                Arial,
                sans-serif;
        }

        .page {
            width: 100%;
            max-width: 1050px;
            margin: 0 auto;
            padding: 36px 24px 50px;
        }

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

            color: #ffffff;
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

        .report-header {
            margin-bottom: 24px;
            padding: 28px;

            background:
                linear-gradient(
                    145deg,
                    rgba(8, 27, 51, 0.98),
                    rgba(5, 19, 38, 0.98)
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

        .risk-high {
            color: #ffffff;
            background: var(--red);
        }

        .risk-medium {
            color: #111827;
            background: var(--orange);
        }

        .risk-low {
            color: #ffffff;
            background: var(--blue);
        }

        .risk-info {
            color: #ffffff;
            background: var(--green);
        }

        .summary-grid {
            margin-bottom: 24px;

            display: grid;
            grid-template-columns: repeat(4, 1fr);
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

            color: #ffffff;
            font-size: 24px;
            font-weight: 900;
        }

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

        .scan-info {
            width: 100%;
            border-collapse: collapse;
        }

        .scan-info td {
            padding: 10px 12px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.12);
            font-size: 13px;
        }

        .scan-info td:first-child {
            color: var(--muted);
            width: 180px;
            font-weight: 700;
        }

        .severity-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }

        .severity-card {
            padding: 16px;

            border-radius: 12px;
            background: var(--card2);
            border: 1px solid rgba(148, 163, 184, 0.18);
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

        .finding {
            margin-bottom: 16px;
            padding: 18px;

            background: var(--card2);
            border: 1px solid rgba(148, 163, 184, 0.18);
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

        .severity-pill {
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 900;
        }

        .pill-high {
            color: #ffffff;
            background: var(--red);
        }

        .pill-medium {
            color: #111827;
            background: var(--orange);
        }

        .pill-low {
            color: #ffffff;
            background: var(--blue);
        }

        .pill-info {
            color: #ffffff;
            background: var(--green);
        }

        .footer {
            color: var(--muted);
            text-align: center;
            font-size: 12px;
            margin-top: 30px;
        }

        @media print {
            body {
                background: #ffffff;
                color: #111827;
            }

            .top-actions {
                display: none;
            }

            .report-header,
            .section,
            .summary-card,
            .finding,
            .severity-card {
                background: #ffffff;
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
            .finding-meta {
                color: #111827;
            }

            .page {
                max-width: none;
                padding: 20px;
            }
        }
    </style>
</head>

<body>

<div class="page">

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
            Overall Risk: <?= e($overallRisk); ?>
        </div>
    </header>

    <section class="summary-grid">
        <div class="summary-card">
            <div class="summary-label">
                Total Issues
            </div>

            <div class="summary-value">
                <?= (int) $totalIssues; ?>
            </div>
        </div>

        <div class="summary-card">
            <div class="summary-label">
                High Risk
            </div>

            <div class="summary-value text-red">
                <?= (int) $severityCounts['HIGH']; ?>
            </div>
        </div>

        <div class="summary-card">
            <div class="summary-label">
                Medium Risk
            </div>

            <div class="summary-value text-orange">
                <?= (int) $severityCounts['MEDIUM']; ?>
            </div>
        </div>

        <div class="summary-card">
            <div class="summary-label">
                Low / Info
            </div>

            <div class="summary-value text-green">
                <?= (int) (
                    $severityCounts['LOW']
                    + $severityCounts['INFO']
                ); ?>
            </div>
        </div>
    </section>

    <section class="section">
        <h2>
            <i class="fa-solid fa-circle-info"></i>
            Scan Information
        </h2>

        <table class="scan-info">
            <tr>
                <td>Scan ID</td>
                <td><?= e($scanId); ?></td>
            </tr>

            <tr>
                <td>Project Name</td>
                <td><?= e($projectName); ?></td>
            </tr>

            <tr>
                <td>Programming Language</td>
                <td><?= e($language); ?></td>
            </tr>

            <tr>
                <td>Total Files Uploaded</td>
                <td><?= e($totalFiles); ?></td>
            </tr>

            <tr>
                <td>Scan Date</td>
                <td><?= e($scanDate); ?></td>
            </tr>

            <tr>
                <td>Status</td>
                <td><?= e($status); ?></td>
            </tr>
        </table>
    </section>

    <section class="section">
        <h2>
            <i class="fa-solid fa-chart-pie"></i>
            Detected Issues by Severity
        </h2>

        <div class="severity-row">
            <div class="severity-card">
                <span>High</span>
                <strong class="text-red">
                    <?= (int) $severityCounts['HIGH']; ?>
                </strong>
            </div>

            <div class="severity-card">
                <span>Medium</span>
                <strong class="text-orange">
                    <?= (int) $severityCounts['MEDIUM']; ?>
                </strong>
            </div>

            <div class="severity-card">
                <span>Low</span>
                <strong class="text-blue">
                    <?= (int) $severityCounts['LOW']; ?>
                </strong>
            </div>

            <div class="severity-card">
                <span>Info</span>
                <strong class="text-green">
                    <?= (int) $severityCounts['INFO']; ?>
                </strong>
            </div>
        </div>
    </section>

    <section class="section">
        <h2>
            <i class="fa-solid fa-list-check"></i>
            Detailed Findings
        </h2>

        <?php if (empty($findings)): ?>

            <p>
                No security findings were detected for this scan.
            </p>

        <?php else: ?>

            <?php foreach ($findings as $index => $finding): ?>

                <?php
                $severity = strtoupper(
                    (string) $finding['Severity']
                );

                $severityClass = strtolower($severity);

                $vulnerabilityName =
                    $finding['VulnerabilityName']
                    ?? 'Logging Finding';

                $description =
                    $finding['Description']
                    ?? '-';

                $lineNumber =
                    (int) ($finding['LineNumber'] ?? 0);

                $lineDisplay =
                    $lineNumber > 0
                        ? (string) $lineNumber
                        : 'Not recorded';

                $recommendation = getRecommendation(
                    $severity,
                    $vulnerabilityName,
                    $description
                );
                ?>

                <div class="finding">
                    <div class="finding-title">
                        <span>
                            <?= $index + 1; ?>.
                            <?= e($vulnerabilityName); ?>
                        </span>

                        <span class="severity-pill pill-<?= e($severityClass); ?>">
                            <?= e($severity); ?>
                        </span>
                    </div>

                    <div class="finding-meta">
                        <div>
                            <strong>File:</strong>
                            <?= e($finding['FilePath'] ?? '-'); ?>
                        </div>

                        <div>
                            <strong>Line:</strong>
                            <?= e($lineDisplay); ?>
                        </div>

                        <div>
                            <strong>Rule ID:</strong>
                            <?= e($finding['RuleID'] ?? '-'); ?>
                        </div>

                        <div>
                            <strong>Result ID:</strong>
                            <?= e($finding['ResultID'] ?? '-'); ?>
                        </div>
                    </div>

                    <div class="description">
                        <strong>Description:</strong><br>
                        <?= e($description); ?>
                    </div>

                    <div class="recommendation">
                        <strong>Recommendation:</strong><br>
                        <?= e($recommendation); ?>
                    </div>
                </div>

            <?php endforeach; ?>

        <?php endif; ?>
    </section>

    <div class="footer">
        Generated by SecureLog SAST Tool.
    </div>

</div>

</body>
</html>