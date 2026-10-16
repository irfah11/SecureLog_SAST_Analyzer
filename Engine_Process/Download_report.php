<?php

/*
|--------------------------------------------------------------------------
| SecureLog - View / Download Scan Report
|--------------------------------------------------------------------------
*/

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/Report/ScanReport.php';


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


require_once __DIR__ . '/connection.php';

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


// Use the same saved result model for HTML and the downloadable PDF.
$rows = [];
while ($row = $findingResult->fetch_assoc()) $rows[] = $row;
$findingStmt->close();
$report = securelogReportModel($scan, $rows);

$format = $_GET['format'] ?? 'html';
$detail = $_GET['detail'] ?? 'compact';
if (!is_string($detail) || !in_array($detail, ['compact', 'full'], true)) {
    http_response_code(400);
    exit('Invalid report detail.');
}
if (!is_string($format) || !in_array($format, ['html', 'pdf'], true)) {
    http_response_code(400);
    exit('Invalid report format.');
}
header('Cache-Control: private, no-store, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
if ($format === 'pdf') {
    try {
        $bytes = securelogReportPdf($report, $detail);
    } catch (Throwable $error) {
        error_log('SecureLog PDF generation failed for scan ' . $scanId . ': ' . $error->getMessage());
        http_response_code(500);
        exit('Unable to generate the PDF. Please try again or contact the administrator.');
    }
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="SecureLog-Scan-' . $scanId . ($detail === 'full' ? '-full' : '') . '.pdf"');
    header('Content-Length: ' . strlen($bytes));
    echo $bytes;
    exit;
}
header('Content-Type: text/html; charset=UTF-8');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
echo securelogReportHtml($report, false, $detail);
