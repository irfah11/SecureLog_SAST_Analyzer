<?php
/**
 * SecureLog Activity Log
 * File: Dashboard/ActivityLog/activityLog.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../authCheck.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}

/* ============================================================
   DATABASE AND ACTIVITY LOGGER
   ============================================================ */

require_once __DIR__ . '/../../Engine_Process/connection.php';
require_once __DIR__ . '/../ActivityLogger.php';

/*
|--------------------------------------------------------------------------
| Support both session ID formats
|--------------------------------------------------------------------------
*/
$currentUserId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

/*
|--------------------------------------------------------------------------
| Record that admin opened the Activity Log page
|--------------------------------------------------------------------------
*/
if (
    $currentUserId > 0
    && function_exists('log_activity')
    && defined('LOG_ADMIN_VIEW')
) {
    log_activity(
        LOG_ADMIN_VIEW,
        $currentUserId,
        'Admin viewed activity log'
    );
}

/* ============================================================
   PAGINATION
   ============================================================ */

$recordsPerPage = 10;

$currentPageNumber = isset($_GET['page'])
    ? max(1, (int) $_GET['page'])
    : 1;

$totalRecords = 0;

$countResult = $conn->query(
    'SELECT COUNT(*) AS total FROM scans'
);

if ($countResult) {
    $countRow = $countResult->fetch_assoc();
    $totalRecords = (int) ($countRow['total'] ?? 0);
}

$totalPages = max(
    1,
    (int) ceil($totalRecords / $recordsPerPage)
);

if ($currentPageNumber > $totalPages) {
    $currentPageNumber = $totalPages;
}

$offset = ($currentPageNumber - 1) * $recordsPerPage;

/* ============================================================
   RECENT SCANS QUERY
   ============================================================ */

$recentScans = [];

$scanQuery = "
    SELECT
        s.ScanID,
        s.ProjectName,
        s.Status,
        s.ScanDate,
        u.username,
        u.fullname
    FROM scans s
    LEFT JOIN users u
        ON s.UserID = u.UserID
    ORDER BY s.ScanDate DESC
    LIMIT {$recordsPerPage}
    OFFSET {$offset}
";

$scanResult = $conn->query($scanQuery);

$queryError = '';

if ($scanResult) {
    while ($scan = $scanResult->fetch_assoc()) {
        $recentScans[] = $scan;
    }
} else {
    $queryError = $conn->error;
}

/* ============================================================
   PAGINATION TEXT
   ============================================================ */

$startingRecord = $totalRecords > 0
    ? $offset + 1
    : 0;

$endingRecord = min(
    $offset + $recordsPerPage,
    $totalRecords
);

/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */

function activityStatusClass(?string $status): string
{
    $normalizedStatus = strtolower(trim($status ?? ''));

    return match ($normalizedStatus) {
        'completed',
        'complete',
        'approved',
        'success',
        'secure' => 'status-completed',

        'failed',
        'rejected',
        'error',
        'vulnerable' => 'status-failed',

        'processing',
        'running',
        'in progress' => 'status-processing',

        default => 'status-pending'
    };
}

function activityStatusLabel(?string $status): string
{
    $status = trim($status ?? '');

    return $status !== ''
        ? ucfirst(strtolower($status))
        : 'Pending';
}

function displayScanUser(array $scan): string
{
    $username = trim($scan['username'] ?? '');
    $fullname = trim($scan['fullname'] ?? '');

    if ($username !== '') {
        return $username;
    }

    if ($fullname !== '') {
        return $fullname;
    }

    return 'Unknown User';
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

    <title>Activity Log | SecureLog</title>

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
            --activity-bg: #020c17;
            --activity-panel: #061729;
            --activity-panel-dark: #03111f;
            --activity-border: #143047;

            --activity-orange: #ff6500;
            --activity-orange-dark: #753000;

            --activity-green: #00e59b;
            --activity-red: #ff4655;
            --activity-blue: #38bdf8;
            --activity-yellow: #ffd20a;

            --activity-text: #f8fafc;
            --activity-muted: #9aa9b9;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
            background: var(--activity-bg);
            color: var(--activity-text);
            font-family: "Inter", "Segoe UI", sans-serif;
        }

        body {
            overflow-x: hidden;
        }

        /* =====================================================
           MAIN PAGE BESIDE SIDEBAR
           ===================================================== */

        .activity-page {
            min-height: 100vh;
            padding: 15px 14px 20px;

            background:
                radial-gradient(
                    circle at 70% 10%,
                    rgba(56, 189, 248, 0.035),
                    transparent 30%
                ),
                var(--activity-bg);
        }

        .activity-container {
            width: 100%;
            max-width: 1500px;
            min-height: calc(100vh - 35px);

            margin: 0 auto;

            background:
                linear-gradient(
                    145deg,
                    rgba(5, 24, 40, 0.98),
                    rgba(2, 14, 26, 0.98)
                );

            border: 1px solid var(--activity-border);
            border-radius: 14px;

            overflow: hidden;
        }

        /* =====================================================
           PAGE HEADER
           ===================================================== */

        .activity-header {
            min-height: 120px;
            padding: 28px 30px;

            display: flex;
            align-items: flex-start;
            gap: 18px;

            border-bottom: 1px solid var(--activity-border);
        }

        .activity-header-icon {
            width: 53px;
            height: 53px;

            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;

            color: var(--activity-orange);
            background: rgba(255, 101, 0, 0.13);

            border-radius: 50%;

            font-size: 25px;
        }

        .activity-header-text h1 {
            margin: 2px 0 7px;

            color: #ffffff;

            font-size: 25px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.2px;
        }

        .activity-header-text p {
            margin: 0;

            color: #b8c3cf;

            font-size: 14px;
        }

        /* =====================================================
           RECENT SCANS PANEL
           ===================================================== */

        .recent-scans-panel {
            margin: 20px;
            padding: 20px;

            background:
                linear-gradient(
                    145deg,
                    rgba(9, 29, 49, 0.98),
                    rgba(4, 19, 34, 0.98)
                );

            border: 1px solid rgba(20, 48, 71, 0.65);
            border-radius: 13px;
        }

        .recent-scans-heading {
            margin-bottom: 25px;

            display: flex;
            align-items: center;
            gap: 15px;
        }

        .recent-scans-icon {
            width: 43px;
            height: 43px;

            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;

            color: var(--activity-orange);
            background: rgba(255, 101, 0, 0.14);

            border-radius: 50%;

            font-size: 21px;
        }

        .recent-scans-title h2 {
            margin: 0 0 6px;

            color: #ffffff;

            font-size: 19px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .recent-scans-title p {
            margin: 0;

            color: #b4bfca;

            font-size: 13px;
        }

        /* =====================================================
           TABLE
           ===================================================== */

        .activity-table-wrapper {
            width: 100%;
            overflow-x: auto;
        }

        .activity-table {
            width: 100%;
            min-width: 850px;

            border-collapse: collapse;
        }

        .activity-table thead {
            background: rgba(2, 14, 26, 0.85);
        }

        .activity-table th {
            padding: 15px 13px;

            color: #b8c3cf;

            border: 1px solid rgba(20, 48, 71, 0.65);

            font-size: 12px;
            font-weight: 600;
            text-align: left;
            text-transform: uppercase;
            letter-spacing: 0.2px;
        }

        .activity-table td {
            padding: 17px 13px;

            color: #ffffff;

            border-bottom: 1px solid rgba(20, 48, 71, 0.55);

            font-size: 14px;
            vertical-align: middle;
        }

        .activity-table tbody tr {
            transition:
                background-color 0.2s ease,
                transform 0.2s ease;
        }

        .activity-table tbody tr:hover {
            background: rgba(255, 101, 0, 0.035);
        }

        .scan-id-link {
            color: var(--activity-orange);
            text-decoration: none;

            font-size: 15px;
            font-weight: 800;
        }

        .scan-id-link:hover {
            color: #ff8b3d;
            text-decoration: underline;
        }

        .project-name {
            color: #ffffff;
            font-weight: 500;
        }

        .scan-user {
            color: #ffffff;
        }

        .scan-date {
            color: #ffffff;
            white-space: nowrap;
        }

        /* =====================================================
           STATUS BADGES
           ===================================================== */

        .scan-status {
            min-width: 72px;
            padding: 5px 12px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            border-radius: 5px;

            font-size: 12px;
            font-weight: 600;
        }

        .status-pending {
            color: #00f5a4;
            background: rgba(0, 229, 155, 0.16);

            box-shadow:
                0 0 15px rgba(0, 229, 155, 0.08);
        }

        .status-completed {
            color: #36d399;
            background: rgba(54, 211, 153, 0.15);
        }

        .status-failed {
            color: #ff6978;
            background: rgba(255, 70, 85, 0.15);
        }

        .status-processing {
            color: var(--activity-blue);
            background: rgba(56, 189, 248, 0.14);
        }

        /* =====================================================
           ERROR AND EMPTY STATES
           ===================================================== */

        .activity-message {
            padding: 35px 20px;

            color: var(--activity-muted);

            font-size: 14px;
            text-align: center;
        }

        .activity-message i {
            display: block;
            margin-bottom: 12px;

            color: var(--activity-orange);

            font-size: 27px;
        }

        .query-error {
            margin-bottom: 20px;
            padding: 12px 16px;

            color: #ff8b96;
            background: rgba(255, 70, 85, 0.1);

            border: 1px solid rgba(255, 70, 85, 0.3);
            border-radius: 7px;

            font-size: 13px;
        }

        /* =====================================================
           FOOTER AND PAGINATION
           ===================================================== */

        .table-footer {
            padding: 25px 8px 5px;

            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }

        .records-summary {
            color: #c2ccd6;

            font-size: 13px;
        }

        .pagination {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .page-button {
            width: 44px;
            height: 44px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            color: #aeb9c5;
            background: #041321;

            border: 1px solid var(--activity-border);
            border-radius: 7px;

            text-decoration: none;

            font-size: 14px;

            transition:
                background-color 0.2s ease,
                border-color 0.2s ease,
                color 0.2s ease;
        }

        .page-button:hover {
            color: #ffffff;
            background: rgba(255, 101, 0, 0.12);
            border-color: var(--activity-orange);
        }

        .page-button.active {
            color: #ffffff;
            background: var(--activity-orange);
            border-color: var(--activity-orange);

            box-shadow:
                0 0 16px rgba(255, 101, 0, 0.25);
        }

        .page-button.disabled {
            color: #526170;

            pointer-events: none;
            opacity: 0.55;
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 800px) {
            .activity-page {
                padding: 10px;
            }

            .activity-header {
                padding: 22px 20px;
            }

            .recent-scans-panel {
                margin: 12px;
                padding: 15px;
            }
        }

        @media (max-width: 600px) {
            .activity-header-text h1 {
                font-size: 21px;
            }

            .table-footer {
                flex-direction: column;
                align-items: flex-start;
            }

            .pagination {
                align-self: center;
            }
        }
    </style>
</head>

<body>

    <!-- =====================================================
         PREVIOUS ADMIN SIDEBAR
         Activity Log will be highlighted automatically because
         the current filename is activityLog.php
         ===================================================== -->

    <?php
    require __DIR__ . '/../../Sidebar/sidebaradmin.php';
    ?>

    <!-- =====================================================
         ACTIVITY LOG CONTENT
         ===================================================== -->

    <main class="admin-page-content activity-page">

        <div class="activity-container">

            <!-- Page header -->
            <header class="activity-header">

                <div class="activity-header-icon">
                    <i class="fa-solid fa-list"></i>
                </div>

                <div class="activity-header-text">
                    <h1>Activity Log</h1>

                    <p>
                        View and monitor all system activities
                        and scan history.
                    </p>
                </div>

            </header>

            <!-- Recent scans -->
            <section class="recent-scans-panel">

                <div class="recent-scans-heading">

                    <div class="recent-scans-icon">
                        <i class="fa-solid fa-clock-rotate-left"></i>
                    </div>

                    <div class="recent-scans-title">
                        <h2>Recent Scans</h2>

                        <p>
                            List of recently executed scans in the system.
                        </p>
                    </div>

                </div>

                <?php if ($queryError !== ''): ?>
                    <div class="query-error">
                        <strong>Database error:</strong>
                        <?= htmlspecialchars($queryError); ?>
                    </div>
                <?php endif; ?>

                <div class="activity-table-wrapper">

                    <table class="activity-table">

                        <thead>
                            <tr>
                                <th>Scan ID</th>
                                <th>Project / Scan Name</th>
                                <th>User</th>
                                <th>Status</th>
                                <th>Scan Date</th>
                            </tr>
                        </thead>

                        <tbody>

                            <?php if (!empty($recentScans)): ?>

                                <?php foreach ($recentScans as $scan): ?>

                                    <?php
                                    $scanId = (int) (
                                        $scan['ScanID'] ?? 0
                                    );

                                    $projectName = trim(
                                        $scan['ProjectName'] ?? ''
                                    );

                                    $status = activityStatusLabel(
                                        $scan['Status'] ?? null
                                    );

                                    $statusClass = activityStatusClass(
                                        $scan['Status'] ?? null
                                    );

                                    $scanDateValue = trim(
                                        $scan['ScanDate'] ?? ''
                                    );

                                    $formattedScanDate =
                                        $scanDateValue !== ''
                                            ? date(
                                                'Y-m-d H:i:s',
                                                strtotime($scanDateValue)
                                            )
                                            : '-';
                                    ?>

                                    <tr>

                                        <td>
                                            <a
                                                href="../Scan/scandetails.php?scan_id=<?= urlencode(
                                                    (string) $scanId
                                                ); ?>"
                                                class="scan-id-link"
                                            >
                                                #<?= $scanId; ?>
                                            </a>
                                        </td>

                                        <td class="project-name">
                                            <?= htmlspecialchars(
                                                $projectName !== ''
                                                    ? $projectName
                                                    : 'Unnamed Scan'
                                            ); ?>
                                        </td>

                                        <td class="scan-user">
                                            <?= htmlspecialchars(
                                                displayScanUser($scan)
                                            ); ?>
                                        </td>

                                        <td>
                                            <span
                                                class="scan-status <?= htmlspecialchars(
                                                    $statusClass
                                                ); ?>"
                                            >
                                                <?= htmlspecialchars(
                                                    $status
                                                ); ?>
                                            </span>
                                        </td>

                                        <td class="scan-date">
                                            <?= htmlspecialchars(
                                                $formattedScanDate
                                            ); ?>
                                        </td>

                                    </tr>

                                <?php endforeach; ?>

                            <?php else: ?>

                                <tr>
                                    <td colspan="5">

                                        <div class="activity-message">
                                            <i class="fa-solid fa-circle-info"></i>

                                            No recent scan activity found.
                                        </div>

                                    </td>
                                </tr>

                            <?php endif; ?>

                        </tbody>

                    </table>

                </div>

                <!-- Footer and pagination -->
                <div class="table-footer">

                    <div class="records-summary">
                        Showing
                        <?= $startingRecord; ?>
                        to
                        <?= $endingRecord; ?>
                        of
                        <?= $totalRecords; ?>
                        scans
                    </div>

                    <nav
                        class="pagination"
                        aria-label="Activity log pagination"
                    >

                        <!-- Previous -->
                        <a
                            href="?page=<?= max(
                                1,
                                $currentPageNumber - 1
                            ); ?>"
                            class="page-button <?= $currentPageNumber <= 1
                                ? 'disabled'
                                : ''; ?>"
                            aria-label="Previous page"
                        >
                            <i class="fa-solid fa-chevron-left"></i>
                        </a>

                        <?php
                        $startPage = max(
                            1,
                            $currentPageNumber - 2
                        );

                        $endPage = min(
                            $totalPages,
                            $currentPageNumber + 2
                        );
                        ?>

                        <?php for (
                            $pageNumber = $startPage;
                            $pageNumber <= $endPage;
                            $pageNumber++
                        ): ?>

                            <a
                                href="?page=<?= $pageNumber; ?>"
                                class="page-button <?= $pageNumber
                                    === $currentPageNumber
                                        ? 'active'
                                        : ''; ?>"
                            >
                                <?= $pageNumber; ?>
                            </a>

                        <?php endfor; ?>

                        <!-- Next -->
                        <a
                            href="?page=<?= min(
                                $totalPages,
                                $currentPageNumber + 1
                            ); ?>"
                            class="page-button <?= $currentPageNumber
                                >= $totalPages
                                    ? 'disabled'
                                    : ''; ?>"
                            aria-label="Next page"
                        >
                            <i class="fa-solid fa-chevron-right"></i>
                        </a>

                    </nav>

                </div>

            </section>

        </div>

    </main>

</body>
</html>