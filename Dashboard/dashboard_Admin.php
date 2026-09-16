```php
<?php
/**
 * SecureLog Admin Dashboard
 * File: Dashboard/dashboard_Admin.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION AND DATABASE
   ============================================================ */

require_once __DIR__ . '/authCheck.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}

require_once __DIR__ . '/../Engine_Process/connection.php';
require_once __DIR__ . '/ActivityLogger.php';

/*
|--------------------------------------------------------------------------
| Support both session key formats
|--------------------------------------------------------------------------
*/
$current_uid = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

$adminUsername = $_SESSION['username']
    ?? $_SESSION['fullname']
    ?? 'Administrator';

/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */

function fetchScalarInt(mysqli $conn, string $sql): int
{
    $result = $conn->query($sql);

    if (!$result) {
        return 0;
    }

    $row = $result->fetch_row();

    return (int) ($row[0] ?? 0);
}

function tableExists(mysqli $conn, string $tableName): bool
{
    $statement = $conn->prepare(
        'SELECT COUNT(*)
         FROM information_schema.tables
         WHERE table_schema = DATABASE()
         AND table_name = ?'
    );

    if (!$statement) {
        return false;
    }

    $statement->bind_param('s', $tableName);
    $statement->execute();
    $statement->bind_result($exists);
    $statement->fetch();
    $statement->close();

    return (int) $exists > 0;
}

function calculateTrend(int $current, int $previous): int
{
    if ($previous === 0) {
        return $current > 0 ? 100 : 0;
    }

    return (int) round(
        (($current - $previous) / $previous) * 100
    );
}

function trendClass(int $trend): string
{
    return $trend >= 0 ? 'trend-up' : 'trend-down';
}

function trendArrow(int $trend): string
{
    return $trend >= 0 ? '↑' : '↓';
}

/* ============================================================
   EXPORT ENCRYPTED LOG
   Supports GET from sidebar and POST
   ============================================================ */

$requestedAction = $_POST['action']
    ?? $_GET['action']
    ?? '';

if ($requestedAction === 'export_log') {
    if (
        $current_uid > 0
        && function_exists('log_activity')
        && defined('LOG_LOG_EXPORTED')
    ) {
        log_activity(
            LOG_LOG_EXPORTED,
            $current_uid,
            'Admin exported encrypted audit log'
        );
    }

    if (function_exists('export_encrypted_log')) {
        export_encrypted_log();
        exit();
    }
}

/* ============================================================
   LOG ADMIN DASHBOARD VIEW
   ============================================================ */

if (
    $current_uid > 0
    && function_exists('log_activity')
    && defined('LOG_ADMIN_VIEW')
) {
    log_activity(
        LOG_ADMIN_VIEW,
        $current_uid,
        'Admin viewed dashboard'
    );
}

/* ============================================================
   ROLE STATISTICS
   ============================================================ */

$roleStats = [
    'admin'     => 0,
    'developer' => 0,
    'guest'     => 0
];

$roleQuery = $conn->query(
    'SELECT LOWER(role) AS role_name, COUNT(*) AS total
     FROM users
     GROUP BY LOWER(role)'
);

if ($roleQuery) {
    while ($roleRow = $roleQuery->fetch_assoc()) {
        $roleName = $roleRow['role_name'];

        if (array_key_exists($roleName, $roleStats)) {
            $roleStats[$roleName] = (int) $roleRow['total'];
        }
    }
}

/* ============================================================
   SEVERITY STATISTICS
   ============================================================ */

$severityStats = [
    'HIGH'   => 0,
    'MEDIUM' => 0,
    'LOW'    => 0,
    'INFO'   => 0
];

$severityQuery = $conn->query(
    'SELECT UPPER(severity) AS severity_name, COUNT(*) AS total
     FROM scan_results
     GROUP BY UPPER(severity)'
);

if ($severityQuery) {
    while ($severityRow = $severityQuery->fetch_assoc()) {
        $severityName = $severityRow['severity_name'];

        if (array_key_exists($severityName, $severityStats)) {
            $severityStats[$severityName] =
                (int) $severityRow['total'];
        }
    }
}

/* ============================================================
   MAIN DASHBOARD TOTALS
   ============================================================ */

$totalUsers = fetchScalarInt(
    $conn,
    'SELECT COUNT(*) FROM users'
);

$totalScans = fetchScalarInt(
    $conn,
    'SELECT COUNT(*) FROM scans'
);

$activeDevelopers = fetchScalarInt(
    $conn,
    "SELECT COUNT(*)
     FROM users
     WHERE LOWER(role) = 'developer'
     AND is_active = 1"
);

$pendingApprovals = fetchScalarInt(
    $conn,
    "SELECT COUNT(*)
     FROM users
     WHERE LOWER(role) = 'developer'
     AND is_active = 0"
);

$totalScanResults = fetchScalarInt(
    $conn,
    'SELECT COUNT(*) FROM scan_results'
);

/*
|--------------------------------------------------------------------------
| Count scanner rules
|--------------------------------------------------------------------------
| It first checks possible rule tables.
| If no rule table exists, it counts distinct RuleID values.
*/
$totalRules = 0;

$possibleRuleTables = [
    'scanner_rules',
    'security_rules',
    'rules'
];

foreach ($possibleRuleTables as $ruleTable) {
    if (tableExists($conn, $ruleTable)) {
        $totalRules = fetchScalarInt(
            $conn,
            "SELECT COUNT(*) FROM `{$ruleTable}`"
        );

        break;
    }
}

if ($totalRules === 0) {
    $totalRules = fetchScalarInt(
        $conn,
        'SELECT COUNT(DISTINCT RuleID)
         FROM scan_results'
    );
}

/* ============================================================
   TREND VALUES
   ============================================================ */

/* Total users: current 7 days versus previous 7 days */
$usersCurrentPeriod = fetchScalarInt(
    $conn,
    'SELECT COUNT(*)
     FROM users
     WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)'
);

$usersPreviousPeriod = fetchScalarInt(
    $conn,
    'SELECT COUNT(*)
     FROM users
     WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
     AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)'
);

$userTrend = calculateTrend(
    $usersCurrentPeriod,
    $usersPreviousPeriod
);

/* Total scans: current 30 days versus previous 30 days */
$scansCurrentPeriod = fetchScalarInt(
    $conn,
    'SELECT COUNT(*)
     FROM scans
     WHERE ScanDate >= DATE_SUB(NOW(), INTERVAL 30 DAY)'
);

$scansPreviousPeriod = fetchScalarInt(
    $conn,
    'SELECT COUNT(*)
     FROM scans
     WHERE ScanDate >= DATE_SUB(NOW(), INTERVAL 60 DAY)
     AND ScanDate < DATE_SUB(NOW(), INTERVAL 30 DAY)'
);

$scanTrend = calculateTrend(
    $scansCurrentPeriod,
    $scansPreviousPeriod
);

/* High severity trend */
$highCurrentPeriod = fetchScalarInt(
    $conn,
    "SELECT COUNT(*)
     FROM scan_results sr
     INNER JOIN scans s ON s.ScanID = sr.ScanID
     WHERE UPPER(sr.severity) = 'HIGH'
     AND s.ScanDate >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
);

$highPreviousPeriod = fetchScalarInt(
    $conn,
    "SELECT COUNT(*)
     FROM scan_results sr
     INNER JOIN scans s ON s.ScanID = sr.ScanID
     WHERE UPPER(sr.severity) = 'HIGH'
     AND s.ScanDate >= DATE_SUB(NOW(), INTERVAL 60 DAY)
     AND s.ScanDate < DATE_SUB(NOW(), INTERVAL 30 DAY)"
);

$highTrend = calculateTrend(
    $highCurrentPeriod,
    $highPreviousPeriod
);

/* Medium severity trend */
$mediumCurrentPeriod = fetchScalarInt(
    $conn,
    "SELECT COUNT(*)
     FROM scan_results sr
     INNER JOIN scans s ON s.ScanID = sr.ScanID
     WHERE UPPER(sr.severity) = 'MEDIUM'
     AND s.ScanDate >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
);

$mediumPreviousPeriod = fetchScalarInt(
    $conn,
    "SELECT COUNT(*)
     FROM scan_results sr
     INNER JOIN scans s ON s.ScanID = sr.ScanID
     WHERE UPPER(sr.severity) = 'MEDIUM'
     AND s.ScanDate >= DATE_SUB(NOW(), INTERVAL 60 DAY)
     AND s.ScanDate < DATE_SUB(NOW(), INTERVAL 30 DAY)"
);

$mediumTrend = calculateTrend(
    $mediumCurrentPeriod,
    $mediumPreviousPeriod
);

/* ============================================================
   SIX-WEEK SEVERITY CHART
   ============================================================ */

$chartLabels = [];

$severityTrend = [
    'HIGH'   => [],
    'MEDIUM' => [],
    'LOW'    => [],
    'INFO'   => []
];

$currentMonday = new DateTimeImmutable('monday this week');

$weeklyStatement = $conn->prepare(
    'SELECT UPPER(sr.severity) AS severity_name,
            COUNT(*) AS total
     FROM scan_results sr
     INNER JOIN scans s ON s.ScanID = sr.ScanID
     WHERE s.ScanDate >= ?
     AND s.ScanDate < ?
     GROUP BY UPPER(sr.severity)'
);

for ($weekIndex = 5; $weekIndex >= 0; $weekIndex--) {
    $weekStart = $currentMonday->modify(
        "-{$weekIndex} weeks"
    );

    $weekEnd = $weekStart->modify('+1 week');

    $chartLabels[] = $weekStart->format('M d');

    $weekCounts = [
        'HIGH'   => 0,
        'MEDIUM' => 0,
        'LOW'    => 0,
        'INFO'   => 0
    ];

    if ($weeklyStatement) {
        $startValue = $weekStart->format('Y-m-d H:i:s');
        $endValue = $weekEnd->format('Y-m-d H:i:s');

        $weeklyStatement->bind_param(
            'ss',
            $startValue,
            $endValue
        );

        $weeklyStatement->execute();

        $weeklyResult = $weeklyStatement->get_result();

        while ($weeklyRow = $weeklyResult->fetch_assoc()) {
            $severityName = $weeklyRow['severity_name'];

            if (array_key_exists($severityName, $weekCounts)) {
                $weekCounts[$severityName] =
                    (int) $weeklyRow['total'];
            }
        }
    }

    foreach ($weekCounts as $severity => $count) {
        $severityTrend[$severity][] = $count;
    }
}

if ($weeklyStatement) {
    $weeklyStatement->close();
}

/* ============================================================
   CHART JSON DATA
   ============================================================ */

$chartLabelsJson = json_encode(
    $chartLabels,
    JSON_UNESCAPED_SLASHES
);

$severityTrendJson = json_encode(
    $severityTrend,
    JSON_NUMERIC_CHECK
);

$roleLabelsJson = json_encode([
    'Admin',
    'Developer',
    'Guest'
]);

$roleValuesJson = json_encode([
    $roleStats['admin'],
    $roleStats['developer'],
    $roleStats['guest']
], JSON_NUMERIC_CHECK);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>SecureLog — Admin Dashboard</title>

    <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
    >

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <script
        src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
    ></script>

    <style>
        :root {
            --dashboard-bg: #020c17;
            --dashboard-card: #031525;
            --dashboard-card-light: #071b2d;
            --dashboard-border: #143047;

            --dashboard-orange: #ff6500;
            --dashboard-blue: #00bff3;
            --dashboard-red: #ff2945;
            --dashboard-yellow: #ffd20a;
            --dashboard-green: #00d89f;

            --dashboard-text: #f8fafc;
            --dashboard-muted: #9aa9b9;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
            background: var(--dashboard-bg);
            color: var(--dashboard-text);
            font-family: "Inter", "Segoe UI", sans-serif;
        }

        body {
            overflow-x: hidden;
        }

        /* =====================================================
           MAIN CONTENT BESIDE PREVIOUS SIDEBAR
           ===================================================== */

        .dashboard-main {
            min-height: 100vh;
            padding: 28px 20px 20px;

            background:
                radial-gradient(
                    circle at 65% 8%,
                    rgba(0, 191, 243, 0.035),
                    transparent 26%
                ),
                var(--dashboard-bg);
        }

        .dashboard-container {
            width: 100%;
            max-width: 1500px;
            margin: 0 auto;
        }

        /* =====================================================
           TOP HEADER
           ===================================================== */

        .dashboard-header {
            min-height: 88px;
            margin-bottom: 18px;
            padding: 6px 14px;

            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 30px;
        }

        .dashboard-heading h1 {
            margin: 0 0 8px;

            color: #ffffff;

            font-size: 29px;
            font-weight: 800;
            letter-spacing: -0.8px;
        }

        .dashboard-heading h1 span {
            color: var(--dashboard-orange);
        }

        .dashboard-heading p {
            margin: 0;

            color: #d6dde5;

            font-size: 15px;
            font-weight: 400;
        }

        .dashboard-header-actions {
            display: flex;
            align-items: center;
            gap: 25px;

            color: #d7dee8;
        }

        .dashboard-date {
            display: flex;
            align-items: center;
            gap: 10px;

            padding-top: 10px;

            font-size: 14px;
            white-space: nowrap;
        }

        .dashboard-date i {
            color: #d7dee8;
        }

        .notification-button {
            position: relative;

            width: 50px;
            height: 50px;

            display: flex;
            align-items: center;
            justify-content: center;

            color: #ffffff;
            background: transparent;

            border: none;
            border-left: 1px solid var(--dashboard-border);

            font-size: 23px;
        }

        .notification-count {
            position: absolute;
            top: 0;
            right: 1px;

            min-width: 20px;
            height: 20px;
            padding: 0 5px;

            display: flex;
            align-items: center;
            justify-content: center;

            color: #ffffff;
            background: var(--dashboard-red);

            border-radius: 50%;

            font-size: 11px;
            font-weight: 800;
        }

        /* =====================================================
           STATISTIC CARDS
           ===================================================== */

        .statistics-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 13px;

            margin-bottom: 16px;
        }

        .statistic-card {
            min-height: 200px;
            padding: 24px 21px;

            position: relative;
            overflow: hidden;

            background:
                linear-gradient(
                    145deg,
                    rgba(7, 27, 45, 0.98),
                    rgba(2, 16, 29, 0.98)
                );

            border: 1px solid var(--dashboard-border);
            border-radius: 15px;
        }

        .statistic-label {
            margin-bottom: 14px;

            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .label-blue {
            color: var(--dashboard-blue);
        }

        .label-orange {
            color: var(--dashboard-orange);
        }

        .label-red {
            color: var(--dashboard-red);
        }

        .label-yellow {
            color: var(--dashboard-yellow);
        }

        .statistic-content {
            display: grid;
            grid-template-columns: 64px 1fr;
            align-items: center;
            gap: 16px;
        }

        .statistic-icon {
            width: 62px;
            height: 62px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 13px;

            font-size: 31px;
        }

        .statistic-icon.blue {
            color: var(--dashboard-blue);
            background: rgba(0, 191, 243, 0.12);
            border: 1px solid rgba(0, 191, 243, 0.25);
        }

        .statistic-icon.orange {
            color: var(--dashboard-orange);
            background: rgba(255, 101, 0, 0.13);
            border: 1px solid rgba(255, 101, 0, 0.28);
        }

        .statistic-icon.red {
            color: var(--dashboard-red);
            background: rgba(255, 41, 69, 0.12);
            border: 1px solid rgba(255, 41, 69, 0.28);
        }

        .statistic-icon.yellow {
            color: var(--dashboard-yellow);
            background: rgba(255, 210, 10, 0.13);
            border: 1px solid rgba(255, 210, 10, 0.26);
        }

        .statistic-value {
            color: #ffffff;

            font-size: 38px;
            font-weight: 800;
            line-height: 1;
        }

        .statistic-description {
            margin-top: 12px;
            margin-left: 80px;

            color: #d5dce4;

            font-size: 12px;
        }

        .statistic-trend {
            margin-top: 6px;

            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 5px;

            color: var(--dashboard-muted);

            font-size: 11px;
        }

        .trend-up {
            color: var(--dashboard-blue);
            font-weight: 800;
        }

        .trend-down {
            color: var(--dashboard-red);
            font-weight: 800;
        }

        .sparkline {
            position: absolute;
            top: 78px;
            right: 16px;

            width: 82px;
            height: 35px;
        }

        /* =====================================================
           PANELS
           ===================================================== */

        .dashboard-charts {
            display: grid;
            grid-template-columns: 1.08fr 1fr;
            gap: 13px;

            margin-bottom: 14px;
        }

        .dashboard-panel {
            min-width: 0;
            padding: 24px 22px;

            background:
                linear-gradient(
                    145deg,
                    rgba(7, 27, 45, 0.98),
                    rgba(2, 16, 29, 0.98)
                );

            border: 1px solid var(--dashboard-border);
            border-radius: 15px;
        }

        .dashboard-panel-title {
            margin-bottom: 18px;

            display: flex;
            align-items: center;
            gap: 12px;

            color: var(--dashboard-orange);

            font-size: 15px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .dashboard-panel-title i {
            font-size: 21px;
        }

        .chart-container {
            position: relative;

            width: 100%;
            height: 315px;
        }

        .role-chart-container {
            position: relative;

            width: 100%;
            height: 315px;
        }

        /* =====================================================
           SYSTEM OVERVIEW
           ===================================================== */

        .system-overview {
            margin-bottom: 16px;
        }

        .system-overview-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
        }

        .overview-item {
            min-height: 145px;
            padding: 20px 26px;

            display: grid;
            grid-template-columns: 70px 1fr;
            align-items: center;
            column-gap: 18px;

            border-right: 1px solid var(--dashboard-border);
        }

        .overview-item:last-child {
            border-right: none;
        }

        .overview-icon {
            width: 66px;
            height: 66px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 13px;

            font-size: 30px;
        }

        .overview-icon.blue {
            color: var(--dashboard-blue);
            background: rgba(0, 191, 243, 0.12);
            border: 1px solid rgba(0, 191, 243, 0.25);
        }

        .overview-icon.orange {
            color: var(--dashboard-orange);
            background: rgba(255, 101, 0, 0.13);
            border: 1px solid rgba(255, 101, 0, 0.28);
        }

        .overview-icon.yellow {
            color: var(--dashboard-yellow);
            background: rgba(255, 210, 10, 0.13);
            border: 1px solid rgba(255, 210, 10, 0.27);
        }

        .overview-icon.red {
            color: var(--dashboard-red);
            background: rgba(255, 41, 69, 0.12);
            border: 1px solid rgba(255, 41, 69, 0.27);
        }

        .overview-number {
            color: #ffffff;

            font-size: 33px;
            font-weight: 800;
            line-height: 1;
        }

        .overview-label {
            margin-top: 10px;

            color: #ffffff;

            font-size: 12px;
            text-transform: uppercase;
        }

        .overview-trend {
            grid-column: 2;
            margin-top: 14px;

            color: var(--dashboard-muted);

            font-size: 10px;
        }

        /* =====================================================
           FOOTER
           ===================================================== */

        .dashboard-footer {
            padding: 10px 0 2px;

            color: #c2cbd4;

            font-size: 13px;
            text-align: center;
        }

        .dashboard-footer span {
            color: var(--dashboard-orange);
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 1250px) {
            .statistics-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .system-overview-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .overview-item:nth-child(2) {
                border-right: none;
            }

            .overview-item:nth-child(-n + 2) {
                border-bottom: 1px solid var(--dashboard-border);
            }
        }

        @media (max-width: 1000px) {
            .dashboard-charts {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 800px) {
            .dashboard-main {
                padding: 18px;
            }
        }

        @media (max-width: 650px) {
            .statistics-grid,
            .system-overview-grid {
                grid-template-columns: 1fr;
            }

            .overview-item {
                border-right: none;
                border-bottom: 1px solid var(--dashboard-border);
            }

            .overview-item:last-child {
                border-bottom: none;
            }

            .dashboard-header {
                flex-direction: column;
            }

            .dashboard-header-actions {
                width: 100%;
                justify-content: space-between;
            }
        }
    </style>
</head>

<body>

    <!-- =====================================================
         CALL THE PREVIOUS ADMIN SIDEBAR
         dashboard_Admin.php is automatically highlighted
         ===================================================== -->

    <?php
    require __DIR__ . '/../Sidebar/sidebaradmin.php';
    ?>

    <!-- =====================================================
         MAIN DASHBOARD CONTENT
         ===================================================== -->

    <main class="admin-page-content dashboard-main">

        <div class="dashboard-container">

            <!-- Header -->
            <header class="dashboard-header">

                <div class="dashboard-heading">
                    <h1>
                        Admin <span>Dashboard</span>
                    </h1>

                    <p>
                        System overview and security monitoring
                    </p>
                </div>

                <div class="dashboard-header-actions">

                    <div class="dashboard-date">
                        <i class="fa-regular fa-calendar"></i>

                        <span>
                            <?= htmlspecialchars(
                                date('D, d M Y H:i:s')
                            ); ?>
                        </span>
                    </div>

                    <div class="notification-button">
                        <i class="fa-regular fa-bell"></i>

                        <?php if ($pendingApprovals > 0): ?>
                            <span class="notification-count">
                                <?= $pendingApprovals; ?>
                            </span>
                        <?php endif; ?>
                    </div>

                </div>

            </header>

            <!-- =================================================
                 STATISTIC CARDS
                 ================================================= -->

            <section class="statistics-grid">

                <!-- Total users -->
                <article class="statistic-card">

                    <div class="statistic-label label-blue">
                        Total Users
                    </div>

                    <div class="statistic-content">

                        <div class="statistic-icon blue">
                            <i class="fa-solid fa-users"></i>
                        </div>

                        <div class="statistic-value">
                            <?= $totalUsers; ?>
                        </div>

                    </div>

                    <svg
                        class="sparkline"
                        viewBox="0 0 90 35"
                        fill="none"
                    >
                        <polyline
                            points="1,26 13,15 25,28 39,5 53,27 66,14 88,28"
                            stroke="#00bff3"
                            stroke-width="2"
                            fill="none"
                        />
                    </svg>

                    <div class="statistic-description">
                        vs last 7 days
                    </div>

                    <div class="statistic-trend">
                        <span class="<?= trendClass($userTrend); ?>">
                            <?= trendArrow($userTrend); ?>
                            <?= abs($userTrend); ?>%
                        </span>

                        <span>vs last 30 days</span>
                    </div>

                </article>

                <!-- Total scans -->
                <article class="statistic-card">

                    <div class="statistic-label label-orange">
                        Total Scans
                    </div>

                    <div class="statistic-content">

                        <div class="statistic-icon orange">
                            <i class="fa-solid fa-laptop-code"></i>
                        </div>

                        <div class="statistic-value">
                            <?= $totalScans; ?>
                        </div>

                    </div>

                    <svg
                        class="sparkline"
                        viewBox="0 0 90 35"
                        fill="none"
                    >
                        <polyline
                            points="1,27 14,16 27,29 42,4 56,28 69,13 89,29"
                            stroke="#ff6500"
                            stroke-width="2"
                            fill="none"
                        />
                    </svg>

                    <div class="statistic-description">
                        All time
                    </div>

                    <div class="statistic-trend">
                        <span class="<?= trendClass($scanTrend); ?>">
                            <?= trendArrow($scanTrend); ?>
                            <?= abs($scanTrend); ?>%
                        </span>

                        <span>vs last 30 days</span>
                    </div>

                </article>

                <!-- High issues -->
                <article class="statistic-card">

                    <div class="statistic-label label-red">
                        High Issues
                    </div>

                    <div class="statistic-content">

                        <div class="statistic-icon red">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                        </div>

                        <div class="statistic-value">
                            <?= $severityStats['HIGH']; ?>
                        </div>

                    </div>

                    <svg
                        class="sparkline"
                        viewBox="0 0 90 35"
                        fill="none"
                    >
                        <polyline
                            points="1,29 22,29 34,14 46,29 89,29"
                            stroke="#ff2945"
                            stroke-width="2"
                            fill="none"
                        />
                    </svg>

                    <div class="statistic-description">
                        CWE-117 &amp; CWE-532
                    </div>

                    <div class="statistic-trend">
                        <span class="<?= trendClass($highTrend); ?>">
                            <?= trendArrow($highTrend); ?>
                            <?= abs($highTrend); ?>%
                        </span>

                        <span>vs last 30 days</span>
                    </div>

                </article>

                <!-- Medium issues -->
                <article class="statistic-card">

                    <div class="statistic-label label-yellow">
                        Medium Issues
                    </div>

                    <div class="statistic-content">

                        <div class="statistic-icon yellow">
                            <i class="fa-solid fa-shield-halved"></i>
                        </div>

                        <div class="statistic-value">
                            <?= $severityStats['MEDIUM']; ?>
                        </div>

                    </div>

                    <svg
                        class="sparkline"
                        viewBox="0 0 90 35"
                        fill="none"
                    >
                        <polyline
                            points="1,27 14,15 27,29 42,8 56,28 69,14 89,29"
                            stroke="#ffd20a"
                            stroke-width="2"
                            fill="none"
                        />
                    </svg>

                    <div class="statistic-description">
                        CWE-778
                    </div>

                    <div class="statistic-trend">
                        <span class="<?= trendClass($mediumTrend); ?>">
                            <?= trendArrow($mediumTrend); ?>
                            <?= abs($mediumTrend); ?>%
                        </span>

                        <span>vs last 30 days</span>
                    </div>

                </article>

            </section>

            <!-- =================================================
                 CHARTS
                 ================================================= -->

            <section class="dashboard-charts">

                <!-- Severity line chart -->
                <article class="dashboard-panel">

                    <div class="dashboard-panel-title">
                        <i class="fa-solid fa-shield-halved"></i>
                        Vulnerabilities by Severity
                    </div>

                    <div class="chart-container">
                        <canvas id="severityTrendChart"></canvas>
                    </div>

                </article>

                <!-- Role doughnut -->
                <article class="dashboard-panel">

                    <div class="dashboard-panel-title">
                        <i class="fa-solid fa-user-group"></i>
                        Users by Role
                    </div>

                    <div class="role-chart-container">
                        <canvas id="roleChart"></canvas>
                    </div>

                </article>

            </section>

            <!-- =================================================
                 SYSTEM OVERVIEW
                 ================================================= -->

            <section class="dashboard-panel system-overview">

                <div class="dashboard-panel-title">
                    <i class="fa-solid fa-list"></i>
                    System Overview
                </div>

                <div class="system-overview-grid">

                    <!-- Active developers -->
                    <div class="overview-item">

                        <div class="overview-icon blue">
                            <i class="fa-solid fa-code"></i>
                        </div>

                        <div>
                            <div class="overview-number">
                                <?= $activeDevelopers; ?>
                            </div>

                            <div class="overview-label">
                                Active Developers
                            </div>
                        </div>

                        <div class="overview-trend">
                            Live user account data
                        </div>

                    </div>

                    <!-- Pending approvals -->
                    <div class="overview-item">

                        <div class="overview-icon orange">
                            <i class="fa-solid fa-user-clock"></i>
                        </div>

                        <div>
                            <div class="overview-number">
                                <?= $pendingApprovals; ?>
                            </div>

                            <div class="overview-label">
                                Pending Approvals
                            </div>
                        </div>

                        <div class="overview-trend">
                            Developer registrations
                        </div>

                    </div>

                    <!-- Total rules -->
                    <div class="overview-item">

                        <div class="overview-icon yellow">
                            <i class="fa-regular fa-file-lines"></i>
                        </div>

                        <div>
                            <div class="overview-number">
                                <?= $totalRules; ?>
                            </div>

                            <div class="overview-label">
                                Total Rules (CWE)
                            </div>
                        </div>

                        <div class="overview-trend">
                            Scanner detection rules
                        </div>

                    </div>

                    <!-- Scan results -->
                    <div class="overview-item">

                        <div class="overview-icon red">
                            <i class="fa-solid fa-shield-virus"></i>
                        </div>

                        <div>
                            <div class="overview-number">
                                <?= $totalScanResults; ?>
                            </div>

                            <div class="overview-label">
                                Total Scan Results
                            </div>
                        </div>

                        <div class="overview-trend">
                            All detected findings
                        </div>

                    </div>

                </div>

            </section>

            <!-- Footer -->
            <footer class="dashboard-footer">
                © 2026 <span>SecureLog</span> v1.0.
                All rights reserved.
            </footer>

        </div>

    </main>

    <!-- =====================================================
         CHART JAVASCRIPT
         ===================================================== -->

    <script>
        Chart.defaults.font.family =
            'Inter, Segoe UI, sans-serif';

        Chart.defaults.color = '#9aa9b9';

        const severityTrendData =
            <?= $severityTrendJson; ?>;

        const chartLabels =
            <?= $chartLabelsJson; ?>;

        /*
        |--------------------------------------------------------------------------
        | Severity line chart
        |--------------------------------------------------------------------------
        */

        new Chart(
            document.getElementById('severityTrendChart'),
            {
                type: 'line',

                data: {
                    labels: chartLabels,

                    datasets: [
                        {
                            label: 'High',
                            data: severityTrendData.HIGH,
                            borderColor: '#ff2945',
                            backgroundColor: '#ff2945',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 5,
                            tension: 0.25
                        },
                        {
                            label: 'Medium',
                            data: severityTrendData.MEDIUM,
                            borderColor: '#ff6500',
                            backgroundColor: '#ff6500',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 5,
                            tension: 0.25
                        },
                        {
                            label: 'Low',
                            data: severityTrendData.LOW,
                            borderColor: '#00bff3',
                            backgroundColor: '#00bff3',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 5,
                            tension: 0.25
                        },
                        {
                            label: 'Info',
                            data: severityTrendData.INFO,
                            borderColor: '#00d89f',
                            backgroundColor: '#00d89f',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 5,
                            tension: 0.25
                        }
                    ]
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: false,

                    interaction: {
                        mode: 'index',
                        intersect: false
                    },

                    plugins: {
                        legend: {
                            position: 'top',

                            labels: {
                                color: '#d8e0e8',
                                usePointStyle: true,
                                pointStyle: 'line',
                                padding: 25,
                                font: {
                                    size: 12,
                                    weight: '600'
                                }
                            }
                        },

                        tooltip: {
                            backgroundColor: '#031525',
                            borderColor: '#143047',
                            borderWidth: 1,
                            titleColor: '#ffffff',
                            bodyColor: '#d8e0e8'
                        }
                    },

                    scales: {
                        x: {
                            border: {
                                color: '#143047'
                            },

                            grid: {
                                display: false
                            },

                            ticks: {
                                color: '#b7c2ce'
                            }
                        },

                        y: {
                            beginAtZero: true,

                            border: {
                                color: '#143047'
                            },

                            grid: {
                                color: 'rgba(20, 48, 71, 0.65)'
                            },

                            ticks: {
                                color: '#b7c2ce',
                                precision: 0
                            }
                        }
                    }
                }
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Doughnut centre text
        |--------------------------------------------------------------------------
        */

        const centreTextPlugin = {
            id: 'centreTextPlugin',

            afterDatasetsDraw(chart) {
                if (chart.config.type !== 'doughnut') {
                    return;
                }

                const meta = chart.getDatasetMeta(0);

                if (!meta.data.length) {
                    return;
                }

                const centreX = meta.data[0].x;
                const centreY = meta.data[0].y;

                const total = chart.data.datasets[0].data.reduce(
                    (sum, value) => sum + Number(value),
                    0
                );

                const context = chart.ctx;

                context.save();

                context.textAlign = 'center';
                context.textBaseline = 'middle';

                context.fillStyle = '#ffffff';
                context.font =
                    '800 34px Inter, Segoe UI, sans-serif';

                context.fillText(
                    total.toLocaleString(),
                    centreX,
                    centreY - 10
                );

                context.fillStyle = '#d2dae3';
                context.font =
                    '500 14px Inter, Segoe UI, sans-serif';

                context.fillText(
                    'Total',
                    centreX,
                    centreY + 25
                );

                context.restore();
            }
        };

        /*
        |--------------------------------------------------------------------------
        | User roles doughnut chart
        |--------------------------------------------------------------------------
        */

        new Chart(
            document.getElementById('roleChart'),
            {
                type: 'doughnut',

                data: {
                    labels: <?= $roleLabelsJson; ?>,

                    datasets: [
                        {
                            data: <?= $roleValuesJson; ?>,

                            backgroundColor: [
                                '#ff6500',
                                '#00bff3',
                                '#607386'
                            ],

                            borderColor: '#031525',
                            borderWidth: 4,

                            hoverOffset: 5
                        }
                    ]
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: false,

                    cutout: '66%',

                    layout: {
                        padding: {
                            left: 15,
                            right: 15
                        }
                    },

                    plugins: {
                        legend: {
                            position: 'right',

                            labels: {
                                color: '#ffffff',
                                boxWidth: 13,
                                boxHeight: 13,
                                padding: 23,

                                font: {
                                    size: 13,
                                    weight: '600'
                                },

                                generateLabels(chart) {
                                    const dataset =
                                        chart.data.datasets[0];

                                    const total =
                                        dataset.data.reduce(
                                            (sum, value) =>
                                                sum + Number(value),
                                            0
                                        );

                                    return chart.data.labels.map(
                                        (label, index) => {
                                            const value =
                                                Number(
                                                    dataset.data[index]
                                                );

                                            const percentage =
                                                total > 0
                                                    ? Math.round(
                                                        value
                                                        / total
                                                        * 100
                                                    )
                                                    : 0;

                                            return {
                                                text:
                                                    `${label}  `
                                                    + `${value} `
                                                    + `(${percentage}%)`,

                                                fillStyle:
                                                    dataset
                                                        .backgroundColor[
                                                            index
                                                        ],

                                                strokeStyle:
                                                    dataset
                                                        .backgroundColor[
                                                            index
                                                        ],

                                                lineWidth: 0,

                                                hidden: false,

                                                index: index
                                            };
                                        }
                                    );
                                }
                            }
                        },

                        tooltip: {
                            backgroundColor: '#031525',
                            borderColor: '#143047',
                            borderWidth: 1,
                            titleColor: '#ffffff',
                            bodyColor: '#d8e0e8'
                        }
                    }
                },

                plugins: [
                    centreTextPlugin
                ]
            }
        );
    </script>

</body>
</html>
```
