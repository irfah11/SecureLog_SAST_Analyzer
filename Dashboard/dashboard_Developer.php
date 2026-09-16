```php
<?php
/**
 * SecureLog Developer Dashboard
 * File: Dashboard/dashboard_Developer.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

if (
    !isset($_SESSION['role'])
    || strtolower((string) $_SESSION['role']) !== 'developer'
) {
    header('Location: ../Registration/login.php');
    exit();
}

/* ============================================================
   CURRENT USER
   ============================================================ */

$username = $_SESSION['username']
    ?? $_SESSION['fullname']
    ?? 'Developer';

    require_once __DIR__ . '/../Engine_Process/connection.php';

$currentUserId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

if ($currentUserId <= 0) {
    session_destroy();

    header('Location: ../Registration/login.php');
    exit();
}

function fetchDeveloperCount(
    mysqli $conn,
    string $sql,
    int $userId
): int {
    $statement = $conn->prepare($sql);

    if (!$statement) {
        return 0;
    }

    $statement->bind_param('i', $userId);
    $statement->execute();

    $statement->bind_result($total);
    $statement->fetch();
    $statement->close();

    return (int) ($total ?? 0);
}

$totalScans = fetchDeveloperCount(
    $conn,
    'SELECT COUNT(*)
     FROM scans
     WHERE UserID = ?',
    $currentUserId
);

$recentScans = [];

$recentStatement = $conn->prepare(
    "SELECT
        s.ScanID,
        s.ProjectName,
        s.ScanDate,
        s.Status,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'HIGH'
                THEN 1 ELSE 0
            END
        ) AS HighCount,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'MEDIUM'
                THEN 1 ELSE 0
            END
        ) AS MediumCount,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'LOW'
                THEN 1 ELSE 0
            END
        ) AS LowCount,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'INFO'
                THEN 1 ELSE 0
            END
        ) AS InfoCount

     FROM scans s

     LEFT JOIN scan_results sr
        ON sr.ScanID = s.ScanID

     WHERE s.UserID = ?

     GROUP BY
        s.ScanID,
        s.ProjectName,
        s.ScanDate,
        s.Status

     ORDER BY s.ScanDate DESC

     LIMIT 5"
);

$recentStatement->bind_param(
    'i',
    $currentUserId
);

$recentStatement->execute();

$recentResult =
    $recentStatement->get_result();

while ($row = $recentResult->fetch_assoc()) {
    $recentScans[] = $row;
}

$recentStatement->close();

/* ============================================================
   SEVERITY CLASSIFICATION
   ============================================================ */

$severityCase = "
    CASE
        WHEN UPPER(COALESCE(sr.Severity, '')) = 'HIGH'
            THEN 'HIGH'

        WHEN UPPER(COALESCE(sr.Severity, '')) = 'MEDIUM'
            THEN 'MEDIUM'

        WHEN UPPER(COALESCE(sr.Severity, '')) = 'LOW'
            THEN 'LOW'

        WHEN UPPER(COALESCE(sr.Severity, '')) = 'INFO'
            THEN 'INFO'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%log does not exist%'
            THEN 'HIGH'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%missing log%'
            THEN 'HIGH'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%no log%'
            THEN 'HIGH'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%plaintext%'
            THEN 'MEDIUM'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%improper format%'
            THEN 'MEDIUM'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%log exists%'
            THEN 'MEDIUM'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%encrypted%'
            THEN 'LOW'

        WHEN LOWER(COALESCE(sr.Description, ''))
            LIKE '%protected%'
            THEN 'LOW'

        ELSE 'INFO'
    END
";

/* ============================================================
   HIGH SEVERITY COUNT
   ============================================================ */

$highSeverityFindings = 0;

$highStatement = $conn->prepare(
    "
    SELECT COUNT(*) AS total
    FROM scan_results sr

    INNER JOIN scans s
        ON s.ScanID = sr.ScanID

    WHERE s.UserID = ?
    AND {$severityCase} = 'HIGH'
    "
);

if ($highStatement) {
    $highStatement->bind_param(
        'i',
        $currentUserId
    );

    $highStatement->execute();

    $highStatement->bind_result(
        $highSeverityFindings
    );

    $highStatement->fetch();
    $highStatement->close();

    $highSeverityFindings =
        (int) $highSeverityFindings;
}

/* ============================================================
   TOTAL SEVERITY COUNTS
   ============================================================ */

$severityCounts = [
    'HIGH' => 0,
    'MEDIUM' => 0,
    'LOW' => 0,
    'INFO' => 0
];

$severityStatement = $conn->prepare(
    "
    SELECT
        {$severityCase} AS SeverityName,
        COUNT(*) AS Total

    FROM scan_results sr

    INNER JOIN scans s
        ON s.ScanID = sr.ScanID

    WHERE s.UserID = ?

    GROUP BY SeverityName
    "
);

if ($severityStatement) {
    $severityStatement->bind_param(
        'i',
        $currentUserId
    );

    $severityStatement->execute();

    $severityResult =
        $severityStatement->get_result();

    while (
        $severityRow =
            $severityResult->fetch_assoc()
    ) {
        $severityName = strtoupper(
            (string) $severityRow['SeverityName']
        );

        if (
            array_key_exists(
                $severityName,
                $severityCounts
            )
        ) {
            $severityCounts[$severityName] =
                (int) $severityRow['Total'];
        }
    }

    $severityStatement->close();
}

/* ============================================================
   SIX-WEEK GRAPH DATA
   ============================================================ */

$chartLabels = [];

$weeklySeverity = [
    'HIGH' => [],
    'MEDIUM' => [],
    'LOW' => [],
    'INFO' => []
];

$currentMonday =
    new DateTimeImmutable('monday this week');

$weeklyStatement = $conn->prepare(
    "
    SELECT
        {$severityCase} AS SeverityName,
        COUNT(*) AS Total

    FROM scan_results sr

    INNER JOIN scans s
        ON s.ScanID = sr.ScanID

    WHERE s.UserID = ?
    AND s.ScanDate >= ?
    AND s.ScanDate < ?

    GROUP BY SeverityName
    "
);

for ($weekIndex = 5; $weekIndex >= 0; $weekIndex--) {
    $weekStart = $currentMonday->modify(
        "-{$weekIndex} weeks"
    );

    $weekEnd =
        $weekStart->modify('+1 week');

    $chartLabels[] =
        $weekStart->format('d M');

    $weekCounts = [
        'HIGH' => 0,
        'MEDIUM' => 0,
        'LOW' => 0,
        'INFO' => 0
    ];

    if ($weeklyStatement) {
        $startDate =
            $weekStart->format('Y-m-d H:i:s');

        $endDate =
            $weekEnd->format('Y-m-d H:i:s');

        $weeklyStatement->bind_param(
            'iss',
            $currentUserId,
            $startDate,
            $endDate
        );

        $weeklyStatement->execute();

        $weeklyResult =
            $weeklyStatement->get_result();

        while (
            $weeklyRow =
                $weeklyResult->fetch_assoc()
        ) {
            $severityName = strtoupper(
                (string) $weeklyRow['SeverityName']
            );

            if (
                isset(
                    $weekCounts[$severityName]
                )
            ) {
                $weekCounts[$severityName] =
                    (int) $weeklyRow['Total'];
            }
        }
    }

    foreach (
        $weekCounts as $severity => $count
    ) {
        $weeklySeverity[$severity][] =
            $count;
    }
}

if ($weeklyStatement) {
    $weeklyStatement->close();
}

/* ============================================================
   JSON FOR JAVASCRIPT
   ============================================================ */

$chartLabelsJson = json_encode(
    $chartLabels,
    JSON_UNESCAPED_SLASHES
);

$weeklySeverityJson = json_encode(
    $weeklySeverity,
    JSON_NUMERIC_CHECK
);

$severityDataJson = json_encode(
    [
        $severityCounts['HIGH'],
        $severityCounts['MEDIUM'],
        $severityCounts['LOW'],
        $severityCounts['INFO']
    ],
    JSON_NUMERIC_CHECK
);


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Developer Dashboard | SecureLog</title>

    <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
        rel="stylesheet"
    >

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <!-- Local Chart.js file -->
    <script src="/FinalYearProject/Asset/js/chart.umd.min.js"></script>

    <style>
        :root {
            --bg-dark: #020817;
            --card-bg: #07162b;
            --border: rgba(59, 130, 246, 0.22);

            --blue: #3b82f6;
            --green: #10b981;
            --orange: #f59e0b;
            --red: #ef4444;
            --purple: #8b5cf6;

            --text-main: #f8fafc;
            --text-dim: #94a3b8;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;

            background: var(--bg-dark);
            color: var(--text-main);

            font-family:
                "Inter",
                "Segoe UI",
                sans-serif;
        }

        body {
            overflow-x: hidden;
        }

        /* =====================================================
           MAIN PAGE
           ===================================================== */

        .main-content {
            min-height: 100vh;
            padding: 40px;

            background:
                radial-gradient(
                    circle at 75% 8%,
                    rgba(59, 130, 246, 0.035),
                    transparent 30%
                ),
                var(--bg-dark);
        }

        .dashboard-container {
            width: 100%;
            max-width: 1600px;
            margin: 0 auto;
        }

        /* =====================================================
           HEADER
           ===================================================== */

        .dashboard-header {
            margin-bottom: 35px;

            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 25px;
        }

        .dashboard-header h1 {
            margin: 0;

            color: #ffffff;

            font-size: 30px;
            font-weight: 900;
        }

        .dashboard-header h1 span {
            color: var(--blue);
        }

        .dashboard-header p {
            margin: 7px 0 0;

            color: var(--text-dim);

            font-size: 15px;
        }

        .user-badge {
            min-height: 44px;
            padding: 0 20px;

            display: flex;
            align-items: center;
            gap: 10px;

            color: #ffffff;
            background: var(--card-bg);

            border: 1px solid var(--border);
            border-radius: 10px;

            font-size: 14px;
        }

        .user-badge i {
            color: var(--blue);
        }

        /* =====================================================
           STATISTIC CARDS
           ===================================================== */

        .stats-grid {
            margin-bottom: 22px;

            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 22px;
        }

        .stat-card {
            min-height: 155px;
            padding: 27px;

            position: relative;
            overflow: hidden;

            background:
                linear-gradient(
                    145deg,
                    rgba(8, 27, 51, 0.98),
                    rgba(5, 19, 38, 0.98)
                );

            border: 1px solid var(--border);
            border-radius: 12px;

            box-shadow:
                0 10px 25px rgba(0, 0, 0, 0.22);
        }

        .stat-card::after {
            content: "";

            position: absolute;
            right: 0;
            bottom: 0;
            left: 0;

            height: 4px;

            background: var(--blue);
        }

        .stat-card.orange::after {
            background: var(--orange);
        }

        .stat-card.green::after {
            background: var(--green);
        }

        .stat-card.purple::after {
            background: var(--purple);
        }

        .stat-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 15px;
        }

        .stat-card h3 {
            margin: 0 0 18px;

            color: #8fb1dc;

            font-size: 12px;
            font-weight: 800;
            letter-spacing: 1.2px;
            text-transform: uppercase;
        }

        .stat-icon {
            width: 34px;
            height: 34px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 8px;

            font-size: 14px;
        }

        .stat-icon.blue {
            color: var(--blue);
            background: rgba(59, 130, 246, 0.14);
        }

        .stat-icon.red {
            color: var(--red);
            background: rgba(239, 68, 68, 0.14);
        }

        .stat-icon.green {
            color: var(--green);
            background: rgba(16, 185, 129, 0.14);
        }

        .stat-icon.purple {
            color: var(--purple);
            background: rgba(139, 92, 246, 0.14);
        }

        .stat-value {
            color: #ffffff;

            font-size: 38px;
            font-weight: 900;
            line-height: 1;
        }

        .stat-footer {
            margin-top: 19px;

            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;

            color: var(--text-dim);

            font-size: 11px;
        }

        .trend-up {
            color: var(--green);
            font-weight: 700;
        }

        .trend-red {
            color: var(--red);
            font-weight: 700;
        }

        /* =====================================================
           CHARTS
           ===================================================== */

        .charts-grid {
            margin-bottom: 22px;

            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 22px;
        }

        .chart-card,
        .table-container {
            background:
                linear-gradient(
                    145deg,
                    rgba(8, 27, 51, 0.98),
                    rgba(5, 19, 38, 0.98)
                );

            border: 1px solid var(--border);
            border-radius: 12px;

            box-shadow:
                0 10px 25px rgba(0, 0, 0, 0.22);
        }

        .chart-card {
            padding: 24px;
        }

        .chart-card h2,
        .table-container h2 {
            margin: 0 0 18px;

            display: flex;
            align-items: center;
            gap: 10px;

            color: #ffffff;

            font-size: 16px;
            font-weight: 800;
        }

        .chart-card h2 i,
        .table-container h2 i {
            color: var(--blue);
        }

        .chart-box {
            position: relative;

            width: 100%;
            height: 310px;
        }

        .severity-layout {
            position: relative;

            width: 100%;
            height: 310px;

            display: flex;
            align-items: center;
            justify-content: center;
        }

        .severity-chart {
            position: relative;

            width: 100%;
            height: 285px;
        }

        .chart-box canvas,
        .severity-chart canvas {
            display: block !important;

            width: 100% !important;
            height: 100% !important;
        }

        .chart-error {
            height: 100%;

            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: 10px;

            color: var(--red);

            font-size: 13px;
            text-align: center;
        }

        .chart-error i {
            font-size: 28px;
        }

        /* =====================================================
           TABLE
           ===================================================== */

        .table-container {
            padding: 26px 28px;
        }

        .table-wrapper {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            min-width: 760px;

            border-collapse: collapse;
        }

        th {
            padding: 14px 12px;

            color: var(--text-dim);

            border-bottom:
                1px solid rgba(148, 163, 184, 0.18);

            font-size: 12px;
            font-weight: 800;
            text-align: left;
        }

        td {
            padding: 16px 12px;

            color: #e5e7eb;

            border-bottom:
                1px solid rgba(148, 163, 184, 0.08);

            font-size: 13px;
        }

        td strong {
            color: #ffffff;
        }

        .status-pill {
            padding: 7px 14px;

            display: inline-flex;
            align-items: center;
            justify-content: center;

            color: var(--green);
            background: rgba(16, 185, 129, 0.13);

            border: 1px solid rgba(16, 185, 129, 0.28);
            border-radius: 20px;

            font-size: 11px;
            font-weight: 800;
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 1250px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 1050px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 800px) {
            .main-content {
                padding: 25px 18px;
            }

            .dashboard-header {
                flex-direction: column;
            }
        }

        @media (max-width: 600px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }

            .chart-box,
            .severity-layout {
                height: 260px;
            }
        }
    </style>
</head>

<body>

    <!-- Developer sidebar -->
    <?php
    require __DIR__ . '/../Sidebar/sidebaruser.php';
    ?>

    <main class="developer-page-content main-content">

        <div class="dashboard-container">

            <!-- Header -->
            <header class="dashboard-header">

                <div>
                    <h1>
                        Developer <span>Dashboard</span>
                    </h1>

                    <p>
                        Quick access to your code scanning status.
                    </p>
                </div>

                <div class="user-badge">
                    <i class="fa-solid fa-code"></i>

                    <strong>
                        <?= htmlspecialchars(
                            $username,
                            ENT_QUOTES,
                            'UTF-8'
                        ); ?>
                    </strong>
                </div>

            </header>

            <!-- =================================================
                 STATISTICS
                 ================================================= -->

            <section class="stats-grid">

                <!-- Total scans -->
                <article class="stat-card">

                    <div class="stat-top">

                        <h3>Total Scans</h3>

                        <div class="stat-icon blue">
                            <i class="fa-solid fa-layer-group"></i>
                        </div>

                    </div>

                     <div class="stat-value">
                        <?= number_format($totalScans); ?>
                    </div>

                    <div class="stat-footer">
                        <span>vs previous 30 days</span>

                        <span class="trend-red">
                            ↑ 12%
                        </span>
                    </div>

                </article>

                <!-- High severity -->
                <article class="stat-card orange">

                    <div class="stat-top">

                        <h3>High Severity</h3>

                        <div class="stat-icon red">
                            <i class="fa-solid fa-shield-halved"></i>
                        </div>

                    </div>

                    <div class="stat-value">
                        <?= number_format($highSeverityFindings); ?>
                    </div>

                    <div class="stat-footer">
                        <span>vs previous 30 days</span>

                        <span class="trend-red">
                            ↑ 8%
                        </span>
                    </div>

                </article>

                <!-- Projects scanned -->
                <article class="stat-card green">

                    <div class="stat-top">

                        <h3>Projects Scanned</h3>

                        <div class="stat-icon green">
                            <i class="fa-regular fa-folder"></i>
                        </div>

                    </div>

                    <div class="stat-value">
                        8
                    </div>

                    <div class="stat-footer">
                        <span>vs previous 30 days</span>

                        <span class="trend-up">
                            ↑ 4%
                        </span>
                    </div>

                </article>

                <!-- Lines of code -->
                <article class="stat-card purple">

                    <div class="stat-top">

                        <h3>Lines of Code Scanned</h3>

                        <div class="stat-icon purple">
                            <i class="fa-solid fa-code"></i>
                        </div>

                    </div>

                    <div class="stat-value">
                        1,200
                    </div>

                    <div class="stat-footer">
                        <span>vs previous 30 days</span>

                        <span class="trend-up">
                            ↑ 10%
                        </span>
                    </div>

                </article>

            </section>

            <!-- =================================================
                 CHARTS
                 ================================================= -->

            <section class="charts-grid">

                <!-- Detected issues over time -->
                <article class="chart-card">

                    <h2>
                        <i class="fa-solid fa-chart-line"></i>
                        Detected Issues Over Time
                    </h2>

                    <div class="chart-box">
                        <canvas id="lineChart"></canvas>
                    </div>

                </article>

                <!-- Detected issues by severity -->
                <article class="chart-card">

                    <h2>
                        <i class="fa-solid fa-chart-pie"></i>
                         Detected Issues by Severity
                    </h2>

                    <div class="severity-layout">

                        <div class="severity-chart">
                            <canvas id="severityChart"></canvas>
                        </div>

                    </div>

                </article>

            </section>

            <!-- =================================================
                 RECENT SCANS
                 ================================================= -->

            <section class="table-container">

                <h2>
                    <i class="fa-solid fa-list-check"></i>
                    Recent Scan Records
                </h2>

                <div class="table-wrapper">

                    <table>

                        <thead>
                            <tr>
                                <th>Project Name</th>
                                <th>Vulnerabilities</th>
                                <th>Scan Date</th>
                                <th>Status</th>
                            </tr>
                        </thead>

                       <tbody>

                            <?php if (empty($recentScans)): ?>

                                <tr>
                                    <td colspan="4">
                                        No scan records found.
                                    </td>
                                </tr>

                            <?php else: ?>

                                <?php foreach ($recentScans as $scan): ?>

                                    <?php
                                    $issues = [];

                                    if ((int) $scan['HighCount'] > 0) {
                                        $issues[] =
                                            $scan['HighCount'] . ' High';
                                    }

                                    if ((int) $scan['MediumCount'] > 0) {
                                        $issues[] =
                                            $scan['MediumCount'] . ' Medium';
                                    }

                                    if ((int) $scan['LowCount'] > 0) {
                                        $issues[] =
                                            $scan['LowCount'] . ' Low';
                                    }

                                    if ((int) $scan['InfoCount'] > 0) {
                                        $issues[] =
                                            $scan['InfoCount'] . ' Info';
                                    }

                                    $issueText = empty($issues)
                                        ? '0 Issues'
                                        : implode(', ', $issues);
                                    ?>

                                    <tr>
                                        <td>
                                            <strong>
                                                <?= htmlspecialchars(
                                                    $scan['ProjectName']
                                                ); ?>
                                            </strong>
                                        </td>

                                        <td>
                                            <?= htmlspecialchars($issueText); ?>
                                        </td>

                                        <td>
                                            <?= date(
                                                'd M Y',
                                                strtotime($scan['ScanDate'])
                                            ); ?>
                                        </td>

                                        <td>
                                            <span class="status-pill">
                                                <?= htmlspecialchars(
                                                    strtoupper($scan['Status'])
                                                ); ?>
                                            </span>
                                        </td>
                                    </tr>

                                <?php endforeach; ?>

                            <?php endif; ?>

                            </tbody>

                    </table>

                </div>

            </section>

        </div>

    </main>

   <script>
document.addEventListener('DOMContentLoaded', function () {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded.');
        return;
    }

    const lineCanvas = document.getElementById('lineChart');
    const severityCanvas = document.getElementById('severityChart');

    const findingsLabels =
        <?= json_encode($chartLabels ?? []); ?>;

    const findingsTrend =
        <?= json_encode(
            $weeklySeverity ?? [
                'HIGH' => [],
                'MEDIUM' => [],
                'LOW' => [],
                'INFO' => []
            ],
            JSON_NUMERIC_CHECK
        ); ?>;

    const severityData =
        <?= json_encode(
            [
                (int) ($severityCounts['HIGH'] ?? 0),
                (int) ($severityCounts['MEDIUM'] ?? 0),
                (int) ($severityCounts['LOW'] ?? 0),
                (int) ($severityCounts['INFO'] ?? 0)
            ],
            JSON_NUMERIC_CHECK
        ); ?>;

    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family =
        'Inter, Segoe UI, sans-serif';

    /* =========================================================
       FINDINGS OVER TIME
       ========================================================= */

    if (lineCanvas) {
        new Chart(
            lineCanvas.getContext('2d'),
            {
                type: 'line',

                data: {
                    labels: findingsLabels,

                    datasets: [
                        {
                            label: 'High',
                            data: findingsTrend.HIGH || [],
                            borderColor: '#ef4444',
                            backgroundColor:
                                'rgba(239, 68, 68, 0.10)',
                            pointBackgroundColor: '#ef4444',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 6,
                            tension: 0.35,
                            fill: false
                        },
                        {
                            label: 'Medium',
                            data: findingsTrend.MEDIUM || [],
                            borderColor: '#f59e0b',
                            backgroundColor:
                                'rgba(245, 158, 11, 0.10)',
                            pointBackgroundColor: '#f59e0b',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 6,
                            tension: 0.35,
                            fill: false
                        },
                        {
                            label: 'Low',
                            data: findingsTrend.LOW || [],
                            borderColor: '#3b82f6',
                            backgroundColor:
                                'rgba(59, 130, 246, 0.10)',
                            pointBackgroundColor: '#3b82f6',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 6,
                            tension: 0.35,
                            fill: false
                        },
                        {
                            label: 'Info',
                            data: findingsTrend.INFO || [],
                            borderColor: '#10b981',
                            backgroundColor:
                                'rgba(16, 185, 129, 0.10)',
                            pointBackgroundColor: '#10b981',
                            borderWidth: 2,
                            pointRadius: 4,
                            pointHoverRadius: 6,
                            tension: 0.35,
                            fill: false
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
                            display: true,
                            position: 'top',

                            labels: {
                                color: '#cbd5e1',
                                usePointStyle: true,
                                pointStyle: 'circle',
                                padding: 20
                            }
                        },

                        tooltip: {
                            backgroundColor: '#07162b',
                            borderColor:
                                'rgba(59, 130, 246, 0.45)',
                            borderWidth: 1,
                            titleColor: '#ffffff',
                            bodyColor: '#cbd5e1'
                        }
                    },

                    scales: {
                        x: {
                            grid: {
                                display: false
                            },

                            ticks: {
                                color: '#94a3b8'
                            }
                        },

                        y: {
                            beginAtZero: true,

                            grid: {
                                color:
                                    'rgba(148, 163, 184, 0.12)'
                            },

                            ticks: {
                                color: '#94a3b8',
                                precision: 0,
                                stepSize: 1
                            }
                        }
                    }
                }
            }
        );
    }

    /* =========================================================
       DOUGHNUT CENTRE TEXT
       ========================================================= */

    const centreTextPlugin = {
        id: 'secureLogCentreText',

        afterDatasetsDraw(chart) {
            if (chart.config.type !== 'doughnut') {
                return;
            }

            const metadata =
                chart.getDatasetMeta(0);

            if (!metadata.data.length) {
                return;
            }

            const realTotal =
                severityData.reduce(
                    function (sum, value) {
                        return sum + Number(value);
                    },
                    0
                );

            const centreX = metadata.data[0].x;
            const centreY = metadata.data[0].y;
            const context = chart.ctx;

            context.save();

            context.textAlign = 'center';
            context.textBaseline = 'middle';

            context.fillStyle = '#ffffff';
            context.font = '800 25px Inter';

            context.fillText(
                realTotal.toLocaleString(),
                centreX,
                centreY - 10
            );

            context.fillStyle = '#94a3b8';
            context.font = '600 12px Inter';

            context.fillText(
                'Total Findings',
                centreX,
                centreY + 19
            );

            context.restore();
        }
    };

    /* =========================================================
       FINDINGS BY SEVERITY
       ========================================================= */

    if (severityCanvas) {
        const hasSeverityData =
            severityData.some(
                function (value) {
                    return Number(value) > 0;
                }
            );

        const chartValues = hasSeverityData
            ? severityData
            : [1];

        const chartLabels = hasSeverityData
            ? ['High', 'Medium', 'Low', 'Info']
            : ['No findings'];

        const chartColours = hasSeverityData
            ? [
                '#ef4444',
                '#f59e0b',
                '#3b82f6',
                '#10b981'
            ]
            : [
                '#334155'
            ];

        new Chart(
            severityCanvas.getContext('2d'),
            {
                type: 'doughnut',

                data: {
                    labels: chartLabels,

                    datasets: [
                        {
                            data: chartValues,
                            backgroundColor: chartColours,
                            borderColor: '#07162b',
                            borderWidth: 4,
                            hoverOffset: 7
                        }
                    ]
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '64%',

                    plugins: {
                        legend: {
                            display: true,
                            position: 'right',

                            labels: {
                                color: '#cbd5e1',
                                boxWidth: 13,
                                boxHeight: 13,
                                padding: 18
                            }
                        },

                        tooltip: {
                            enabled: hasSeverityData
                        }
                    }
                },

                plugins: [
                    centreTextPlugin
                ]
            }
        );
    }
});
</script>

</body>
</html>
