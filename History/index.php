<?php

session_start();

require_once '../Engine_Process/connection.php';

/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
| History belongs to the currently logged-in developer.
|--------------------------------------------------------------------------
*/

if (
    !isset($_SESSION['user_id']) ||
    empty($_SESSION['user_id'])
) {
    header('Location: ../Registration/login.php');
    exit;
}

$currentUserId = (int) $_SESSION['user_id'];


/*
|--------------------------------------------------------------------------
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

if (
    !isset($_SESSION['role']) ||
    $_SESSION['role'] !== 'developer'
) {
    http_response_code(403);

    header('Location: ../Dashboard/403.php');
    exit;
}


/*
|--------------------------------------------------------------------------
| FILTER VALUES
|--------------------------------------------------------------------------
*/

$start_date = trim($_GET['start_date'] ?? '');
$language   = trim($_GET['language'] ?? '');
$search     = trim($_GET['search'] ?? '');


/*
|--------------------------------------------------------------------------
| ALLOWED LANGUAGES
|--------------------------------------------------------------------------
*/

$allowedLanguages = [
    'php',
    'java',
    'javascript',
    'c'
];

if (
    $language !== '' &&
    !in_array($language, $allowedLanguages, true)
) {
    $language = '';
}


/*
|--------------------------------------------------------------------------
| BUILD HISTORY QUERY
|--------------------------------------------------------------------------
|
| IMPORTANT SECURITY CONTROL:
|
| s.UserID = ?
|
| means a developer can retrieve ONLY scans belonging
| to their authenticated account.
|
|--------------------------------------------------------------------------
*/

$sql = "
    SELECT
        s.ScanID,
        s.UserID,
        s.ProjectName,
        s.ScanDate,
        s.ProgrammingLanguage,
        s.total_files,

        COUNT(sr.ResultID) AS total_issues,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'HIGH'
                THEN 1
                ELSE 0
            END
        ) AS high_issues,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'MEDIUM'
                THEN 1
                ELSE 0
            END
        ) AS medium_issues,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'LOW'
                THEN 1
                ELSE 0
            END
        ) AS low_issues,

        SUM(
            CASE
                WHEN UPPER(sr.Severity) = 'INFO'
                THEN 1
                ELSE 0
            END
        ) AS info_issues

    FROM scans s

    LEFT JOIN scan_results sr
        ON sr.ScanID = s.ScanID

    WHERE s.UserID = ?
";


/*
|--------------------------------------------------------------------------
| PREPARED STATEMENT PARAMETERS
|--------------------------------------------------------------------------
*/

$params = [$currentUserId];
$types  = 'i';


/*
|--------------------------------------------------------------------------
| DATE FILTER
|--------------------------------------------------------------------------
*/

if ($start_date !== '') {

    $dateObject = DateTime::createFromFormat(
        'Y-m-d',
        $start_date
    );

    if (
        $dateObject &&
        $dateObject->format('Y-m-d') === $start_date
    ) {

        $sql .= "
            AND DATE(s.ScanDate) = ?
        ";

        $params[] = $start_date;
        $types .= 's';

    } else {

        $start_date = '';
    }
}


/*
|--------------------------------------------------------------------------
| LANGUAGE FILTER
|--------------------------------------------------------------------------
*/

if ($language !== '') {

    $sql .= "
        AND LOWER(s.ProgrammingLanguage) = ?
    ";

    $params[] = $language;
    $types .= 's';
}


/*
|--------------------------------------------------------------------------
| SEARCH FILTER
|--------------------------------------------------------------------------
|
| User can search:
|
| - Scan ID
| - Project Name
|
|--------------------------------------------------------------------------
*/

if ($search !== '') {

    $sql .= "
        AND (
            CAST(s.ScanID AS CHAR) LIKE ?
            OR s.ProjectName LIKE ?
        )
    ";

    $searchPattern = '%' . $search . '%';

    $params[] = $searchPattern;
    $params[] = $searchPattern;

    $types .= 'ss';
}


/*
|--------------------------------------------------------------------------
| GROUP AND SORT
|--------------------------------------------------------------------------
*/

$sql .= "
    GROUP BY
        s.ScanID,
        s.UserID,
        s.ProjectName,
        s.ScanDate,
        s.ProgrammingLanguage,
        s.total_files

    ORDER BY s.ScanDate DESC
";


/*
|--------------------------------------------------------------------------
| EXECUTE QUERY
|--------------------------------------------------------------------------
*/

$stmt = $conn->prepare($sql);

if (!$stmt) {

    die(
        'Unable to prepare scan history query.'
    );
}

$stmt->bind_param(
    $types,
    ...$params
);

$stmt->execute();

$history = $stmt->get_result();

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
        Scan History - SecureLog
    </title>


    <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
        rel="stylesheet"
    >

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
    >


    <style>

        :root {

            --bg-main: #020817;
            --card-bg: #07162b;
            --input-bg: #050d19;

            --border:
                rgba(59, 130, 246, 0.20);

            --border-soft:
                rgba(148, 163, 184, 0.13);

            --blue: #0d6efd;

            --text-main: #f8fafc;
            --text-muted: #94a3b8;

            --danger-bg:
                rgba(239, 68, 68, 0.18);

            --danger-text:
                #f87171;

            --medium-bg:
                rgba(245, 158, 11, 0.18);

            --medium-text:
                #fbbf24;

            --low-bg:
                rgba(59, 130, 246, 0.13);

            --low-text:
                #93c5fd;

            --info-bg:
                rgba(16, 185, 129, 0.14);

            --info-text:
                #6ee7b7;
        }


        * {
            box-sizing: border-box;
        }


        body {

            margin: 0;

            min-height: 100vh;

            background:
                var(--bg-main);

            color:
                var(--text-main);

            font-family:
                'Inter',
                'Segoe UI',
                sans-serif;

            overflow-x:
                hidden;
        }


        /*
        |--------------------------------------------------------------------------
        | CONTENT
        |--------------------------------------------------------------------------
        */

        .content {

            margin-left: 260px;

            padding: 40px;

            min-height: 100vh;

            background:

                radial-gradient(
                    circle at top left,
                    rgba(37, 99, 235, 0.06),
                    transparent 30%
                ),

                var(--bg-main);
        }


        .history-container {

            width: 100%;
            max-width: 100%;

            margin: 0;
        }


        .page-title {

            font-size: 1.75rem;

            font-weight: 900;

            color: #ffffff;

            margin:
                0 0 8px 0;

            text-transform:
                uppercase;

            letter-spacing:
                0.5px;
        }


        .page-subtitle {

            color:
                var(--text-muted);

            margin:
                0 0 28px 0;

            font-size:
                0.88rem;
        }


        /*
        |--------------------------------------------------------------------------
        | FILTER
        |--------------------------------------------------------------------------
        */

        .filter-card {

            background:
                rgba(7, 22, 43, 0.92);

            border:
                1px solid var(--border);

            border-radius:
                12px;

            padding:
                22px;

            margin-bottom:
                25px;
        }


        .filter-form {

            display:
                grid;

            grid-template-columns:
                1.2fr
                1.2fr
                1.6fr
                0.9fr;

            gap:
                18px;

            align-items:
                end;
        }


        .filter-group label {

            display:
                block;

            color:
                #cbd5e1;

            font-size:
                0.85rem;

            font-weight:
                700;

            margin-bottom:
                9px;
        }


        .filter-group input,
        .filter-group select {

            width:
                100%;

            height:
                42px;

            background:
                var(--input-bg);

            border:
                1px solid
                var(--border-soft);

            color:
                #dbeafe;

            border-radius:
                6px;

            padding:
                0 14px;

            outline:
                none;

            font-size:
                0.9rem;
        }


        .filter-group input::placeholder {

            color:
                #64748b;
        }


        .filter-group input:focus,
        .filter-group select:focus {

            border-color:
                rgba(
                    13,
                    110,
                    253,
                    0.85
                );

            box-shadow:
                0 0 0 3px
                rgba(
                    13,
                    110,
                    253,
                    0.15
                );
        }


        input[type="date"]
        ::-webkit-calendar-picker-indicator {

            filter:
                invert(1);

            opacity:
                0.75;
        }


        .filter-btn {

            height:
                42px;

            width:
                100%;

            background:
                transparent;

            color:
                #93c5fd;

            border:
                1px solid
                rgba(
                    13,
                    110,
                    253,
                    0.75
                );

            border-radius:
                6px;

            font-size:
                0.9rem;

            font-weight:
                800;

            cursor:
                pointer;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            gap:
                9px;

            transition:
                all 0.2s ease;
        }


        .filter-btn:hover {

            background:
                rgba(
                    13,
                    110,
                    253,
                    0.12
                );
        }


        /*
        |--------------------------------------------------------------------------
        | TABLE
        |--------------------------------------------------------------------------
        */

        .table-card {

            background:
                rgba(7, 22, 43, 0.92);

            border:
                1px solid
                var(--border);

            border-radius:
                12px;

            padding:
                24px;

            box-shadow:
                0 12px 28px
                rgba(
                    0,
                    0,
                    0,
                    0.28
                );
        }


        .table-responsive {

            width:
                100%;

            overflow-x:
                auto;
        }


        table {

            width:
                100%;

            border-collapse:
                collapse;

            color:
                #dbeafe;
        }


        thead {

            background:
                rgba(
                    15,
                    32,
                    56,
                    0.85
                );
        }


        th {

            text-align:
                left;

            padding:
                16px 18px;

            color:
                #93a4b8;

            font-size:
                0.78rem;

            font-weight:
                800;

            text-transform:
                uppercase;

            letter-spacing:
                0.5px;

            border-bottom:
                1px solid
                rgba(
                    148,
                    163,
                    184,
                    0.18
                );

            white-space:
                nowrap;
        }


        td {

            padding:
                20px 18px;

            font-size:
                0.9rem;

            color:
                #dbeafe;

            border-bottom:
                1px solid
                rgba(
                    148,
                    163,
                    184,
                    0.08
                );

            vertical-align:
                middle;

            white-space:
                nowrap;
        }


        tbody tr:hover {

            background:
                rgba(
                    59,
                    130,
                    246,
                    0.05
                );
        }


        .scan-id {

            color:
                #cbd5e1;

            font-weight:
                800;
        }


        .project-name {

            color:
                #ffffff;

            font-weight:
                700;
        }


        .language-badge {

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            padding:
                4px 10px;

            border-radius:
                14px;

            border:
                1px solid
                rgba(
                    148,
                    163,
                    184,
                    0.22
                );

            color:
                #cbd5e1;

            background:
                rgba(
                    148,
                    163,
                    184,
                    0.06
                );

            font-size:
                0.75rem;

            font-weight:
                800;
        }


        .files-count {

            font-weight:
                700;

            color:
                #dbeafe;
        }


        .issues-total {

            color:
                #ffffff;

            font-weight:
                900;

            margin-bottom:
                8px;
        }


        .issue-badge {

            font-size:
                0.75rem;

            font-weight:
                800;

            padding:
                5px 8px;

            border-radius:
                5px;

            margin-right:
                4px;

            display:
                inline-block;
        }


        .bg-high {

            background:
                var(--danger-bg);

            color:
                var(--danger-text);
        }


        .bg-medium {

            background:
                var(--medium-bg);

            color:
                var(--medium-text);
        }


        .bg-low {

            background:
                var(--low-bg);

            color:
                var(--low-text);
        }


        .bg-info {

            background:
                var(--info-bg);

            color:
                var(--info-text);
        }


        /*
        |--------------------------------------------------------------------------
        | VIEW REPORT BUTTON
        |--------------------------------------------------------------------------
        */

        .btn-view-report {

            background:
                #0d6efd;

            color:
                #ffffff;

            border-radius:
                6px;

            font-weight:
                800;

            font-size:
                0.82rem;

            padding:
                10px 18px;

            text-decoration:
                none;

            transition:
                all 0.2s ease;

            border:
                none;

            display:
                inline-flex;

            align-items:
                center;

            gap:
                9px;
        }


        .btn-view-report:hover {

            background:
                #0b5ed7;

            color:
                #ffffff;

            transform:
                translateY(-1px);
        }


        .empty-row {

            text-align:
                center;

            padding:
                40px;

            color:
                var(--text-muted);
        }


        /*
        |--------------------------------------------------------------------------
        | RESPONSIVE
        |--------------------------------------------------------------------------
        */

        @media (max-width: 1100px) {

            .filter-form {

                grid-template-columns:
                    1fr 1fr;
            }
        }


        @media (max-width: 992px) {

            .content {

                margin-left:
                    0;

                padding:
                    22px;
            }
        }


        @media (max-width: 576px) {

            .filter-form {

                grid-template-columns:
                    1fr;
            }


            .page-title {

                font-size:
                    1.3rem;
            }
        }

    </style>

</head>


<body>


<?php

include '../Sidebar/sidebaruser.php';

?>


<main class="content">

    <div class="history-container">


        <h2 class="page-title">
            Scan History & Reports
        </h2>


        <p class="page-subtitle">

            Your personal SecureLog scan history.

        </p>


        <!-- ================================================================
             FILTERS
        ================================================================= -->

        <div class="filter-card">

            <form
                method="GET"
                class="filter-form"
            >


                <!-- DATE -->

                <div class="filter-group">

                    <label>
                        Filter By Date:
                    </label>

                    <input
                        type="date"
                        name="start_date"
                        value="<?=
                            htmlspecialchars(
                                $start_date,
                                ENT_QUOTES,
                                'UTF-8'
                            );
                        ?>"
                    >

                </div>


                <!-- LANGUAGE -->

                <div class="filter-group">

                    <label>
                        Programming Language:
                    </label>

                    <select name="language">

                        <option value="">
                            All Languages
                        </option>


                        <option
                            value="php"
                            <?= $language === 'php'
                                ? 'selected'
                                : ''; ?>
                        >
                            PHP
                        </option>


                        <option
                            value="java"
                            <?= $language === 'java'
                                ? 'selected'
                                : ''; ?>
                        >
                            Java
                        </option>


                        <option
                            value="javascript"
                            <?= $language === 'javascript'
                                ? 'selected'
                                : ''; ?>
                        >
                            JavaScript
                        </option>


                        <option
                            value="c"
                            <?= $language === 'c'
                                ? 'selected'
                                : ''; ?>
                        >
                            C
                        </option>

                    </select>

                </div>


                <!-- SEARCH -->

                <div class="filter-group">

                    <label>
                        Search Scan / Project Name:
                    </label>

                    <input
                        type="text"
                        name="search"
                        placeholder="Enter Scan ID or project name..."
                        value="<?=
                            htmlspecialchars(
                                $search,
                                ENT_QUOTES,
                                'UTF-8'
                            );
                        ?>"
                    >

                </div>


                <!-- FILTER BUTTON -->

                <div class="filter-group">

                    <button
                        type="submit"
                        class="filter-btn"
                    >

                        <i class="fas fa-filter"></i>

                        Filter

                    </button>

                </div>


            </form>

        </div>


        <!-- ================================================================
             HISTORY TABLE
        ================================================================= -->

        <div class="table-card">

            <div class="table-responsive">

                <table>


                    <thead>

                        <tr>

                            <th>
                                Scan ID
                            </th>

                            <th>
                                Project Name
                            </th>

                            <th>
                                Scan Date
                            </th>

                            <th>
                                Language
                            </th>

                            <th>
                                Total Files
                            </th>

                            <th>
                                Findings
                            </th>

                            <th>
                                Action
                            </th>

                        </tr>

                    </thead>


                    <tbody>


                    <?php if (
                        $history &&
                        $history->num_rows > 0
                    ): ?>


                        <?php while (
                            $row =
                                $history->fetch_assoc()
                        ): ?>


                            <?php

                            /*
                            |--------------------------------------------------------------------------
                            | REAL DATABASE VALUES
                            |--------------------------------------------------------------------------
                            */

                            $scanId =
                                (int) $row['ScanID'];

                            $projectName =
                                $row['ProjectName']
                                ?? '-';

                            $languageDisplay =
                                strtoupper(
                                    $row[
                                        'ProgrammingLanguage'
                                    ]
                                    ?? '-'
                                );

                            if (
                                strtolower(
                                    $row[
                                        'ProgrammingLanguage'
                                    ]
                                    ?? ''
                                ) === 'javascript'
                            ) {
                                $languageDisplay =
                                    'JavaScript';
                            }


                            $totalFiles =
                                (int) (
                                    $row['total_files']
                                    ?? 0
                                );


                            $high =
                                (int) (
                                    $row['high_issues']
                                    ?? 0
                                );

                            $medium =
                                (int) (
                                    $row['medium_issues']
                                    ?? 0
                                );

                            $low =
                                (int) (
                                    $row['low_issues']
                                    ?? 0
                                );

                            $info =
                                (int) (
                                    $row['info_issues']
                                    ?? 0
                                );

                            $totalIssues =
                                (int) (
                                    $row['total_issues']
                                    ?? 0
                                );


                            $scanDate = '-';

                            if (
                                !empty(
                                    $row['ScanDate']
                                )
                            ) {

                                $timestamp =
                                    strtotime(
                                        $row['ScanDate']
                                    );

                                if ($timestamp !== false) {

                                    $scanDate =
                                        date(
                                            'M d, Y, h:i A',
                                            $timestamp
                                        );
                                }
                            }

                            ?>


                            <tr>


                                <!-- SCAN ID -->

                                <td class="scan-id">

                                    #<?= $scanId; ?>

                                </td>


                                <!-- PROJECT -->

                                <td class="project-name">

                                    <?=
                                        htmlspecialchars(
                                            $projectName,
                                            ENT_QUOTES,
                                            'UTF-8'
                                        );
                                    ?>

                                </td>


                                <!-- DATE -->

                                <td>

                                    <?=
                                        htmlspecialchars(
                                            $scanDate,
                                            ENT_QUOTES,
                                            'UTF-8'
                                        );
                                    ?>

                                </td>


                                <!-- LANGUAGE -->

                                <td>

                                    <span
                                        class="language-badge"
                                    >

                                        <?=
                                            htmlspecialchars(
                                                $languageDisplay,
                                                ENT_QUOTES,
                                                'UTF-8'
                                            );
                                        ?>

                                    </span>

                                </td>


                                <!-- FILE COUNT -->

                                <td
                                    class="files-count"
                                >

                                    <?= $totalFiles; ?>

                                </td>


                                <!-- FINDINGS -->

                                <td>

                                    <div
                                        class="issues-total"
                                    >

                                        <?= $totalIssues; ?>
                                        Finding<?= $totalIssues !== 1 ? 's' : ''; ?>

                                    </div>


                                    <div>

                                        <?php if ($high > 0): ?>

                                            <span
                                                class="issue-badge bg-high"
                                            >
                                                <?= $high; ?> H
                                            </span>

                                        <?php endif; ?>


                                        <?php if ($medium > 0): ?>

                                            <span
                                                class="issue-badge bg-medium"
                                            >
                                                <?= $medium; ?> M
                                            </span>

                                        <?php endif; ?>


                                        <?php if ($low > 0): ?>

                                            <span
                                                class="issue-badge bg-low"
                                            >
                                                <?= $low; ?> L
                                            </span>

                                        <?php endif; ?>


                                        <?php if ($info > 0): ?>

                                            <span
                                                class="issue-badge bg-info"
                                            >
                                                <?= $info; ?> I
                                            </span>

                                        <?php endif; ?>


                                        <?php if (
                                            $totalIssues === 0
                                        ): ?>

                                            <span
                                                class="issue-badge bg-info"
                                            >
                                                No findings
                                            </span>

                                        <?php endif; ?>

                                    </div>

                                </td>


                                <!-- REPORT -->

                                <td>

                                    <a
                                        href="../Engine_Process/Download_report.php?scan_id=<?= $scanId; ?>"
                                        class="btn-view-report"
                                    >

                                        View Report

                                        <i
                                            class="fa-solid fa-arrow-right"
                                        ></i>

                                    </a>

                                </td>


                            </tr>


                        <?php endwhile; ?>


                    <?php else: ?>


                        <tr>

                            <td
                                colspan="7"
                                class="empty-row"
                            >

                                <i
                                    class="fa-solid fa-clock-rotate-left"
                                ></i>

                                No scan history found
                                for your account.

                            </td>

                        </tr>


                    <?php endif; ?>


                    </tbody>


                </table>

            </div>

        </div>


    </div>

</main>


</body>

</html>

<?php

$stmt->close();

?>