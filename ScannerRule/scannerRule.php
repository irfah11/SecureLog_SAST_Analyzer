<?php
/**
 * SecureLog - Manage Scanner Rules
 * File: ScannerRule/scannerRule.php
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
   SESSION
   ============================================================ */

$currentAdminId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

/* ============================================================
   CSRF TOKEN
   ============================================================ */

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(
        random_bytes(32)
    );
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

function scannerRuleUrl(
    array $parameters = []
): string {
    if (empty($parameters)) {
        return 'scannerRule.php';
    }

    return 'scannerRule.php?'
        . http_build_query($parameters);
}

/* ============================================================
   FILTER VALUES
   ============================================================ */

$search = trim(
    $_GET['search'] ?? ''
);

$language = strtoupper(
    trim($_GET['language'] ?? '')
);

$detectionType = strtoupper(
    trim($_GET['detection_type'] ?? '')
);

$severity = strtoupper(
    trim($_GET['severity'] ?? '')
);

$status = strtoupper(
    trim($_GET['status'] ?? '')
);

/* ============================================================
   VALID FILTERS
   ============================================================ */

$validLanguages = [
    'PHP',
    'JAVA',
    'JAVASCRIPT',
    'C'
];

$validDetectionTypes = [
    'LOGGING',
    'TXT_FORMAT',
    'ENCRYPTION'
];

$validSeverities = [
    'HIGH',
    'MEDIUM',
    'LOW',
    'INFO'
];

$validStatuses = [
    'DRAFT',
    'ACTIVE',
    'DISABLED'
];

if (
    $language !== ''
    && !in_array(
        $language,
        $validLanguages,
        true
    )
) {
    $language = '';
}

if (
    $detectionType !== ''
    && !in_array(
        $detectionType,
        $validDetectionTypes,
        true
    )
) {
    $detectionType = '';
}

if (
    $severity !== ''
    && !in_array(
        $severity,
        $validSeverities,
        true
    )
) {
    $severity = '';
}

if (
    $status !== ''
    && !in_array(
        $status,
        $validStatuses,
        true
    )
) {
    $status = '';
}

/* ============================================================
   SUMMARY COUNTS
   ============================================================ */

$totalRules = 0;
$activeRules = 0;
$draftRules = 0;
$disabledRules = 0;

$summarySql = "
    SELECT
        COUNT(*) AS TotalRules,

        SUM(
            CASE
                WHEN Status = 'ACTIVE'
                THEN 1
                ELSE 0
            END
        ) AS ActiveRules,

        SUM(
            CASE
                WHEN Status = 'DRAFT'
                THEN 1
                ELSE 0
            END
        ) AS DraftRules,

        SUM(
            CASE
                WHEN Status = 'DISABLED'
                THEN 1
                ELSE 0
            END
        ) AS DisabledRules

    FROM scanner_rules
";

$summaryResult = $conn->query(
    $summarySql
);

if ($summaryResult) {

    $summaryRow =
        $summaryResult->fetch_assoc();

    $totalRules =
        (int) (
            $summaryRow['TotalRules']
            ?? 0
        );

    $activeRules =
        (int) (
            $summaryRow['ActiveRules']
            ?? 0
        );

    $draftRules =
        (int) (
            $summaryRow['DraftRules']
            ?? 0
        );

    $disabledRules =
        (int) (
            $summaryRow['DisabledRules']
            ?? 0
        );
}

/* ============================================================
   BUILD RULE QUERY
   ============================================================ */

$sql = "
    SELECT
        RuleID,
        RuleCode,
        RuleName,
        Language,
        DetectionType,
        CWEID,
        OWASPCategory,
        Severity,
        Status,
        Description,
        Pattern,
        Recommendation,
        CreatedBy,
        CreatedAt,
        UpdatedAt

    FROM scanner_rules
";

$where = [];
$parameters = [];
$types = '';

/* Search */
if ($search !== '') {

    $where[] = "
        (
            RuleCode LIKE ?
            OR RuleName LIKE ?
            OR Description LIKE ?
            OR CWEID LIKE ?
        )
    ";

    $searchValue =
        '%' . $search . '%';

    $parameters[] = $searchValue;
    $parameters[] = $searchValue;
    $parameters[] = $searchValue;
    $parameters[] = $searchValue;

    $types .= 'ssss';
}

/* Language */
if ($language !== '') {

    $where[] =
        'Language = ?';

    $parameters[] =
        $language;

    $types .= 's';
}

/* Detection type */
if ($detectionType !== '') {

    $where[] =
        'DetectionType = ?';

    $parameters[] =
        $detectionType;

    $types .= 's';
}

/* Severity */
if ($severity !== '') {

    $where[] =
        'Severity = ?';

    $parameters[] =
        $severity;

    $types .= 's';
}

/* Status */
if ($status !== '') {

    $where[] =
        'Status = ?';

    $parameters[] =
        $status;

    $types .= 's';
}

/* Add WHERE */
if (!empty($where)) {

    $sql .= "
        WHERE "
        . implode(
            ' AND ',
            $where
        );
}

/* Sorting */
$sql .= "
    ORDER BY
        CASE Status
            WHEN 'DRAFT' THEN 1
            WHEN 'ACTIVE' THEN 2
            WHEN 'DISABLED' THEN 3
            ELSE 4
        END,
        RuleID DESC
";

/* ============================================================
   EXECUTE RULE QUERY
   ============================================================ */

$rules = [];

$statement =
    $conn->prepare($sql);

if (!$statement) {

    die(
        'Unable to prepare scanner rule query.'
    );
}

if (!empty($parameters)) {

    $statement->bind_param(
        $types,
        ...$parameters
    );
}

$statement->execute();

$result =
    $statement->get_result();

while (
    $row =
        $result->fetch_assoc()
) {
    $rules[] = $row;
}

$statement->close();

/* ============================================================
   FLASH MESSAGE
   ============================================================ */

$messageType =
    $_GET['type'] ?? '';

$messageText =
    $_GET['message'] ?? '';

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
        Manage Scanner Rules | SecureLog
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

            --yellow: #fbbf24;

            --red: #ff4355;

            --purple: #a78bfa;

            --text: #f8fafc;

            --muted: #9eacb9;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;

            background: var(--bg);

            color: var(--text);

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

            padding: 14px 18px;

            background:
                radial-gradient(
                    circle at 75% 5%,
                    rgba(56, 189, 248, 0.045),
                    transparent 32%
                ),
                var(--bg);
        }

        .scanner-rule-container {

            width: 100%;

            max-width: 1580px;

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
                1px solid var(--border);

            border-radius: 14px;
        }

        /* =====================================================
           HEADER
           ===================================================== */

        .page-header {

            margin-bottom: 28px;

            display: flex;

            justify-content:
                space-between;

            align-items:
                flex-start;

            gap: 20px;
        }

        .page-title h1 {

            margin: 0 0 9px;

            font-size: 27px;

            font-weight: 800;

            text-transform:
                uppercase;
        }

        .page-title p {

            margin: 0;

            max-width: 700px;

            color: #bdc8d3;

            font-size: 13px;

            line-height: 1.7;
        }

        .header-actions {

            display: flex;

            align-items: center;

            gap: 12px;
        }

        .add-button {

            min-height: 44px;

            padding: 0 18px;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            gap: 9px;

            color: #fff;

            background:
                linear-gradient(
                    90deg,
                    var(--orange),
                    var(--orange-light)
                );

            border-radius: 7px;

            text-decoration: none;

            font-size: 13px;

            font-weight: 700;
        }

        .add-button:hover {

            filter:
                brightness(1.08);
        }

        /* =====================================================
           BREADCRUMB
           ===================================================== */

        .breadcrumb {

            margin-bottom: 24px;

            display: flex;

            align-items: center;

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

            padding: 14px 17px;

            border-radius: 8px;

            font-size: 13px;
        }

        .message.success {

            color: #5ef0b9;

            background:
                rgba(
                    0,
                    217,
                    149,
                    0.09
                );

            border:
                1px solid
                rgba(
                    0,
                    217,
                    149,
                    0.30
                );
        }

        .message.error {

            color: #ff8c97;

            background:
                rgba(
                    255,
                    67,
                    85,
                    0.09
                );

            border:
                1px solid
                rgba(
                    255,
                    67,
                    85,
                    0.30
                );
        }

        .message.warning {

            color: #fbd56d;

            background:
                rgba(
                    251,
                    191,
                    36,
                    0.08
                );

            border:
                1px solid
                rgba(
                    251,
                    191,
                    36,
                    0.28
                );
        }

        /* =====================================================
           SUMMARY CARDS
           ===================================================== */

        .summary-grid {

            margin-bottom: 25px;

            display: grid;

            grid-template-columns:
                repeat(
                    4,
                    minmax(0, 1fr)
                );

            gap: 15px;
        }

        .summary-card {

            padding: 19px 20px;

            background:
                linear-gradient(
                    145deg,
                    rgba(
                        8,
                        29,
                        49,
                        0.96
                    ),
                    rgba(
                        4,
                        18,
                        31,
                        0.96
                    )
                );

            border:
                1px solid
                var(--border);

            border-radius: 10px;
        }

        .summary-label {

            margin-bottom: 8px;

            color: var(--muted);

            font-size: 11px;

            font-weight: 700;

            text-transform:
                uppercase;

            letter-spacing:
                0.7px;
        }

        .summary-value {

            display: flex;

            align-items: center;

            justify-content:
                space-between;

            gap: 15px;

            font-size: 26px;

            font-weight: 800;
        }

        .summary-icon {

            font-size: 20px;
        }

        .icon-total {
            color: var(--blue);
        }

        .icon-active {
            color: var(--green);
        }

        .icon-draft {
            color: var(--yellow);
        }

        .icon-disabled {
            color: var(--red);
        }

        /* =====================================================
           FILTERS
           ===================================================== */

        .filter-panel {

            margin-bottom: 22px;

            padding: 19px;

            background:
                rgba(
                    5,
                    22,
                    37,
                    0.85
                );

            border:
                1px solid
                var(--border);

            border-radius: 10px;
        }

        .filter-grid {

            display: grid;

            grid-template-columns:
                minmax(230px, 1.5fr)
                repeat(
                    4,
                    minmax(130px, 0.7fr)
                )
                auto;

            gap: 10px;
        }

        .filter-control {

            width: 100%;

            height: 43px;

            padding: 0 13px;

            color: #fff;

            background:
                var(--input);

            border:
                1px solid
                var(--border);

            border-radius: 6px;

            outline: none;

            font-family: inherit;

            font-size: 12px;
        }

        .filter-control:focus {

            border-color:
                var(--orange);

            box-shadow:
                0 0 0 3px
                rgba(
                    255,
                    101,
                    0,
                    0.08
                );
        }

        .filter-control option {

            color: #fff;

            background:
                #071521;
        }

        .filter-button {

            height: 43px;

            padding: 0 17px;

            display:
                inline-flex;

            align-items: center;

            justify-content: center;

            gap: 7px;

            color: #fff;

            background:
                #11283a;

            border:
                1px solid
                var(--border);

            border-radius: 6px;

            cursor: pointer;

            font-family: inherit;

            font-weight: 600;
        }

        .filter-button:hover {

            border-color:
                var(--orange);
        }

        .reset-row {

            margin-top: 12px;

            display: flex;

            justify-content:
                flex-end;
        }

        .reset-link {

            color: var(--muted);

            font-size: 12px;

            text-decoration: none;
        }

        .reset-link:hover {

            color: var(--orange);
        }

        /* =====================================================
           TABLE PANEL
           ===================================================== */

        .table-panel {

            overflow: hidden;

            background:
                rgba(
                    4,
                    18,
                    31,
                    0.86
                );

            border:
                1px solid
                var(--border);

            border-radius: 11px;
        }

        .table-header {

            padding: 18px 20px;

            display: flex;

            align-items: center;

            justify-content:
                space-between;

            gap: 20px;

            border-bottom:
                1px solid
                var(--border);
        }

        .table-header h2 {

            margin: 0;

            color: var(--orange);

            font-size: 16px;

            font-weight: 800;

            text-transform:
                uppercase;
        }

        .result-count {

            color: var(--muted);

            font-size: 12px;
        }

        .table-responsive {

            width: 100%;

            overflow-x: auto;
        }

        table {

            width: 100%;

            min-width: 1100px;

            border-collapse:
                collapse;
        }

        th {

            padding:
                14px
                13px;

            color: #aebdca;

            background:
                rgba(
                    8,
                    29,
                    49,
                    0.72
                );

            border-bottom:
                1px solid
                var(--border);

            text-align: left;

            font-size: 10px;

            font-weight: 800;

            letter-spacing:
                0.6px;

            text-transform:
                uppercase;
        }

        td {

            padding:
                16px
                13px;

            color: #dce5ec;

            border-bottom:
                1px solid
                rgba(
                    24,
                    50,
                    71,
                    0.62
                );

            vertical-align: middle;

            font-size: 12px;
        }

        tbody tr:hover {

            background:
                rgba(
                    56,
                    189,
                    248,
                    0.025
                );
        }

        tbody tr:last-child td {

            border-bottom: none;
        }

        /* =====================================================
           RULE INFO
           ===================================================== */

        .rule-code {

            display: inline-block;

            color: var(--orange);

            font-family:
                Consolas,
                Monaco,
                monospace;

            font-weight: 700;
        }

        .rule-name {

            max-width: 250px;

            color: #fff;

            font-weight: 700;

            line-height: 1.4;
        }

        .rule-meta {

            margin-top: 4px;

            color: #8192a2;

            font-size: 10px;
        }

        /* =====================================================
           BADGES
           ===================================================== */

        .badge {

            padding:
                5px
                9px;

            display:
                inline-flex;

            align-items: center;

            justify-content:
                center;

            border-radius: 5px;

            font-size: 9px;

            font-weight: 800;

            letter-spacing:
                0.4px;
        }

        .language-badge {

            color: #9edfff;

            background:
                rgba(
                    56,
                    189,
                    248,
                    0.09
                );

            border:
                1px solid
                rgba(
                    56,
                    189,
                    248,
                    0.25
                );
        }

        .type-badge {

            color: #ccbaff;

            background:
                rgba(
                    167,
                    139,
                    250,
                    0.09
                );

            border:
                1px solid
                rgba(
                    167,
                    139,
                    250,
                    0.26
                );
        }

        .severity-high {

            color: #ff7d89;

            background:
                rgba(
                    255,
                    67,
                    85,
                    0.10
                );
        }

        .severity-medium {

            color: #fbd56d;

            background:
                rgba(
                    251,
                    191,
                    36,
                    0.10
                );
        }

        .severity-low {

            color: #75cfff;

            background:
                rgba(
                    56,
                    189,
                    248,
                    0.10
                );
        }

        .severity-info {

            color: #b3c0cb;

            background:
                rgba(
                    148,
                    163,
                    184,
                    0.10
                );
        }

        .status-active {

            color: #5ef0b9;

            background:
                rgba(
                    0,
                    217,
                    149,
                    0.10
                );

            border:
                1px solid
                rgba(
                    0,
                    217,
                    149,
                    0.26
                );
        }

        .status-draft {

            color: #fbd56d;

            background:
                rgba(
                    251,
                    191,
                    36,
                    0.10
                );

            border:
                1px solid
                rgba(
                    251,
                    191,
                    36,
                    0.26
                );
        }

        .status-disabled {

            color: #ff8c97;

            background:
                rgba(
                    255,
                    67,
                    85,
                    0.10
                );

            border:
                1px solid
                rgba(
                    255,
                    67,
                    85,
                    0.26
                );
        }

        /* =====================================================
           ACTIONS
           ===================================================== */

        .actions {

            display: flex;

            align-items: center;

            flex-wrap: wrap;

            gap: 7px;
        }

        .action-button {

            min-height: 32px;

            padding: 0 10px;

            display:
                inline-flex;

            align-items: center;

            justify-content:
                center;

            gap: 6px;

            color: #dce5ec;

            background:
                #0b1c2b;

            border:
                1px solid
                var(--border);

            border-radius: 5px;

            text-decoration: none;

            font-family: inherit;

            font-size: 10px;

            font-weight: 700;

            cursor: pointer;
        }

        .action-button:hover {

            border-color:
                var(--orange);

            color: #fff;
        }

        .action-edit {

            color: #9edfff;
        }

        .action-test {

            color: #ccbaff;
        }

        .action-activate {

            color: #5ef0b9;
        }

        .action-disable {

            color: #ff8c97;
        }

        .inline-form {

            margin: 0;

            display: inline;
        }

        /* =====================================================
           EMPTY STATE
           ===================================================== */

        .empty-state {

            padding:
                65px
                20px;

            text-align: center;
        }

        .empty-icon {

            margin-bottom: 17px;

            color:
                var(--orange);

            font-size: 39px;
        }

        .empty-state h3 {

            margin:
                0
                0
                8px;

            color: #fff;

            font-size: 17px;
        }

        .empty-state p {

            margin:
                0 auto
                20px;

            max-width: 430px;

            color: var(--muted);

            font-size: 12px;

            line-height: 1.6;
        }

        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (
            max-width: 1200px
        ) {

            .filter-grid {

                grid-template-columns:
                    repeat(
                        3,
                        minmax(0, 1fr)
                    );
            }
        }

        @media (
            max-width: 850px
        ) {

            .summary-grid {

                grid-template-columns:
                    repeat(
                        2,
                        minmax(0, 1fr)
                    );
            }

            .page-header {

                flex-direction:
                    column;
            }

            .filter-grid {

                grid-template-columns:
                    repeat(
                        2,
                        minmax(0, 1fr)
                    );
            }
        }

        @media (
            max-width: 550px
        ) {

            .scanner-rule-page {

                padding: 8px;
            }

            .scanner-rule-container {

                padding:
                    20px
                    13px
                    25px;
            }

            .summary-grid {

                grid-template-columns:
                    1fr;
            }

            .filter-grid {

                grid-template-columns:
                    1fr;
            }

            .add-button {

                width: 100%;
            }

            .header-actions {

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

    <div
        class="
            scanner-rule-container
        "
    >

        <!-- ===================================================
             HEADER
             =================================================== -->

        <header class="page-header">

            <div class="page-title">

                <h1>
                    Manage Scanner Rules
                </h1>

                <p>
                    Manage detection rules used by
                    SecureLog to identify logging,
                    log-format and encryption-related
                    security conditions in source code.
                </p>

            </div>

            <div class="header-actions">

                <a
                    href="addRule.php"
                    class="add-button"
                >

                    <i
                        class="
                            fa-solid
                            fa-plus
                        "
                    ></i>

                    Add New Rule

                </a>

            </div>

        </header>

        <!-- ===================================================
             BREADCRUMB
             =================================================== -->

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

            <span
                class="
                    breadcrumb-current
                "
            >
                Scanner Rules
            </span>

        </nav>

        <!-- ===================================================
             FLASH MESSAGE
             =================================================== -->

        <?php if (
            $messageType !== ''
            && $messageText !== ''
        ): ?>

            <div
                class="
                    message
                    <?= e($messageType); ?>
                "
            >

                <?php if (
                    $messageType ===
                    'success'
                ): ?>

                    <i
                        class="
                            fa-solid
                            fa-circle-check
                        "
                    ></i>

                <?php elseif (
                    $messageType ===
                    'warning'
                ): ?>

                    <i
                        class="
                            fa-solid
                            fa-triangle-exclamation
                        "
                    ></i>

                <?php else: ?>

                    <i
                        class="
                            fa-solid
                            fa-circle-exclamation
                        "
                    ></i>

                <?php endif; ?>

                <?= e($messageText); ?>

            </div>

        <?php endif; ?>

        <!-- ===================================================
             SUMMARY
             =================================================== -->

        <section class="summary-grid">

            <article class="summary-card">

                <div class="summary-label">
                    Total Rules
                </div>

                <div class="summary-value">

                    <?= $totalRules; ?>

                    <i
                        class="
                            fa-solid
                            fa-shield-halved
                            summary-icon
                            icon-total
                        "
                    ></i>

                </div>

            </article>

            <article class="summary-card">

                <div class="summary-label">
                    Active
                </div>

                <div class="summary-value">

                    <?= $activeRules; ?>

                    <i
                        class="
                            fa-solid
                            fa-circle-check
                            summary-icon
                            icon-active
                        "
                    ></i>

                </div>

            </article>

            <article class="summary-card">

                <div class="summary-label">
                    Draft
                </div>

                <div class="summary-value">

                    <?= $draftRules; ?>

                    <i
                        class="
                            fa-solid
                            fa-pen-ruler
                            summary-icon
                            icon-draft
                        "
                    ></i>

                </div>

            </article>

            <article class="summary-card">

                <div class="summary-label">
                    Disabled
                </div>

                <div class="summary-value">

                    <?= $disabledRules; ?>

                    <i
                        class="
                            fa-solid
                            fa-ban
                            summary-icon
                            icon-disabled
                        "
                    ></i>

                </div>

            </article>

        </section>

        <!-- ===================================================
             FILTERS
             =================================================== -->

        <section class="filter-panel">

            <form
                method="GET"
                action="scannerRule.php"
            >

                <div class="filter-grid">

                    <input
                        type="text"
                        name="search"
                        class="filter-control"
                        placeholder="Search rule code, name, CWE..."
                        value="<?= e($search); ?>"
                    >

                    <select
                        name="language"
                        class="filter-control"
                    >

                        <option value="">
                            All Languages
                        </option>

                        <?php foreach (
                            $validLanguages
                            as $option
                        ): ?>

                            <option
                                value="<?= e($option); ?>"
                                <?= $language === $option
                                    ? 'selected'
                                    : ''; ?>
                            >
                                <?= e(
                                    $option === 'JAVASCRIPT'
                                        ? 'JavaScript'
                                        : (
                                            $option === 'JAVA'
                                                ? 'Java'
                                                : $option
                                        )
                                ); ?>
                            </option>

                        <?php endforeach; ?>

                    </select>

                    <select
                        name="detection_type"
                        class="filter-control"
                    >

                        <option value="">
                            All Detection Types
                        </option>

                        <option
                            value="LOGGING"
                            <?= $detectionType ===
                                'LOGGING'
                                ? 'selected'
                                : ''; ?>
                        >
                            Logging
                        </option>

                        <option
                            value="TXT_FORMAT"
                            <?= $detectionType ===
                                'TXT_FORMAT'
                                ? 'selected'
                                : ''; ?>
                        >
                            TXT Format
                        </option>

                        <option
                            value="ENCRYPTION"
                            <?= $detectionType ===
                                'ENCRYPTION'
                                ? 'selected'
                                : ''; ?>
                        >
                            Encryption
                        </option>

                    </select>

                    <select
                        name="severity"
                        class="filter-control"
                    >

                        <option value="">
                            All Severities
                        </option>

                        <?php foreach (
                            $validSeverities
                            as $option
                        ): ?>

                            <option
                                value="<?= e($option); ?>"
                                <?= $severity === $option
                                    ? 'selected'
                                    : ''; ?>
                            >
                                <?= e(
                                    ucfirst(
                                        strtolower(
                                            $option
                                        )
                                    )
                                ); ?>
                            </option>

                        <?php endforeach; ?>

                    </select>

                    <select
                        name="status"
                        class="filter-control"
                    >

                        <option value="">
                            All Statuses
                        </option>

                        <?php foreach (
                            $validStatuses
                            as $option
                        ): ?>

                            <option
                                value="<?= e($option); ?>"
                                <?= $status === $option
                                    ? 'selected'
                                    : ''; ?>
                            >
                                <?= e(
                                    ucfirst(
                                        strtolower(
                                            $option
                                        )
                                    )
                                ); ?>
                            </option>

                        <?php endforeach; ?>

                    </select>

                    <button
                        type="submit"
                        class="filter-button"
                    >

                        <i
                            class="
                                fa-solid
                                fa-filter
                            "
                        ></i>

                        Filter

                    </button>

                </div>

                <?php if (
                    $search !== ''
                    || $language !== ''
                    || $detectionType !== ''
                    || $severity !== ''
                    || $status !== ''
                ): ?>

                    <div class="reset-row">

                        <a
                            href="scannerRule.php"
                            class="reset-link"
                        >

                            <i
                                class="
                                    fa-solid
                                    fa-rotate-left
                                "
                            ></i>

                            Reset Filters

                        </a>

                    </div>

                <?php endif; ?>

            </form>

        </section>

        <!-- ===================================================
             RULE TABLE
             =================================================== -->

        <section class="table-panel">

            <div class="table-header">

                <h2>
                    Scanner Rule Registry
                </h2>

                <div class="result-count">

                    <?= count($rules); ?>

                    rule<?= count($rules) === 1
                        ? ''
                        : 's'; ?>

                    displayed

                </div>

            </div>

            <?php if (
                empty($rules)
            ): ?>

                <div class="empty-state">

                    <div class="empty-icon">

                        <i
                            class="
                                fa-solid
                                fa-shield-halved
                            "
                        ></i>

                    </div>

                    <h3>
                        No scanner rules found
                    </h3>

                    <p>

                        No rules currently match
                        your search and filter
                        criteria. Create a scanner
                        rule to begin building the
                        SecureLog rule registry.

                    </p>

                    <?php if (
                        $totalRules === 0
                    ): ?>

                        <a
                            href="addRule.php"
                            class="add-button"
                        >

                            <i
                                class="
                                    fa-solid
                                    fa-plus
                                "
                            ></i>

                            Create First Rule

                        </a>

                    <?php else: ?>

                        <a
                            href="scannerRule.php"
                            class="add-button"
                        >

                            Clear Filters

                        </a>

                    <?php endif; ?>

                </div>

            <?php else: ?>

                <div class="table-responsive">

                    <table>

                        <thead>

                        <tr>

                            <th>
                                Rule
                            </th>

                            <th>
                                Language
                            </th>

                            <th>
                                Detection Type
                            </th>

                            <th>
                                Severity
                            </th>

                            <th>
                                Status
                            </th>

                            <th>
                                Updated
                            </th>

                            <th>
                                Actions
                            </th>

                        </tr>

                        </thead>

                        <tbody>

                        <?php foreach (
                            $rules
                            as $rule
                        ): ?>

                            <?php

                            $ruleId =
                                (int) $rule[
                                    'RuleID'
                                ];

                            $ruleStatus =
                                strtoupper(
                                    (string) $rule[
                                        'Status'
                                    ]
                                );

                            $ruleSeverity =
                                strtoupper(
                                    (string) $rule[
                                        'Severity'
                                    ]
                                );

                            $updatedAt =
                                $rule[
                                    'UpdatedAt'
                                ]
                                ?: $rule[
                                    'CreatedAt'
                                ];

                            ?>

                            <tr>

                                <!-- Rule -->

                                <td>

                                    <span
                                        class="
                                            rule-code
                                        "
                                    >
                                        <?= e(
                                            $rule[
                                                'RuleCode'
                                            ]
                                        ); ?>
                                    </span>

                                    <div
                                        class="
                                            rule-name
                                        "
                                    >
                                        <?= e(
                                            $rule[
                                                'RuleName'
                                            ]
                                        ); ?>
                                    </div>

                                    <?php if (
                                        !empty(
                                            $rule[
                                                'CWEID'
                                            ]
                                        )
                                    ): ?>

                                        <div
                                            class="
                                                rule-meta
                                            "
                                        >
                                            <?= e(
                                                $rule[
                                                    'CWEID'
                                                ]
                                            ); ?>
                                        </div>

                                    <?php endif; ?>

                                </td>

                                <!-- Language -->

                                <td>

                                    <span
                                        class="
                                            badge
                                            language-badge
                                        "
                                    >
                                        <?= e(
                                            $rule[
                                                'Language'
                                            ] ===
                                            'JAVASCRIPT'
                                                ? 'JavaScript'
                                                : (
                                                    $rule[
                                                        'Language'
                                                    ] ===
                                                    'JAVA'
                                                        ? 'Java'
                                                        : $rule[
                                                            'Language'
                                                        ]
                                                )
                                        ); ?>
                                    </span>

                                </td>

                                <!-- Detection type -->

                                <td>

                                    <span
                                        class="
                                            badge
                                            type-badge
                                        "
                                    >
                                        <?= e(
                                            str_replace(
                                                '_',
                                                ' ',
                                                $rule[
                                                    'DetectionType'
                                                ]
                                            )
                                        ); ?>
                                    </span>

                                </td>

                                <!-- Severity -->

                                <td>

                                    <span
                                        class="
                                            badge
                                            severity-<?= e(
                                                strtolower(
                                                    $ruleSeverity
                                                )
                                            ); ?>
                                        "
                                    >
                                        <?= e(
                                            $ruleSeverity
                                        ); ?>
                                    </span>

                                </td>

                                <!-- Status -->

                                <td>

                                    <span
                                        class="
                                            badge
                                            status-<?= e(
                                                strtolower(
                                                    $ruleStatus
                                                )
                                            ); ?>
                                        "
                                    >
                                        <?= e(
                                            $ruleStatus
                                        ); ?>
                                    </span>

                                </td>

                                <!-- Updated -->

                                <td>

                                    <?php if (
                                        !empty(
                                            $updatedAt
                                        )
                                    ): ?>

                                        <?= e(
                                            date(
                                                'd M Y',
                                                strtotime(
                                                    $updatedAt
                                                )
                                            )
                                        ); ?>

                                        <div
                                            class="
                                                rule-meta
                                            "
                                        >
                                            <?= e(
                                                date(
                                                    'h:i A',
                                                    strtotime(
                                                        $updatedAt
                                                    )
                                                )
                                            ); ?>
                                        </div>

                                    <?php else: ?>

                                        -

                                    <?php endif; ?>

                                </td>

                                <!-- Actions -->

                                <td>

                                    <div class="actions">

                                        <!-- Edit -->

                                        <a
                                            href="editRule.php?rule_id=<?= $ruleId; ?>"
                                            class="
                                                action-button
                                                action-edit
                                            "
                                        >

                                            <i
                                                class="
                                                    fa-solid
                                                    fa-pen
                                                "
                                            ></i>

                                            Edit

                                        </a>

                                        <!-- Test -->

                                        <a
                                            href="testRule.php?rule_id=<?= $ruleId; ?>"
                                            class="
                                                action-button
                                                action-test
                                            "
                                        >

                                            <i
                                                class="
                                                    fa-solid
                                                    fa-flask
                                                "
                                            ></i>

                                            Test

                                        </a>

                                        <!-- Activate -->

                                        <?php if (
                                            $ruleStatus !==
                                            'ACTIVE'
                                        ): ?>

                                            <form
                                                method="POST"
                                                action="ruleAction.php"
                                                class="
                                                    inline-form
                                                "
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
                                                    class="
                                                        action-button
                                                        action-activate
                                                    "
                                                >

                                                    <i
                                                        class="
                                                            fa-solid
                                                            fa-circle-play
                                                        "
                                                    ></i>

                                                    Activate

                                                </button>

                                            </form>

                                        <?php endif; ?>

                                        <!-- Disable -->

                                        <?php if (
                                            $ruleStatus ===
                                            'ACTIVE'
                                        ): ?>

                                            <form
                                                method="POST"
                                                action="ruleAction.php"
                                                class="
                                                    inline-form
                                                "
                                                onsubmit="
                                                    return confirm(
                                                        'Disable this scanner rule?'
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
                                                    value="disable"
                                                >

                                                <button
                                                    type="submit"
                                                    class="
                                                        action-button
                                                        action-disable
                                                    "
                                                >

                                                    <i
                                                        class="
                                                            fa-solid
                                                            fa-circle-pause
                                                        "
                                                    ></i>

                                                    Disable

                                                </button>

                                            </form>

                                        <?php endif; ?>

                                    </div>

                                </td>

                            </tr>

                        <?php endforeach; ?>

                        </tbody>

                    </table>

                </div>

            <?php endif; ?>

        </section>

    </div>

</main>

</body>

</html>