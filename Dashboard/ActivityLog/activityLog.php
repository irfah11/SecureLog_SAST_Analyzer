<?php

/**
 * SecureLog Activity Log
 *
 * File:
 * Dashboard/ActivityLog/activityLog.php
 *
 * Purpose:
 * - Admin-only audit log viewer
 * - Reads structured JSON activity events from ActivityLogger.php
 * - Supports filtering, searching and pagination
 * - Read-only: no delete/edit/clear functionality
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
   ACTIVITY LOGGER
   ============================================================ */

require_once __DIR__ . '/../ActivityLogger.php';


/* ============================================================
   CONFIGURATION
   ============================================================ */

$recordsPerPage = 10;


/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */

/**
 * Escape output for HTML.
 */
function e(mixed $value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}


/**
 * Convert values such as:
 *
 * ScannerRule -> Scanner Rule
 * UserManagement -> User Management
 */
function formatModuleName(?string $module): string
{
    $module = trim((string) $module);

    if ($module === '') {
        return 'Unknown';
    }

    $formatted = preg_replace(
        '/(?<!^)([A-Z])/',
        ' $1',
        $module
    );

    return trim((string) $formatted);
}


/**
 * Convert:
 *
 * RULE_ACTIVATED -> Rule Activated
 * LOGIN_SUCCESS  -> Login Success
 */
function formatEventName(?string $event): string
{
    $event = trim((string) $event);

    if ($event === '') {
        return 'Unknown Event';
    }

    return ucwords(
        strtolower(
            str_replace('_', ' ', $event)
        )
    );
}


/**
 * Format ISO timestamp.
 *
 * Example:
 * 2026-09-23T17:25:43+08:00
 *
 * becomes:
 * 23 Sep 2026, 05:25:43 PM
 */
function formatActivityTimestamp(?string $timestamp): string
{
    $timestamp = trim((string) $timestamp);

    if ($timestamp === '') {
        return '-';
    }

    try {

        $date = new DateTimeImmutable($timestamp);

        return $date->format(
            'd M Y, h:i:s A'
        );

    } catch (Throwable $exception) {

        return $timestamp;
    }
}


/**
 * Return YYYY-MM-DD from event timestamp.
 * Used for date filtering.
 */
function activityDateValue(?string $timestamp): string
{
    $timestamp = trim((string) $timestamp);

    if ($timestamp === '') {
        return '';
    }

    try {

        $date = new DateTimeImmutable($timestamp);

        return $date->format('Y-m-d');

    } catch (Throwable $exception) {

        return '';
    }
}


/**
 * Severity CSS class.
 */
function severityClass(?string $severity): string
{
    return match (
        strtoupper(
            trim((string) $severity)
        )
    ) {

        'INFO' =>
            'severity-info',

        'WARNING' =>
            'severity-warning',

        'ERROR' =>
            'severity-error',

        'CRITICAL' =>
            'severity-critical',

        default =>
            'severity-default'
    };
}


/**
 * Result CSS class.
 */
function resultClass(?string $result): string
{
    return match (
        strtoupper(
            trim((string) $result)
        )
    ) {

        'SUCCESS' =>
            'result-success',

        'FAILURE' =>
            'result-failure',

        'DENIED' =>
            'result-denied',

        default =>
            'result-default'
    };
}


/**
 * Module icon.
 */
function moduleIcon(?string $module): string
{
    return match (
        strtolower(
            trim((string) $module)
        )
    ) {

        'authentication' =>
            'fa-solid fa-key',

        'accesscontrol',
        'access control' =>
            'fa-solid fa-lock',

        'usermanagement',
        'user management' =>
            'fa-solid fa-users-gear',

        'scanner' =>
            'fa-solid fa-magnifying-glass',

        'scannerrule',
        'scanner rule' =>
            'fa-solid fa-shield-halved',

        'vault',
        'securelogvault',
        'secure log vault' =>
            'fa-solid fa-vault',

        default =>
            'fa-solid fa-circle-info'
    };
}


/**
 * Safely obtain actor username.
 */
function actorUsername(array $event): string
{
    $actor = $event['actor'] ?? [];

    if (!is_array($actor)) {
        return 'System / Unknown';
    }

    $username = trim(
        (string) ($actor['username'] ?? '')
    );

    if ($username !== '') {
        return $username;
    }

    return 'System / Unknown';
}


/**
 * Actor role.
 */
function actorRole(array $event): string
{
    $actor = $event['actor'] ?? [];

    if (!is_array($actor)) {
        return '-';
    }

    $role = trim(
        (string) ($actor['role'] ?? '')
    );

    return $role !== ''
        ? ucfirst(strtolower($role))
        : '-';
}


/**
 * Actor ID.
 */
function actorId(array $event): ?int
{
    $actor = $event['actor'] ?? [];

    if (!is_array($actor)) {
        return null;
    }

    $userId = $actor['user_id'] ?? null;

    if (
        $userId === null
        || $userId === ''
    ) {
        return null;
    }

    return (int) $userId;
}


/**
 * Target label.
 */
function targetLabel(array $event): string
{
    $target = $event['target'] ?? null;

    if (
        !is_array($target)
        || empty($target)
    ) {
        return '-';
    }

    $type = trim(
        (string) ($target['type'] ?? '')
    );

    $id = $target['id'] ?? null;

    if ($type === '') {
        return '-';
    }

    $label = str_replace(
        '_',
        ' ',
        $type
    );

    $label = ucwords(
        strtolower($label)
    );

    if (
        $id !== null
        && $id !== ''
    ) {
        $label .= ' #' . $id;
    }

    return $label;
}


/**
 * Convert metadata key:
 *
 * rule_code -> Rule Code
 */
function formatMetadataKey(string $key): string
{
    return ucwords(
        strtolower(
            str_replace(
                ['_', '-'],
                ' ',
                $key
            )
        )
    );
}


/**
 * Convert metadata values safely.
 */
function formatMetadataValue(mixed $value): string
{
    if (is_bool($value)) {
        return $value
            ? 'Yes'
            : 'No';
    }

    if ($value === null) {
        return '-';
    }

    if (is_array($value)) {

        $encoded = json_encode(
            $value,
            JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
        );

        return $encoded !== false
            ? $encoded
            : '-';
    }

    return (string) $value;
}


/**
 * Generate URL while preserving current filters.
 */
function activityPageUrl(
    int $page,
    array $filters
): string {

    $parameters = [];

    foreach ($filters as $key => $value) {

        if (
            $value !== ''
            && $value !== null
        ) {
            $parameters[$key] = $value;
        }
    }

    $parameters['page'] = $page;

    return '?'
        . http_build_query($parameters);
}


/* ============================================================
   LOAD ACTIVITY LOGS
   ============================================================ */

$activityEvents = [];
$logReadError = '';

try {

    if (!function_exists('read_logs')) {

        throw new RuntimeException(
            'Activity log reader is unavailable.'
        );
    }

    $rawLogs = read_logs();

    if (!is_array($rawLogs)) {
        $rawLogs = [];
    }

    foreach ($rawLogs as $rawLog) {

        /*
         * Support both possibilities:
         *
         * 1. read_logs() returns raw JSON lines
         * 2. read_logs() already returns parsed arrays
         */

        if (is_array($rawLog)) {

            $parsedEvent = $rawLog;

        } elseif (
            function_exists('parse_log_line')
        ) {

            $parsedEvent =
                parse_log_line(
                    (string) $rawLog
                );

        } else {

            $parsedEvent =
                json_decode(
                    (string) $rawLog,
                    true
                );
        }

        if (
            is_array($parsedEvent)
            && !empty($parsedEvent)
        ) {
            $activityEvents[] =
                $parsedEvent;
        }
    }

} catch (Throwable $exception) {

    $logReadError =
        'Unable to read the SecureLog audit trail.';
}


/* ============================================================
   SORT NEWEST FIRST
   ============================================================ */

usort(
    $activityEvents,
    function (
        array $first,
        array $second
    ): int {

        $firstTime =
            strtotime(
                (string) (
                    $first['timestamp']
                    ?? ''
                )
            );

        $secondTime =
            strtotime(
                (string) (
                    $second['timestamp']
                    ?? ''
                )
            );

        return $secondTime
            <=> $firstTime;
    }
);


/* ============================================================
   SUMMARY STATISTICS
   ============================================================ */

$totalEvents = count($activityEvents);

$totalWarnings = 0;
$totalErrorsCritical = 0;
$totalAccessDenied = 0;

foreach ($activityEvents as $event) {

    $severity = strtoupper(
        trim(
            (string) (
                $event['severity']
                ?? ''
            )
        )
    );

    $eventType = strtoupper(
        trim(
            (string) (
                $event['event']
                ?? ''
            )
        )
    );

    if ($severity === 'WARNING') {
        $totalWarnings++;
    }

    if (
        $severity === 'ERROR'
        || $severity === 'CRITICAL'
    ) {
        $totalErrorsCritical++;
    }

    if ($eventType === 'ACCESS_DENIED') {
        $totalAccessDenied++;
    }
}


/* ============================================================
   AVAILABLE FILTER OPTIONS
   ============================================================ */

$availableModules = [];
$availableEvents = [];
$availableSeverities = [];

foreach ($activityEvents as $event) {

    $module = trim(
        (string) (
            $event['module']
            ?? ''
        )
    );

    $eventType = trim(
        (string) (
            $event['event']
            ?? ''
        )
    );

    $severity = strtoupper(
        trim(
            (string) (
                $event['severity']
                ?? ''
            )
        )
    );

    if ($module !== '') {
        $availableModules[$module] = true;
    }

    if ($eventType !== '') {
        $availableEvents[$eventType] = true;
    }

    if ($severity !== '') {
        $availableSeverities[$severity] = true;
    }
}

$availableModules =
    array_keys($availableModules);

$availableEvents =
    array_keys($availableEvents);

$availableSeverities =
    array_keys($availableSeverities);

sort(
    $availableModules,
    SORT_NATURAL | SORT_FLAG_CASE
);

sort(
    $availableEvents,
    SORT_NATURAL | SORT_FLAG_CASE
);

sort(
    $availableSeverities,
    SORT_NATURAL | SORT_FLAG_CASE
);


/* ============================================================
   FILTER INPUT
   ============================================================ */

$searchQuery = trim(
    (string) (
        $_GET['search']
        ?? ''
    )
);

$moduleFilter = trim(
    (string) (
        $_GET['module']
        ?? ''
    )
);

$eventFilter = trim(
    (string) (
        $_GET['event']
        ?? ''
    )
);

$severityFilter = strtoupper(
    trim(
        (string) (
            $_GET['severity']
            ?? ''
        )
    )
);

$dateFrom = trim(
    (string) (
        $_GET['date_from']
        ?? ''
    )
);

$dateTo = trim(
    (string) (
        $_GET['date_to']
        ?? ''
    )
);


/* ============================================================
   APPLY FILTERS
   ============================================================ */

$filteredEvents = array_values(
    array_filter(
        $activityEvents,
        function (array $event) use (
            $searchQuery,
            $moduleFilter,
            $eventFilter,
            $severityFilter,
            $dateFrom,
            $dateTo
        ): bool {

            $module = trim(
                (string) (
                    $event['module']
                    ?? ''
                )
            );

            $eventType = trim(
                (string) (
                    $event['event']
                    ?? ''
                )
            );

            $severity = strtoupper(
                trim(
                    (string) (
                        $event['severity']
                        ?? ''
                    )
                )
            );

            $eventDate =
                activityDateValue(
                    $event['timestamp']
                    ?? ''
                );


            /* Module filter */

            if (
                $moduleFilter !== ''
                && $module !== $moduleFilter
            ) {
                return false;
            }


            /* Event filter */

            if (
                $eventFilter !== ''
                && $eventType !== $eventFilter
            ) {
                return false;
            }


            /* Severity filter */

            if (
                $severityFilter !== ''
                && $severity !== $severityFilter
            ) {
                return false;
            }


            /* Date from */

            if (
                $dateFrom !== ''
                && $eventDate !== ''
                && $eventDate < $dateFrom
            ) {
                return false;
            }


            /* Date to */

            if (
                $dateTo !== ''
                && $eventDate !== ''
                && $eventDate > $dateTo
            ) {
                return false;
            }


            /* Search */

            if ($searchQuery !== '') {

                $actor =
                    $event['actor']
                    ?? [];

                $source =
                    $event['source']
                    ?? [];

                $target =
                    $event['target']
                    ?? [];

                $metadata =
                    $event['metadata']
                    ?? [];

                $searchableData = [
                    $event['event_id']
                        ?? '',

                    $event['timestamp']
                        ?? '',

                    $module,

                    $eventType,

                    $severity,

                    $event['result']
                        ?? '',

                    $event['description']
                        ?? '',

                    is_array($actor)
                        ? ($actor['username'] ?? '')
                        : '',

                    is_array($actor)
                        ? ($actor['role'] ?? '')
                        : '',

                    is_array($source)
                        ? ($source['ip'] ?? '')
                        : '',

                    is_array($source)
                        ? ($source['request_uri'] ?? '')
                        : '',

                    is_array($target)
                        ? ($target['type'] ?? '')
                        : '',

                    is_array($target)
                        ? ($target['id'] ?? '')
                        : '',

                    is_array($metadata)
                        ? json_encode(
                            $metadata,
                            JSON_UNESCAPED_SLASHES
                            | JSON_UNESCAPED_UNICODE
                        )
                        : ''
                ];

                $haystack =
                    strtolower(
                        implode(
                            ' ',
                            array_map(
                                'strval',
                                $searchableData
                            )
                        )
                    );

                if (
                    !str_contains(
                        $haystack,
                        strtolower($searchQuery)
                    )
                ) {
                    return false;
                }
            }

            return true;
        }
    )
);


/* ============================================================
   PAGINATION
   ============================================================ */

$totalFilteredRecords =
    count($filteredEvents);

$totalPages = max(
    1,
    (int) ceil(
        $totalFilteredRecords
        / $recordsPerPage
    )
);

$currentPageNumber =
    isset($_GET['page'])
        ? max(
            1,
            (int) $_GET['page']
        )
        : 1;

if ($currentPageNumber > $totalPages) {
    $currentPageNumber = $totalPages;
}

$offset =
    ($currentPageNumber - 1)
    * $recordsPerPage;

$paginatedEvents =
    array_slice(
        $filteredEvents,
        $offset,
        $recordsPerPage
    );

$startingRecord =
    $totalFilteredRecords > 0
        ? $offset + 1
        : 0;

$endingRecord = min(
    $offset + $recordsPerPage,
    $totalFilteredRecords
);


/* ============================================================
   FILTERS FOR PAGINATION URL
   ============================================================ */

$paginationFilters = [
    'search' =>
        $searchQuery,

    'module' =>
        $moduleFilter,

    'event' =>
        $eventFilter,

    'severity' =>
        $severityFilter,

    'date_from' =>
        $dateFrom,

    'date_to' =>
        $dateTo
];


/* ============================================================
   MODAL EVENT DATA
   ============================================================ */

$modalEvents = [];

foreach (
    $paginatedEvents as $index => $event
) {
    $modalEvents[$index] = $event;
}

$modalEventsJson = json_encode(
    $modalEvents,
    JSON_UNESCAPED_SLASHES
    | JSON_UNESCAPED_UNICODE
    | JSON_HEX_TAG
    | JSON_HEX_AMP
    | JSON_HEX_APOS
    | JSON_HEX_QUOT
);

if ($modalEventsJson === false) {
    $modalEventsJson = '{}';
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
        Activity Log | SecureLog
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

            --activity-bg:
                #020c17;

            --activity-panel:
                #061729;

            --activity-panel-dark:
                #03111f;

            --activity-border:
                #143047;

            --activity-orange:
                #ff6500;

            --activity-green:
                #00e59b;

            --activity-red:
                #ff4655;

            --activity-blue:
                #38bdf8;

            --activity-yellow:
                #ffd20a;

            --activity-purple:
                #c084fc;

            --activity-text:
                #f8fafc;

            --activity-muted:
                #9aa9b9;
        }


        * {
            box-sizing: border-box;
        }


        html,
        body {

            margin: 0;

            min-height: 100%;

            background:
                var(--activity-bg);

            color:
                var(--activity-text);

            font-family:
                "Inter",
                "Segoe UI",
                sans-serif;
        }


        body {
            overflow-x: hidden;
        }


        button,
        input,
        select {

            font-family:
                inherit;
        }


        /* =====================================================
           PAGE
           ===================================================== */

        .activity-page {

            min-height: 100vh;

            padding:
                15px 14px 25px;

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

            min-height:
                calc(100vh - 35px);

            margin:
                0 auto;

            background:

                linear-gradient(
                    145deg,
                    rgba(5, 24, 40, 0.98),
                    rgba(2, 14, 26, 0.98)
                );

            border:
                1px solid
                var(--activity-border);

            border-radius:
                14px;

            overflow:
                hidden;
        }


        /* =====================================================
           HEADER
           ===================================================== */

        .activity-header {

            min-height:
                120px;

            padding:
                28px 30px;

            display:
                flex;

            align-items:
                flex-start;

            gap:
                18px;

            border-bottom:
                1px solid
                var(--activity-border);
        }


        .activity-header-icon {

            width:
                53px;

            height:
                53px;

            display:
                flex;

            align-items:
                center;

            justify-content:
                center;

            flex-shrink:
                0;

            color:
                var(--activity-orange);

            background:
                rgba(255, 101, 0, 0.13);

            border-radius:
                50%;

            font-size:
                25px;
        }


        .activity-header-text h1 {

            margin:
                2px 0 7px;

            color:
                #ffffff;

            font-size:
                25px;

            font-weight:
                800;

            text-transform:
                uppercase;

            letter-spacing:
                0.2px;
        }


        .activity-header-text p {

            margin:
                0;

            color:
                #b8c3cf;

            font-size:
                14px;

            line-height:
                1.6;
        }


        /* =====================================================
           SUMMARY CARDS
           ===================================================== */

        .activity-summary {

            margin:
                20px;

            display:
                grid;

            grid-template-columns:
                repeat(4, 1fr);

            gap:
                14px;
        }


        .summary-card {

            position:
                relative;

            min-height:
                120px;

            padding:
                20px;

            overflow:
                hidden;

            background:

                linear-gradient(
                    145deg,
                    rgba(9, 29, 49, 0.98),
                    rgba(4, 19, 34, 0.98)
                );

            border:
                1px solid
                rgba(20, 48, 71, 0.75);

            border-radius:
                12px;
        }


        .summary-label {

            margin-bottom:
                12px;

            color:
                #9fb0bf;

            font-size:
                11px;

            font-weight:
                700;

            letter-spacing:
                0.7px;

            text-transform:
                uppercase;
        }


        .summary-value {

            color:
                #ffffff;

            font-size:
                30px;

            font-weight:
                800;
        }


        .summary-icon {

            position:
                absolute;

            right:
                18px;

            bottom:
                18px;

            font-size:
                24px;

            opacity:
                0.95;
        }


        .summary-card.total
        .summary-icon {

            color:
                var(--activity-blue);
        }


        .summary-card.warning
        .summary-icon {

            color:
                var(--activity-yellow);
        }


        .summary-card.error
        .summary-icon {

            color:
                var(--activity-red);
        }


        .summary-card.denied
        .summary-icon {

            color:
                var(--activity-orange);
        }


        /* =====================================================
           PANEL
           ===================================================== */

        .activity-panel {

            margin:
                20px;

            padding:
                20px;

            background:

                linear-gradient(
                    145deg,
                    rgba(9, 29, 49, 0.98),
                    rgba(4, 19, 34, 0.98)
                );

            border:
                1px solid
                rgba(20, 48, 71, 0.65);

            border-radius:
                13px;
        }


        .panel-heading {

            margin-bottom:
                22px;

            display:
                flex;

            align-items:
                center;

            gap:
                15px;
        }


        .panel-icon {

            width:
                43px;

            height:
                43px;

            display:
                flex;

            align-items:
                center;

            justify-content:
                center;

            flex-shrink:
                0;

            color:
                var(--activity-orange);

            background:
                rgba(255, 101, 0, 0.14);

            border-radius:
                50%;

            font-size:
                20px;
        }


        .panel-title h2 {

            margin:
                0 0 5px;

            color:
                #ffffff;

            font-size:
                19px;

            font-weight:
                800;

            text-transform:
                uppercase;
        }


        .panel-title p {

            margin:
                0;

            color:
                #b4bfca;

            font-size:
                13px;

            line-height:
                1.5;
        }


        /* =====================================================
           FILTERS
           ===================================================== */

        .filter-form {

            display:
                grid;

            grid-template-columns:
                2fr repeat(3, 1fr);

            gap:
                12px;
        }


        .filter-group {

            display:
                flex;

            flex-direction:
                column;

            gap:
                7px;
        }


        .filter-group label {

            color:
                #aebbc7;

            font-size:
                11px;

            font-weight:
                700;

            text-transform:
                uppercase;

            letter-spacing:
                0.4px;
        }


        .filter-control {

            width:
                100%;

            min-height:
                44px;

            padding:
                10px 12px;

            color:
                #ffffff;

            background:
                #031321;

            border:
                1px solid
                #17354c;

            border-radius:
                7px;

            outline:
                none;

            font-size:
                13px;

            transition:
                border-color 0.2s ease,
                box-shadow 0.2s ease;
        }


        .filter-control:focus {

            border-color:
                var(--activity-orange);

            box-shadow:
                0 0 0 2px
                rgba(255, 101, 0, 0.08);
        }


        .filter-control::placeholder {
            color:
                #617587;
        }


        select.filter-control option {

            color:
                #ffffff;

            background:
                #061729;
        }


        .date-filter-row {

            margin-top:
                12px;

            display:
                grid;

            grid-template-columns:
                1fr 1fr auto;

            gap:
                12px;

            align-items:
                end;
        }


        .filter-actions {

            display:
                flex;

            gap:
                9px;
        }


        .filter-button {

            min-height:
                44px;

            padding:
                0 17px;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            gap:
                8px;

            border:
                none;

            border-radius:
                7px;

            cursor:
                pointer;

            font-size:
                12px;

            font-weight:
                700;

            text-decoration:
                none;
        }


        .filter-button.apply {

            color:
                #ffffff;

            background:
                var(--activity-orange);
        }


        .filter-button.apply:hover {
            background:
                #e85d00;
        }


        .filter-button.reset {

            color:
                #c6d1db;

            background:
                #0b2235;

            border:
                1px solid
                #1b3a51;
        }


        .filter-button.reset:hover {

            color:
                #ffffff;

            border-color:
                #31536c;
        }


        /* =====================================================
           TABLE
           ===================================================== */

        .activity-table-wrapper {

            width:
                100%;

            overflow-x:
                auto;
        }


        .activity-table {

            width:
                100%;

            min-width:
                1120px;

            border-collapse:
                collapse;
        }


        .activity-table thead {

            background:
                rgba(2, 14, 26, 0.85);
        }


        .activity-table th {

            padding:
                14px 12px;

            color:
                #b8c3cf;

            border-bottom:
                1px solid
                rgba(20, 48, 71, 0.8);

            font-size:
                11px;

            font-weight:
                700;

            text-align:
                left;

            text-transform:
                uppercase;

            letter-spacing:
                0.35px;
        }


        .activity-table td {

            padding:
                16px 12px;

            color:
                #ffffff;

            border-bottom:
                1px solid
                rgba(20, 48, 71, 0.55);

            font-size:
                13px;

            vertical-align:
                middle;
        }


        .activity-table tbody tr {

            transition:
                background-color 0.2s ease;
        }


        .activity-table tbody tr:hover {

            background:
                rgba(255, 101, 0, 0.035);
        }


        .timestamp {

            min-width:
                165px;

            color:
                #d8e1e9;

            font-size:
                12px;

            white-space:
                nowrap;
        }


        .actor-name {

            margin-bottom:
                4px;

            color:
                #ffffff;

            font-weight:
                700;
        }


        .actor-meta {

            color:
                #8193a3;

            font-size:
                11px;
        }


        .module-cell {

            display:
                flex;

            align-items:
                center;

            gap:
                9px;
        }


        .module-icon {

            width:
                29px;

            height:
                29px;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            flex-shrink:
                0;

            color:
                var(--activity-orange);

            background:
                rgba(255, 101, 0, 0.1);

            border-radius:
                6px;
        }


        .event-code {

            color:
                #e9f1f7;

            font-size:
                12px;

            font-weight:
                700;
        }


        /* =====================================================
           BADGES
           ===================================================== */

        .badge {

            padding:
                5px 9px;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            border-radius:
                5px;

            font-size:
                10px;

            font-weight:
                800;

            letter-spacing:
                0.3px;
        }


        .severity-info {

            color:
                #70d8ff;

            background:
                rgba(56, 189, 248, 0.14);
        }


        .severity-warning {

            color:
                #ffe05c;

            background:
                rgba(255, 210, 10, 0.14);
        }


        .severity-error {

            color:
                #ff7b86;

            background:
                rgba(255, 70, 85, 0.14);
        }


        .severity-critical {

            color:
                #f2a7ff;

            background:
                rgba(192, 132, 252, 0.15);

            box-shadow:
                0 0 12px
                rgba(192, 132, 252, 0.07);
        }


        .severity-default {

            color:
                #b9c5cf;

            background:
                rgba(154, 169, 185, 0.12);
        }


        .result-success {

            color:
                #39e9aa;

            background:
                rgba(0, 229, 155, 0.13);
        }


        .result-failure {

            color:
                #ff7a87;

            background:
                rgba(255, 70, 85, 0.13);
        }


        .result-denied {

            color:
                #ffad69;

            background:
                rgba(255, 101, 0, 0.14);
        }


        .result-default {

            color:
                #b9c5cf;

            background:
                rgba(154, 169, 185, 0.12);
        }


        /* =====================================================
           VIEW BUTTON
           ===================================================== */

        .view-button {

            width:
                35px;

            height:
                35px;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            color:
                var(--activity-orange);

            background:
                rgba(255, 101, 0, 0.09);

            border:
                1px solid
                rgba(255, 101, 0, 0.25);

            border-radius:
                6px;

            cursor:
                pointer;

            transition:
                all 0.2s ease;
        }


        .view-button:hover {

            color:
                #ffffff;

            background:
                var(--activity-orange);

            border-color:
                var(--activity-orange);
        }


        /* =====================================================
           EMPTY / ERROR
           ===================================================== */

        .activity-message {

            padding:
                45px 20px;

            color:
                var(--activity-muted);

            font-size:
                13px;

            text-align:
                center;
        }


        .activity-message i {

            display:
                block;

            margin-bottom:
                12px;

            color:
                var(--activity-orange);

            font-size:
                27px;
        }


        .log-error {

            margin:
                20px;

            padding:
                13px 16px;

            color:
                #ff8b96;

            background:
                rgba(255, 70, 85, 0.1);

            border:
                1px solid
                rgba(255, 70, 85, 0.3);

            border-radius:
                7px;

            font-size:
                13px;
        }


        /* =====================================================
           TABLE FOOTER
           ===================================================== */

        .table-footer {

            padding:
                24px 5px 4px;

            display:
                flex;

            align-items:
                center;

            justify-content:
                space-between;

            gap:
                20px;
        }


        .records-summary {

            color:
                #c2ccd6;

            font-size:
                12px;
        }


        .pagination {

            display:
                flex;

            align-items:
                center;

            gap:
                8px;
        }


        .page-button {

            min-width:
                40px;

            height:
                40px;

            padding:
                0 10px;

            display:
                inline-flex;

            align-items:
                center;

            justify-content:
                center;

            color:
                #aeb9c5;

            background:
                #041321;

            border:
                1px solid
                var(--activity-border);

            border-radius:
                7px;

            text-decoration:
                none;

            font-size:
                12px;

            transition:
                all 0.2s ease;
        }


        .page-button:hover {

            color:
                #ffffff;

            background:
                rgba(255, 101, 0, 0.12);

            border-color:
                var(--activity-orange);
        }


        .page-button.active {

            color:
                #ffffff;

            background:
                var(--activity-orange);

            border-color:
                var(--activity-orange);

            box-shadow:
                0 0 16px
                rgba(255, 101, 0, 0.25);
        }


        .page-button.disabled {

            color:
                #526170;

            pointer-events:
                none;

            opacity:
                0.55;
        }


        /* =====================================================
           MODAL
           ===================================================== */

        .activity-modal {

            position:
                fixed;

            inset:
                0;

            z-index:
                99999;

            display:
                none;

            align-items:
                center;

            justify-content:
                center;

            padding:
                20px;

            background:
                rgba(0, 7, 14, 0.78);

            backdrop-filter:
                blur(5px);
        }


        .activity-modal.open {
            display:
                flex;
        }


        .modal-card {

            width:
                100%;

            max-width:
                820px;

            max-height:
                88vh;

            overflow-y:
                auto;

            background:
                #061729;

            border:
                1px solid
                #1a405c;

            border-radius:
                13px;

            box-shadow:
                0 25px 80px
                rgba(0, 0, 0, 0.45);
        }


        .modal-header {

            position:
                sticky;

            top:
                0;

            z-index:
                2;

            padding:
                19px 21px;

            display:
                flex;

            align-items:
                center;

            justify-content:
                space-between;

            gap:
                15px;

            background:
                #061729;

            border-bottom:
                1px solid
                #17354c;
        }


        .modal-heading {

            display:
                flex;

            align-items:
                center;

            gap:
                11px;
        }


        .modal-heading i {

            color:
                var(--activity-orange);

            font-size:
                19px;
        }


        .modal-heading h3 {

            margin:
                0;

            color:
                #ffffff;

            font-size:
                16px;

            text-transform:
                uppercase;
        }


        .modal-close {

            width:
                35px;

            height:
                35px;

            display:
                flex;

            align-items:
                center;

            justify-content:
                center;

            color:
                #9fb0bf;

            background:
                transparent;

            border:
                1px solid
                #1b3b53;

            border-radius:
                6px;

            cursor:
                pointer;
        }


        .modal-close:hover {

            color:
                #ffffff;

            border-color:
                var(--activity-orange);
        }


        .modal-body {

            padding:
                21px;
        }


        .detail-section {

            margin-bottom:
                22px;
        }


        .detail-section:last-child {
            margin-bottom:
                0;
        }


        .detail-section-title {

            margin-bottom:
                12px;

            color:
                var(--activity-orange);

            font-size:
                11px;

            font-weight:
                800;

            letter-spacing:
                0.7px;

            text-transform:
                uppercase;
        }


        .detail-grid {

            display:
                grid;

            grid-template-columns:
                repeat(2, 1fr);

            gap:
                10px;
        }


        .detail-item {

            min-width:
                0;

            padding:
                12px 13px;

            background:
                #031321;

            border:
                1px solid
                #123149;

            border-radius:
                7px;
        }


        .detail-item.full {
            grid-column:
                1 / -1;
        }


        .detail-label {

            margin-bottom:
                6px;

            color:
                #8195a6;

            font-size:
                10px;

            font-weight:
                700;

            letter-spacing:
                0.3px;

            text-transform:
                uppercase;
        }


        .detail-value {

            color:
                #ffffff;

            font-size:
                12px;

            line-height:
                1.55;

            overflow-wrap:
                anywhere;
        }


        .metadata-empty {

            color:
                #718596;

            font-size:
                12px;
        }


        /* =====================================================
           RESPONSIVE
           ===================================================== */

        @media (max-width: 1100px) {

            .activity-summary {

                grid-template-columns:
                    repeat(2, 1fr);
            }


            .filter-form {

                grid-template-columns:
                    repeat(2, 1fr);
            }
        }


        @media (max-width: 800px) {

            .activity-page {
                padding:
                    10px;
            }


            .activity-header {
                padding:
                    22px 20px;
            }


            .activity-panel,
            .activity-summary {

                margin:
                    12px;
            }


            .date-filter-row {

                grid-template-columns:
                    1fr;
            }


            .detail-grid {

                grid-template-columns:
                    1fr;
            }


            .detail-item.full {

                grid-column:
                    auto;
            }
        }


        @media (max-width: 600px) {

            .activity-header-text h1 {

                font-size:
                    21px;
            }


            .activity-summary {

                grid-template-columns:
                    1fr;
            }


            .filter-form {

                grid-template-columns:
                    1fr;
            }


            .filter-actions {

                flex-direction:
                    column;
            }


            .filter-button {

                width:
                    100%;
            }


            .table-footer {

                flex-direction:
                    column;

                align-items:
                    flex-start;
            }


            .pagination {

                align-self:
                    center;
            }
        }

    </style>

</head>


<body>


    <!-- =====================================================
         ADMIN SIDEBAR
         ===================================================== -->

    <?php

    require __DIR__
        . '/../../Sidebar/sidebaradmin.php';

    ?>


    <!-- =====================================================
         ACTIVITY LOG
         ===================================================== -->

    <main
        class="admin-page-content activity-page"
    >

        <div class="activity-container">


            <!-- =============================================
                 HEADER
                 ============================================= -->

            <header class="activity-header">

                <div class="activity-header-icon">

                    <i
                        class="fa-solid fa-clock-rotate-left"
                    ></i>

                </div>


                <div class="activity-header-text">

                    <h1>
                        Activity Log
                    </h1>

                    <p>
                        Monitor security-relevant activities,
                        authentication events, access control,
                        user management, scans and scanner rule
                        operations recorded by SecureLog.
                    </p>

                </div>

            </header>


            <!-- =============================================
                 SUMMARY
                 ============================================= -->

            <section class="activity-summary">


                <article class="summary-card total">

                    <div class="summary-label">
                        Total Events
                    </div>

                    <div class="summary-value">
                        <?= number_format(
                            $totalEvents
                        ); ?>
                    </div>

                    <div class="summary-icon">

                        <i
                            class="fa-solid fa-list-check"
                        ></i>

                    </div>

                </article>


                <article class="summary-card warning">

                    <div class="summary-label">
                        Warnings
                    </div>

                    <div class="summary-value">
                        <?= number_format(
                            $totalWarnings
                        ); ?>
                    </div>

                    <div class="summary-icon">

                        <i
                            class="fa-solid fa-triangle-exclamation"
                        ></i>

                    </div>

                </article>


                <article class="summary-card error">

                    <div class="summary-label">
                        Error / Critical
                    </div>

                    <div class="summary-value">
                        <?= number_format(
                            $totalErrorsCritical
                        ); ?>
                    </div>

                    <div class="summary-icon">

                        <i
                            class="fa-solid fa-circle-exclamation"
                        ></i>

                    </div>

                </article>


                <article class="summary-card denied">

                    <div class="summary-label">
                        Access Denied
                    </div>

                    <div class="summary-value">
                        <?= number_format(
                            $totalAccessDenied
                        ); ?>
                    </div>

                    <div class="summary-icon">

                        <i
                            class="fa-solid fa-ban"
                        ></i>

                    </div>

                </article>


            </section>


            <!-- =============================================
                 LOG ERROR
                 ============================================= -->

            <?php if ($logReadError !== ''): ?>

                <div class="log-error">

                    <i
                        class="fa-solid fa-triangle-exclamation"
                    ></i>

                    <?= e($logReadError); ?>

                </div>

            <?php endif; ?>


            <!-- =============================================
                 FILTER PANEL
                 ============================================= -->

            <section class="activity-panel">


                <div class="panel-heading">

                    <div class="panel-icon">

                        <i
                            class="fa-solid fa-filter"
                        ></i>

                    </div>


                    <div class="panel-title">

                        <h2>
                            Filter Activity
                        </h2>

                        <p>
                            Search and filter recorded audit
                            events.
                        </p>

                    </div>

                </div>


                <form
                    method="GET"
                    action=""
                >


                    <div class="filter-form">


                        <!-- Search -->

                        <div class="filter-group">

                            <label for="search">
                                Search
                            </label>

                            <input
                                type="text"
                                id="search"
                                name="search"
                                class="filter-control"
                                value="<?= e(
                                    $searchQuery
                                ); ?>"
                                placeholder="Event, user, IP, description..."
                            >

                        </div>


                        <!-- Module -->

                        <div class="filter-group">

                            <label for="module">
                                Module
                            </label>

                            <select
                                id="module"
                                name="module"
                                class="filter-control"
                            >

                                <option value="">
                                    All Modules
                                </option>

                                <?php foreach (
                                    $availableModules
                                    as $module
                                ): ?>

                                    <option
                                        value="<?= e(
                                            $module
                                        ); ?>"
                                        <?= $moduleFilter
                                            === $module
                                            ? 'selected'
                                            : ''; ?>
                                    >
                                        <?= e(
                                            formatModuleName(
                                                $module
                                            )
                                        ); ?>
                                    </option>

                                <?php endforeach; ?>

                            </select>

                        </div>


                        <!-- Event -->

                        <div class="filter-group">

                            <label for="event">
                                Event Type
                            </label>

                            <select
                                id="event"
                                name="event"
                                class="filter-control"
                            >

                                <option value="">
                                    All Events
                                </option>

                                <?php foreach (
                                    $availableEvents
                                    as $eventType
                                ): ?>

                                    <option
                                        value="<?= e(
                                            $eventType
                                        ); ?>"
                                        <?= $eventFilter
                                            === $eventType
                                            ? 'selected'
                                            : ''; ?>
                                    >
                                        <?= e(
                                            formatEventName(
                                                $eventType
                                            )
                                        ); ?>
                                    </option>

                                <?php endforeach; ?>

                            </select>

                        </div>


                        <!-- Severity -->

                        <div class="filter-group">

                            <label for="severity">
                                Severity
                            </label>

                            <select
                                id="severity"
                                name="severity"
                                class="filter-control"
                            >

                                <option value="">
                                    All Severities
                                </option>

                                <?php foreach (
                                    $availableSeverities
                                    as $severity
                                ): ?>

                                    <option
                                        value="<?= e(
                                            $severity
                                        ); ?>"
                                        <?= $severityFilter
                                            === $severity
                                            ? 'selected'
                                            : ''; ?>
                                    >
                                        <?= e($severity); ?>
                                    </option>

                                <?php endforeach; ?>

                            </select>

                        </div>


                    </div>


                    <div class="date-filter-row">


                        <div class="filter-group">

                            <label for="date_from">
                                From Date
                            </label>

                            <input
                                type="date"
                                id="date_from"
                                name="date_from"
                                class="filter-control"
                                value="<?= e(
                                    $dateFrom
                                ); ?>"
                            >

                        </div>


                        <div class="filter-group">

                            <label for="date_to">
                                To Date
                            </label>

                            <input
                                type="date"
                                id="date_to"
                                name="date_to"
                                class="filter-control"
                                value="<?= e(
                                    $dateTo
                                ); ?>"
                            >

                        </div>


                        <div class="filter-actions">

                            <button
                                type="submit"
                                class="filter-button apply"
                            >

                                <i
                                    class="fa-solid fa-magnifying-glass"
                                ></i>

                                Apply Filter

                            </button>


                            <a
                                href="activityLog.php"
                                class="filter-button reset"
                            >

                                <i
                                    class="fa-solid fa-rotate-left"
                                ></i>

                                Reset

                            </a>

                        </div>


                    </div>


                </form>


            </section>


            <!-- =============================================
                 AUDIT EVENTS
                 ============================================= -->

            <section class="activity-panel">


                <div class="panel-heading">

                    <div class="panel-icon">

                        <i
                            class="fa-solid fa-shield-halved"
                        ></i>

                    </div>


                    <div class="panel-title">

                        <h2>
                            Security Activity
                        </h2>

                        <p>
                            Read-only structured audit trail
                            generated by SecureLog.
                        </p>

                    </div>

                </div>


                <div class="activity-table-wrapper">


                    <table class="activity-table">


                        <thead>

                            <tr>

                                <th>
                                    Timestamp
                                </th>

                                <th>
                                    Actor
                                </th>

                                <th>
                                    Module
                                </th>

                                <th>
                                    Event
                                </th>

                                <th>
                                    Severity
                                </th>

                                <th>
                                    Result
                                </th>

                                <th>
                                    Target
                                </th>

                                <th>
                                    Details
                                </th>

                            </tr>

                        </thead>


                        <tbody>


                        <?php if (
                            !empty(
                                $paginatedEvents
                            )
                        ): ?>


                            <?php foreach (
                                $paginatedEvents
                                as $index => $event
                            ): ?>


                                <?php

                                $actorIdValue =
                                    actorId($event);

                                $module =
                                    (string) (
                                        $event['module']
                                        ?? 'Unknown'
                                    );

                                $eventType =
                                    (string) (
                                        $event['event']
                                        ?? 'UNKNOWN'
                                    );

                                $severity =
                                    strtoupper(
                                        (string) (
                                            $event['severity']
                                            ?? 'INFO'
                                        )
                                    );

                                $result =
                                    strtoupper(
                                        (string) (
                                            $event['result']
                                            ?? '-'
                                        )
                                    );

                                ?>


                                <tr>


                                    <!-- Timestamp -->

                                    <td class="timestamp">

                                        <?= e(
                                            formatActivityTimestamp(
                                                $event[
                                                    'timestamp'
                                                ]
                                                ?? ''
                                            )
                                        ); ?>

                                    </td>


                                    <!-- Actor -->

                                    <td>

                                        <div class="actor-name">

                                            <?= e(
                                                actorUsername(
                                                    $event
                                                )
                                            ); ?>

                                        </div>


                                        <div class="actor-meta">

                                            <?= e(
                                                actorRole(
                                                    $event
                                                )
                                            ); ?>

                                            <?php if (
                                                $actorIdValue
                                                !== null
                                            ): ?>

                                                · #<?= e(
                                                    $actorIdValue
                                                ); ?>

                                            <?php endif; ?>

                                        </div>

                                    </td>


                                    <!-- Module -->

                                    <td>

                                        <div class="module-cell">

                                            <span
                                                class="module-icon"
                                            >

                                                <i
                                                    class="<?= e(
                                                        moduleIcon(
                                                            $module
                                                        )
                                                    ); ?>"
                                                ></i>

                                            </span>


                                            <span>

                                                <?= e(
                                                    formatModuleName(
                                                        $module
                                                    )
                                                ); ?>

                                            </span>

                                        </div>

                                    </td>


                                    <!-- Event -->

                                    <td>

                                        <span
                                            class="event-code"
                                            title="<?= e(
                                                formatEventName(
                                                    $eventType
                                                )
                                            ); ?>"
                                        >

                                            <?= e(
                                                $eventType
                                            ); ?>

                                        </span>

                                    </td>


                                    <!-- Severity -->

                                    <td>

                                        <span
                                            class="badge <?= e(
                                                severityClass(
                                                    $severity
                                                )
                                            ); ?>"
                                        >

                                            <?= e(
                                                $severity
                                            ); ?>

                                        </span>

                                    </td>


                                    <!-- Result -->

                                    <td>

                                        <span
                                            class="badge <?= e(
                                                resultClass(
                                                    $result
                                                )
                                            ); ?>"
                                        >

                                            <?= e(
                                                $result
                                            ); ?>

                                        </span>

                                    </td>


                                    <!-- Target -->

                                    <td>

                                        <?= e(
                                            targetLabel(
                                                $event
                                            )
                                        ); ?>

                                    </td>


                                    <!-- Details -->

                                    <td>

                                        <button
                                            type="button"
                                            class="view-button"
                                            data-event-index="<?= e(
                                                $index
                                            ); ?>"
                                            title="View event details"
                                            aria-label="View event details"
                                        >

                                            <i
                                                class="fa-solid fa-eye"
                                            ></i>

                                        </button>

                                    </td>


                                </tr>


                            <?php endforeach; ?>


                        <?php else: ?>


                            <tr>

                                <td colspan="8">

                                    <div
                                        class="activity-message"
                                    >

                                        <i
                                            class="fa-solid fa-circle-info"
                                        ></i>

                                        No activity events
                                        matched the selected
                                        filters.

                                    </div>

                                </td>

                            </tr>


                        <?php endif; ?>


                        </tbody>


                    </table>


                </div>


                <!-- =========================================
                     PAGINATION
                     ========================================= -->

                <div class="table-footer">


                    <div class="records-summary">

                        Showing

                        <?= e(
                            $startingRecord
                        ); ?>

                        to

                        <?= e(
                            $endingRecord
                        ); ?>

                        of

                        <?= e(
                            $totalFilteredRecords
                        ); ?>

                        events

                        <?php if (
                            $totalFilteredRecords
                            !== $totalEvents
                        ): ?>

                            (filtered from
                            <?= e(
                                $totalEvents
                            ); ?>)

                        <?php endif; ?>

                    </div>


                    <?php if (
                        $totalPages > 1
                    ): ?>


                        <nav
                            class="pagination"
                            aria-label="Activity log pagination"
                        >


                            <!-- Previous -->

                            <a
                                href="<?= e(
                                    activityPageUrl(
                                        max(
                                            1,
                                            $currentPageNumber
                                            - 1
                                        ),
                                        $paginationFilters
                                    )
                                ); ?>"
                                class="page-button <?= $currentPageNumber
                                    <= 1
                                        ? 'disabled'
                                        : ''; ?>"
                                aria-label="Previous page"
                            >

                                <i
                                    class="fa-solid fa-chevron-left"
                                ></i>

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
                                $pageNumber =
                                    $startPage;

                                $pageNumber
                                    <= $endPage;

                                $pageNumber++
                            ): ?>


                                <a
                                    href="<?= e(
                                        activityPageUrl(
                                            $pageNumber,
                                            $paginationFilters
                                        )
                                    ); ?>"
                                    class="page-button <?= $pageNumber
                                        === $currentPageNumber
                                            ? 'active'
                                            : ''; ?>"
                                >

                                    <?= e(
                                        $pageNumber
                                    ); ?>

                                </a>


                            <?php endfor; ?>


                            <!-- Next -->

                            <a
                                href="<?= e(
                                    activityPageUrl(
                                        min(
                                            $totalPages,
                                            $currentPageNumber
                                            + 1
                                        ),
                                        $paginationFilters
                                    )
                                ); ?>"
                                class="page-button <?= $currentPageNumber
                                    >= $totalPages
                                        ? 'disabled'
                                        : ''; ?>"
                                aria-label="Next page"
                            >

                                <i
                                    class="fa-solid fa-chevron-right"
                                ></i>

                            </a>


                        </nav>


                    <?php endif; ?>


                </div>


            </section>


        </div>

    </main>


    <!-- =====================================================
         EVENT DETAILS MODAL
         ===================================================== -->

    <div
        id="activityModal"
        class="activity-modal"
        aria-hidden="true"
    >


        <div
            class="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="modalTitle"
        >


            <div class="modal-header">


                <div class="modal-heading">

                    <i
                        class="fa-solid fa-file-shield"
                    ></i>

                    <h3 id="modalTitle">
                        Activity Details
                    </h3>

                </div>


                <button
                    type="button"
                    id="modalClose"
                    class="modal-close"
                    aria-label="Close"
                >

                    <i
                        class="fa-solid fa-xmark"
                    ></i>

                </button>


            </div>


            <div
                id="modalBody"
                class="modal-body"
            ></div>


        </div>


    </div>


    <!-- =====================================================
         SAFE EVENT DATA FOR MODAL
         ===================================================== -->

    <script
        id="activityEventData"
        type="application/json"
    ><?= $modalEventsJson; ?></script>


    <script>

        "use strict";


        /* =====================================================
           EVENT DATA
           ===================================================== */

        const eventDataElement =
            document.getElementById(
                "activityEventData"
            );


        let activityEvents = {};


        try {

            activityEvents =
                JSON.parse(
                    eventDataElement.textContent
                    || "{}"
                );

        } catch (error) {

            activityEvents = {};
        }


        /* =====================================================
           ELEMENTS
           ===================================================== */

        const modal =
            document.getElementById(
                "activityModal"
            );


        const modalBody =
            document.getElementById(
                "modalBody"
            );


        const modalClose =
            document.getElementById(
                "modalClose"
            );


        const viewButtons =
            document.querySelectorAll(
                ".view-button"
            );


        /* =====================================================
           HTML ESCAPE
           ===================================================== */

        function escapeHtml(value) {

            const element =
                document.createElement(
                    "div"
                );

            element.textContent =
                value === null
                || value === undefined
                    ? "-"
                    : String(value);

            return element.innerHTML;
        }


        /* =====================================================
           FORMAT KEY
           ===================================================== */

        function formatKey(key) {

            return String(key)
                .replace(/[_-]+/g, " ")
                .replace(
                    /\b\w/g,
                    character =>
                        character.toUpperCase()
                );
        }


        /* =====================================================
           FORMAT VALUE
           ===================================================== */

        function formatValue(value) {

            if (value === true) {
                return "Yes";
            }

            if (value === false) {
                return "No";
            }

            if (
                value === null
                || value === undefined
                || value === ""
            ) {
                return "-";
            }

            if (
                typeof value === "object"
            ) {

                try {

                    return JSON.stringify(
                        value,
                        null,
                        2
                    );

                } catch (error) {

                    return "-";
                }
            }

            return String(value);
        }


        /* =====================================================
           DETAIL ITEM
           ===================================================== */

        function detailItem(
            label,
            value,
            full = false
        ) {

            return `
                <div class="detail-item ${
                    full
                        ? "full"
                        : ""
                }">

                    <div class="detail-label">
                        ${escapeHtml(label)}
                    </div>

                    <div class="detail-value">
                        ${escapeHtml(
                            formatValue(value)
                        )}
                    </div>

                </div>
            `;
        }


        /* =====================================================
           OPEN MODAL
           ===================================================== */

        function openActivityModal(event) {

            if (!event) {
                return;
            }


            const actor =
                event.actor
                && typeof event.actor
                    === "object"
                    ? event.actor
                    : {};


            const source =
                event.source
                && typeof event.source
                    === "object"
                    ? event.source
                    : {};


            const target =
                event.target
                && typeof event.target
                    === "object"
                    ? event.target
                    : {};


            const metadata =
                event.metadata
                && typeof event.metadata
                    === "object"
                    ? event.metadata
                    : {};


            let metadataHtml = "";


            const metadataEntries =
                Object.entries(
                    metadata
                );


            if (
                metadataEntries.length > 0
            ) {

                metadataHtml =
                    metadataEntries
                        .map(
                            ([key, value]) =>
                                detailItem(
                                    formatKey(key),
                                    value
                                )
                        )
                        .join("");

            } else {

                metadataHtml = `
                    <div class="metadata-empty">
                        No additional metadata
                        recorded for this event.
                    </div>
                `;
            }


            modalBody.innerHTML = `

                <section class="detail-section">

                    <div class="detail-section-title">
                        Event Information
                    </div>

                    <div class="detail-grid">

                        ${detailItem(
                            "Event ID",
                            event.event_id
                        )}

                        ${detailItem(
                            "Timestamp",
                            event.timestamp
                        )}

                        ${detailItem(
                            "Application",
                            event.application
                        )}

                        ${detailItem(
                            "Module",
                            event.module
                        )}

                        ${detailItem(
                            "Event",
                            event.event
                        )}

                        ${detailItem(
                            "Severity",
                            event.severity
                        )}

                        ${detailItem(
                            "Result",
                            event.result
                        )}

                        ${detailItem(
                            "Description",
                            event.description,
                            true
                        )}

                    </div>

                </section>


                <section class="detail-section">

                    <div class="detail-section-title">
                        Actor
                    </div>

                    <div class="detail-grid">

                        ${detailItem(
                            "User ID",
                            actor.user_id
                        )}

                        ${detailItem(
                            "Username",
                            actor.username
                        )}

                        ${detailItem(
                            "Role",
                            actor.role
                        )}

                    </div>

                </section>


                <section class="detail-section">

                    <div class="detail-section-title">
                        Source
                    </div>

                    <div class="detail-grid">

                        ${detailItem(
                            "IP Address",
                            source.ip
                        )}

                        ${detailItem(
                            "HTTP Method",
                            source.http_method
                        )}

                        ${detailItem(
                            "Request URI",
                            source.request_uri,
                            true
                        )}

                    </div>

                </section>


                <section class="detail-section">

                    <div class="detail-section-title">
                        Target
                    </div>

                    <div class="detail-grid">

                        ${detailItem(
                            "Target Type",
                            target.type
                        )}

                        ${detailItem(
                            "Target ID",
                            target.id
                        )}

                    </div>

                </section>


                <section class="detail-section">

                    <div class="detail-section-title">
                        Metadata
                    </div>

                    <div class="detail-grid">

                        ${metadataHtml}

                    </div>

                </section>
            `;


            modal.classList.add(
                "open"
            );


            modal.setAttribute(
                "aria-hidden",
                "false"
            );


            document.body.style.overflow =
                "hidden";
        }


        /* =====================================================
           CLOSE MODAL
           ===================================================== */

        function closeActivityModal() {

            modal.classList.remove(
                "open"
            );


            modal.setAttribute(
                "aria-hidden",
                "true"
            );


            document.body.style.overflow =
                "";
        }


        /* =====================================================
           VIEW BUTTONS
           ===================================================== */

        viewButtons.forEach(
            button => {

                button.addEventListener(
                    "click",
                    function () {

                        const index =
                            this.dataset
                                .eventIndex;


                        const event =
                            activityEvents[
                                index
                            ];


                        openActivityModal(
                            event
                        );
                    }
                );
            }
        );


        /* =====================================================
           CLOSE BUTTON
           ===================================================== */

        modalClose.addEventListener(
            "click",
            closeActivityModal
        );


        /* =====================================================
           CLICK BACKDROP
           ===================================================== */

        modal.addEventListener(
            "click",
            function (event) {

                if (
                    event.target
                    === modal
                ) {
                    closeActivityModal();
                }
            }
        );


        /* =====================================================
           ESCAPE KEY
           ===================================================== */

        document.addEventListener(
            "keydown",
            function (event) {

                if (
                    event.key === "Escape"
                    && modal.classList
                        .contains("open")
                ) {
                    closeActivityModal();
                }
            }
        );

    </script>


</body>

</html>