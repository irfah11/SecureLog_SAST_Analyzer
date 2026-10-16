<?php
require_once __DIR__ . '/../Engine_Process/ScanPresentation.php';
require_once __DIR__ . '/../Engine_Process/Scanner/PHPScanner.php';
$assert = static function (bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
    echo "PASS: {$label}\n";
};
$sources = [
    'login.php' => '<?php require_once "logger.php"; if (!password_verify($password, $hash)) { log_activity("LOGIN_FAILED"); }',
    'logger.php' => '<?php function log_activity($m) { error_log($m); }',
    'dashboard.php' => '<?php function dashboard_total($values) { return array_sum($values); }',
    'denied.php' => '<?php if ($role !== "admin") { http_response_code(403); exit; }'
];
$rows = []; $files = []; $events = []; $nextId = 1;
foreach ($sources as $path => $content) {
    $findings = scanPHP($path, $content, $sources);
    $files[] = ['file' => $path, 'status' => $findings ? 'analyzed' : 'no_events',
        'event_count' => count(array_unique(array_column($findings, 'event_key'))),
        'checks' => count($findings), 'saved_checks' => count($findings),
        'reason' => $findings ? 'Analysis returned security checks.' : 'Analyzed: no supported security event detected.'];
    foreach ($findings as $finding) {
        $row = ['ResultID' => $nextId, 'Status' => $finding['status'], 'VulnerabilityName' => $finding['check'],
            'Description' => $finding['description'], 'FilePath' => $path, 'LineNumber' => $finding['line_number'],
            'Standard' => $finding['standard'], 'Severity' => $finding['severity']];
        $rows[] = $row;
        $events[(string) $nextId] = ['file' => $path, 'key' => $finding['event_key'],
            'name' => $finding['event_name'], 'line' => $finding['event_line']];
        $nextId++;
    }
}
$coverage = ['version' => 1, 'scan_id' => 1234, 'user_id' => 5678, 'outcome' => 'completed', 'files' => $files, 'events' => $events];
$presentation = securelogPresentation($rows, $coverage);
$assert(count($rows) === 8 && count($presentation['files']) === 2, 'Helper and dashboard do not create redundant result rows');
$assert($presentation['events'] === 2, 'Separate authentication and denial events are retained');
$assert(array_key_first($presentation['files']) === 'denied.php', 'File with FAIL appears first');
$first = reset($presentation['files']['denied.php']['events']);
$assert($first['rows'][0]['Status'] === 'FAIL', 'FAIL row appears first within event');
$assert($presentation['counts'] === ['FAIL' => 1, 'PASS' => 1, 'N/A' => 6, 'SYSTEM' => 0], 'Counts match actual checks');
$scan_info = ['ScanID' => 1234, 'total_files' => 4];
ob_start(); require __DIR__ . '/../Engine_Process/scan_results_view.php'; $html = ob_get_clean();
$assert(str_contains($html, 'dashboard.php') && str_contains($html, 'No supported event'), 'Coverage lists analyzed dashboard without findings');
$assert(str_contains($html, 'logger.php'), 'Coverage also lists helper file');
$assert(str_contains($html, 'class="scan-file" open') && str_contains($html, 'class="scan-event" open'), 'Failed groups open automatically');
$assert(str_contains($html, 'class="scan-file" >'), 'Non-failed file groups remain collapsible and closed');
$assert(str_contains($html, 'Scan Coverage') && str_contains($html, 'Only submitted files are covered'), 'Coverage explanation is visible');
$legacy = securelogPresentation($rows, null);
$assert($legacy['events'] === 2 && $legacy['coverage'] === null, 'Old rows can be grouped without inventing coverage');
$presentation = $legacy;
ob_start(); require __DIR__ . '/../Engine_Process/scan_results_view.php'; $oldHtml = ob_get_clean();
$assert(str_contains($oldHtml, 'Per-file coverage was not recorded'), 'Old scans explicitly disclose missing coverage');
$sameLine = scanPHP('same.php', '<?php if (!password_verify($a,$b)) {error_log("bad");} if (!password_verify($c,$d)) {error_log("bad");}');
$assert(count(array_unique(array_column($sameLine, 'event_key'))) === 2, 'Two events sharing a line have different keys');
$xss = $rows;
$xss[0]['FilePath'] = '<img src=x onerror=alert(1)>';
$xss[0]['Description'] = '<script>alert(1)</script>';
$presentation = securelogPresentation($xss, null);
ob_start(); require __DIR__ . '/../Engine_Process/scan_results_view.php'; $safe = ob_get_clean();
$assert(!str_contains($safe, '<script>') && !str_contains($safe, '<img'), 'File paths and detail text are escaped');
$presentation = securelogPresentation([], ['outcome' => 'completed', 'files' => $files, 'events' => []]);
ob_start(); require __DIR__ . '/../Engine_Process/scan_results_view.php'; $empty = ob_get_clean();
$assert(str_contains($empty, 'Analysis completed with no security checks generated'), 'Completed no-event scan has a meaningful empty state');
$assert(securelogLoadCoverage(-1, 1) === null && securelogLoadCoverage(1234, 0) === null, 'Coverage reads reject invalid identities');
$scan_info = null;
$presentation = securelogPresentation([], null);
ob_start(); require __DIR__ . '/../Engine_Process/scan_results_view.php'; $readyHtml = ob_get_clean();
$assert(str_contains($readyHtml, 'Ready to analyze'), 'New-scan page works before a scan ID is selected');
$scan_info = ['ScanID' => 1234, 'total_files' => 4];
// Persist only a unique synthetic sidecar, then remove that exact file.
$id = random_int(1000000000, 2000000000);
$path = __DIR__ . '/../Dashboard/logs/scan_coverage/' . $id . '.json';
if (file_exists($path)) throw new RuntimeException('Synthetic coverage ID collision.');
try {
    $assert(securelogSaveCoverage($id, 5678, $files, $events, 'completed'), 'Coverage metadata persists without a database change');
    $assert(securelogLoadCoverage($id, 5678)['files'] === $files, 'Coverage round-trips the per-file states');
    $assert(securelogLoadCoverage($id, 9999) === null, 'Coverage does not load for a different owner');
} finally {
    if (is_file($path)) unlink($path);
}
if (isset($argv[1])) {
    $presentation = securelogPresentation($rows, $coverage);
    ob_start(); require __DIR__ . '/../Engine_Process/scan_results_view.php'; $view = ob_get_clean();
    $pageSource = file_get_contents(__DIR__ . '/../Engine_Process/index.php');
    preg_match('/<style>(.*?)<\/style>/s', $pageSource, $style);
    $preview = '<!doctype html><html><head><meta charset="utf-8"><title>SecureLog grouping preview (synthetic)</title><style>'
        . ($style[1] ?? '') . 'body{padding:28px;background:#020817;color:#e6edf6;font-family:Arial,sans-serif}.preview{max-width:1000px;margin:auto}.result-body{max-height:none}.card{padding:24px;border:1px solid #263b52;background:#07111f}.scan-event .analysis-table{font-size:13px}</style></head><body><main class="preview">'
        . '<p class="logging-reminder">Not every file requires security logging. SecureLog checks supported security events and their logging paths. Files without detected events appear in Scan Coverage.</p>'
        . '<section class="card result-card"><h2>Analysis Result - synthetic project</h2><div class="result-body">' . $view . '</div></section></main></body></html>';
    file_put_contents($argv[1], $preview);
}
