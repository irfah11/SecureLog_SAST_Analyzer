<?php
require_once __DIR__ . '/../Engine_Process/Report/ScanReport.php';
$assert = static function (bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
    echo "PASS: {$label}\n";
};
$scan = ['ScanID' => 2202, 'ProjectName' => 'Project review - synthetic example',
    'ProgrammingLanguage' => 'PHP', 'ScanDate' => '2026-10-16 09:00:00', 'Status' => 'Completed', 'total_files' => 12];
$rows = [];
$names = ['Security Logging', 'Log Neutralization', 'Log Storage', 'Log Protection'];
foreach (['FAIL' => 29, 'PASS' => 37, 'N/A' => 142] as $status => $count) {
    for ($i = 0; $i < $count; $i++) {
        $rows[] = ['ResultID' => count($rows) + 1, 'Status' => $status,
            'VulnerabilityName' => $names[$i % 4], 'Standard' => $i % 4 === 0 ? 'CWE-778' : ($i % 4 === 1 ? 'CWE-117' : 'SecureLog Policy'),
            'Severity' => $status === 'FAIL' ? ($i % 3 === 0 ? 'HIGH' : 'MEDIUM') : 'INFO',
            'FilePath' => 'src/security/module_' . ($i % 12) . '.php', 'LineNumber' => 10 + $i,
            'Description' => 'INDIVIDUAL_EVIDENCE_' . $status . '_' . $i,
            'MatchedCode' => 'SAVED_CODE_EVIDENCE', 'Remediation' => 'SPECIFIC_SAVED_RECOMMENDATION'];
    }
}
$report = securelogReportModel($scan, $rows);
$html = securelogReportHtml($report);
$full = securelogReportHtml($report, false, 'full');
$assert(str_contains($html, 'COMPACT REPORT'), 'Compact layout is the default');
$assert(str_contains($html, 'All 29 failed checks'), 'Summary states exact number of failed checks');
foreach ($report['groups']['FAIL'] as $row) {
    $assert(str_contains($html, $row['Reference']), 'Failed check retained: ' . $row['Reference']);
}
$assert(!str_contains($html, 'INDIVIDUAL_EVIDENCE_PASS_') && !str_contains($html, 'INDIVIDUAL_EVIDENCE_N/A_'), 'PASS and N/A explanations are aggregated');
$assert(str_contains($html, '142') && str_contains($html, '37'), 'PASS and N/A counts remain visible');
$assert(str_contains($html, 'detail=full') && str_contains($full, 'detail=full'), 'Full-report preview and its PDF link preserve full mode');
$assert(str_contains($full, 'INDIVIDUAL_EVIDENCE_N/A_141') && str_contains($full, 'SPECIFIC_SAVED_RECOMMENDATION') && str_contains($full, 'SAVED_CODE_EVIDENCE'), 'Full report preserves original detail and evidence');
$assert(strlen($html) < strlen($full) / 3, 'Compact HTML materially reduces repeated content');
$empty = securelogReportModel(array_merge($scan, ['Status' => 'Pending']), []);
$assert(str_contains(securelogReportHtml($empty), 'No security-check records are available.') && $empty['status'] === 'Pending', 'Empty scan remains honest about completion');
$invalidRejected = false;
try { securelogReportHtml($report, false, 'invalid'); } catch (InvalidArgumentException $e) { $invalidRejected = true; }
$assert($invalidRejected, 'Unknown detail mode rejected');
$malicious = $rows;
$malicious[0]['FilePath'] = '<script>alert(1)</script>';
$safe = securelogReportHtml(securelogReportModel($scan, $malicious));
$assert(!str_contains($safe, '<script>') && str_contains($safe, '&lt;script&gt;'), 'Compact paths remain escaped');
$bytes = securelogReportPdf($report);
$assert(str_starts_with($bytes, '%PDF-'), 'Compact report renders to real PDF');
if (isset($argv[1])) {
    $directory = rtrim($argv[1], '/\\');
    if (!is_dir($directory)) mkdir($directory, 0700, true);
    file_put_contents($directory . '/SecureLog-compact-example.pdf', $bytes);
    file_put_contents($directory . '/SecureLog-compact-example.html', $html);
    file_put_contents($directory . '/SecureLog-compact-empty.pdf', securelogReportPdf($empty));
}
