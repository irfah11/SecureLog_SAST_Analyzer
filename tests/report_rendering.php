<?php
require_once __DIR__ . '/../Engine_Process/Report/ScanReport.php';
$assert = static function (bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
    echo "PASS: {$message}\n";
};
$scan = ['ScanID' => 2201, 'ProjectName' => 'Test 22 - plaintext logging',
    'ProgrammingLanguage' => 'PHP', 'ScanDate' => '2026-10-16 14:30:00',
    'Status' => 'Completed', 'total_files' => 1];
$rows = [];
foreach (['Security Logging', 'Log Neutralization', 'Log Storage', 'Log Protection'] as $index => $name) {
    $failed = $index === 3;
    $rows[] = ['ResultID' => 101 + $index, 'RuleID' => $failed ? 90002 : null,
        'Status' => $failed ? 'FAIL' : 'PASS', 'Severity' => $failed ? 'MEDIUM' : 'INFO',
        'Standard' => $index === 0 ? 'CWE-778' : ($index === 1 ? 'CWE-117' : 'SecureLog Policy'),
        'VulnerabilityName' => $name, 'FilePath' => 'test22_plaintext_logged.php', 'LineNumber' => 32,
        'Description' => $failed ? 'Plaintext $message is written instead of the encrypted payload.' : 'Supported static evidence for this check was detected.',
        'MatchedCode' => $failed ? "file_put_contents(\n    __DIR__ . '/security.txt',\n    \$message . PHP_EOL,\n    FILE_APPEND | LOCK_EX\n);" : '',
        'Remediation' => $failed ? 'Write base64_encode($nonce . $encryptedLog), rather than $message. Keep the encryption key outside the source code.' : ''];
}
$report = securelogReportModel($scan, $rows);
$assert(count($report['groups']['FAIL']) === 1 && count($report['groups']['PASS']) === 3, 'Test 22 counts one failure and three passes');
$assert($report['standards'] === ['security' => 0, 'policy' => 1], 'Policy failure is separate from CWE failures');
$assert($report['highest'] === 'MEDIUM' && $report['severityCounts']['INFO'] === 0, 'Pass severity does not increase failed-check severity');
$allPassed = $rows;
$allPassed[3]['Status'] = 'PASS';
$allPassedModel = securelogReportModel($scan, $allPassed);
$assert(count($allPassedModel['groups']['PASS']) === 4 && $allPassedModel['groups']['FAIL'] === []
    && $allPassedModel['highest'] === 'No failed checks recorded', 'Test 21 all-pass report has zero failed checks');
$html = securelogReportHtml($report);
$assert(str_contains($html, 'format=pdf') && !str_contains($html, 'window.print'), 'Preview provides a real PDF download link');
$assert(str_contains($html, 'SL-2201-R104') && str_contains($html, 'Write base64_encode'), 'Stable references and saved remediation are included');
$assert(str_contains($html, 'file_put_contents('), 'Saved source evidence is included');
foreach (['Security Logging', 'Log Neutralization', 'Log Storage'] as $name) {
    $assert(str_contains($html, $name), 'Passed check details preserved: ' . $name);
}
$empty = securelogReportModel(array_merge($scan, ['Status' => 'Pending']), []);
$emptyHtml = securelogReportHtml($empty);
$assert(str_contains($emptyHtml, 'No security-check records are available.') && $empty['status'] === 'Pending', 'Zero results do not imply completed or secure scan');
$naRows = $rows;
$naRows[0]['Status'] = 'N/A';
$naRows[0]['Description'] = 'Dynamic include could not be resolved.';
$naRows[] = ['Status' => 'N/A', 'Standard' => 'SecureLog System', 'VulnerabilityName' => 'Scan Validation', 'Description' => 'Source file skipped.'];
$na = securelogReportModel($scan, $naRows);
$assert($na['total'] === 4 && count($na['groups']['SYSTEM']) === 1, 'Processing notes are separate from security check counts');
$assert(str_contains(securelogReportHtml($na), 'Dynamic include could not be resolved.'), 'Individual N/A reasons remain visible');
$attack = $rows;
$attack[3]['Description'] = '<script>alert(1)</script><img src="file:///secret">';
$attack[3]['MatchedCode'] = '<?php echo "<b>code</b>"; ?>';
$safeHtml = securelogReportHtml(securelogReportModel($scan, $attack));
$assert(!str_contains($safeHtml, '<script>') && !str_contains($safeHtml, '<img') && str_contains($safeHtml, '&lt;?php'), 'Untrusted descriptions and source are escaped');
$missing = $rows;
$missing[3]['MatchedCode'] = '';
$assert(str_contains(securelogReportHtml(securelogReportModel($scan, $missing)), 'No code snippet was saved.'), 'Missing snippets are disclosed without reading disk paths');
$bytes = securelogReportPdf($report);
$assert(str_starts_with($bytes, '%PDF-'), 'Sample report is actual PDF bytes');
$emptyPdf = securelogReportPdf($empty);
$assert(str_starts_with($emptyPdf, '%PDF-'), 'Zero-result report remains downloadable');
$stressRows = $rows;
for ($i = 0; $i < 16; $i++) {
    $row = $rows[3];
    $row['ResultID'] = 200 + $i;
    $row['FilePath'] = 'src/' . str_repeat('long-directory/', 8) . 'module_' . $i . '.php';
    $row['Description'] = str_repeat('Review the plaintext data flow before writing the log. ', 12);
    $row['MatchedCode'] = implode("\n", array_fill(0, $i === 15 ? 100 : 5, '// Recorded code evidence: plaintext message'));
    $stressRows[] = $row;
}
$stressRows[count($stressRows) - 1]['Description'] .= ' END_OF_STRESS_EVIDENCE';
$stress = securelogReportPdf(securelogReportModel($scan, $stressRows));
$assert(str_starts_with($stress, '%PDF-'), 'Long multi-page report renders');
if (isset($argv[1])) {
    $output = rtrim($argv[1], '/\\');
    if (!is_dir($output) && !mkdir($output, 0700, true)) throw new RuntimeException('Unable to create output directory.');
    file_put_contents($output . '/SecureLog-report-example.pdf', $bytes);
    file_put_contents($output . '/SecureLog-empty-check.pdf', $emptyPdf);
    file_put_contents($output . '/SecureLog-stress-check.pdf', $stress);
    file_put_contents($output . '/SecureLog-report-example.html', $html);
    echo "Saved synthetic preview PDFs.\n";
}
