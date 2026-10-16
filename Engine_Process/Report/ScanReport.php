<?php
/** Shared report data and rendering. Never loads source files or executes snippets. */
function securelogReportEscape(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function securelogReportModel(array $scan, array $rows): array
{
    $scanId = (int) ($scan['ScanID'] ?? 0);
    $groups = ['FAIL' => [], 'PASS' => [], 'N/A' => [], 'SYSTEM' => []];
    $severityCounts = array_fill_keys(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], 0);
    $standards = ['security' => 0, 'policy' => 0];
    foreach ($rows as $index => $row) {
        $status = strtoupper(trim((string) ($row['Status'] ?? 'N/A')));
        if (!in_array($status, ['FAIL', 'PASS', 'N/A'], true)) $status = 'N/A';
        $severity = strtoupper(trim((string) ($row['Severity'] ?? 'INFO')));
        if (!array_key_exists($severity, $severityCounts)) $severity = 'INFO';
        $ruleId = (int) ($row['RuleID'] ?? 0);
        $standard = trim((string) ($row['Standard'] ?? ''));
        if ($standard === '') {
            $standard = in_array($ruleId, [77801, 77802, 77803], true) ? 'CWE-778'
                : (($ruleId >= 11700 && $ruleId < 11800) ? 'CWE-117' : 'SecureLog Policy');
        }
        $name = trim((string) ($row['VulnerabilityName'] ?? '')) ?: 'Security Check';
        $group = $standard === 'SecureLog System' || $name === 'Scan Validation' ? 'SYSTEM' : $status;
        $row = array_merge($row, ['Status' => $status, 'Severity' => $severity,
            'Standard' => $standard, 'VulnerabilityName' => $name,
            'Reference' => 'SL-' . $scanId . '-R' . ((int) ($row['ResultID'] ?? 0) ?: $index + 1)]);
        $groups[$group][] = $row;
        if ($group === 'FAIL') {
            $severityCounts[$severity]++;
            $standards[str_starts_with($standard, 'CWE-') ? 'security' : 'policy']++;
        }
    }
    $ranks = array_flip(array_keys($severityCounts));
    usort($groups['FAIL'], static fn(array $a, array $b): int =>
        ($ranks[$a['Severity']] <=> $ranks[$b['Severity']])
        ?: strcmp((string) ($a['FilePath'] ?? ''), (string) ($b['FilePath'] ?? ''))
        ?: ((int) ($a['LineNumber'] ?? 0) <=> (int) ($b['LineNumber'] ?? 0)));
    $highest = 'No failed checks recorded';
    foreach ($severityCounts as $severity => $count) {
        if ($count > 0) { $highest = $severity; break; }
    }
    return ['id' => $scanId,
        'project' => $scan['ProjectName'] ?? $scan['projectName'] ?? $scan['project_name'] ?? 'Untitled project',
        'language' => $scan['ProgrammingLanguage'] ?? $scan['Language'] ?? 'Not recorded',
        'date' => $scan['ScanDate'] ?? $scan['scan_date'] ?? 'Not recorded',
        // Preserve recorded state; never turn a Pending scan into Completed.
        'status' => $scan['Status'] ?? $scan['status'] ?? 'Not recorded',
        'files' => (int) ($scan['total_files'] ?? $scan['TotalFiles'] ?? 0),
        'generated' => (new DateTimeImmutable('now', new DateTimeZone('Asia/Kuala_Lumpur')))->format('d M Y, H:i T'),
        'groups' => $groups, 'severityCounts' => $severityCounts, 'standards' => $standards,
        'total' => count($groups['FAIL']) + count($groups['PASS']) + count($groups['N/A']),
        'highest' => $highest];
}

function securelogReportRecommendation(array $row): string
{
    $saved = trim((string) ($row['Remediation'] ?? ''));
    if ($saved !== '') return $saved;
    if ($row['Status'] === 'N/A') return 'Review the reason below and inspect the logger implementation or deployment configuration where static evidence is unavailable.';
    return match (strtolower($row['VulnerabilityName'])) {
        'security logging' => 'Record the security event on every relevant path, including failure and denial paths. Exclude passwords, tokens and other secrets.',
        'log neutralization' => 'Neutralize CR, LF and unsafe control characters in external input before the actual value reaches the logging operation.',
        'log storage' => 'Use an explicit .txt destination if required by the SecureLog project policy. Verify filesystem permissions and access restrictions separately.',
        'log protection' => 'Write the protected payload to the log, rather than plaintext. Manage encryption keys separately and verify integrity during decryption.',
        default => 'Review the recorded evidence, correct the failed check, and rescan the affected files.'
    };
}

function securelogReportImpact(array $row): string
{
    return match (strtolower($row['VulnerabilityName'])) {
        'security logging' => 'A missing event record can make suspicious activity harder to detect and investigate.',
        'log neutralization' => 'Untrusted control characters may create misleading or forged log entries.',
        'log storage' => 'The recorded destination does not meet this project\'s storage policy. File extensions alone do not establish secure storage.',
        'log protection' => 'Unprotected log contents may be exposed to anyone who can read the stored data.',
        default => 'Review this finding in the context of the application and its deployment.'
    };
}

function securelogReportHtml(array $report, bool $pdf = false): string
{
    ob_start();
    require __DIR__ . '/report_template.php';
    return (string) ob_get_clean();
}

function securelogReportPdf(array $report): string
{
    require_once dirname(__DIR__, 2) . '/vendor/autoload.php';
    $options = new Dompdf\Options();
    $options->setDefaultFont('DejaVu Sans');
    $options->setIsRemoteEnabled(false);
    $options->setIsPhpEnabled(false);
    $options->setIsJavascriptEnabled(false);
    $options->setChroot(dirname(__DIR__, 2) . '/vendor/dompdf/dompdf');
    $options->setAllowedProtocols([]);
    $options->setDefaultMediaType('print');
    $pdf = new Dompdf\Dompdf($options);
    $pdf->setPaper('A4', 'portrait');
    $pdf->loadHtml(securelogReportHtml($report, true), 'UTF-8');
    $pdf->render();
    $id = (int) $report['id'];
    $pdf->getCanvas()->page_script(static function ($pageNumber, $pageCount, $canvas, $fontMetrics) use ($id): void {
        $font = $fontMetrics->getFont('DejaVu Sans', 'normal');
        $canvas->text(38, 809, 'SECURELOG  |  Scan #' . $id, $font, 8, [0.67, 0.74, 0.82]);
        $label = 'Page ' . $pageNumber . ' of ' . $pageCount;
        $width = $fontMetrics->getTextWidth($label, $font, 8);
        $canvas->text(557 - $width, 809, $label, $font, 8, [0.67, 0.74, 0.82]);
    });
    $pdf->addInfo('Title', 'SecureLog Report - Scan ' . $id);
    $pdf->addInfo('Author', 'SecureLog');
    return $pdf->output();
}
