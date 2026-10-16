<?php
if (!isset($report, $pdf) || !function_exists('securelogReportEscape')) {
    http_response_code(404); exit('Not found.');
}
$esc = 'securelogReportEscape';
$groups = $report['groups'];
$summary = [];
$fixes = [];
foreach (['FAIL', 'PASS', 'N/A'] as $status) {
    foreach ($groups[$status] as $row) {
        $key = $row['VulnerabilityName'] . '|' . $row['Standard'];
        $summary[$key] ??= ['name' => $row['VulnerabilityName'], 'standard' => $row['Standard'], 'FAIL' => 0, 'PASS' => 0, 'N/A' => 0];
        $summary[$key][$status]++;
        if ($status === 'FAIL') $fixes[$key] ??= $row;
    }
}
?>
<!doctype html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureLog Compact Report - Scan <?= (int) $report['id'] ?></title>
<style>
@page { margin:38pt 38pt 48pt; }
body { margin:0; color:#e6edf6; background:#07111f; font-family:"DejaVu Sans",sans-serif; font-size:8.2pt; line-height:1.45; }
.pdf-background { position:fixed; top:-38pt; right:-38pt; bottom:-48pt; left:-38pt; background:#07111f; z-index:-1000; }
.page { max-width:1000px; margin:auto; }
.actions { background:#102238; padding:12px; margin-bottom:18px; }
.actions a { color:#e6edf6; display:inline-block; margin-right:14px; text-decoration:none; }
.download { background:#087e52; padding:7px 12px; border-radius:4px; }
.header { border-top:4px solid #3c9de5; padding-top:12px; }
.eyebrow { color:#69bfff; font-size:7pt; letter-spacing:1.3px; }
h1 { margin:5px 0; font-size:21pt; color:#f3f7fc; }
h2 { margin:16px 0 7px; font-size:11pt; color:#f3f7fc; page-break-after:avoid; }
p { margin:5px 0; }
.muted,.ref { color:#acbdd0; }
.ref { font-size:6.8pt; }
.stats { border-collapse:collapse; table-layout:fixed; width:100%; margin:12px 0; }
.stats td { background:#102238; padding:9px; border:2px solid #07111f; }
.stats strong { font-size:18pt; display:block; }
.stats span { color:#acbdd0; font-size:7pt; }
.notice { background:#102238; padding:9px; border-left:3px solid #3c9de5; }
table.list { width:100%; table-layout:fixed; border-collapse:collapse; }
.list thead { display:table-header-group; }
.list th { color:#69bfff; font-size:7pt; text-align:left; background:#102238; }
.list th,.list td { padding:6px; vertical-align:top; border-bottom:1px solid #263b52; word-wrap:break-word; }
.list tr { page-break-inside:avoid; }
.badge { font-weight:bold; font-size:7pt; color:#ffacb7; }
.action { border-bottom:1px solid #263b52; padding:7px 0; page-break-inside:avoid; }
.action p { margin:3px 0; }
.notes { margin-top:14px; padding-top:8px; border-top:1px solid #263b52; font-size:7.2pt; color:#acbdd0; }
@media screen { body { background:#020817; } .page { background:#07111f; padding:25px 30px; margin:20px auto; } }
@media print { .actions { display:none; } body { print-color-adjust:exact; -webkit-print-color-adjust:exact; } }
</style></head><body>
<?php if ($pdf): ?><div class="pdf-background"></div><?php endif; ?>
<main class="page">
<?php if (!$pdf): ?><nav class="actions">
<a href="index.php?scan_id=<?= (int) $report['id'] ?>">Back to scan</a>
<a class="download" href="Download_report.php?scan_id=<?= (int) $report['id'] ?>&amp;format=pdf">Download PDF</a>
<a href="Download_report.php?scan_id=<?= (int) $report['id'] ?>&amp;detail=full">Full report &amp; evidence</a>
</nav><?php endif; ?>
<header class="header"><div class="eyebrow">SECURELOG / COMPACT REPORT</div>
<h1><?= $esc($report['project']) ?></h1>
<p class="muted">Scan #<?= (int) $report['id'] ?> · <?= $esc($report['language']) ?> · Scan date: <?= $esc($report['date']) ?></p>
<p class="muted">Recorded status: <?= $esc($report['status']) ?> · Generated <?= $esc($report['generated']) ?></p></header>
<table class="stats"><tr>
<?php foreach (['FAIL' => 'Failed checks', 'PASS' => 'Passed checks', 'N/A' => 'N/A checks'] as $key => $label): ?>
<td><strong><?= count($groups[$key]) ?></strong><span><?= $label ?></span></td>
<?php endforeach; ?><td><strong><?= (int) $report['files'] ?></strong><span>Files submitted</span></td>
</tr></table>
<p><strong>Highest failed-check severity:</strong> <?= $esc($report['highest']) ?>.</p>
<p class="muted"><?= (int) $report['standards']['security'] ?> failed CWE check(s); <?= (int) $report['standards']['policy'] ?> failed project-policy or other check(s).</p>
<?php if ($report['total'] === 0): ?>
<div class="notice"><strong>No security-check records are available.</strong> Confirm the processing outcome in Scan Coverage or the activity log. No results does not prove completion or secure code.</div>
<?php else: ?>
<div class="notice">All <?= count($groups['FAIL']) ?> failed checks are listed below. PASS and N/A are aggregated by check type; individual reasons and saved code evidence remain in the full report.</div>
<?php endif; ?>
<h2>1. Fix these first (<?= count($groups['FAIL']) ?>)</h2>
<?php if (!$groups['FAIL']): ?><p>No failed checks recorded. Review N/A checks before accepting the result.</p><?php else: ?>
<table class="list"><thead><tr><th style="width:12%">Severity</th><th style="width:36%">File / line</th><th style="width:52%">Check / finding reference</th></tr></thead><tbody>
<?php foreach ($groups['FAIL'] as $row): ?>
<tr><td><span class="badge"><?= $esc($row['Severity']) ?></span></td>
<td><?= $esc($row['FilePath'] ?? 'Not recorded') ?><br><span class="ref">Line <?= (int) ($row['LineNumber'] ?? 0) > 0 ? (int) $row['LineNumber'] : 'not recorded' ?></span></td>
<td><strong><?= $esc($row['VulnerabilityName']) ?></strong><br><span class="ref"><?= $esc($row['Standard']) ?> · <?= $esc($row['Reference']) ?></span></td></tr>
<?php endforeach; ?></tbody></table>
<?php endif; ?>
<?php if ($fixes): ?><h2>2. Recommended actions by check type</h2>
<?php foreach ($fixes as $fix): ?>
<div class="action"><strong><?= $esc($fix['VulnerabilityName']) ?></strong> <span class="ref"><?= $esc($fix['Standard']) ?></span>
<?php $generic = $fix; $generic['Remediation'] = ''; ?>
<p><?= $esc(securelogReportRecommendation($generic)) ?></p></div>
<?php endforeach; ?>
<p class="muted">Actions above are general guidance. Use the full report for each finding's recorded explanation and specific recommendation.</p>
<?php endif; ?>
<?php if ($summary): ?><h2><?= $fixes ? '3' : '2' ?>. Check summary</h2>
<table class="list"><thead><tr><th style="width:64%">Check / standard</th><th style="width:12%">FAIL</th><th style="width:12%">PASS</th><th style="width:12%">N/A</th></tr></thead><tbody>
<?php foreach ($summary as $item): ?>
<tr><td><?= $esc($item['name']) ?> <span class="ref"><?= $esc($item['standard']) ?></span></td><td><?= (int) $item['FAIL'] ?></td><td><?= (int) $item['PASS'] ?></td><td><?= (int) $item['N/A'] ?></td></tr>
<?php endforeach; ?></tbody></table><?php endif; ?>
<?php if ($groups['SYSTEM']): ?><div class="notice"><?= count($groups['SYSTEM']) ?> processing note(s) recorded. Review the full report for skipped files or processing errors; these are not included in security-check counts.</div><?php endif; ?>
<div class="notes"><strong>Read with these limits:</strong> PASS means supported static criteria were met; N/A means not applicable or unverified. Neither proves secure code. Only FAIL counts as a failed check. The .txt and encryption requirements are project policies. Submitted files are not necessarily analyzed files; check Scan Coverage. Full report: History → View Report → Full report &amp; evidence. Keep Scan #<?= (int) $report['id'] ?> with the matching source revision.</div>
</main></body></html>
