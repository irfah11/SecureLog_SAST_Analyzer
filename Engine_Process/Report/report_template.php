<?php
if (!isset($report, $pdf) || !function_exists('securelogReportEscape')) {
    http_response_code(404);
    exit('Not found.');
}
$esc = 'securelogReportEscape';
$groups = $report['groups'];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureLog Report - Scan <?= (int) $report['id'] ?></title>
<style>
@page { margin: 38pt 38pt 48pt; background-color:#07111f; }
* { box-sizing: border-box; }
body { margin:0; color:#e6edf6; background:#07111f; font-family:"DejaVu Sans",sans-serif; font-size:9pt; line-height:1.55; }
.page { max-width:950px; margin:auto; }
.pdf-background { position:fixed; top:-38pt; right:-38pt; bottom:-48pt; left:-38pt; background:#07111f; z-index:-1000; }
.actions { background:#07162b; padding:15px 22px; margin-bottom:26px; }
.actions a { display:inline-block; color:white; text-decoration:none; margin-right:18px; }
.actions .download { background:#087e52; padding:9px 16px; border-radius:5px; }
.eyebrow { font-size:8pt; font-weight:bold; color:#69bfff; letter-spacing:1.6px; }
h1 { font-size:25pt; line-height:1.2; margin:7px 0 8px; color:#f3f7fc; }
h2 { font-size:13pt; margin:23px 0 10px; color:#f3f7fc; border-bottom:1px solid #2b4058; padding-bottom:6px; page-break-after:avoid; }
h3 { font-size:10pt; margin:0 0 7px; page-break-after:avoid; }
p { margin:6px 0; }
.muted { color:#acbdd0; }
.header { border-top:5px solid #3c9de5; border-bottom:1px solid #2b4058; padding:18px 0 15px; }
.stats { width:100%; border-collapse:collapse; margin:17px 0 12px; table-layout:fixed; }
.stats td { background:#102238; border:3px solid #07111f; padding:11px 9px; vertical-align:top; }
.stats strong { display:block; font-size:21pt; color:#f3f7fc; }
.stats span { font-size:8pt; color:#acbdd0; }
.notice { background:#102238; border-left:3px solid #3c9de5; padding:10px 12px; margin:10px 0; }
.metadata { width:100%; border-collapse:collapse; table-layout:fixed; }
.metadata td { padding:5px 7px; border-bottom:1px solid #263b52; vertical-align:top; word-wrap:break-word; }
.metadata td:first-child { width:29%; color:#acbdd0; }
.finding { border-top:2px solid #2b4058; padding-top:12px; margin-top:17px; }
.finding-head { page-break-inside:avoid; page-break-after:avoid; }
.finding p { white-space:pre-wrap; word-wrap:break-word; }
.ref { font-size:8pt; color:#acbdd0; margin-bottom:5px; }
.badge { font-size:8pt; font-weight:bold; padding:3px 7px; background:#22364b; }
.fail { color:#ffacb7; background:#482333; }
.pass { color:#8ce4b8; background:#163c32; }
.na { color:#cad6e4; background:#22364b; }
.field { font-size:8pt; text-transform:uppercase; color:#acbdd0; font-weight:bold; margin-top:10px; page-break-after:avoid; }
pre { background:#0b192b; padding:9px; font-family:"DejaVu Sans Mono",monospace; font-size:7.4pt; white-space:pre-wrap; word-wrap:break-word; }
.compact { border-top:1px solid #2b4058; padding:9px 0; page-break-inside:avoid; }
.compact p { white-space:pre-wrap; word-wrap:break-word; }
.compact-title { page-break-after:avoid; font-weight:bold; }
.footer-note { border-top:1px solid #2b4058; margin-top:23px; padding-top:9px; color:#acbdd0; font-size:8pt; }
@media screen { body { background:#020817; } .page { background:#07111f; padding:26px 36px 40px; margin:22px auto; } }
@media print { body { print-color-adjust:exact; -webkit-print-color-adjust:exact; } .actions { display:none; } }
</style>
</head>
<body>
<?php if ($pdf): ?><div class="pdf-background"></div><?php endif; ?>
<main class="page">
<?php if (!$pdf): ?>
<nav class="actions" aria-label="Report actions">
<a href="index.php?scan_id=<?= (int) $report['id'] ?>">Back to scan</a>
<a class="download" href="Download_report.php?scan_id=<?= (int) $report['id'] ?>&amp;format=pdf">Download PDF</a>
</nav>
<?php endif; ?>
<header class="header">
<div class="eyebrow">SECURELOG / ENGINEERING REPORT</div>
<h1>Security logging review</h1>
<p><?= $esc($report['project']) ?></p>
<p class="muted">Scan #<?= (int) $report['id'] ?> &nbsp; | &nbsp; Generated <?= $esc($report['generated']) ?></p>
</header>
<table class="stats"><tr>
<?php foreach (['FAIL' => 'Failed checks', 'PASS' => 'Passed checks', 'N/A' => 'N/A checks'] as $key => $label): ?>
<td><strong><?= count($groups[$key]) ?></strong><span><?= $label ?></span></td>
<?php endforeach; ?>
<td><strong><?= (int) $report['files'] ?></strong><span>Files submitted</span></td>
</tr></table>
<p><strong>Highest failed-check severity:</strong> <?= $esc($report['highest']) ?>.</p>
<p class="muted"><?= (int) $report['standards']['security'] ?> failed CWE check(s); <?= (int) $report['standards']['policy'] ?> failed project-policy or other check(s). PASS and N/A are not vulnerabilities.</p>
<?php if ($report['total'] === 0): ?>
<div class="notice"><strong>No security-check records are available.</strong>
<p>A file without supported security events generates no event checks. This report alone cannot distinguish that outcome from an incomplete scan; confirm the scan outcome in the application activity log. An empty result is not proof that the code is secure.</p></div>
<?php elseif ($groups['FAIL'] === []): ?>
<div class="notice">No failed checks were recorded. Review the N/A checks and analysis limits before accepting the result.</div>
<?php else: ?>
<div class="notice">Start with the failed checks below, ordered by severity. Each reference identifies a saved result for follow-up and rescanning.</div>
<?php endif; ?>
<h2>1. Scan details</h2>
<table class="metadata">
<?php foreach (['Project' => $report['project'], 'Scan ID' => $report['id'],
    'Language' => $report['language'], 'Scan date (recorded)' => $report['date'],
    'Status (recorded)' => $report['status'], 'Files submitted' => $report['files'],
    'Security checks recorded' => $report['total'], 'Scan processing notes' => count($groups['SYSTEM'])] as $label => $value): ?>
<tr><td><?= $esc($label) ?></td><td><?= $esc($value) ?></td></tr>
<?php endforeach; ?>
</table>
<p class="muted">Dates and status are reproduced from the saved scan. Submitted files are not necessarily successfully analyzed files.</p>
<h2>2. Issues requiring action (<?= count($groups['FAIL']) ?>)</h2>
<?php if (!$groups['FAIL']): ?><p>No failed security or policy checks were recorded.</p><?php endif; ?>
<?php foreach ($groups['FAIL'] as $row): ?>
<article class="finding">
<div class="finding-head">
<div class="ref"><?= $esc($row['Reference']) ?> | Saved result #<?= (int) ($row['ResultID'] ?? 0) ?></div>
<h3><?= $esc($row['VulnerabilityName']) ?> &nbsp; <span class="badge fail">FAIL / <?= $esc($row['Severity']) ?></span></h3>
<table class="metadata">
<tr><td>File</td><td><?= $esc($row['FilePath'] ?? 'Not recorded') ?></td></tr>
<tr><td>Line</td><td><?= (int) ($row['LineNumber'] ?? 0) > 0 ? (int) $row['LineNumber'] : 'Not recorded' ?></td></tr>
<tr><td>Standard / policy</td><td><?= $esc($row['Standard']) ?><?= !empty($row['RuleID']) ? ' | Rule ' . (int) $row['RuleID'] : '' ?></td></tr>
</table>
</div>
<div class="field">What was detected</div><p><?= $esc($row['Description'] ?? 'No description recorded.') ?></p>
<div class="field">Why it matters</div><p><?= $esc(securelogReportImpact($row)) ?></p>
<div class="field">Recommended action</div><p><?= $esc(securelogReportRecommendation($row)) ?></p>
<div class="field">Recorded code evidence</div>
<?php if (trim((string) ($row['MatchedCode'] ?? '')) !== ''): ?>
<pre><?= $esc($row['MatchedCode']) ?></pre>
<?php else: ?><p class="muted">No code snippet was saved. Inspect the original source at the file and line shown above.</p><?php endif; ?>
<p class="muted">Verification: rescan the affected files after the change, and test the relevant logging behavior.</p>
</article>
<?php endforeach; ?>
<?php foreach (['PASS' => '3. Passed checks', 'N/A' => '4. Checks requiring interpretation', 'SYSTEM' => '5. Scan processing notes'] as $key => $heading): ?>
<h2><?= $heading ?> (<?= count($groups[$key]) ?>)</h2>
<?php if (!$groups[$key]): ?><p class="muted">No records in this section.</p><?php endif; ?>
<?php foreach ($groups[$key] as $row): ?>
<div class="compact">
<div class="finding-head">
<div class="ref"><?= $esc($row['Reference']) ?></div>
<div class="compact-title"><span class="badge <?= $key === 'PASS' ? 'pass' : 'na' ?>"><?= $key === 'SYSTEM' ? 'SCAN NOTE' : $key ?></span> <?= $esc($row['VulnerabilityName']) ?></div>
</div>
<p class="muted"><?= $esc($row['FilePath'] ?? 'Not recorded') ?> | Line <?= (int) ($row['LineNumber'] ?? 0) > 0 ? (int) $row['LineNumber'] : 'not recorded' ?> | <?= $esc($row['Standard']) ?></p>
<p><?= $esc($row['Description'] ?? 'No description recorded.') ?></p>
<?php if ($key === 'N/A'): ?><p><strong>Follow-up:</strong> <?= $esc(securelogReportRecommendation($row)) ?></p><?php endif; ?>
</div>
<?php endforeach; ?>
<?php endforeach; ?>
<h2>6. How to interpret this report</h2>
<p><strong>FAIL:</strong> a security or policy check failed. Validate the evidence and prioritize remediation.</p>
<p><strong>PASS:</strong> the recorded check met the scanner's supported static criteria. It does not guarantee runtime logging or application security.</p>
<p><strong>N/A:</strong> the check was not applicable or could not be verified. Read each reason; N/A is not PASS.</p>
<p>SecureLog examines selected source patterns without running the uploaded application. Complex control flow, dynamic includes, external logger implementations and deployment configuration may require manual review. Analysis capabilities differ by language.</p>
<p>The .txt storage requirement and log-encryption checks are SecureLog project policies, separate from CWE-778 and CWE-117. A file extension does not establish secure storage, and an encryption call alone does not prove correct key management.</p>
<div class="footer-note">Saved scan snapshot | Scan #<?= (int) $report['id'] ?> | Keep this report with the matching source revision. Correcting code does not update an earlier scan; run a new scan to verify changes.</div>
</main></body></html>
