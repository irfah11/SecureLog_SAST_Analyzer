<?php
if (!isset($presentation) || !function_exists('securelogPresentationEscape')) {
    http_response_code(404); exit('Not found.');
}
$escape = 'securelogPresentationEscape';
$scan_info = $scan_info ?? null;
$counts = $presentation['counts'];
$coverage = $presentation['coverage'];
?>
<?php if (!$scan_info): ?>
<div class="empty-state"><div><i class="fas fa-info"></i><strong>Ready to analyze</strong><p>Upload source files or a project folder to start a scan.</p></div></div>
<?php else: ?>
<div class="scan-overview" aria-label="Scan summary">
<?php foreach (['FAIL' => 'Failed checks', 'PASS' => 'Passed checks', 'N/A' => 'N/A checks'] as $key => $label): ?>
<div><strong><?= (int) $counts[$key] ?></strong><span><?= $label ?></span></div>
<?php endforeach; ?>
</div>
<p class="scan-guidance">Each file shows four check summaries. Status priority: FAIL, then N/A, then PASS. Expand event details to inspect the original evidence. Counts above are recorded event checks, not file summaries.</p>
<?php if (!$presentation['files']): ?>
<div class="scan-message">
<?php if ($coverage && $coverage['outcome'] === 'completed'): ?>
<strong>Analysis completed with no security checks generated.</strong>
<p>Review Scan Coverage below. Files without supported events do not generate event checks; this does not prove the code is secure.</p>
<?php else: ?>
<strong>No security-check records are available.</strong>
<p>Review Scan Coverage or the activity log to confirm the processing outcome. An empty result does not establish that the scan completed or the code is secure.</p>
<?php endif; ?>
</div>
<?php endif; ?>
<?php foreach ($presentation['files'] as $fileNumber => $file): ?>
<details class="scan-file" <?= $file['failed'] > 0 || count($presentation['files']) === 1 ? 'open' : '' ?>>
<summary><span class="scan-path"><?= $escape($file['path']) ?></span></summary>
<div class="scan-file-content">
<?php if ($file['summary']): ?>
<table class="analysis-table file-check-summary"><thead><tr><th>Status</th><th>Check</th><th>Summary</th></tr></thead><tbody>
<?php foreach ($file['summary'] as $summary): ?>
<tr><td><span class="status <?= $escape(getStatusClass($summary['status'])) ?>"><i class="fas <?= $escape(getStatusIcon($summary['status'])) ?>"></i> <?= $escape($summary['status']) ?></span></td>
<td><span class="check-name"><?= $escape($summary['name']) ?></span></td>
<td><div class="detail-text"><?= $escape($summary['description']) ?></div>
<div class="result-meta"><?php foreach (['FAIL','PASS','N/A'] as $status): ?><span class="meta-badge"><?= (int)$summary['counts'][$status] ?> <?= $escape($status) ?></span><?php endforeach; ?></div></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php endif; ?>
<?php if (!empty($file['custom_rules'])): ?>
<section class="custom-rule-results" style="margin:14px;border:1px solid #263b52;border-radius:8px;overflow:hidden;">
<h4 style="margin:14px;color:#b9d5f2;">Custom rules used in this scan</h4>
<p class="scan-guidance" style="margin:14px;">Active rules for the selected language. No match is not a security PASS.</p>
<table class="analysis-table"><thead><tr><th>Result</th><th>Rule</th><th>Detail</th></tr></thead><tbody>
<?php foreach ($file['custom_rules'] as $custom): ?>
<tr><td><?= $escape($custom['status'] ?? 'Unknown') ?></td>
<td><strong><?= $escape($custom['code'] ?? '') ?></strong><br><?= $escape($custom['name'] ?? '') ?></td>
<td><?= (int) ($custom['matches'] ?? 0) ?> match(es)<div class="result-meta"><span class="meta-badge"><?= $escape($custom['standard'] ?? '') ?></span><span class="meta-badge"><?= $escape($custom['language'] ?? '') ?></span></div></td></tr>
<?php endforeach; ?>
</tbody></table></section>
<?php else: ?>
<?php if (!empty($file['custom_rule_error'])): ?>
<p class="scan-guidance" style="margin:14px;">Custom rules could not be loaded for this file. They were not evaluated.</p>
<?php elseif (array_key_exists('custom_rules',$file)): ?>
<p class="scan-guidance" style="margin:14px;">No active custom rules for this language were loaded at scan time.</p>
<?php else: ?>
<p class="scan-guidance" style="margin:14px;">No per-file custom-rule evaluation record is available here. Scan Coverage identifies the files processed; rerun older scans to capture which active rules were evaluated.</p>
<?php endif; ?>
<?php endif; ?>
<?php if ($file['rows']): ?>
<details class="scan-event-details" style="margin:14px;border:1px solid #263b52;border-radius:8px;overflow:hidden;">
<summary style="cursor:pointer;padding:12px;color:#9acfff;">View details · <?= count($file['rows']) ?> recorded checks / additional findings</summary>
<p class="scan-guidance" style="padding:0 14px;">Original event results are retained below. Custom rules and historical extra checks are shown here separately from the four summaries.</p>
<?php foreach ($file['events'] as $event): ?>
<section class="scan-event-evidence" style="padding:0 10px 12px;">
<h4 style="margin:14px 4px;color:#b9d5f2;font-size:13px;"><?= $escape($event['name']) ?> · Line <?= (int)$event['line'] ?></h4>
<table class="analysis-table"><thead><tr><th>Status</th><th>Check</th><th>Detail</th></tr></thead><tbody>
<?php foreach ($event['rows'] as $row): ?>
<tr id="result-<?= (int) ($row['ResultID'] ?? 0) ?>">
<td><span class="status <?= $escape(getStatusClass($row['Status'])) ?>"><i class="fas <?= $escape(getStatusIcon($row['Status'])) ?>"></i> <?= $escape($row['Status']) ?></span></td>
<td><span class="check-name"><?= $escape(getCheckName($row)) ?></span></td>
<td><div class="detail-text"><?= $escape(getDetail($row)) ?></div>
<div class="result-meta">
<?php foreach (['Standard' => '', 'Severity' => 'Severity: ', 'RuleID' => 'Rule: ', 'LineNumber' => 'Line: '] as $field => $label): ?>
<?php if (!empty($row[$field])): ?><span class="meta-badge"><?= $escape($label . $row[$field]) ?></span><?php endif; ?>
<?php endforeach; ?>
</div></td></tr>
<?php endforeach; ?>
</tbody></table>

</section>
<?php endforeach; ?>
</details>
<?php endif; ?>
<?php foreach ($file['notes'] as $note): ?>
<div class="scan-message"><strong>Processing note</strong><p><?= $escape($note['Description'] ?? '') ?></p></div>
<?php endforeach; ?>
</div></details>
<?php endforeach; ?>
<details class="scan-coverage"><summary>Scan Coverage</summary>
<?php if (!$coverage): ?>
<p class="scan-guidance">Per-file coverage was not recorded for this scan. <?= (int) ($scan_info['total_files'] ?? $scan_info['TotalFiles'] ?? 0) ?> file(s) were submitted, but files without findings cannot be confirmed as analyzed from these records. Run a new scan to capture coverage.</p>
<?php else: ?>
<?php
$coverageCounts = ['analyzed' => 0, 'no_events' => 0, 'unsupported' => 0, 'rejected' => 0, 'analysis_failed' => 0];
foreach ($coverage['files'] as $item) {
    if (isset($coverageCounts[$item['status'] ?? ''])) $coverageCounts[$item['status']]++;
}
$labels = ['analyzed' => 'Analyzed with checks', 'no_events' => 'No supported event',
    'unsupported' => 'Unsupported extension', 'rejected' => 'Validation rejected', 'analysis_failed' => 'Analysis failed'];
?>
<p class="scan-guidance"><strong>Outcome:</strong> <?= $escape(str_replace('_', ' ', $coverage['outcome'])) ?> · <?= count($coverage['files']) ?> submitted file(s).</p>
<p class="scan-guidance"><?= $coverageCounts['analyzed'] ?> analyzed with checks · <?= $coverageCounts['no_events'] ?> analyzed without supported events · <?= $coverageCounts['unsupported'] + $coverageCounts['rejected'] + $coverageCounts['analysis_failed'] ?> unsupported, rejected or failed.</p>
<table class="analysis-table coverage-table"><thead><tr><th>File</th><th>Processing status</th><th>Detail</th></tr></thead><tbody>
<?php foreach ($coverage['files'] as $item): ?>
<tr><td class="scan-path"><?= $escape($item['file'] ?? '') ?></td>
<td><?= $escape($labels[$item['status'] ?? ''] ?? 'Unknown') ?></td>
<td><?= $escape($item['reason'] ?? '') ?>
<?php if (($item['status'] ?? '') === 'analyzed'): ?><div class="result-meta"><span class="meta-badge"><?= (int) ($item['saved_checks'] ?? 0) ?> saved / <?= (int) ($item['checks'] ?? 0) ?> returned checks</span></div><?php endif; ?>
</td></tr>
<?php endforeach; ?>
</tbody></table>
<?php endif; ?>
<p class="scan-guidance">No supported event detected does not mean logging is unnecessary. Supply the relevant project files, including logger implementations. Only submitted files are covered.</p>
</details>
<?php endif; ?>
