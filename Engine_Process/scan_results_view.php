<?php
if (!isset($presentation, $scan_info) || !function_exists('securelogPresentationEscape')) {
    http_response_code(404); exit('Not found.');
}
$escape = 'securelogPresentationEscape';
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
<div><strong><?= (int) $presentation['events'] ?></strong><span>Event / check groups</span></div>
</div>
<p class="scan-guidance">Files and event groups with failed checks appear first and open automatically. PASS and N/A remain available inside each group.</p>
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
<details class="scan-file" <?= $file['failed'] > 0 ? 'open' : '' ?>>
<summary><span class="scan-path"><?= $escape($file['path']) ?></span>
<span class="scan-count <?= $file['failed'] > 0 ? 'has-fail' : '' ?>"><?= (int) $file['failed'] ?> FAIL · <?= count($file['events']) ?> group(s)</span></summary>
<div class="scan-file-content">
<?php foreach ($file['events'] as $event): ?>
<details class="scan-event" <?= $event['failed'] > 0 ? 'open' : '' ?>>
<summary><span><?= $escape($event['name']) ?><?= $event['line'] > 0 ? ' · Line ' . (int) $event['line'] : '' ?></span>
<span class="scan-count"><?= (int) $event['counts']['FAIL'] ?> FAIL / <?= (int) $event['counts']['PASS'] ?> PASS / <?= (int) $event['counts']['N/A'] ?> N/A</span></summary>
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
</tbody></table></details>
<?php endforeach; ?>
<?php foreach ($file['notes'] as $note): ?>
<div class="scan-message"><strong>Processing note</strong><p><?= $escape($note['Description'] ?? '') ?></p></div>
<?php endforeach; ?>
</div></details>
<?php endforeach; ?>
<?php if (!$coverage && $presentation['files']): ?><p class="scan-guidance">This scan predates event metadata. Groups are reconstructed from saved check order and are not a complete event inventory.</p><?php endif; ?>
<details class="scan-coverage" open><summary>Scan Coverage</summary>
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
