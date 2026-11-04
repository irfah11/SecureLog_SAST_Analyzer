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
<!--<p class="scan-guidance">Each file shows three core check summaries. Neutralization is available through custom rules. Status priority: FAIL, then N/A, then PASS. Select Lihat sebab on a check to inspect its event evidence. Counts above are recorded event checks, not file summaries.</p>-->
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
<?php $displayedCustomResults = []; ?>
<?php if ($file['summary'] || !empty($file['custom_rules'])): ?>
<table class="analysis-table file-check-summary"><thead><tr><th>Status</th><th>Check</th><th>Summary</th></tr></thead><tbody>
<?php foreach ($file['summary'] as $summary): ?>
<tr><td><span class="status <?= $escape(getStatusClass($summary['status'])) ?>"><i class="fas <?= $escape(getStatusIcon($summary['status'])) ?>"></i> <?= $escape($summary['status']) ?></span></td>
<td><span class="check-name"><?= $escape($summary['name']) ?></span></td>
<td><div class="detail-text"><?= $escape($summary['description']) ?></div>
<div class="result-meta"><?php foreach (['FAIL','PASS','N/A'] as $status): ?><span class="meta-badge"><?= (int)$summary['counts'][$status] ?> <?= $escape($status) ?></span><?php endforeach; ?></div>
<details class="check-reasons" style="margin-top:10px;">
<summary style="cursor:pointer;color:#9acfff;padding:6px 0;">more details</summary>
<?php foreach ($file['events'] as $event): foreach ($event['rows'] as $row):
if (str_starts_with((string)($row['VulnerabilityName'] ?? ''),'[')) continue;
$evidenceCheck = ($row['VulnerabilityName'] ?? '') === 'Log Context' ? 'Security Logging' : getCheckName($row);
if ($evidenceCheck !== $summary['name']) continue;
?>
<div id="result-<?= (int)($row['ResultID'] ?? 0) ?>" style="padding:12px 0;border-top:1px solid #263b52;">
<strong><?= $escape($event['name']) ?></strong> · <span class="status <?= $escape(getStatusClass($row['Status'])) ?>"><?= $escape($row['Status']) ?></span> · Line <?= (int)($row['LineNumber'] ?? $event['line']) ?>
<p style="margin:8px 0;line-height:1.6;"><?= $escape(getDetail($row)) ?></p>
<div class="result-meta"><?php foreach (['Standard'=>'','Severity'=>'Severity: ','RuleID'=>'Rule: '] as $field=>$label): if (!empty($row[$field])): ?><span class="meta-badge"><?= $escape($label.$row[$field]) ?></span><?php endif; endforeach; ?></div>
</div>
<?php endforeach; endforeach; ?>
</details></td></tr>
<?php endforeach; ?>
<?php foreach (($file['custom_rules'] ?? []) as $custom):
$matchingRows = array_filter($file['rows'], static fn($row) => (int)($row['RuleID'] ?? 0) === (int)($custom['id'] ?? -1)
    && str_starts_with((string)($row['VulnerabilityName'] ?? ''),'['));
foreach ($matchingRows as $matchedRow) $displayedCustomResults[(int)($matchedRow['ResultID'] ?? 0)] = true;
$customStatus = $custom['status'] ?? 'Unknown';
?>
<tr class="custom-rule-inline" style="background:rgba(0,191,243,.055);">
<td style="border-left:3px solid #00c9ed;"><span style="color:<?= $customStatus === 'Matched' ? '#ff8799' : '#a9bdd2' ?>;font-weight:600;"><?= $escape($customStatus) ?></span></td>
<td><span class="check-name"><?= $escape($custom['name'] ?? '') ?></span>
<span style="display:inline-block;border:1px solid #00c9ed;color:#55e4ff;border-radius:5px;padding:2px 6px;margin:6px 0;font-size:10px;">*NEW RULE</span>
<div style="color:#9bb1c9;font-size:11px;overflow-wrap:anywhere;"><?= $escape($custom['code'] ?? '') ?></div></td>
<td><div class="detail-text"><?= $escape($customStatus === 'Matched' ? 'Matching code was found. Review the evidence below.' : ($customStatus === 'No match' ? 'No matching code found for this custom rule. This is not a security PASS.' : 'This rule could not be evaluated. Review processing notes.')) ?></div>
<div class="result-meta"><span class="meta-badge"><?= $escape($custom['standard'] ?? '') ?></span><span class="meta-badge"><?= $escape($custom['language'] ?? '') ?></span><span class="meta-badge"><?= (int)($custom['matches'] ?? 0) ?> matches</span></div>
<details class="custom-rule-reasons" style="margin-top:10px;"><summary style="cursor:pointer;color:#9acfff;padding:6px 0;">more details</summary>
<?php if (!$matchingRows): ?><p>No matched finding was saved for this rule. The label *NEW RULE identifies a custom rule, not its creation date.</p><?php endif; ?>
<?php foreach ($matchingRows as $row): ?><div id="result-<?= (int)($row['ResultID'] ?? 0) ?>" style="padding:12px 0;border-top:1px solid #263b52;"><strong><?= $escape($row['Status']) ?></strong> · Line <?= (int)($row['LineNumber'] ?? 0) ?><p><?= $escape(getDetail($row)) ?></p></div><?php endforeach; ?>
</details></td></tr>
<?php endforeach; ?>
</tbody></table>
<?php endif; ?>
<?php if (empty($file['custom_rules'])): ?>
<?php if (!empty($file['custom_rule_error'])): ?>
<p class="scan-guidance" style="margin:14px;">Custom rules could not be loaded for this file. They were not evaluated.</p>
<?php elseif (array_key_exists('custom_rules',$file)): ?>
<p class="scan-guidance" style="margin:14px;">No active custom rules for this language were loaded at scan time.</p>
<?php else: ?>
<p class="scan-guidance" style="margin:14px;">No per-file custom-rule evaluation record is available here. Scan Coverage identifies the files processed; rerun older scans to capture which active rules were evaluated.</p>
<?php endif; ?>
<?php endif; ?>
<?php
$additional = array_filter($file['rows'], static fn($row) => !isset($displayedCustomResults[(int)($row['ResultID'] ?? 0)]) && (str_starts_with((string)($row['VulnerabilityName'] ?? ''),'[')
    || (!in_array(getCheckName($row),['Security Logging','Log Neutralization','Log Storage','Log Encryption'],true)
        && ($row['VulnerabilityName'] ?? '') !== 'Log Context')));
?>
<?php if ($additional): ?><details style="margin:14px;"><summary>Additional finding details</summary>
<?php foreach ($additional as $row): ?><div id="result-<?= (int)($row['ResultID'] ?? 0) ?>" style="padding:12px;border-bottom:1px solid #263b52;"><strong><?= $escape($row['VulnerabilityName']) ?></strong> · <?= $escape($row['Status']) ?> · Line <?= (int)($row['LineNumber'] ?? 0) ?><p><?= $escape(getDetail($row)) ?></p></div><?php endforeach; ?>
</details><?php endif; ?>
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
