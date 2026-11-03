<?php
/** Shared, line-based matcher. A match is a configured weakness, never a proof of safety. */
function securelogMatchRule(string $pattern, string $source, ?string $secondary = null): array
{
    $matches = [];
    foreach (preg_split('/\r\n|\n|\r/', $source) as $index => $line) {
        $primary = @preg_match($pattern, $line);
        $context = $secondary === null ? null : @preg_match($secondary, $line);
        if ($primary === false || $context === false) {
            throw new RuntimeException('Invalid pattern or regex execution limit reached.');
        }
        if ($primary === 1 && ($secondary === null || $context === 1)) {
            $matches[] = ['line_number' => $index + 1, 'line_content' => $line,
                'primary_match' => true, 'secondary_match' => $secondary === null ? null : true];
        }
    }
    return ['matched' => $matches !== [], 'matches' => $matches];
}

/** Snapshot once per scan. Failure is surfaced to the caller, not silently ignored. */
function securelogLoadActiveRules(mysqli $conn, string $language): array
{
    $statement = $conn->prepare("SELECT RuleID, RuleCode, RuleName, Language, Status,
        MatchType, Pattern, SecondaryPattern, Severity, CWEID, Description, Recommendation
        FROM scanner_rules WHERE Status = 'ACTIVE' AND UPPER(Language) = ? ORDER BY RuleID");
    if (!$statement) throw new RuntimeException('Unable to load active scanner rules.');
    try {
        $language = strtoupper($language);
        $statement->bind_param('s', $language);
        if (!$statement->execute()) throw new RuntimeException('Unable to load active scanner rules.');
        return $statement->get_result()->fetch_all(MYSQLI_ASSOC);
    } finally {
        $statement->close();
    }
}

function securelogScanDatabaseRules(array $rules, string $language, string $file, string $source, ?array &$evaluations = null): array
{
    $evaluations = [];
    $findings = [];
    $seen = [];
    foreach ($rules as $rule) {
        if (strtoupper($rule['Status'] ?? '') !== 'ACTIVE'
            || strcasecmp($rule['Language'] ?? '', $language) !== 0) continue;
        $id = (int) $rule['RuleID'];
        $record = ['id'=>$id,'code'=>$rule['RuleCode'],'name'=>$rule['RuleName'],
            'language'=>$rule['Language'],'standard'=>$rule['CWEID'] ?: 'SecureLog Custom Rule',
            'status'=>'No match','matches'=>0];
        try {
            $type = $rule['MatchType'];
            if (!in_array($type, ['SIMPLE_PATTERN', 'CONTEXT_PATTERN'], true)) {
                throw new RuntimeException('Unsupported rule match type.');
            }
            $secondary = $type === 'CONTEXT_PATTERN' ? (string) ($rule['SecondaryPattern'] ?? '') : null;
            if ($rule['Pattern'] === '' || $secondary === '') throw new RuntimeException('Missing rule pattern.');
            $result = securelogMatchRule($rule['Pattern'], $source, $secondary);
            foreach ($result['matches'] as $match) {
                $line = $match['line_number'];
                if (isset($seen[$id . ':' . $line])) continue;
                $seen[$id . ':' . $line] = true;
                $finding = createFinding($id, '[' . $rule['RuleCode'] . '] ' . $rule['RuleName'],
                    $rule['Severity'], $file, $line,
                    'Configured rule matched: ' . $rule['Description'], $rule['Recommendation'], 'FAIL',
                    $rule['CWEID'] ?: 'SecureLog Custom Rule');
                $finding['event_key'] = 'custom-rule-' . $id . '-' . $line;
                $finding['event_name'] = 'Custom rule: ' . $rule['RuleCode'];
                $finding['event_line'] = $line;
                $findings[] = $finding;
                $record['matches']++;
            }
            if ($record['matches'] > 0) $record['status'] = 'Matched';
        } catch (Throwable $exception) {
            $record['status'] = 'Could not evaluate';
            $findings[] = createFinding(null, 'Scan Validation', 'INFO', $file, 0,
                'Custom rule ' . $id . ' could not be evaluated. ' . $exception->getMessage(),
                'Review and retest this rule.', 'N/A', 'SecureLog System');
        }
        $evaluations[] = $record;
    }
    return $findings;
}
