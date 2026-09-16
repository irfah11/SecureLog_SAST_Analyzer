<?php

/**
 * ============================================================
 * SecureLog Scanner Engine
 * ============================================================
 *
 * Standard result structure used by all language scanners.
 *
 * STATUS:
 * PASS = security requirement satisfied
 * FAIL = weakness / policy violation detected
 * N/A  = check cannot be evaluated / not applicable
 *
 * RULE ID:
 * FAIL -> contains CWE / SecureLog Policy Rule ID
 * PASS -> null
 * N/A  -> null
 * ============================================================
 */


/**
 * Create scanner analysis result.
 */
function createFinding(
    ?int $ruleId,
    string $vulnerabilityName,
    string $severity,
    string $filePath,
    int $lineNumber,
    string $description,
    string $recommendation = '',
    string $status = 'FAIL',
    string $standard = ''
): array {

    return [
        'status' => strtoupper($status),

        'check' => $vulnerabilityName,

        'rule_id' => $ruleId,

        'standard' => $standard,

        'vulnerability_name' => $vulnerabilityName,

        'severity' => strtoupper($severity),

        'file_path' => $filePath,

        'line_number' => $lineNumber,

        'description' => $description,

        'recommendation' => $recommendation
    ];
}