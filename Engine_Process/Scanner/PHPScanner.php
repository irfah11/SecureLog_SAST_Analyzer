<?php

require_once __DIR__ . '/ScannerEngine.php';

/**
 * ============================================================
 * SecureLog PHP Static Analyzer
 * ============================================================
 *
 * FINAL PIPELINE
 *
 * Security Event
 *      |
 *      v
 * [1] SECURITY LOGGING
 *     CWE-778
 *
 *      |
 *      v
 * [2] LOG NEUTRALIZATION
 *     CWE-117
 *
 *      |
 *      v
 * [3] LOG STORAGE
 *     SecureLog Policy (.txt)
 *
 *      |
 *      v
 * [4] LOG PROTECTION
 *     SecureLog Policy (Evidence-based protection assessment)
 *
 *
 * STATUS
 * ------------------------------------------------------------
 * PASS = requirement satisfied
 * FAIL = weakness/problem detected
 * N/A  = cannot/does not need to be evaluated
 *
 *
 * RULES
 * ------------------------------------------------------------
 *
 * CWE-778
 * 77801 - Authentication Failure Without Logging      HIGH
 * 77802 - Access Control Failure Without Logging       HIGH
 * 77803 - Exception Handling Without Logging           MEDIUM
 *
 * CWE-117
 * 11701 - Unneutralized User Input in Log              HIGH
 *
 * SecureLog Policy
 * 90001 - Non-approved Log Storage                     MEDIUM
 * 90002 - Unprotected Log Data                         MEDIUM
 *
 *
 * IMPORTANT
 * ------------------------------------------------------------
 *
 * .txt is a SecureLog project-specific policy.
 * CWE-117 does NOT require .txt.
 *
 * Encryption is also a SecureLog project-specific policy.
 * It is NOT classified as CWE-778 or CWE-117.
 */


/* ============================================================
   RESULT CREATOR
   ============================================================ */

/**
 * Create one PASS / FAIL / N/A analysis result.
 *
 * IMPORTANT:
 * rule_id is only populated when an actual weakness exists.
 *
 * PASS and N/A use rule_id = null.
 */
function createPhpCheckResult(
    string $status,
    string $check,
    ?int $ruleId,
    string $standard,
    string $severity,
    string $filePath,
    int $lineNumber,
    string $description,
    string $recommendation = ''
): array {

    return [
        'status'             => strtoupper($status),
        'check'              => $check,
        'rule_id'            => $ruleId,
        'standard'           => $standard,
        'vulnerability_name' => $check,
        'severity'           => $severity,
        'file_path'          => $filePath,
        'line_number'        => $lineNumber,
        'description'        => $description,
        'recommendation'     => $recommendation
    ];
}


/* ============================================================
   MAIN PHP SCANNER
   ============================================================ */

function scanPHP(string $fileName, string $content, array $projectSources = []): array
{
    $results = [];
    $events = securelogPhpDiscoverEvents($content);
    $definitions = securelogPhpProjectDefinitions($fileName, $content, $projectSources);

    foreach ($events as $event) {
        $rule = $event['rule'];
        $eventName = $rule === 77801 ? 'Authentication Failure'
            : ($rule === 77802 ? 'Access Control Failure' : 'Exception Handling');

        $description = $rule === 77801
            ? 'SecureLog detected an authentication failure path without an associated security logging operation.'
            : ($rule === 77802
                ? 'SecureLog detected an access-control denial or authorization failure without an associated security logging operation.'
                : 'SecureLog detected exception handling without an associated logging operation.');

        $recommendation = $rule === 77801
            ? 'Record failed authentication attempts using an appropriate security logging mechanism. Do not log passwords, tokens, or credentials.'
            : ($rule === 77802
                ? 'Record denied or unauthorized access attempts using an appropriate security logging mechanism.'
                : 'Record security-relevant or operational exceptions using an appropriate logger while avoiding sensitive information.');

        // Resolve same-file custom logger wrappers, without trusting their names.
        $sinkEvidence = securelogPhpResolveSink($event['body'], $definitions);

        // A sink somewhere in the body is not proof that every execution path
        // logs the event (e.g. if ($enableLogging) error_log(...)).
        $pathStatus = securelogPhpAssessLoggingPaths($event['body'], $definitions);
        $sinkEvidence['path_gap'] = $pathStatus === 'FAIL' && $sinkEvidence['status'] === 'PASS';
        $sinkEvidence['path_uncertain'] = $pathStatus === 'N/A' && $sinkEvidence['status'] === 'PASS';
        if ($pathStatus !== 'PASS') {
            $sinkEvidence['status'] = $pathStatus;
        }

        // IMPORTANT: Analyze only statements on the detected event path.
        // Code preceding the condition, and code after its closing brace,
        // must not make the event appear logged.
        analyzePhpSecurityEventStatus(
            $results,
            $fileName,
            $event['line'],
            $event['body'],
            $rule,
            $eventName,
            $description,
            $recommendation,
            $sinkEvidence
        );
    }

    // A file without supported events belongs to scan coverage, not findings.

    return $results;
}

/** Resolve only leading, unconditional static includes in the uploaded source map.
 * Uploaded PHP is tokenized, never executed; no include target is read from disk.
 * Dynamic paths, conditional includes and namespace/class binding are unsupported.
 */
function securelogPhpProjectDefinitions(string $fileName, string $content, array $sources): array
{
    $definitions = securelogPhpCollectDefinitions($content);
    $seen = [];
    $duplicates = [];
    $visit = function (string $path, string $code, int $depth) use (
        &$visit, &$seen, &$definitions, &$duplicates, $sources
    ): void {
        if ($depth > 12 || isset($seen[$path])) return;
        $seen[$path] = true;
        $tokens = securelogPhpTokens($code);
        $at = securelogPhpNextToken($tokens, 0);
        // PHP permits blank text before the opening tag in uploaded files.
        while ($at !== null && $tokens[$at]['id'] === T_INLINE_HTML
            && trim($tokens[$at]['text']) === '') {
            $at = securelogPhpNextToken($tokens, $at + 1);
        }
        if ($at !== null && $tokens[$at]['id'] === T_OPEN_TAG) {
            $at = securelogPhpNextToken($tokens, $at + 1);
        }
        while ($at !== null && in_array($tokens[$at]['id'],
            [T_REQUIRE, T_REQUIRE_ONCE, T_INCLUDE, T_INCLUDE_ONCE], true)) {
            $end = $at + 1;
            while (isset($tokens[$end]) && $tokens[$end]['text'] !== ';') $end++;
            if (!isset($tokens[$end])) break;
            $expr = [];
            for ($i = $at + 1; $i < $end; $i++) {
                if (!in_array($tokens[$i]['id'], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $expr[] = $tokens[$i];
                }
            }
            if (count($expr) >= 2 && $expr[0]['text'] === '(' && end($expr)['text'] === ')') {
                $expr = array_slice($expr, 1, -1);
            }
            $literal = null;
            if (count($expr) === 1 && $expr[0]['id'] === T_CONSTANT_ENCAPSED_STRING) {
                $literal = $expr[0]['text'];
            } elseif (count($expr) === 3 && $expr[0]['id'] === T_DIR
                && $expr[1]['text'] === '.' && $expr[2]['id'] === T_CONSTANT_ENCAPSED_STRING) {
                $literal = $expr[2]['text'];
                // __DIR__ suffix must start with a directory separator.
                if (!in_array(substr($literal, 1, 1), ['/', '\\'], true)) $literal = null;
            }
            if ($literal !== null) {
                $target = substr($literal, 1, -1);
                // Escaped literals are left unresolved instead of guessing PHP decoding.
                if (!str_contains($target, '\\') && !str_contains($target, ':')
                    && (count($expr) === 3 || !str_starts_with($target, '/'))) {
                    $segments = explode('/', (dirname($path) === '.' ? '' : dirname($path) . '/')
                        . (count($expr) === 3 ? ltrim($target, '/') : $target));
                    $normalized = [];
                    $safe = true;
                    foreach ($segments as $segment) {
                        if ($segment === '' || $segment === '.') continue;
                        if ($segment === '..') {
                            if ($normalized === []) { $safe = false; break; }
                            array_pop($normalized);
                        } else $normalized[] = $segment;
                    }
                    $resolved = implode('/', $normalized);
                    if ($safe && isset($sources[$resolved]) && !isset($seen[$resolved]) && $depth < 12) {
                        $dependency = $sources[$resolved];
                        $dependencyTokens = securelogPhpTokens($dependency);
                        $unsupported = false;
                        foreach ($dependencyTokens as $token) {
                            if (in_array($token['id'], [T_NAMESPACE, T_CLASS, T_TRAIT, T_INTERFACE,
                                T_IF, T_ELSEIF, T_SWITCH, T_FOR, T_FOREACH, T_WHILE, T_DO], true)) {
                                $unsupported = true; break;
                            }
                        }
                        if (!$unsupported) {
                            foreach (securelogPhpCollectDefinitions($dependency) as $name => $body) {
                                if (isset($definitions[$name])) $duplicates[$name] = true;
                                else $definitions[$name] = $body;
                            }
                            $visit($resolved, $dependency, $depth + 1);
                        }
                    }
                }
            }
            $at = securelogPhpNextToken($tokens, $end + 1);
        }
    };
    $visit($fileName, $content, 0);
    foreach ($duplicates as $name => $_) unset($definitions[$name]);
    return $definitions;
}

/**
 * Tokenize real PHP syntax instead of scanning overlapping text windows.
 * Token offsets uniquely identify events, including two events on one line.
 */
function securelogPhpTokens(string $content): array
{
    $result = [];
    $line = 1;
    foreach (token_get_all($content) as $token) {
        if (is_array($token)) {
            $id = $token[0];
            $text = $token[1];
            $tokenLine = $token[2];
        } else {
            $id = null;
            $text = $token;
            $tokenLine = $line;
        }
        $result[] = ['id' => $id, 'text' => $text, 'line' => $tokenLine];
        $line = $tokenLine + substr_count($text, "\n");
    }
    return $result;
}

function securelogPhpNextToken(array $tokens, int $from): ?int
{
    for ($i = $from, $n = count($tokens); $i < $n; $i++) {
        if (!in_array($tokens[$i]['id'], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            return $i;
        }
    }
    return null;
}

function securelogPhpMatchPair(array $tokens, int $start, string $open, string $close): ?int
{
    if (!isset($tokens[$start]) || $tokens[$start]['text'] !== $open) {
        return null;
    }
    $depth = 0;
    for ($i = $start, $n = count($tokens); $i < $n; $i++) {
        if ($tokens[$i]['text'] === $open) {
            $depth++;
        } elseif ($tokens[$i]['text'] === $close && --$depth === 0) {
            return $i;
        }
    }
    return null;
}

function securelogPhpSlice(array $tokens, int $start, int $end): string
{
    $text = '';
    for ($i = $start; $i <= $end && isset($tokens[$i]); $i++) {
        $text .= $tokens[$i]['text'];
    }
    return $text;
}

/** Extract only the body of an if/catch. Never include following else or statements. */
function securelogPhpBodyBounds(array $tokens, int $afterCondition): ?array
{
    $start = securelogPhpNextToken($tokens, $afterCondition);
    if ($start === null) {
        return null;
    }
    if ($tokens[$start]['text'] === '{') {
        $close = securelogPhpMatchPair($tokens, $start, '{', '}');
        return $close === null ? null : [$start + 1, $close - 1, $close];
    }

    // Single-statement bodies: if ($bad) return false;
    $paren = 0;
    $bracket = 0;
    for ($i = $start, $n = count($tokens); $i < $n; $i++) {
        $ch = $tokens[$i]['text'];
        if ($ch === '(') $paren++;
        elseif ($ch === ')') $paren--;
        elseif ($ch === '[') $bracket++;
        elseif ($ch === ']') $bracket--;
        elseif ($ch === ';' && $paren === 0 && $bracket === 0) {
            return [$start, $i, $i];
        }
    }
    return null;
}

/**
 * Ignore code after a top-level return/throw/exit/die on the same path.
 * This is deliberately lightweight; complex nested branches remain a limitation.
 */
function securelogPhpReachableBody(array $tokens, int $start, int $end): string
{
    $depth = 0;
    $stop = $end;
    for ($i = $start; $i <= $end; $i++) {
        $id = $tokens[$i]['id'];
        $ch = $tokens[$i]['text'];
        if ($depth === 0 && (in_array($id, [T_RETURN, T_THROW, T_EXIT], true)
            || ($id === T_STRING && strtolower($ch) === 'die'))) {
            $stop = $i - 1;
            break;
        }
        if ($ch === '{') $depth++;
        elseif ($ch === '}') $depth--;
    }
    return $stop < $start ? '' : securelogPhpSlice($tokens, $start, $stop);
}

/** Detect actual logging calls, not fake call names inside strings/comments. */
function securelogPhpHasActualSink(string $code, array $excludeFunctions = []): bool
{
    $tokens = securelogPhpTokens("<?php\n" . $code);
    $methods = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency', 'log'];
    $functions = ['error_log', 'syslog', 'logger'];

    foreach ($tokens as $i => $token) {
        if ($token['id'] !== T_STRING) continue;
        $name = strtolower($token['text']);
        $next = securelogPhpNextToken($tokens, $i + 1);
        if ($next === null || $tokens[$next]['text'] !== '(') continue;
        $prev = $i - 1;
        while ($prev >= 0 && in_array($tokens[$prev]['id'], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $prev--;
        $prevId = $prev >= 0 ? $tokens[$prev]['id'] : null;
        $prevText = $prev >= 0 ? $tokens[$prev]['text'] : '';

        if (in_array($name, $functions, true)
            && !in_array($name, $excludeFunctions, true)
            && !in_array($prevId, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true)) return true;
        if (in_array($name, $methods, true)
            && in_array($prevId, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) {
            // Method names alone are insufficient: e.g. $calculator->log(100)
            // is a mathematical operation, not a security logging sink.
            // Accept only clearly logger/audit-related receivers or Log:: facade.
            $receiverAt = $prev - 1;
            while ($receiverAt >= 0 && in_array($tokens[$receiverAt]['id'],
                [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $receiverAt--;
            $receiver = $receiverAt >= 0 ? $tokens[$receiverAt]['text'] : '';
            if (preg_match('/^(?:\$?(?:logger|log|audit|monolog)|\$?[A-Za-z_][A-Za-z0-9_]*(?:Logger|Log|Audit))$/', $receiver) === 1) return true;
        }

        if (in_array($name, ['file_put_contents', 'fwrite'], true)) {
            $close = securelogPhpMatchPair($tokens, $next, '(', ')');
            if ($close !== null) {
                $args = securelogPhpSlice($tokens, $next + 1, $close - 1);
                if (preg_match('/(?:log|audit|security|message|event)/i', $args) === 1) return true;
            }
        }
    }
    return false;
}

/**
 * Collect same-file named function and method implementations.
 * Duplicate names are deliberately excluded: without a reliable receiver/class
 * binding, choosing one implementation would be an unsafe assumption.
 */
function securelogPhpCollectDefinitions(string $content): array
{
    $tokens = securelogPhpTokens($content);
    $definitions = [];
    $duplicates = [];
    $n = count($tokens);

    for ($i = 0; $i < $n; $i++) {
        if ($tokens[$i]['id'] !== T_FUNCTION) continue;
        $nameAt = securelogPhpNextToken($tokens, $i + 1);
        if ($nameAt === null) continue;
        // Skip the optional reference marker in function &name(...).
        if ($tokens[$nameAt]['text'] === '&') $nameAt = securelogPhpNextToken($tokens, $nameAt + 1);
        if ($nameAt === null || $tokens[$nameAt]['id'] !== T_STRING) continue;
        $name = strtolower($tokens[$nameAt]['text']);
        $paramsOpen = securelogPhpNextToken($tokens, $nameAt + 1);
        if ($paramsOpen === null || $tokens[$paramsOpen]['text'] !== '(') continue;
        $paramsClose = securelogPhpMatchPair($tokens, $paramsOpen, '(', ')');
        if ($paramsClose === null) continue;
        $bodyOpen = securelogPhpNextToken($tokens, $paramsClose + 1);
        // Support return type declarations, including nullable/union types.
        while ($bodyOpen !== null && $bodyOpen < $n &&
               $tokens[$bodyOpen]['text'] !== '{' && $tokens[$bodyOpen]['text'] !== ';') {
            $bodyOpen = securelogPhpNextToken($tokens, $bodyOpen + 1);
        }
        if ($bodyOpen === null || $tokens[$bodyOpen]['text'] !== '{') continue;
        $bodyClose = securelogPhpMatchPair($tokens, $bodyOpen, '{', '}');
        if ($bodyClose === null) continue;
        if (isset($definitions[$name])) $duplicates[$name] = true;
        // Analyze only code reachable before a top-level return/throw/exit.
        // A wrapper such as `return true; error_log($message);` must not
        // produce a false Security Logging PASS from dead code.
        $definitions[$name] = securelogPhpReachableBody($tokens, $bodyOpen + 1, $bodyClose - 1);
        $i = $bodyClose;
    }
    foreach ($duplicates as $name => $_) unset($definitions[$name]);
    return $definitions;
}

/**
 * Bounded, cycle-safe same-file call resolution. Only a real recognized sink
 * inside a reachable wrapper body can confirm logging. No name-based PASS.
 * This is intentionally a lightweight approximation, not full call-graph/CFG.
 * @return array{status:string,indirect:bool,context:string}
 */
function securelogPhpResolveSink(string $code, array $definitions, array $visited = [], int $depth = 0): array
{
    if (securelogPhpHasActualSink($code, array_keys($definitions))) {
        return ['status' => 'PASS', 'indirect' => $depth > 0, 'context' => $code];
    }
    if ($depth >= 6) return ['status' => 'N/A', 'indirect' => true, 'context' => ''];

    $tokens = securelogPhpTokens('<?php ' . $code);
    $unknown = false;
    foreach ($tokens as $i => $token) {
        if ($token['id'] !== T_STRING) continue;
        $name = strtolower($token['text']);
        $next = securelogPhpNextToken($tokens, $i + 1);
        if ($next === null || $tokens[$next]['text'] !== '(') continue;
        $prev = $i - 1;
        while ($prev >= 0 && in_array($tokens[$prev]['id'], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $prev--;
        if ($prev >= 0 && in_array($tokens[$prev]['id'], [T_FUNCTION, T_NEW], true)) continue;
        if (isset($definitions[$name])) {
            if (isset($visited[$name])) { $unknown = true; continue; }
            $nextVisited = $visited;
            $nextVisited[$name] = true;
            $resolved = securelogPhpResolveSink($definitions[$name], $definitions, $nextVisited, $depth + 1);
            if ($resolved['status'] === 'PASS') {
                $definitionTokens = securelogPhpTokens('<?php ' . $definitions[$name]);
                $hasBranches = false;
                foreach ($definitionTokens as $definitionToken) {
                    if (in_array($definitionToken['id'], [T_IF, T_ELSEIF, T_SWITCH,
                        T_FOR, T_FOREACH, T_WHILE, T_DO, T_TRY, T_MATCH], true)) {
                        $hasBranches = true;
                        break;
                    }
                }
                if ($hasBranches && securelogPhpAssessLoggingPaths($definitions[$name], []) !== 'PASS') {
                    $unknown = true;
                    continue;
                }
                // Include the call-site and actual implementation for policy review.
                return ['status' => 'PASS', 'indirect' => true,
                        'context' => $code . "\n" . $resolved['context']];
            }
            if ($resolved['status'] === 'N/A') $unknown = true;
        } elseif (preg_match('/(?:log|audit|record.*event|security.*event)/i', $name)) {
            // External custom logger: its implementation is not in this file.
            $unknown = true;
        }
    }
    return ['status' => $unknown ? 'N/A' : 'FAIL', 'indirect' => $depth > 0, 'context' => $code];
}

/**
 * Lightweight path-sensitive assessment of logging within ONE security-event
 * body. PASS requires a verified sink on every supported path. FAIL requires
 * at least one demonstrably unlogged path. Unsupported constructs are N/A.
 *
 * This is deliberately NOT a full interprocedural control-flow graph.
 */
function securelogPhpAssessLoggingPaths(string $code, array $definitions): string
{
    $tokens = securelogPhpTokens("<?php\n" . $code);
    $paths = securelogPhpFlowWalk($tokens, 0, count($tokens) - 1,
        $definitions, [['logged' => false, 'unknown' => false, 'ended' => false]], 0);

    if ($paths === null || $paths === []) return 'N/A';
    $unknown = false;
    foreach ($paths as $path) {
        if (!$path['logged']) {
            if (!$path['unknown']) return 'FAIL';
            $unknown = true;
        }
    }
    return $unknown ? 'N/A' : 'PASS';
}

/** Read one if/elseif/else chain, returning its branch bodies and next token. */
function securelogPhpFlowIfChain(array $tokens, int $start, int $end): ?array
{
    $branches = [];
    $cursor = $start;
    $hasElse = false;
    while ($cursor <= $end) {
        $id = $tokens[$cursor]['id'];
        if ($id === T_ELSE) {
            $bounds = securelogPhpBodyBounds($tokens, $cursor + 1);
            if ($bounds === null) return null;
            $branches[] = [$bounds[0], $bounds[1]];
            $cursor = $bounds[2] + 1;
            $hasElse = true;
            break;
        }
        if ($id !== T_IF && $id !== T_ELSEIF) return null;
        $open = securelogPhpNextToken($tokens, $cursor + 1);
        if ($open === null || $tokens[$open]['text'] !== '(') return null;
        $close = securelogPhpMatchPair($tokens, $open, '(', ')');
        if ($close === null) return null;
        $bounds = securelogPhpBodyBounds($tokens, $close + 1);
        if ($bounds === null) return null;
        $branches[] = [$bounds[0], $bounds[1]];
        $cursor = securelogPhpNextToken($tokens, $bounds[2] + 1);
        if ($cursor === null) { $cursor = $end + 1; break; }
        if ($cursor > $end || !in_array($tokens[$cursor]['id'], [T_ELSEIF, T_ELSE], true)) break;
    }
    if (!$hasElse) $branches[] = null; // Condition(s) can all be false.
    return ['branches' => $branches, 'next' => $cursor];
}

/**
 * Walk a bounded token range and carry the logged/unknown state for each path.
 * A return/throw/exit terminates only the path on which it executes.
 */
function securelogPhpFlowWalk(array $tokens, int $start, int $end,
    array $definitions, array $paths, int $depth): ?array
{
    if ($depth > 16 || count($paths) > 128) return null;
    $i = $start;
    while ($i <= $end) {
        $at = securelogPhpNextToken($tokens, $i);
        if ($at === null || $at > $end) break;
        $id = $tokens[$at]['id'];
        $ch = $tokens[$at]['text'];
        if ($id === T_OPEN_TAG || $ch === ';') { $i = $at + 1; continue; }

        if ($id === T_IF) {
            $chain = securelogPhpFlowIfChain($tokens, $at, $end);
            if ($chain === null) return null;
            $nextPaths = [];
            foreach ($chain['branches'] as $branch) {
                if ($branch === null) {
                    $branchPaths = $paths;
                } else {
                    $branchPaths = securelogPhpFlowWalk($tokens, $branch[0], $branch[1],
                        $definitions, $paths, $depth + 1);
                }
                if ($branchPaths === null) return null;
                array_push($nextPaths, ...$branchPaths);
            }
            $paths = $nextPaths;
            if (count($paths) > 128) return null;
            $i = $chain['next'];
            continue;
        }

        if ($ch === '{') {
            $close = securelogPhpMatchPair($tokens, $at, '{', '}');
            if ($close === null) return null;
            $paths = securelogPhpFlowWalk($tokens, $at + 1, $close - 1,
                $definitions, $paths, $depth + 1);
            if ($paths === null) return null;
            $i = $close + 1;
            continue;
        }

        // Loops, switch, try/catch, declarations and other compound forms
        // require richer CFG semantics. They must never yield a guessed PASS.
        if (in_array($id, [T_FOR, T_FOREACH, T_WHILE, T_DO, T_SWITCH,
            T_TRY, T_CATCH, T_FUNCTION, T_FN, T_MATCH], true)) {
            foreach ($paths as &$path) {
                if (!$path['ended'] && !$path['logged']) $path['unknown'] = true;
            }
            unset($path);
            // We cannot safely identify a complete compound statement here.
            // Return N/A unless a prior unconditional sink covered all paths.
            return $paths;
        }

        // Ordinary expression or return statement: locate the ending semicolon.
        $paren = 0; $bracket = 0; $curly = 0;
        $stop = null;
        for ($j = $at; $j <= $end; $j++) {
            $t = $tokens[$j]['text'];
            if ($t === '(') $paren++;
            elseif ($t === ')') $paren--;
            elseif ($t === '[') $bracket++;
            elseif ($t === ']') $bracket--;
            elseif ($t === '{') $curly++;
            elseif ($t === '}') $curly--;
            if ($t === ';' && $paren === 0 && $bracket === 0 && $curly === 0) {
                $stop = $j; break;
            }
        }
        if ($stop === null) return null;
        $statement = securelogPhpSlice($tokens, $at, $stop);
        $resolved = securelogPhpResolveSink($statement, $definitions);
        $terminates = in_array($id, [T_RETURN, T_THROW, T_EXIT], true)
            || ($id === T_STRING && strtolower($ch) === 'die');
        // A ternary/short-circuit expression may bypass its embedded logger.
        $conditionalExpression = preg_match('/\\?|&&|\\|\\||\\band\\b|\\bor\\b/i', $statement) === 1;
        foreach ($paths as &$path) {
            if ($path['ended']) continue;
            if ($resolved['status'] === 'PASS') {
                if ($conditionalExpression) $path['unknown'] = true;
                else $path['logged'] = true;
            } elseif ($resolved['status'] === 'N/A') {
                $path['unknown'] = true;
            }
            if ($terminates) $path['ended'] = true;
        }
        unset($path);
        $i = $stop + 1;
    }
    return $paths;
}

/**
 * Only explicit, directly inspectable storage destinations count as evidence.
 * An ordinary error_log($message) has an environment-configured destination.
 * @return array{status:string,description:string}
 */
/** Split actual call arguments without treating commas in strings as separators. */
function securelogPhpCallArguments(array $tokens, int $open, int $close): array
{
    $args = [];
    $start = $open + 1;
    $depth = 0;
    for ($i = $start; $i < $close; $i++) {
        $text = $tokens[$i]['text'];
        if ($tokens[$i]['id'] !== null) continue;
        if (in_array($text, ['(', '[', '{'], true)) $depth++;
        elseif (in_array($text, [')', ']', '}'], true)) $depth--;
        elseif ($text === ',' && $depth === 0) {
            $args[] = trim(securelogPhpSlice($tokens, $start, $i - 1));
            $start = $i + 1;
        }
    }
    $args[] = trim(securelogPhpSlice($tokens, $start, $close - 1));
    return $args;
}

/** Actual built-in calls only; text in comments/strings is never a call. */
function securelogPhpBuiltinCalls(string $code): array
{
    $tokens = securelogPhpTokens('<?php ' . $code);
    $calls = [];
    foreach ($tokens as $i => $token) {
        if ($token['id'] !== T_STRING) continue;
        $previous = $i - 1;
        while ($previous >= 0 && in_array($tokens[$previous]['id'],
            [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $previous--;
        if ($previous >= 0 && in_array($tokens[$previous]['id'],
            [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true)) continue;
        $open = securelogPhpNextToken($tokens, $i + 1);
        if ($open === null || $tokens[$open]['text'] !== '(') continue;
        $close = securelogPhpMatchPair($tokens, $open, '(', ')');
        if ($close === null) continue;
        $calls[] = ['name' => strtolower($token['text']),
            'args' => securelogPhpCallArguments($tokens, $open, $close), 'line' => $token['line']];
    }
    return $calls;
}

/** Resolve literal strings and __DIR__ suffixes only, never filesystem paths. */
function securelogPhpStaticLogPath(string $expression): ?string
{
    $parts = array_values(array_filter(securelogPhpTokens('<?php ' . $expression),
        static fn(array $token): bool => !in_array($token['id'],
            [T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)));
    if (count($parts) === 3 && $parts[0]['id'] === T_DIR && $parts[1]['text'] === '.') {
        $parts = [$parts[2]];
    }
    if (count($parts) !== 1 || $parts[0]['id'] !== T_CONSTANT_ENCAPSED_STRING) return null;
    $literal = $parts[0]['text'];
    $value = substr($literal, 1, -1);
    // Leave escaped/interpolated expressions unresolved rather than guessing.
    return str_contains($value, '\\') ? null : $value;
}

function securelogPhpStorageEvidence(string $code): array
{
    $approved = false;
    foreach (securelogPhpBuiltinCalls($code) as $call) {
        $name = $call['name'];
        if (!in_array($name, ['file_put_contents', 'fopen', 'error_log'], true)) continue;
        $args = $call['args'];
        if ($name === 'error_log') {
            // error_log(message, 3, destination) only; otherwise config unknown.
            if (trim($args[1] ?? '') !== '3') continue;
            $path = securelogPhpStaticLogPath($args[2] ?? '');
        } else {
            $path = securelogPhpStaticLogPath($args[0] ?? '');
            if ($path !== null && !preg_match('/(?:log|audit|security|event)/i', $path)) continue;
        }
        if ($path === null) continue;
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($extension === 'txt') { $approved = true; continue; }
        return ['status' => 'FAIL', 'description' => 'Explicit log destination does not meet the SecureLog .txt policy: ' . basename($path) . '.'];
    }
    if ($approved) return ['status' => 'PASS', 'description' => 'Explicit approved .txt log destination detected.'];
    return ['status' => 'N/A', 'description' => 'The actual log destination cannot be established from this event and its resolved logger implementation.'];
}

/** Identify only clearly unprotected direct literal or raw-superglobal writes. */
function securelogPhpExplicitPlaintextWrite(string $code): bool
{
    return findPhpEncryptionToLogFlow($code)['plaintext'];
}

/**
 * Discover supported security paths once per syntactic condition/catch.
 * The original isPhp*() patterns remain the event vocabulary.
 */
function securelogPhpDiscoverEvents(string $content): array
{
    $tokens = securelogPhpTokens($content);
    $events = [];
    $seen = [];
    $coveredDenials = [];
    $n = count($tokens);

    for ($i = 0; $i < $n; $i++) {
        $id = $tokens[$i]['id'];
        if (!in_array($id, [T_IF, T_ELSEIF, T_CATCH], true)) {
            continue;
        }
        $open = securelogPhpNextToken($tokens, $i + 1);
        if ($open === null || $tokens[$open]['text'] !== '(') continue;
        $close = securelogPhpMatchPair($tokens, $open, '(', ')');
        if ($close === null) continue;
        $bounds = securelogPhpBodyBounds($tokens, $close + 1);
        if ($bounds === null) continue;
        [$bodyStart, $bodyEnd, $bodyFinish] = $bounds;
        $condition = securelogPhpSlice($tokens, $open + 1, $close - 1);
        // Keep the full event body: nested single-statement returns are not
        // necessarily unconditional. Path analysis handles reachability.
        $body = securelogPhpSlice($tokens, $bodyStart, $bodyEnd);

        if ($id === T_CATCH) {
            $rules = [77803];
        } else {
            $rules = [];
            $isAuth = isPhpAuthenticationFailure($condition);
            if ($isAuth) $rules[] = 77801;
            // A 403 response inside a failed-login path is not, by itself,
            // a second independent authorization event.
            if (isPhpAccessControlFailure($condition)
                || (!$isAuth && isPhpAccessControlFailure($body))) $rules[] = 77802;
        }
        foreach ($rules as $rule) {
            $key = $rule . ':' . $i;
            if (isset($seen[$key])) continue;
            $seen[$key] = true;
            $events[] = [
                'rule' => $rule,
                'line' => $tokens[$i]['line'],
                'body' => $body,
            ];
            if ($rule === 77802) {
                for ($j = $bodyStart; $j <= $bodyFinish; $j++) $coveredDenials[$j] = true;
            }
        }
    }

    // Preserve detection of standalone abort(403) / http_response_code(403).
    for ($i = 0; $i < $n; $i++) {
        if ($tokens[$i]['id'] !== T_STRING || isset($coveredDenials[$i])) continue;
        if (!in_array(strtolower($tokens[$i]['text']), ['abort', 'http_response_code'], true)) continue;
        $open = securelogPhpNextToken($tokens, $i + 1);
        if ($open === null || $tokens[$open]['text'] !== '(') continue;
        $close = securelogPhpMatchPair($tokens, $open, '(', ')');
        if ($close === null || trim(securelogPhpSlice($tokens, $open + 1, $close - 1)) !== '403') continue;
        $events[] = ['rule' => 77802, 'line' => $tokens[$i]['line'], 'body' => ''];
    }

    usort($events, static fn(array $a, array $b): int => $a['line'] <=> $b['line']);
    return $events;
}


/* ============================================================
   SECURITY EVENT ANALYSIS
   ============================================================ */

function analyzePhpSecurityEventStatus(
    array &$results,
    string $fileName,
    int $lineNumber,
    string $context,

    int $cwe778RuleId,
    string $eventName,
    string $cwe778FailureDescription,
    string $cwe778Recommendation,
    ?array $sinkEvidence = null
): void {


    /* =========================================================
       CHECK 1
       SECURITY LOGGING — CWE-778
       ========================================================= */

    $sinkEvidence = $sinkEvidence ?? [
        'status' => securelogPhpHasActualSink($context) ? 'PASS' : 'FAIL',
        'indirect' => false, 'context' => $context
    ];
    $loggingStatus = $sinkEvidence['status'];
    $effectiveContext = $sinkEvidence['context'];


    if ($loggingStatus !== 'PASS') {

        /*
         * FAIL
         *
         * A security event exists but no LOG_SINK exists.
         */

        $results[] = createPhpCheckResult(
            $loggingStatus,
            'Security Logging',
            $loggingStatus === 'FAIL' ? $cwe778RuleId : null,
            'CWE-778',
            (
                $loggingStatus === 'N/A' ? 'INFO' : ($cwe778RuleId === 77803
                    ? 'MEDIUM'
                    : 'HIGH')
            ),
            $fileName,
            $lineNumber,

            $loggingStatus === 'N/A'
                ? (!empty($sinkEvidence['path_uncertain'])
                    ? $eventName . ': logging was found, but complete path coverage could not be verified.'
                    : $eventName . ': a potential external logging wrapper was found, but its implementation could not be verified in this file.')
                : (!empty($sinkEvidence['path_gap'])
                    ? $eventName . ': a logging operation exists, but at least one reachable event path can bypass it.'
                    : $eventName . ': ' . $cwe778FailureDescription),

            $loggingStatus === 'N/A' ? 'Include the logger implementation in a project-folder scan to verify this call.' : $cwe778Recommendation
        );


        $dependentReason = !empty($sinkEvidence['path_gap'])
            ? 'Not evaluated because logging can be bypassed on this security-event path.'
            : (!empty($sinkEvidence['path_uncertain'])
                ? 'Not evaluated because logging path coverage could not be verified.'
                : 'Not evaluated because no security logging operation exists for this event.');

        /*
         * CWE-117 cannot be evaluated because there is
         * no logging operation.
         */

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Neutralization',
            null,
            'CWE-117',
            'INFO',
            $fileName,
            $lineNumber,

            $dependentReason
        );


        /*
         * Storage cannot be evaluated because there is
         * no log operation.
         */

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Storage',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            $lineNumber,

            $dependentReason
        );


        /*
         * Encryption cannot be evaluated because there is
         * no log data being written.
         */

        $results[] = createPhpCheckResult(
            'N/A',
            'Log Protection',
            null,
            'SecureLog Policy',
            'INFO',
            $fileName,
            $lineNumber,

            $dependentReason
        );


        return;
    }


    /*
     * PASS — CWE-778
     */

    $results[] = createPhpCheckResult(
        'PASS',
        'Security Logging',
        null,
        'CWE-778',
        'INFO',
        $fileName,
        $lineNumber,

        'Required security event logging was detected for: ' .
        $eventName . '.'
    );



    // The current data-flow analyzer cannot prove parameter propagation through
    // arbitrary custom wrappers. Do not report a misleading CWE-117 PASS.
    if ($sinkEvidence['indirect']) {
        $results[] = createPhpCheckResult('N/A', 'Log Neutralization', null,
            'CWE-117', 'INFO', $fileName, $lineNumber,
            'Custom logger resolved, but argument-to-sink neutralization flow was not verified.');
    } else {

    /* =========================================================
       CHECK 2
       LOG NEUTRALIZATION — CWE-117
       ========================================================= */

    $flow = findPhpUserInputToLogFlow(
        $context
    );


    /*
     * CASE A:
     *
     * User-controlled input reaches LOG_SINK.
     */
    if ($flow['reaches_sink']) {


        /*
         * User input reaches the log AND is neutralized.
         */
        if ($flow['neutralized']) {

            $results[] = createPhpCheckResult(
                'PASS',
                'Log Neutralization',
                null,
                'CWE-117',
                'INFO',
                $fileName,
                $lineNumber,

                'Logged external input is properly neutralized before reaching the logging operation.'
            );

        } else {

            /*
             * User input reaches the log but is NOT neutralized.
             *
             * CWE-117
             */

            $findingLine = $lineNumber;

            if (
                isset($flow['sink_line'])
                &&
                $flow['sink_line'] > 0
            ) {

                $findingLine = max(
                    1,
                    $lineNumber
                    + $flow['sink_line']
                    - ($flow['event_offset'] ?? 1)
                );
            }


            $results[] = createPhpCheckResult(
                'FAIL',
                'Log Neutralization',
                11701,
                'CWE-117',
                'HIGH',
                $fileName,
                $findingLine,

                'Logged external input is not properly neutralized.',

                'Neutralize carriage returns, line feeds, and unsafe control characters before user-controlled data is written to logs.'
            );
        }

    } else {

        /*
         * CASE B:
         *
         * No user-controlled input reaches LOG_SINK.
         *
         * This is NOT a CWE-117 failure.
         */

        $results[] = createPhpCheckResult(
            'PASS',
            'Log Neutralization',
            null,
            'CWE-117',
            'INFO',
            $fileName,
            $lineNumber,

            'No unneutralized user-controlled input was detected reaching the logging operation.'
        );
    }



    } // End direct-sink neutralization assessment.

    /* =========================================================
       CHECK 3
       LOG STORAGE — SECURELOG .TXT POLICY
       ========================================================= */

    $storage = securelogPhpStorageEvidence($effectiveContext);
    $storageStatus = $storage['status'];
    $results[] = createPhpCheckResult(
        $storageStatus, 'Log Storage',
        $storageStatus === 'FAIL' ? 90001 : null,
        'SecureLog Policy', $storageStatus === 'FAIL' ? 'MEDIUM' : 'INFO',
        $fileName, $lineNumber, $storage['description'],
        $storageStatus === 'FAIL' ? 'Use an approved .txt log destination under the project-specific storage policy.' : ''
    );


    /* =========================================================
       CHECK 4
       LOG PROTECTION — SECURELOG ENCRYPTION POLICY
       ========================================================= */

    /*
     * Encryption analysis is independent from CWE-117.
     *
     * SecureLog checks whether encrypted/protected data
     * actually reaches LOG_SINK.
     */

    $encryptionFlow = $sinkEvidence['indirect']
        ? ['encrypted' => false]
        : findPhpEncryptionToLogFlow($context);

    if ($encryptionFlow['encrypted']) {
        $protectionStatus = 'PASS';
        $protectionDescription = 'Recognized encryption flow to the logging operation was detected in this event.';
    } elseif (!$sinkEvidence['indirect'] && securelogPhpExplicitPlaintextWrite($context)) {
        $protectionStatus = 'FAIL';
        $protectionDescription = 'Explicit direct plaintext write to a log file was detected without a protection step.';
    } else {
        $protectionStatus = 'N/A';
        $protectionDescription = 'Protection at the logging destination or archive layer cannot be verified from this event.';
    }

    $results[] = createPhpCheckResult(
        $protectionStatus, 'Log Protection',
        $protectionStatus === 'FAIL' ? 90002 : null,
        'SecureLog Policy', $protectionStatus === 'FAIL' ? 'MEDIUM' : 'INFO',
        $fileName, $lineNumber, $protectionDescription,
        $protectionStatus === 'FAIL' ? 'Apply the project-required protection before storing the log, or use a verifiably protected logging service.' : ''
    );
}


/* ============================================================
   IMPORTANT
   ============================================================

   KEEP ALL YOUR EXISTING FUNCTIONS BELOW THIS POINT:

   hasPhpLogSink()
   hasPhpTxtLogTarget()
   containsPhpUserInputSource()
   hasPhpLogNeutralization()
   findPhpUserInputToLogFlow()
   hasPhpEncryptionOperation()
   findPhpEncryptionToLogFlow()
   isPhpAuthenticationFailure()
   isPhpAccessControlFailure()
   isPhpExceptionHandling()
   getPhpEventWindow()
   getPhpCodeBlock()
   getPhpAnalysisContext()
   getPhpLogicalStatements()

   DO NOT DELETE THEM.
   ============================================================ */


    /* =========================================================
       GATE 1
       CWE-778 — SECURITY LOGGING REQUIRED
       ========================================================= */


/* ============================================================
   NORMALIZED PHP LOG SINK DETECTOR
   ============================================================ */

/**
 * Different PHP/framework logging implementations are
 * normalized into:
 *
 *                  LOG_SINK
 *
 * Supported examples:
 *
 * error_log(...)
 * syslog(...)
 *
 * $logger->warning(...)
 * $logger->error(...)
 *
 * Log::warning(...)
 * Log::error(...)
 *
 * logger(...)
 *
 * log_activity(...)
 * writeLog(...)
 * auditLog(...)
 *
 * file_put_contents(...)
 * fwrite(...)
 */
function hasPhpLogSink(
    string $code
): bool {

    $patterns = [

        /* Native PHP */

        '/\berror_log\s*\(/i',

        '/\bsyslog\s*\(/i',


        /* PSR / Monolog */

        '/->\s*(?:debug|info|notice|warning|error|critical|alert|emergency|log)\s*\(/i',


        /* Laravel Log facade */

        '/\bLog::\s*(?:debug|info|notice|warning|error|critical|alert|emergency|log)\s*\(/i',


        /* Laravel logger() helper */

        '/\blogger\s*\(/i',


        /* Custom / SecureLog functions */

        '/\blog_activity\s*\(/i',

        '/\bwriteLog\s*\(/i',

        '/\bauditLog\s*\(/i',

        '/\bsecurityLog\s*\(/i',

        '/\bwriteSecurityLog\s*\(/i',


        /*
         * File-based logging.
         *
         * Destination should appear related to:
         *
         * log
         * audit
         * security
         */

        '/\bfile_put_contents\s*\([^;]*(?:log|audit|security)[^;]*\)/is',


        /*
         * fwrite($handle, ...)
         *
         * Accepted when surrounding context indicates
         * logging/audit/security.
         */

        '/\bfwrite\s*\([^;]*(?:log|audit|security|message|event)[^;]*\)/is'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   SECURELOG APPROVED .TXT STORAGE POLICY
   ============================================================ */

/**
 * IMPORTANT:
 *
 * .txt is a SecureLog project-specific requirement.
 *
 * CWE-117 itself does NOT require logs to use .txt.
 */
function hasPhpTxtLogTarget(
    string $code
): bool {

    $patterns = [

        /*
         * file_put_contents(
         *     'security.txt',
         *     ...
         * )
         */

        '/\bfile_put_contents\s*\(\s*[\'"][^\'"]+\.txt[\'"]/is',


        /*
         * fopen(
         *     'audit.txt',
         *     'a'
         * )
         */

        '/\bfopen\s*\(\s*[\'"][^\'"]+\.txt[\'"]/is',


        /*
         * $logFile = 'security.txt';
         * $auditFile = 'audit.txt';
         */

        '/\$[A-Za-z_][A-Za-z0-9_]*(?:log|audit|security)[A-Za-z0-9_]*\s*=\s*[\'"][^\'"]+\.txt[\'"]/i',


        /*
         * $file = 'security_log.txt';
         */

        '/\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*[\'"][^\'"]*(?:log|audit|security)[^\'"]*\.txt[\'"]/i',


        /*
         * Literal .txt log-related target anywhere
         * inside the local analysis context.
         */

        '/[\'"][^\'"]*(?:log|audit|security)[^\'"]*\.txt[\'"]/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   USER-CONTROLLED INPUT SOURCE DETECTOR
   ============================================================ */

/**
 * Normalize common PHP/Laravel external input into:
 *
 *                  SOURCE
 */
function containsPhpUserInputSource(
    string $code
): bool {

    $patterns = [

        /* PHP superglobals */

        '/\$_POST\s*\[/i',

        '/\$_GET\s*\[/i',

        '/\$_REQUEST\s*\[/i',

        '/\$_COOKIE\s*\[/i',

        '/\$_FILES\s*\[/i',


        /* Laravel request helper */

        '/\brequest\s*\(/i',


        /*
         * Laravel Request object:
         *
         * $request->input(...)
         * $request->get(...)
         * $request->query(...)
         * $request->all(...)
         */

        '/\$request\s*->\s*(?:input|get|query|all|string)\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   CWE-117
   LOG NEUTRALIZATION DETECTOR
   ============================================================ */

/**
 * Detect recognized log-neutralization operations.
 *
 * Example:
 *
 * $safeUsername = str_replace(
 *     ["\r", "\n"],
 *     '',
 *     $username
 * );
 *
 * This is different from encryption.
 *
 * Neutralization protects the STRUCTURE of log records.
 * Encryption protects stored log DATA.
 */
function hasPhpLogNeutralization(
    string $code
): bool {

    $patterns = [

        /*
         * Remove CR/LF with str_replace().
         */

        '/\bstr_replace\s*\([^;]*(?:\\\\r|\\\\n)[^;]*\)/is',


        /*
         * Remove CR/LF/control characters with preg_replace().
         */

        '/\bpreg_replace\s*\([^;]*(?:\\\\r|\\\\n|\\\\x0D|\\\\x0A|\\\\x00)[^;]*\)/is',


        /* Custom neutralizers */

        '/\bsanitizeLog\s*\(/i',

        '/\bsanitize_log\s*\(/i',

        '/\bneutralizeLog\s*\(/i',

        '/\bneutralize_log\s*\(/i',

        '/\bescapeLog\s*\(/i',

        '/\bescape_log\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   CWE-117
   LIGHTWEIGHT SOURCE → LOG_SINK DATA FLOW
   ============================================================ */

/**
 * Supported flows:
 *
 * DIRECT
 * ------
 *
 * file_put_contents(
 *     'security.txt',
 *     $_POST['username']
 * );
 *
 *
 * VARIABLE
 * --------
 *
 * $username = $_POST['username'];
 *
 * file_put_contents(
 *     'security.txt',
 *     $username
 * );
 *
 *
 * PROPAGATION
 * -----------
 *
 * $username = $_POST['username'];
 *
 * $message =
 *     "Login failed: " . $username;
 *
 * file_put_contents(
 *     'security.txt',
 *     $message
 * );
 */
function findPhpUserInputToLogFlow(
    string $code
): array {

    $result = [

        'reaches_sink' => false,

        'neutralized' => false,

        'sink_line' => 0,

        'source' => null,

        'variable' => null,

        'event_offset' => 1
    ];


    $statements =
        getPhpLogicalStatements($code);


    if (empty($statements)) {
        return $result;
    }


    /*
     * Variables containing user-controlled data.
     */
    $taintedVariables = [];


    foreach ($statements as $statementData) {

        $statement =
            $statementData['code'];

        $statementLine =
            $statementData['line'];


        /* =====================================================
           STEP 1
           DIRECT SOURCE → LOG_SINK
           ===================================================== */

        if (
            hasPhpLogSink($statement)
            &&
            containsPhpUserInputSource($statement)
        ) {

            $result['reaches_sink'] =
                true;

            $result['sink_line'] =
                $statementLine;

            $result['source'] =
                'direct-user-input';

            $result['neutralized'] =
                hasPhpLogNeutralization(
                    $statement
                );

            return $result;
        }


        /* =====================================================
           STEP 2
           SOURCE → VARIABLE
           ===================================================== */

        if (
            preg_match(
                '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?$/is',
                $statement,
                $assignment
            ) === 1
        ) {

            $variableName =
                $assignment[1];

            $expression =
                $assignment[2];


            /*
             * Example:
             *
             * $username = $_POST['username'];
             */
            if (
                containsPhpUserInputSource(
                    $expression
                )
            ) {

                $taintedVariables[$variableName] = [

                    'neutralized' =>
                        hasPhpLogNeutralization(
                            $expression
                        ),

                    'source' =>
                        trim($expression)
                ];

                continue;
            }


            /* =================================================
               STEP 3
               TAINT PROPAGATION
               ================================================= */

            foreach (
                $taintedVariables
                as $taintedName => $taintInfo
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $taintedName,
                            '/'
                        ) .
                        '\b/',
                        $expression
                    ) === 1
                ) {

                    $isNeutralized =
                        $taintInfo['neutralized']
                        ||
                        hasPhpLogNeutralization(
                            $expression
                        );


                    $taintedVariables[$variableName] = [

                        'neutralized' =>
                            $isNeutralized,

                        'source' =>
                            $taintInfo['source']
                    ];

                    break;
                }
            }
        }


        /* =====================================================
           STEP 4
           TAINTED VARIABLE → LOG_SINK
           ===================================================== */

        if (hasPhpLogSink($statement)) {

            foreach (
                $taintedVariables
                as $variableName => $taintInfo
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $variableName,
                            '/'
                        ) .
                        '\b/',
                        $statement
                    ) === 1
                ) {

                    $result['reaches_sink'] =
                        true;

                    $result['sink_line'] =
                        $statementLine;

                    $result['source'] =
                        $taintInfo['source'];

                    $result['variable'] =
                        '$' . $variableName;


                    $result['neutralized'] =
                        $taintInfo['neutralized']
                        ||
                        hasPhpLogNeutralization(
                            $statement
                        );


                    return $result;
                }
            }
        }
    }


    return $result;
}


/* ============================================================
   SECURELOG ENCRYPTION OPERATION DETECTOR
   ============================================================ */

/**
 * Recognized encryption/protection operations.
 *
 * IMPORTANT:
 *
 * Finding openssl_encrypt() somewhere in the source file
 * does NOT automatically mean the log is encrypted.
 *
 * The encrypted result must reach LOG_SINK.
 *
 * hash_hmac() is intentionally NOT treated as encryption.
 */
function hasPhpEncryptionOperation(
    string $code
): bool {

    $patterns = [

        /* PHP OpenSSL */

        '/\bopenssl_encrypt\s*\(/i',


        /* Sodium Secretbox */

        '/\bsodium_crypto_secretbox\s*\(/i',


        /* Sodium AEAD encryption */

        '/\bsodium_crypto_aead_[A-Za-z0-9_]+_encrypt\s*\(/i',


        /* Custom SecureLog encryption wrappers */

        '/\bencryptLog\s*\(/i',

        '/\bencrypt_log\s*\(/i',

        '/\bprotectLog\s*\(/i',

        '/\bprotect_log\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   SECURELOG ENCRYPTION
   LIGHTWEIGHT ENCRYPTION → LOG_SINK DATA FLOW
   ============================================================ */

/**
 * Supported flows:
 *
 * DIRECT
 * ------
 *
 * file_put_contents(
 *     'security.txt',
 *     openssl_encrypt($message, ...)
 * );
 *
 *
 * VARIABLE
 * --------
 *
 * $encryptedLog =
 *     openssl_encrypt($message, ...);
 *
 * file_put_contents(
 *     'security.txt',
 *     $encryptedLog
 * );
 *
 *
 * PROPAGATION
 * -----------
 *
 * $encryptedLog =
 *     openssl_encrypt($message, ...);
 *
 * $payload =
 *     $encryptedLog;
 *
 * file_put_contents(
 *     'security.txt',
 *     $payload
 * );
 */
function findPhpEncryptionToLogFlow(
    string $code
): array {

    $result = [

        'encrypted' => false,

        'sink_line' => 0,

        'variable' => null
    ];


    $statements =
        getPhpLogicalStatements($code);


    if (empty($statements)) {
        return $result;
    }


    /*
     * Variables known to contain encrypted data.
     */
    $encryptedVariables = [];


    foreach ($statements as $statementData) {

        $statement =
            $statementData['code'];

        $statementLine =
            $statementData['line'];


        /* =====================================================
           STEP 1
           DIRECT ENCRYPTION → LOG_SINK
           ===================================================== */

        if (
            hasPhpLogSink($statement)
            &&
            hasPhpEncryptionOperation($statement)
        ) {

            $result['encrypted'] =
                true;

            $result['sink_line'] =
                $statementLine;

            return $result;
        }


        /* =====================================================
           STEP 2
           ENCRYPTION → VARIABLE
           ===================================================== */

        if (
            preg_match(
                '/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?$/is',
                $statement,
                $assignment
            ) === 1
        ) {

            $variableName =
                $assignment[1];

            $expression =
                $assignment[2];


            /*
             * Example:
             *
             * $encryptedLog =
             *     openssl_encrypt(...);
             */
            if (
                hasPhpEncryptionOperation(
                    $expression
                )
            ) {

                $encryptedVariables[$variableName] =
                    true;

                continue;
            }


            /* =================================================
               STEP 3
               ENCRYPTED DATA PROPAGATION
               ================================================= */

            foreach (
                $encryptedVariables
                as $encryptedName => $status
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $encryptedName,
                            '/'
                        ) .
                        '\b/',
                        $expression
                    ) === 1
                ) {

                    $encryptedVariables[$variableName] =
                        true;

                    break;
                }
            }
        }


        /* =====================================================
           STEP 4
           ENCRYPTED VARIABLE → LOG_SINK
           ===================================================== */

        if (hasPhpLogSink($statement)) {

            /*
             * Remember where a LOG_SINK exists even if
             * its data is not encrypted.
             */
            if ($result['sink_line'] === 0) {

                $result['sink_line'] =
                    $statementLine;
            }


            foreach (
                $encryptedVariables
                as $variableName => $status
            ) {

                if (
                    preg_match(
                        '/\$' .
                        preg_quote(
                            $variableName,
                            '/'
                        ) .
                        '\b/',
                        $statement
                    ) === 1
                ) {

                    $result['encrypted'] =
                        true;

                    $result['sink_line'] =
                        $statementLine;

                    $result['variable'] =
                        '$' . $variableName;

                    return $result;
                }
            }
        }
    }


    return $result;
}


/* ============================================================
   AUTHENTICATION FAILURE DETECTOR
   ============================================================ */

function isPhpAuthenticationFailure(
    string $code
): bool {

    $patterns = [

        /*
         * Native PHP:
         *
         * if (!password_verify(...))
         */

        '/!\s*password_verify\s*\(/i',


        /*
         * password_verify(...) === false
         */

        '/password_verify\s*\([^;]*?\)\s*(?:===|==)\s*false/i',


        /*
         * Laravel:
         *
         * if (!Auth::attempt(...))
         */

        '/!\s*Auth::attempt\s*\(/i',


        /*
         * Auth::attempt(...) === false
         */

        '/Auth::attempt\s*\([^;]*?\)\s*(?:===|==)\s*false/i',


        /*
         * Generic authentication functions.
         */

        '/!\s*(?:authenticate|authenticateUser|loginUser|verifyLogin)\s*\(/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   ACCESS CONTROL FAILURE DETECTOR
   ============================================================ */

function isPhpAccessControlFailure(
    string $code
): bool {

    $patterns = [

        /*
         * Laravel:
         *
         * Gate::denies(...)
         */

        '/\bGate::denies\s*\(/i',


        /*
         * !$user->can(...)
         * !$user->hasRole(...)
         * !$user->hasPermissionTo(...)
         */

        '/!\s*[^;\n]*(?:->|::)\s*(?:can|hasRole|hasPermissionTo|isAuthorized)\s*\(/i',


        /*
         * Role / permission comparisons.
         *
         * $_SESSION['role'] !== 'admin'
         */

        '/(?:role|permission|is_admin|isAdmin|authorized|authorization)[^;\n]*(?:!==|!=)\s*[\'"][^\'"]+[\'"]/i',


        /*
         * HTTP 403 denial.
         */

        '/\babort\s*\(\s*403\b/i',

        '/\bhttp_response_code\s*\(\s*403\s*\)/i'
    ];


    foreach ($patterns as $pattern) {

        if (preg_match($pattern, $code) === 1) {
            return true;
        }
    }


    return false;
}


/* ============================================================
   EXCEPTION HANDLING DETECTOR
   ============================================================ */

function isPhpExceptionHandling(
    string $code
): bool {

    /*
     * Examples:
     *
     * catch (Exception $e)
     *
     * catch (Throwable $e)
     *
     * catch (\RuntimeException $e)
     *
     * catch (Exception | RuntimeException $e)
     */

    return preg_match(
        '/\bcatch\s*\(\s*(?:\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*)(?:\s*\|\s*\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*)*\s+\$[A-Za-z_][A-Za-z0-9_]*\s*\)/i',
        $code
    ) === 1;
}


/* ============================================================
   EVENT WINDOW
   ============================================================ */

/**
 * Security conditions can span several lines.
 */
function getPhpEventWindow(
    array $lines,
    int $startIndex,
    int $lineCount = 8
): string {

    $result = [];

    $maxIndex = min(
        count($lines),
        $startIndex + $lineCount
    );


    for (
        $i = $startIndex;
        $i < $maxIndex;
        $i++
    ) {

        $result[] =
            $lines[$i];
    }


    return implode(
        "\n",
        $result
    );
}


/* ============================================================
   PHP EVENT BLOCK EXTRACTOR
   ============================================================ */

/**
 * Extract the block belonging to the detected event.
 */
function getPhpCodeBlock(
    array $lines,
    int $startIndex,
    int $maxLines = 40
): string {

    $context = [];

    $braceDepth = 0;

    $foundOpeningBrace = false;


    $lineLimit = min(
        count($lines),
        $startIndex + $maxLines
    );


    for (
        $i = $startIndex;
        $i < $lineLimit;
        $i++
    ) {

        $currentLine =
            $lines[$i];


        $context[] =
            $currentLine;


        $openingBraces =
            substr_count(
                $currentLine,
                '{'
            );


        $closingBraces =
            substr_count(
                $currentLine,
                '}'
            );


        if ($openingBraces > 0) {

            $foundOpeningBrace =
                true;
        }


        $braceDepth +=
            $openingBraces;


        $braceDepth -=
            $closingBraces;


        if (
            $foundOpeningBrace
            &&
            $braceDepth <= 0
        ) {

            break;
        }
    }


    return implode(
        "\n",
        $context
    );
}


/* ============================================================
   ANALYSIS CONTEXT
   ============================================================ */

/**
 * Creates a wider analysis context.
 *
 * Why?
 *
 * User input may be assigned BEFORE the security event:
 *
 * $username = $_POST['username'];
 *
 * if (!password_verify(...)) {
 *     ...
 * }
 *
 * If SecureLog only analyzes the IF block, it cannot see
 * that $username originated from $_POST.
 *
 * Therefore:
 *
 * - look backwards for source/variable assignments
 * - analyze the security-event block itself
 */
function getPhpAnalysisContext(
    array $lines,
    int $eventIndex,
    int $maxBlockLines = 40,
    int $lookBackLines = 20
): string {

    $startIndex = max(
        0,
        $eventIndex - $lookBackLines
    );


    $prefix = [];


    for (
        $i = $startIndex;
        $i < $eventIndex;
        $i++
    ) {

        $prefix[] =
            $lines[$i];
    }


    $eventBlock =
        getPhpCodeBlock(
            $lines,
            $eventIndex,
            $maxBlockLines
        );


    if (!empty($prefix)) {

        return implode(
            "\n",
            $prefix
        )
        .
        "\n"
        .
        $eventBlock;
    }


    return $eventBlock;
}


/* ============================================================
   PHP LOGICAL STATEMENT NORMALIZER
   ============================================================ */

/**
 * Convert multi-line PHP statements into logical statements.
 *
 * Example:
 *
 * $encryptedLog =
 *     openssl_encrypt(
 *         $message,
 *         'AES-256-CBC',
 *         $key,
 *         0,
 *         $iv
 *     );
 *
 * becomes one statement.
 *
 *
 * Same for:
 *
 * file_put_contents(
 *     'security.txt',
 *     $encryptedLog,
 *     FILE_APPEND
 * );
 */
function getPhpLogicalStatements(
    string $code
): array {

    $lines = preg_split(
        "/\r\n|\n|\r/",
        $code
    );


    if ($lines === false) {
        return [];
    }


    $statements = [];

    $buffer = '';

    $startLine = 1;

    $parenthesisDepth = 0;


    foreach ($lines as $index => $line) {

        $trimmedLine =
            trim($line);


        if ($trimmedLine === '') {
            continue;
        }


        if ($buffer === '') {

            $startLine =
                $index + 1;
        }


        $buffer .=
            ($buffer === '' ? '' : ' ')
            .
            $trimmedLine;


        /*
         * Lightweight parenthesis tracking.
         */
        $parenthesisDepth +=
            substr_count(
                $trimmedLine,
                '('
            );


        $parenthesisDepth -=
            substr_count(
                $trimmedLine,
                ')'
            );


        /*
         * Statement normally ends at ;
         * when parentheses are balanced.
         */
        if (
            str_contains(
                $trimmedLine,
                ';'
            )
            &&
            $parenthesisDepth <= 0
        ) {

            $statements[] = [

                'code' =>
                    trim($buffer),

                'line' =>
                    $startLine
            ];


            $buffer = '';

            $parenthesisDepth = 0;

            continue;
        }


        /*
         * Handle structural braces.
         */
        if (
            (
                $trimmedLine === '}'
                ||
                str_ends_with(
                    $trimmedLine,
                    '{'
                )
            )
            &&
            $parenthesisDepth <= 0
        ) {

            if (trim($buffer) !== '') {

                $statements[] = [

                    'code' =>
                        trim($buffer),

                    'line' =>
                        $startLine
                ];
            }


            $buffer = '';

            $parenthesisDepth = 0;
        }
    }


    if (trim($buffer) !== '') {

        $statements[] = [

            'code' =>
                trim($buffer),

            'line' =>
                $startLine
        ];
    }


    return $statements;
}
