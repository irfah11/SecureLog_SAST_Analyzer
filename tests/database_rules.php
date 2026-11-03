<?php
require_once __DIR__ . '/../Engine_Process/Scanner/ScannerEngine.php';
require_once __DIR__ . '/../Engine_Process/Scanner/DatabaseRuleScanner.php';
function checkRule(bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
    echo "PASS: $label\n";
}
$rule = ['RuleID' => 42, 'RuleCode' => 'SECRET_LOG', 'RuleName' => 'Secret in log',
    'Language' => 'PHP', 'Status' => 'ACTIVE', 'MatchType' => 'SIMPLE_PATTERN',
    'Pattern' => '/error_log\(.*password/', 'SecondaryPattern' => null,
    'Severity' => 'HIGH', 'CWEID' => 'CWE-532', 'Description' => 'Password logged.',
    'Recommendation' => 'Remove secrets from logs.'];
$source = "<?php\r\nerror_log(\$password);\r\n";
$rows = securelogScanDatabaseRules([$rule], 'php', 'login.php', $source);
checkRule(count($rows) === 1 && $rows[0]['status'] === 'FAIL' && $rows[0]['line_number'] === 2
    && $rows[0]['rule_id'] === 42 && $rows[0]['standard'] === 'CWE-532', 'Active rule produces traceable finding and CRLF line');
checkRule(securelogScanDatabaseRules([$rule], 'php', 'safe.php', '<?php error_log("Failure");') === [], 'Safe example produces no finding or invented PASS');
foreach (['DRAFT', 'DISABLED'] as $status) {
    checkRule(securelogScanDatabaseRules([array_replace($rule, ['Status' => $status])], 'php', 'x.php', $source) === [], "$status ignored");
}
checkRule(securelogScanDatabaseRules([$rule], 'java', 'x.java', $source) === [], 'Language isolation');
checkRule(count(securelogScanDatabaseRules([$rule, $rule], 'php', 'x.php', $source)) === 1, 'Duplicate rule and line suppressed');
$context = array_replace($rule, ['MatchType' => 'CONTEXT_PATTERN', 'Pattern' => '/error_log/', 'SecondaryPattern' => '/password/']);
checkRule(count(securelogScanDatabaseRules([$context], 'php', 'x.php', $source)) === 1, 'Context on same line matches');
checkRule(securelogScanDatabaseRules([$context], 'php', 'x.php', "error_log('failure');\npassword") === [], 'Context on different lines does not match');
$bad = array_replace($rule, ['Pattern' => '/[/']);
$rows = securelogScanDatabaseRules([$bad, $rule], 'php', 'x.php', $source);
checkRule(count($rows) === 2 && $rows[0]['status'] === 'N/A' && $rows[1]['status'] === 'FAIL', 'Invalid regex is visible and does not stop other rules');
checkRule(securelogMatchRule($rule['Pattern'], $source)['matches'][0]['line_number'] === 2, 'Shared test matcher agrees with scanner');
$evaluation = [];
securelogScanDatabaseRules([$rule],'php','safe.php','<?php error_log("Failed");',$evaluation);
checkRule(count($evaluation) === 1 && $evaluation[0]['code'] === 'SECRET_LOG'
    && $evaluation[0]['status'] === 'No match','Active rule stays visible when no match is found');
checkRule(!isset($evaluation[0]['Pattern']) && !isset($evaluation[0]['source']), 'Rule snapshot stores no pattern or source code');
securelogScanDatabaseRules([$rule],'php','login.php',$source,$evaluation);
checkRule($evaluation[0]['status'] === 'Matched' && $evaluation[0]['matches'] === 1,'Rule evaluation records match count');
securelogScanDatabaseRules([$bad],'php','login.php',$source,$evaluation);
checkRule($evaluation[0]['status'] === 'Could not evaluate','Regex failure is distinguished from no match');
