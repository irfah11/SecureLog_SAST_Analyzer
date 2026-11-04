<?php
require_once __DIR__ . '/../Engine_Process/Scanner/PHPScanner.php';
require_once __DIR__ . '/../Engine_Process/Scanner/DatabaseRuleScanner.php';
$cases = ['<?php if (!authenticate($u,$p)) { error_log($_POST["username"]); }',
    '<?php if (!authenticate($u,$p)) { return false; }',
    '<?php if (!filter_var($email,FILTER_VALIDATE_EMAIL)) { return false; }'];
foreach ($cases as $source) {
    $rows = scanPHP('test.php',$source,[],true,false);
    if (array_column($rows,'check') !== ['Security Logging','Log Storage','Log Encryption']) {
        throw new RuntimeException('Upload-mode core checks must be exactly three');
    }
    echo "PASS: three core checks with no built-in neutralization result\n";
}
$rules = [['RuleID'=>42,'RuleCode'=>'RAW_LOG','RuleName'=>'Potential log injection','Language'=>'PHP',
    'Status'=>'ACTIVE','MatchType'=>'SIMPLE_PATTERN','Pattern'=>'/error_log/','SecondaryPattern'=>null,
    'Severity'=>'MEDIUM','CWEID'=>'CWE-117','Description'=>'Review raw input.','Recommendation'=>'Encode log data.']];
$rows = securelogScanDatabaseRules($rules,'php','test.php',$cases[0]);
if (count($rows)!==1 || $rows[0]['standard']!=='CWE-117') throw new RuntimeException('Custom neutralization rule must remain available');
echo "PASS: custom CWE-117 rule can add its own finding\n";
