<?php
require_once __DIR__ . '/../Engine_Process/Scanner/PHPScanner.php';
$assert = static function (bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
    echo "PASS: $label\n";
};
$context = <<<'PHP'
['timestamp' => date('c'), 'event' => 'LOGIN_FAILED', 'result' => 'FAILURE',
 'reason' => 'INVALID_CREDENTIALS', 'source_ip' => $_SERVER['REMOTE_ADDR'],
 'claimed_identity' => $_POST['username']]
PHP;
$login = '<?php if (!authenticate($name, $password)) { error_log(json_encode(' . $context . ')); }';
$rows = scanPHP('login.php',$login,[],true);
$assert(count($rows) === 4,'Extended login review produces exactly four checks');
$assert($rows[0]['check'] === 'Security Logging' && $rows[0]['status'] === 'PASS','Explicit login-failure context recognized without authenticated ID');
$assert(array_column($rows,'check') === ['Security Logging','Log Neutralization','Log Storage','Log Encryption'],'Only the four requested checks are emitted');
$assert(count(scanPHP('login.php',$login)) === 4,'Baseline four-check API preserved');
$missing = str_replace("'claimed_identity' => \$_POST['username']", "'role' => 'customer'", $login);
$assert(scanPHP('login.php',$missing,[],true)[0]['status'] === 'FAIL','Role alone cannot replace attempted login identity');
$plain = '<?php if (!authenticate($u,$p)) { error_log("Login failed"); }';
$assert(scanPHP('login.php',$plain,[],true)[0]['status'] === 'N/A','Plain text context stays unknown, not an invented PASS');
$before = '<?php $context=' . $context . '; if (!authenticate($u,$p)) { error_log("Failed"); }';
$assert(scanPHP('login.php',$before,[],true)[0]['status'] === 'N/A','Unlogged neighboring context cannot satisfy check');
$bypass = '<?php if (!authenticate($u,$p)) { if ($enabled) error_log(json_encode(' . $context . ')); }';
$assert(scanPHP('login.php',$bypass,[],true)[0]['status'] === 'FAIL','Conditional logging gap remains Security Logging FAIL');
$validation = '<?php if (filter_var($_POST["email"], FILTER_VALIDATE_EMAIL) === false) { return false; }';
$rows = scanPHP('validation.php',$validation,[],true);
$assert(count($rows) === 4 && $rows[0]['status'] === 'FAIL' && $rows[0]['event_name'] === 'Input Validation Failure','Unlogged server validation failure detected');
$assert(scanPHP('validation.php',$validation) === [],'Validation extension respects baseline mode');
$assert(scanPHP('sanitize.php','<?php if (!filter_var($x, FILTER_SANITIZE_EMAIL)) { return; }',[],true) === [],'Sanitization is not treated as validation');
$assert(scanPHP('business.php','<?php if (!in_array($color,$colors)) { return; }',[],true) === [],'Arbitrary business predicate is not validation event');
$assert(count(scanPHP('validation.php','<?php if (!in_array($_POST["mode"], ["a","b"], true)) { return; }',[],true)) === 4,'Request allowlist failure detected');
$assert(count(scanPHP('validation.php','<?php if (preg_match("/^[a-z]+$/", $_POST["name"]) !== 1) { return; }',[],true)) === 4,'Request regex failure detected');
$assert(scanPHP('comment.php','<?php /* if (!filter_var($x, FILTER_VALIDATE_EMAIL)) { return; } */',[],true) === [],'Comment is not an event');
$authBranches = '<?php if (authenticate($u,$p)) { error_log("OK"); } else { error_log("Failed"); }';
$rows = scanPHP('branches.php',$authBranches,[],true);
$assert(count($rows) === 8 && in_array('Authentication Success',array_column($rows,'event_name'),true)
    && in_array('Authentication Failure',array_column($rows,'event_name'),true),'Positive login and its failed else branch both reviewed');
$accessContext = str_replace("'claimed_identity' => \$_POST['username']", "'actor_id' => \$_SESSION['UserID'], 'target' => 'admin_panel'",$context);
foreach (['admin','customer','staff'] as $role) {
    $code = '<?php if ($_SESSION["role"] !== "' . $role . '") { error_log(json_encode(' . $accessContext . ')); }';
    $assert(scanPHP('access.php',$code,[],true)[0]['status'] === 'PASS',"Context recognition is role-independent: $role");
}
$spoof = str_replace("\$_SESSION['UserID']", "\$_POST['user_id']",$accessContext);
$code = '<?php if ($_SESSION["role"] !== "admin") { error_log(json_encode(' . $spoof . ')); }';
$assert(scanPHP('spoof.php',$code,[],true)[0]['status'] === 'FAIL','Client-supplied authenticated actor ID rejected');
$logger = '<?php function audit_event($message) { error_log($message); }';
$code = '<?php require_once __DIR__ . "/logger.php"; if (!authenticate($u,$p)) { audit_event("Failed"); }';
$assert(scanPHP('login.php',$code,['logger.php'=>$logger],true)[0]['status'] === 'N/A','Wrapper-added context not falsely inferred');
$assert(scanPHP('compound.php','<?php if (authenticate($u,$p) || bypass()) { error_log("OK"); }',[],true) === [],'Compound success condition cannot prove authentication');
$assert(scanPHP('compound.php','<?php if (!filter_var($x,FILTER_VALIDATE_EMAIL) || bypass()) { return; }',[],true) === [],'Compound validation predicate stays unsupported');
$withoutTime = str_replace("'timestamp' => date('c'),", '',$login);
$assert(scanPHP('login.php',$withoutTime,[],true)[0]['status'] === 'N/A','Missing explicit timestamp does not fail automatic runtime enrichment');
$wrongResult = str_replace("'result' => 'FAILURE'", "'result' => 'SUCCESS'",$login);
$assert(scanPHP('login.php',$wrongResult,[],true)[0]['status'] === 'FAIL','Result contradicting failure path detected');
$successContext = str_replace(["'claimed_identity' => \$_POST['username']", "'result' => 'FAILURE'", "'event' => 'LOGIN_FAILED'"],
    ["'actor_id' => \$_SESSION['UserID'], 'action' => 'LOGIN'", "'result' => 'SUCCESS'", "'event' => 'LOGIN_SUCCESS'"],$context);
$success = '<?php if (authenticate($u,$p)) { error_log(json_encode(' . $successContext . ')); }';
$assert(scanPHP('success.php',$success,[],true)[0]['status'] === 'PASS','Login success requires server identity and action');
$fixture = __DIR__ . '/fixtures/extended_php_logging/validation_with_context.php';
$assert(scanPHP(basename($fixture),file_get_contents($fixture),[],true)[0]['status'] === 'PASS','Anonymous validation fixture has sufficient static context');
require_once __DIR__ . '/../Engine_Process/Report/ScanReport.php';
require_once __DIR__ . '/../Engine_Process/ScanPresentation.php';
$fixture = __DIR__ . '/fixtures/extended_php_logging/access_missing_context.php';
$rows = scanPHP(basename($fixture),file_get_contents($fixture),[],true);
$assert(array_column($rows,'status') === ['FAIL','PASS','N/A','N/A'], 'Missing context changes only Security Logging; actual sink still assessed');
$assert($rows[0]['standard'] === 'CWE-223' && $rows[0]['rule_id'] === 22301,'Context omission retains its specific CWE inside Security Logging');
$saved = [];
foreach ($rows as $i => $row) $saved[] = ['ResultID'=>$i+1,'Status'=>$row['status'],'VulnerabilityName'=>$row['check'],
    'Severity'=>$row['severity'],'RuleID'=>$row['rule_id'],'Standard'=>$row['standard'],
    'Description'=>$row['description'],'Recommendation'=>$row['recommendation'],
    'FilePath'=>$row['file_path'],'LineNumber'=>$row['line_number']];
$report = securelogReportModel(['ScanID'=>1,'ProjectName'=>'Context review'], $saved);
$html = securelogReportHtml($report);
$assert(str_contains($html,'Security Logging') && str_contains($html,'Log Encryption')
    && !str_contains($html,'Log Retention') && !str_contains($html,'Log Context'), 'Report presents four checks without separate context or retention rows');
$assert(getCheckName(['VulnerabilityName'=>'Log Protection']) === 'Log Encryption','Legacy protection label maps to requested encryption label');
