<?php
// Isolated scanner checks: no application bootstrap, database or audit writes.
require_once __DIR__ . '/../Engine_Process/Scanner/PHPScanner.php';

$login = '<?php require_once __DIR__ . "/logger.php";
if (!authenticate($username, $password)) { log_activity("Login failed"); }';
$logger = '<?php function log_activity($message) { error_log($message); }';
$sources = ['login.php' => $login, 'logger.php' => $logger];
$assert = function (bool $condition, string $name): void {
    if (!$condition) throw new RuntimeException($name);
    echo "PASS: $name\n";
};
$statuses = fn(array $rows): array => array_column($rows, 'status');
$rows = scanPHP('login.php', $login, $sources);
$assert($statuses($rows) === ['PASS', 'N/A', 'N/A', 'N/A'], 'Static included logger has four evidence-based checks');
$assert($statuses(scanPHP('login.php', "\n" . $login, $sources)) === ['PASS', 'N/A', 'N/A', 'N/A'], 'Leading whitespace does not hide a static include');
$assert(scanPHP('logger.php', $logger, $sources) === [], 'Helper file creates no redundant summary');
$assert(count($rows) + count(scanPHP('logger.php', $logger, $sources)) === 4, 'Two uploaded files produce four results');
$assert($statuses(scanPHP('login.php', $login))[0] === 'N/A', 'Missing include implementation cannot pass');
$assert($statuses(scanPHP('login.php', $login, ['logger.php' => '<?php function log_activity($m) {}']))[0] === 'FAIL', 'Included no-op logger fails');
$assert($statuses(scanPHP('login.php', $login, ['logger.php' => '<?php function log_activity($m) { return; error_log($m); }']))[0] === 'FAIL', 'Dead sink does not pass');
$noInclude = '<?php if (!authenticate($username, $password)) { log_activity("Login failed"); }';
$assert($statuses(scanPHP('login.php', $noInclude, $sources))[0] === 'N/A', 'Unreferenced uploaded logger is not trusted');
$dynamic = str_replace('__DIR__ . "/logger.php"', '$loggerPath', $login);
$assert($statuses(scanPHP('login.php', $dynamic, $sources))[0] === 'N/A', 'Dynamic include is unresolved');
$conditional = str_replace('require_once', 'if ($enabled) require_once', $login);
$assert($statuses(scanPHP('login.php', $conditional, $sources))[0] === 'N/A', 'Conditional include is unresolved');
$nested = str_replace('"/logger.php"', '"/../lib/logger.php"', $login);
$assert($statuses(scanPHP('app/login.php', $nested, ['lib/logger.php' => $logger]))[0] === 'PASS', 'Relative include remains within uploaded project');
$traversal = str_replace('"/logger.php"', '"/../logger.php"', $login);
$assert($statuses(scanPHP('login.php', $traversal, $sources))[0] === 'N/A', 'Include cannot escape uploaded project');
$chain = ['logger.php' => '<?php require_once "sink.php"; function log_activity($m) { record_event($m); }',
    'sink.php' => '<?php require_once "logger.php"; function record_event($m) { error_log($m); }'];
$assert($statuses(scanPHP('login.php', $login, $chain))[0] === 'PASS', 'Transitive static includes resolve with cycle protection');
$direct = '<?php if (!authenticate($username, $password)) { error_log("Login failed"); }';
$assert($statuses(scanPHP('direct.php', $direct)) === ['PASS', 'PASS', 'N/A', 'N/A'], 'Direct sink behavior is preserved');
$unlogged = '<?php if (!authenticate($username, $password)) { echo "Login failed"; }';
$assert($statuses(scanPHP('unlogged.php', $unlogged)) === ['FAIL', 'N/A', 'N/A', 'N/A'], 'Missing logging behavior is preserved');
$sameFile = '<?php function log_activity($m) { error_log($m); } if (!authenticate($username, $password)) { log_activity("Login failed"); }';
$assert($statuses(scanPHP('same.php', $sameFile)) === ['PASS', 'N/A', 'N/A', 'N/A'], 'Same-file wrapper behavior is preserved');
$bypass = '<?php if (!authenticate($username, $password)) { if ($enabled) { error_log("Login failed"); } }';
$assert($statuses(scanPHP('bypass.php', $bypass))[0] === 'FAIL', 'Conditional sink bypass still fails');
