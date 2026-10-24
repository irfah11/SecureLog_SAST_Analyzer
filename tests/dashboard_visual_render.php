<?php
// Read-only render check. No login, scan, user or audit data is changed.
require_once __DIR__ . '/../Engine_Process/connection.php';
$role = $argv[1] ?? 'developer';
if (!in_array($role, ['admin','developer'], true)) exit(2);
$actor = $conn->query("SELECT UserID FROM users WHERE LOWER(role)='$role' AND is_active=1 LIMIT 1")->fetch_assoc();
if (!$actor) exit(2);
ini_set('session.use_cookies','0');
session_start();
$_SESSION = ['UserID'=>(int)$actor['UserID'],'role'=>$role,'username'=>'Dashboard check'];
$_SERVER['PHP_SELF'] = '/FinalYearProject/Dashboard/dashboard_' . ucfirst($role) . '.php';
ob_start();
require __DIR__ . '/../Dashboard/dashboard_' . ucfirst($role) . '.php';
$html = ob_get_clean();
session_destroy();
foreach (['welcome-panel', "type: 'line'", "type: 'doughnut'", '/FinalYearProject/Asset/js/chart.umd.min.js'] as $marker) {
    if (!str_contains($html,$marker)) throw new RuntimeException('Missing visual component: '.$marker);
}
if (str_contains($html,'Fatal error') || str_starts_with($html,'```')) throw new RuntimeException('Invalid HTML response');
echo "PASS: $role dashboard renders with live data, welcome banner, line and donut charts.\n";
