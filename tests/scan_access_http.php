<?php
/** Read-only HTTP boundary checks against an isolated loopback PHP server.
 * Sessions are test-only files in the OS temp directory. No user login, upload,
 * scan insertion, report download or activity-log action is performed.
 */
require_once __DIR__ . '/../Engine_Process/connection.php';
$sample = $conn->query('SELECT ScanID, UserID FROM scans WHERE UserID > 0 ORDER BY ScanID DESC LIMIT 1')->fetch_assoc();
if (!$sample) {
    fwrite(STDERR, "No existing scan available; ownership checks cannot run.\n");
    exit(2);
}
$scanId = (int) $sample['ScanID'];
$ownerId = (int) $sample['UserID'];
$otherId = $ownerId === 2147483000 ? 2147482999 : 2147483000;
$scratch = sys_get_temp_dir() . '/securelog-access-' . bin2hex(random_bytes(6));
mkdir($scratch, 0700);
ini_set('session.save_path', $scratch);
ini_set('session.use_cookies', '0');
$sessions = [];
foreach (['owner' => [$ownerId, 'developer'], 'other' => [$otherId, 'developer'],
    'admin' => [$otherId, 'admin'], 'guest' => [$otherId, 'guest'],
    'invalid' => [0, 'developer'], 'legacy' => [$ownerId, 'developer']] as $label => [$id, $role]) {
    $sid = bin2hex(random_bytes(16));
    session_id($sid);
    session_start();
    $_SESSION = [$label === 'legacy' ? 'user_id' : 'UserID' => $id, 'role' => $role];
    session_write_close();
    $sessions[$label] = $sid;
}
$port = random_int(20000, 45000);
$root = dirname(__DIR__);
$process = proc_open([PHP_BINARY, '-d', 'session.save_path=' . $scratch,
    '-S', '127.0.0.1:' . $port, '-t', $root],
    [0 => ['pipe', 'r'], 1 => ['file', $scratch . '/server.log', 'a'],
     2 => ['file', $scratch . '/server.log', 'a']], $pipes, $root);
if (!is_resource($process)) throw new RuntimeException('Unable to start test server.');
fclose($pipes[0]);
$request = function (string $path, ?string $identity = null) use ($sessions, $port): array {
    $headers = $identity === null ? '' : 'Cookie: PHPSESSID=' . $sessions[$identity] . "\r\n";
    $context = stream_context_create(['http' => ['ignore_errors' => true,
        'follow_location' => 0, 'timeout' => 10, 'header' => $headers]]);
    $body = file_get_contents('http://127.0.0.1:' . $port . '/' . $path, false, $context);
    $status = 0;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('/^HTTP\/\S+ (\d+)/', $header, $match)) $status = (int) $match[1];
    }
    return [$status, (string) $body, $http_response_header ?? []];
};
$assert = function (bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException($label);
    echo 'PASS: ' . $label . "\n";
};
try {
    $ready = false;
    for ($i = 0; $i < 40; $i++) {
        $socket = @fsockopen('127.0.0.1', $port);
        if ($socket) { fclose($socket); $ready = true; break; }
        usleep(100000);
    }
    $assert($ready, 'Isolated loopback server starts');
    foreach (['Engine_Process/index.php', 'Engine_Process/scan_process.php',
        'Engine_Process/Download_report.php?scan_id=' . $scanId] as $endpoint) {
        [$status, $body, $headers] = $request($endpoint);
        $assert($status === 302 && str_contains(implode('\n', $headers), 'Registration/login.php'), 'Anonymous redirected: ' . strtok($endpoint, '?'));
        [$status] = $request($endpoint, 'guest');
        $assert($status === 403, 'Guest denied: ' . strtok($endpoint, '?'));
    }
    $page = 'Engine_Process/index.php?scan_id=' . $scanId;
    [$status, $body] = $request($page, 'owner');
    $assert($status === 200 && !str_contains($body, 'Fatal error'), 'Owner can view existing scan');
    [$status, $body] = $request($page, 'other');
    $assert($status === 404 && trim($body) === 'Scan report not found.', 'Other developer receives no scan results');
    [$status, $body] = $request($page, 'admin');
    $assert($status === 200 && !str_contains($body, 'Fatal error'), 'Admin can view existing scan');
    [$status] = $request($page, 'legacy');
    $assert($status === 200, 'Legacy user_id session remains supported');
    [$status] = $request($page, 'invalid');
    $assert($status === 302, 'Zero identity rejected');
    foreach (['0', '-1', 'abc', '1%20OR%201=1', ''] as $invalid) {
        [$status] = $request('Engine_Process/index.php?scan_id=' . $invalid, 'owner');
        $assert($status === 400, 'Invalid scan ID rejected: ' . $invalid);
    }
    [$status, $body] = $request('Engine_Process/Download_report.php?scan_id=' . $scanId, 'other');
    $assert($status === 404 && trim($body) === 'Scan report not found.', 'Report endpoint also denies other developer');
} finally {
    proc_terminate($process);
    proc_close($process);
    foreach (glob($scratch . '/*') as $file) unlink($file);
    rmdir($scratch);
}
