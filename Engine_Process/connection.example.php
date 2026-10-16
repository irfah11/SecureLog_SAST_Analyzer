<?php
// Copy this file to connection.php and enter your local database settings.
// connection.php is ignored by Git. Never put real credentials in this example.
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$host_name = '127.0.0.1';
$db_user = 'YOUR_DATABASE_USER';
$db_pwd = 'YOUR_DATABASE_PASSWORD';
$db_name = 'YOUR_DATABASE_NAME';

try {
    $conn = new mysqli($host_name, $db_user, $db_pwd, $db_name);
    $conn->set_charset('utf8mb4');
} catch (Throwable $e) {
    error_log('SecureLog database connection failed.');
    http_response_code(500);
    exit('Unable to connect to the database. Check your local configuration.');
}
