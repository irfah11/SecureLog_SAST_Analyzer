<?php
// connection.php - Letak di folder utama (root)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$host_name = "127.0.0.1";
$db_user = "root";
$db_pwd = "";
$db_name = "sast_tool_db1"; 

try {
    $conn = new mysqli($host_name, $db_user, $db_pwd, $db_name);
    $conn->set_charset("utf8mb4");
} catch (Throwable $e) {

    error_log(
        "Database Connection Failed: "
        . $e->getMessage()
    );

    http_response_code(500);

    die(
        "<pre>"
        . "DATABASE ERROR: "
        . htmlspecialchars(
            $e->getMessage(),
            ENT_QUOTES,
            'UTF-8'
        )
        . "</pre>"
    );
}
?>