<?php
session_start();

// Get database credentials from Railway environment variables
$db_host = $_ENV['MYSQLHOST'] ?? getenv('MYSQLHOST') ?? 'localhost';
$db_user = $_ENV['MYSQLUSER'] ?? getenv('MYSQLUSER') ?? 'root';
$db_pass = $_ENV['MYSQLPASSWORD'] ?? getenv('MYSQLPASSWORD') ?? '';
$db_name = $_ENV['MYSQLDATABASE'] ?? getenv('MYSQLDATABASE') ?? 'railway';
$db_port = $_ENV['MYSQLPORT'] ?? getenv('MYSQLPORT') ?? 3306;

try {
    // Use PDO instead of MySQLi
    $dsn = "mysql:host=$db_host;port=$db_port;dbname=$db_name;charset=utf8mb4";
    $conn = new PDO($dsn, $db_user, $db_pass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log("Database Error: " . $e->getMessage());
    die('Database connection failed: ' . $e->getMessage());
}

function generateCertificateHash($studentName, $email, $course, $date) {
    $data = $studentName . $email . $course . $date;
    return hash('sha256', $data);
}

function hashPassword($password) {
    return hash('sha256', $password);
}
?>
