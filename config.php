<?php
session_start();

// Railway provides these as environment variables
$db_host = $_ENV['MYSQLHOST'] ?? getenv('MYSQLHOST') ?? 'localhost';
$db_user = $_ENV['MYSQLUSER'] ?? getenv('MYSQLUSER') ?? 'root';
$db_pass = $_ENV['MYSQLPASSWORD'] ?? getenv('MYSQLPASSWORD') ?? '';
$db_name = $_ENV['MYSQLDATABASE'] ?? getenv('MYSQLDATABASE') ?? 'railway';
$db_port = $_ENV['MYSQLPORT'] ?? getenv('MYSQLPORT') ?? 3306;

// Create connection using MySQLi
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name, (int)$db_port);

// Check connection
if ($conn->connect_error) {
    // For debugging - remove this in production
    error_log("Database Error: " . $conn->connect_error);
    die('Database connection failed. Please contact support.');
}

$conn->set_charset('utf8mb4');

function generateCertificateHash($studentName, $email, $course, $date) {
    $data = $studentName . $email . $course . $date;
    return hash('sha256', $data);
}

function hashPassword($password) {
    return hash('sha256', $password);
}
?>
