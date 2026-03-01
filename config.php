<?php
session_start();

// Get database credentials from Railway environment variables
$db_host = getenv('MYSQLHOST') ?: 'localhost';
$db_user = getenv('MYSQLUSER') ?: 'root';
$db_pass = getenv('MYSQLPASSWORD') ?: '';
$db_name = getenv('MYSQLDATABASE') ?: 'blockchain_cert';
$db_port = getenv('MYSQLPORT') ?: 3306;

// Create connection
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);

// Check connection
if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
}

$conn->set_charset('utf8');

function generateCertificateHash($studentName, $email, $course, $date) {
    $data = $studentName . $email . $course . $date;
    return hash('sha256', $data);
}

function hashPassword($password) {
    return hash('sha256', $password);
}
?>
