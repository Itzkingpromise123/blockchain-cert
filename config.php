<?php
session_start();

// Use SQLite - no server needed!
$db_path = __DIR__ . '/certificates.db';

try {
    $conn = new PDO('sqlite:' . $db_path);
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
