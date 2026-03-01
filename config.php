<?php
session_start();

// Use SQLite - built into PHP, no external server needed
$db_file = __DIR__ . '/certificates.db';

try {
    $conn = new PDO('sqlite:' . $db_file);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(Exception $e) {
    die('Database error: ' . $e->getMessage());
}

function generateCertificateHash($studentName, $email, $course, $date) {
    $data = $studentName . $email . $course . $date;
    return hash('sha256', $data);
}

function hashPassword($password) {
    return hash('sha256', $password);
}
?>
