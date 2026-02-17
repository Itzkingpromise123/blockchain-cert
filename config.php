<?php
// Show errors (for debugging only)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session
session_start();

// Database credentials (REPLACE WITH YOUR RAILWAY VALUES)
$host = getenv("DB_HOST");
$user = getenv("DB_USER");
$pass = getenv("DB_PASSWORD");
$db   = getenv("DB_NAME");

// Create connection
$conn = new mysqli($host, $user, $pass, $db);

// Check connection
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
?>
<content of the file>
