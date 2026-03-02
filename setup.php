<?php
require 'config.php';

try {
    // Create users table
    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    
    $conn->exec($sql);
    echo "✅ Users table created successfully<br>";
    
    // Create certificates table
    $sql = "CREATE TABLE IF NOT EXISTS certificates (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        cert_code VARCHAR(100) UNIQUE NOT NULL,
        student_name VARCHAR(100) NOT NULL,
        student_email VARCHAR(100),
        course_name VARCHAR(150) NOT NULL,
        cert_hash VARCHAR(64) NOT NULL,
        issue_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )";
    
    $conn->exec($sql);
    echo "✅ Certificates table created successfully<br>";
    
    // Insert demo users
    $admin_hash = hash('sha256', 'admin123');
    $student_hash = hash('sha256', 'pass123');
    $verifier_hash = hash('sha256', 'verify123');
    
    $sql = "INSERT IGNORE INTO users (username, password_hash, role) VALUES 
            ('admin', '$admin_hash', 'admin'),
            ('student1', '$student_hash', 'student'),
            ('verifier1', '$verifier_hash', 'verifier')";
    
    $conn->exec($sql);
    echo "✅ Demo users created successfully<br>";
    echo "<br><strong>Database setup complete!</strong><br>";
    echo '<a href="index.php">Go to Login Page</a>';
    
} catch (PDOException $e) {
    echo "❌ Error: " . $e->getMessage() . "<br>";
}

$conn = null;
?>
