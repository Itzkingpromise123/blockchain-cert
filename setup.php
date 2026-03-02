<?php
require 'config.php';

try {
    // Create users table
    $sql = "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    
    $conn->exec($sql);
    echo "✅ Users table created successfully<br>";
    
    // Create certificates table
    $sql = "CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        cert_code TEXT UNIQUE NOT NULL,
        student_name TEXT NOT NULL,
        student_email TEXT,
        course_name TEXT NOT NULL,
        cert_hash TEXT NOT NULL,
        issue_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )";
    
    $conn->exec($sql);
    echo "✅ Certificates table created successfully<br>";
    
    // Check if users already exist
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users");
    $stmt->execute();
    $count = $stmt->fetchColumn();
    
    if($count == 0) {
        // Insert demo users only if they don't exist
        $admin_hash = hash('sha256', 'admin123');
        $student_hash = hash('sha256', 'pass123');
        $verifier_hash = hash('sha256', 'verify123');
        
        $sql = "INSERT INTO users (username, password_hash, role) VALUES 
                (?, ?, ?),
                (?, ?, ?),
                (?, ?, ?)";
        
        $stmt = $conn->prepare($sql);
        $stmt->execute(['admin', $admin_hash, 'admin']);
        $stmt->execute(['student1', $student_hash, 'student']);
        $stmt->execute(['verifier1', $verifier_hash, 'verifier']);
        
        echo "✅ Demo users created successfully<br>";
    } else {
        echo "ℹ️ Users already exist<br>";
    }
    
    echo "<br><strong style='color:green;'>✅ Database setup complete!</strong><br>";
    echo '<a href="index.php" class="btn btn-primary">Go to Login Page</a>';
    
} catch (PDOException $e) {
    echo "❌ Error: " . $e->getMessage() . "<br>";
}

$conn = null;
?>
