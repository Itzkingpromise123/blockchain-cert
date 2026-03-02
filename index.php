<?php
require 'config.php';
session_start();

$error = '';

if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $_POST['username'];
    $password = hashPassword($_POST['password']);
    
    try {
        $stmt = $conn->prepare('SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?');
        $stmt->execute([$username, $password]);
        $result = $stmt->fetch();
        
        if($result) {
            $_SESSION['user_id'] = $result['id'];
            $_SESSION['username'] = $result['username'];
            $_SESSION['role'] = $result['role'];
            
            // Redirect based on role
            if($result['role'] === 'admin') {
                header('Location: admin_dashboard.php');
            } elseif($result['role'] === 'student') {
                header('Location: student_dashboard.php');
            } else {
                header('Location: verifier_dashboard.php');
            }
            exit;
        } else {
            $error = 'Invalid username or password!';
        }
    } catch (PDOException $e) {
        $error = 'Database error: ' . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Blockchain Certificate System - Login</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            border-radius: 10px;
        }
    </style>
</head>
<body>

<div class="container" style="max-width: 400px;">
    <div class="card">
        <div class="card-header bg-primary text-white text-center">
            <h3>🔐 Blockchain Certificate System</h3>
            <small>Secure Digital Certificates</small>
        </div>
        <div class="card-body">
            <?php if($error): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label><strong>Username</strong></label>
                    <input type="text" class="form-control" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label><strong>Password</strong></label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <input type="hidden" name="action" value="login">
                <button type="submit" class="btn btn-primary btn-block btn-lg"><strong>LOGIN</strong></button>
            </form>
            
            <hr>
            <p class="text-center"><strong>Demo Credentials:</strong></p>
            <div class="alert alert-info" style="font-size: 13px;">
                <strong>Admin:</strong><br>
                Username: <code>admin</code><br>
                Password: <code>admin123</code><br><br>
                <strong>Student:</strong><br>
                Username: <code>student1</code><br>
                Password: <code>pass123</code><br><br>
                <strong>Verifier:</strong><br>
                Username: <code>verifier1</code><br>
                Password: <code>verify123</code>
            </div>
        </div>
    </div>
</div>

</body>
</html>
