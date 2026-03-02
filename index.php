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
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if($result) {
            $_SESSION['user_id'] = $result['id'];
            $_SESSION['username'] = $result['username'];
            $_SESSION['role'] = $result['role'];
            header('Location: dashboard.php');
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
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320"><path fill="rgba(255,255,255,0.1)" fill-opacity="1" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,122.7C672,117,768,139,864,144C960,149,1056,139,1152,128C1248,117,1344,107,1392,101.3L1440,96L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path></svg>');
            background-repeat: no-repeat;
            background-position: bottom;
            background-size: cover;
            opacity: 0.3;
        }
        
        .login-container {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 450px;
            padding: 20px;
        }
        
        .login-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }
        
        .school-logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .login-header h2 {
            font-size: 24px;
            margin: 10px 0 5px;
            font-weight: 700;
        }
        
        .login-header p {
            font-size: 12px;
            opacity: 0.9;
        }
        
        .login-body {
            padding: 40px 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            font-weight: 600;
            color: #333;
            margin-bottom: 8px;
        }
        
        .form-control {
            height: 45px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 15px;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .form-control::placeholder {
            color: #999;
        }
        
        .btn-login {
            width: 100%;
            height: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            margin-top: 10px;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            color: white;
        }
        
        .alert {
            border-radius: 10px;
            border: none;
            margin-bottom: 20px;
        }
        
        .alert-danger {
            background-color: #ffe5e5;
            color: #c33;
        }
        
        .demo-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            border: 1px solid #e0e0e0;
        }
        
        .demo-section h5 {
            font-size: 13px;
            font-weight: 700;
            color: #333;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .demo-user {
            background: white;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
            font-size: 12px;
        }
        
        .demo-user strong {
            color: #667eea;
        }
        
        .demo-user code {
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
        }
        
        .footer-text {
            text-align: center;
            font-size: 12px;
            color: #999;
            margin-top: 20px;
        }
    </style>
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <div class="login-header">
            <div class="school-logo">
                <i class="fas fa-graduation-cap"></i>
            </div>
            <h2>NASARAWA UNIVERSITY</h2>
            <p>Blockchain Certificate Verification System</p>
        </div>
        
        <div class="login-body">
            <?php if($error): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Username</label>
                    <input type="text" class="form-control" name="username" placeholder="Enter your username" required autofocus>
                </div>
                
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Password</label>
                    <input type="password" class="form-control" name="password" placeholder="Enter your password" required>
                </div>
                
                <input type="hidden" name="action" value="login">
                <button type="submit" class="btn btn-login">
                    <i class="fas fa-sign-in-alt"></i> LOGIN
                </button>
            </form>
            
            <div class="demo-section">
                <h5>📋 Demo Credentials</h5>
                
                <div class="demo-user">
                    <strong><i class="fas fa-shield-alt"></i> Admin</strong><br>
                    Username: <code>admin</code><br>
                    Password: <code>admin123</code>
                </div>
                
                <div class="demo-user">
                    <strong><i class="fas fa-user-graduate"></i> Student</strong><br>
                    Username: <code>student1</code><br>
                    Password: <code>pass123</code>
                </div>
                
                <div class="demo-user">
                    <strong><i class="fas fa-check-circle"></i> Verifier</strong><br>
                    Username: <code>verifier1</code><br>
                    Password: <code>verify123</code>
                </div>
            </div>
            
            <div class="footer-text">
                <i class="fas fa-lock-alt"></i> Your data is secure and encrypted
            </div>
        </div>
    </div>
</div>

</body>
</html>
