<?php
require 'config.php';
session_start();

$error = '';

if($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'login') {
    $username = $_POST['username'];
    $password = hashPassword($_POST['password']);
    
    $stmt = $conn->prepare('SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?');
    $stmt->bind_param('ss', $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        // REDIRECT BASED ON ROLE
        if($user['role'] === 'admin') {
            header('Location: admin_dashboard.php');
        } elseif($user['role'] === 'student') {
            header('Location: student_dashboard.php');
        } else {
            header('Location: verifier_dashboard.php');
        }
        exit;
    } else {
        $error = 'Invalid username or password!';
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login - Blockchain Certificate</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">

<div class="container" style="max-width: 400px; margin-top: 100px;">
    <div class="card">
        <div class="card-header bg-primary text-white text-center">
            <h3>🔐 Blockchain Certificate System</h3>
        </div>
        <div class="card-body">
            <?php if($error): ?>
                <div class="alert alert-danger"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label><strong>Username</strong></label>
                    <input type="text" class="form-control" name="username" required>
                </div>
                <div class="form-group">
                    <label><strong>Password</strong></label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <input type="hidden" name="action" value="login">
                <button type="submit" class="btn btn-primary btn-block"><strong>LOGIN</strong></button>
            </form>
            
            <hr>
            <p class="text-center"><strong>Demo Login:</strong></p>
            <p class="text-center text-muted">Admin: <code>admin</code> / <code>admin123</code></p>
            <p class="text-center text-muted">Student: <code>student1</code> / <code>pass123</code></p>
        </div>
    </div>
</div>

</body>
</html>
