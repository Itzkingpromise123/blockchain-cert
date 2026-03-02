<?php
require 'config.php';
session_start();

if(!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
    <style>
        body { background: #f5f5f5; }
        .navbar { box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>

<nav class="navbar navbar-dark bg-danger sticky-top">
    <span class="navbar-brand">🔐 ADMIN PANEL</span>
    <div>
        <span class="text-white mr-3">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="logout.php" class="btn btn-light btn-sm">Logout</a>
    </div>
</nav>

<div class="container mt-5">
    <h2 class="mb-4">Admin Dashboard</h2>
    
    <div class="row">
        <div class="col-md-4 mb-3">
            <div class="card border-left-primary">
                <div class="card-body">
                    <h5 class="card-title">📜 Issue Certificate</h5>
                    <p class="card-text">Create and issue new certificates</p>
                    <a href="issue_certificate.php" class="btn btn-primary">Go</a>
                </div>
            </div>
        </div>
        
        <div class="col-md-4 mb-3">
            <div class="card border-left-success">
                <div class="card-body">
                    <h5 class="card-title">📋 View Certificates</h5>
                    <p class="card-text">See all issued certificates</p>
                    <a href="view_certificates.php" class="btn btn-success">Go</a>
                </div>
            </div>
        </div>
        
        <div class="col-md-4 mb-3">
            <div class="card border-left-info">
                <div class="card-body">
                    <h5 class="card-title">👥 Manage Users</h5>
                    <p class="card-text">Add and manage system users</p>
                    <a href="manage_users.php" class="btn btn-info">Go</a>
                </div>
            </div>
        </div>
    </div>
</div>

</body>
</html>
