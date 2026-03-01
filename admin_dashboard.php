<?php
require 'config.php';
session_start();

// Check if user is admin
if($_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-dark bg-danger">
    <span class="navbar-brand">🔐 ADMIN PANEL</span>
    <a href="logout.php" class="btn btn-light">Logout</a>
</nav>

<div class="container mt-5">
    <div class="row">
        <div class="col-md-3">
            <div class="card bg-primary text-white">
                <div class="card-body">
                    <h5>Issue Certificate</h5>
                    <p>Create new certificates</p>
                    <a href="issue_certificate.php" class="btn btn-light">Go</a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-success text-white">
                <div class="card-body">
                    <h5>View All Certificates</h5>
                    <p>See issued certificates</p>
                    <a href="view_certificates.php" class="btn btn-light">Go</a>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-info text-white">
                <div class="card-body">
                    <h5>Manage Users</h5>
                    <p>Add/Edit users</p>
                    <a href="manage_users.php" class="btn btn-light">Go</a>
                </div>
            </div>
        </div>
    </div>
</div>

</body>
</html>