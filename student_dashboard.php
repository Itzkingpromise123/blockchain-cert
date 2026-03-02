<?php
require 'config.php';
session_start();

if(!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'student') {
    header('Location: index.php');
    exit;
}

$student_id = $_SESSION['user_id'];
try {
    $stmt = $conn->prepare('SELECT * FROM certificates WHERE user_id = ? ORDER BY created_at DESC');
    $stmt->execute([$student_id]);
    $certificates = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $certificates = [];
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>My Certificates</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body>

<nav class="navbar navbar-dark bg-success sticky-top">
    <span class="navbar-brand">📜 MY CERTIFICATES</span>
    <div>
        <span class="text-white mr-3">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="logout.php" class="btn btn-light btn-sm">Logout</a>
    </div>
</nav>

<div class="container mt-5">
    <h2 class="mb-4">Your Certificates</h2>
    
    <?php if(empty($certificates)): ?>
        <div class="alert alert-info">
            <p>You don't have any certificates yet.</p>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>Certificate Code</th>
                        <th>Course</th>
                        <th>Issue Date</th>
                        <th>Hash (First 16 chars)</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($certificates as $cert): ?>
                    <tr>
                        <td><code><?php echo htmlspecialchars($cert['cert_code']); ?></code></td>
                        <td><?php echo htmlspecialchars($cert['course_name']); ?></td>
                        <td><?php echo htmlspecialchars($cert['issue_date']); ?></td>
                        <td><code><?php echo substr($cert['cert_hash'], 0, 16); ?>...</code></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

</body>
</html>
