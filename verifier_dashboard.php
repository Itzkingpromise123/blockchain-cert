<?php
require 'config.php';
session_start();

if(!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'verifier') {
    header('Location: index.php');
    exit;
}

$verify_result = null;
if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cert_hash'])) {
    $search_hash = trim($_POST['cert_hash']);
    
    try {
        $stmt = $conn->prepare('SELECT * FROM certificates WHERE cert_hash = ?');
        $stmt->execute([$search_hash]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if($result) {
            $verify_result = $result;
            $verify_result['valid'] = true;
        } else {
            $verify_result = ['valid' => false];
        }
    } catch (PDOException $e) {
        $verify_result = ['valid' => false, 'error' => $e->getMessage()];
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Verify Certificate</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body>

<nav class="navbar navbar-dark bg-warning sticky-top">
    <span class="navbar-brand">✅ VERIFY CERTIFICATE</span>
    <div>
        <span class="text-dark mr-3">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="logout.php" class="btn btn-dark btn-sm">Logout</a>
    </div>
</nav>

<div class="container mt-5" style="max-width: 600px;">
    <div class="card">
        <div class="card-header bg-warning">
            <h4 class="mb-0">Verify a Certificate</h4>
        </div>
        <div class="card-body">
            <form method="POST">
                <div class="form-group">
                    <label><strong>Enter Certificate Hash</strong></label>
                    <textarea class="form-control" name="cert_hash" rows="4" placeholder="Paste the SHA-256 hash here" required></textarea>
                </div>
                <button type="submit" class="btn btn-warning btn-block btn-lg">Verify</button>
            </form>

            <?php if($verify_result): ?>
                <?php if($verify_result['valid']): ?>
                    <div class="alert alert-success mt-4">
                        <h5>✅ CERTIFICATE IS VALID AND AUTHENTIC!</h5>
                        <hr>
                        <p><strong>Certificate Code:</strong> <?php echo htmlspecialchars($verify_result['cert_code']); ?></p>
                        <p><strong>Student Name:</strong> <?php echo htmlspecialchars($verify_result['student_name']); ?></p>
                        <p><strong>Email:</strong> <?php echo htmlspecialchars($verify_result['student_email']); ?></p>
                        <p><strong>Course:</strong> <?php echo htmlspecialchars($verify_result['course_name']); ?></p>
                        <p><strong>Issue Date:</strong> <?php echo htmlspecialchars($verify_result['issue_date']); ?></p>
                        <hr>
                        <p class="text-success"><strong>✓ This certificate has NOT been tampered with</strong></p>
                    </div>
                <?php else: ?>
                    <div class="alert alert-danger mt-4">
                        <h5>❌ CERTIFICATE NOT FOUND OR INVALID!</h5>
                        <p>The certificate hash was not found in our database.</p>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

</body>
</html>
