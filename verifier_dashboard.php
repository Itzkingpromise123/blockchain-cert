<?php
require 'config.php';
session_start();

if($_SESSION['role'] !== 'verifier') {
    header("Location: login.php");
    exit;
}

$verify_result = null;
if($_POST) {
    $search_hash = $_POST['cert_hash'];
    $query = "SELECT * FROM certificates WHERE cert_hash = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $search_hash);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if($result->num_rows > 0) {
        $verify_result = $result->fetch_assoc();
        $verify_result['valid'] = true;
    } else {
        $verify_result = ['valid' => false];
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Verify Certificates</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-dark bg-warning">
    <span class="navbar-brand">✅ VERIFY CERTIFICATE</span>
    <a href="logout.php" class="btn btn-dark">Logout</a>
</nav>

<div class="container mt-5">
    <div class="card">
        <div class="card-header bg-warning">
            <h4>Verify a Certificate</h4>
        </div>
        <div class="card-body">
            <form method="POST">
                <div class="form-group">
                    <label>Enter Certificate Hash</label>
                    <textarea class="form-control" name="cert_hash" rows="4" required></textarea>
                </div>
                <button type="submit" class="btn btn-warning btn-block">Verify</button>
            </form>

            <?php if($verify_result): ?>
                <?php if($verify_result['valid']): ?>
                    <div class="alert alert-success mt-3">
                        <h5>✅ CERTIFICATE IS VALID!</h5>
                        <p><strong>Student:</strong> <?php echo $verify_result['student_name']; ?></p>
                        <p><strong>Course:</strong> <?php echo $verify_result['course_name']; ?></p>
                        <p><strong>Date:</strong> <?php echo $verify_result['issue_date']; ?></p>
                    </div>
                <?php else: ?>
                    <div class="alert alert-danger mt-3">
                        <h5>❌ CERTIFICATE NOT FOUND!</h5>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

</body>
</html>