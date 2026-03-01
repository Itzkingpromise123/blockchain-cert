<?php
require 'config.php';
session_start();

if($_SESSION['role'] !== 'student') {
    header("Location: login.php");
    exit;
}

$student_id = $_SESSION['user_id'];
$query = "SELECT * FROM certificates WHERE user_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $student_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html>
<head>
    <title>My Certificates</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-dark bg-success">
    <span class="navbar-brand">📜 MY CERTIFICATES</span>
    <a href="logout.php" class="btn btn-light">Logout</a>
</nav>

<div class="container mt-5">
    <h2>Your Certificates</h2>
    <table class="table table-striped">
        <thead>
            <tr>
                <th>Certificate Code</th>
                <th>Course</th>
                <th>Issue Date</th>
                <th>Hash</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php while($row = $result->fetch_assoc()): ?>
            <tr>
                <td><?php echo $row['cert_code']; ?></td>
                <td><?php echo $row['course_name']; ?></td>
                <td><?php echo $row['issue_date']; ?></td>
                <td><code><?php echo substr($row['cert_hash'], 0, 16); ?>...</code></td>
                <td>
                    <a href="download_certificate.php?id=<?php echo $row['id']; ?>" class="btn btn-sm btn-primary">Download</a>
                </td>
            </tr>
            <?php endwhile; ?>
        </tbody>
    </table>
</div>

</body>
</html>