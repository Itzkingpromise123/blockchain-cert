<?php
require 'config.php';

$error = '';
$success = '';
$verify_result = null;

// LOGIN
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'login') {
    $username = $_POST['username'];
    $password = hashPassword($_POST['password']);
    
    $stmt = $conn->prepare('SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?');
    $stmt->bind_param('ss', $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        header('Location: index.php');
        exit;
    } else {
        $error = 'Invalid username or password!';
    }
}

// ISSUE CERTIFICATE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'issue') {
    $student_name = $_POST['student_name'];
    $student_email = $_POST['student_email'];
    $course_name = $_POST['course_name'];
    $issue_date = $_POST['issue_date'];
    
    $cert_code = 'CERT-' . strtoupper(uniqid());
    $cert_hash = generateCertificateHash($student_name, $student_email, $course_name, $issue_date);
    
    $stmt = $conn->prepare('INSERT INTO certificates (cert_code, student_name, student_email, course_name, cert_hash, issue_date) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('ssssss', $cert_code, $student_name, $student_email, $course_name, $cert_hash, $issue_date);
    
    if ($stmt->execute()) {
        $success = "Certificate issued! Code: $cert_code | Hash: $cert_hash";
    } else {
        $error = 'Database error: ' . $stmt->error;
    }
}

// VERIFY CERTIFICATE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'verify') {
    $search_hash = $_POST['cert_hash'];
    
    $stmt = $conn->prepare('SELECT cert_code, student_name, student_email, course_name, cert_hash, issue_date FROM certificates WHERE cert_hash = ?');
    $stmt->bind_param('s', $search_hash);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $verify_result = $result->fetch_assoc();
        $verify_result['valid'] = true;
    } else {
        $verify_result = ['valid' => false];
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Blockchain Digital Certification System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
        .container { max-width: 900px; }
        .navbar { box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
    </style>
</head>
<body>

<?php if (!isset($_SESSION['user_id'])): ?>

    <!-- LOGIN PAGE -->
    <div class="container" style="max-width: 500px; margin-top: 50px;">
        <div class="card">
            <div class="card-header bg-primary text-white text-center">
                <h3>🔐 Blockchain Digital Certification System</h3>
                <small>Design and Implementation of a Blockchain-Enabled Digital Certification and Verification System</small>
            </div>
            <div class="card-body">
                <?php if ($error): ?>
                    <div class="alert alert-danger"><?php echo $error; ?></div>
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
                    <button type="submit" class="btn btn-primary btn-block"><strong>LOGIN</strong></button>
                </form>
                
                <hr>
                <p class="text-center"><strong>Demo Credentials:</strong></p>
                <p class="text-center text-muted">Username: <code>admin</code></p>
                <p class="text-center text-muted">Password: <code>admin123</code></p>
            </div>
        </div>
    </div>

<?php else: ?>

    <!-- NAVBAR -->
    <nav class="navbar navbar-dark bg-primary">
        <span class="navbar-brand mb-0 h5">📜 Blockchain Certification - <?php echo $_SESSION['username']; ?></span>
        <a href="?logout=1" class="btn btn-danger">Logout</a>
    </nav>

    <!-- DASHBOARD -->
    <div class="container mt-4">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">Dashboard</h5>
            </div>
            <div class="card-body">
                
                <ul class="nav nav-tabs" role="tablist">
                    <li class="nav-item">
                        <a class="nav-link active" data-toggle="tab" href="#issue">📜 Issue Certificate</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-toggle="tab" href="#verify">✅ Verify Certificate</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" data-toggle="tab" href="#list">📋 Certificate List</a>
                    </li>
                </ul>

                <div class="tab-content mt-3">
                    
                    <!-- ISSUE CERTIFICATE -->
                    <div id="issue" class="tab-pane fade show active">
                        <?php if ($success): ?>
                            <div class="alert alert-success alert-dismissible fade show">
                                <h5>✅ Certificate Issued!</h5>
                                <p><?php echo $success; ?></p>
                                <button type="button" class="close" data-dismiss="alert">&times;</button>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <div class="form-group">
                                <label>Student Name</label>
                                <input type="text" class="form-control" name="student_name" required>
                            </div>
                            <div class="form-group">
                                <label>Email</label>
                                <input type="email" class="form-control" name="student_email" required>
                            </div>
                            <div class="form-group">
                                <label>Course Name</label>
                                <input type="text" class="form-control" name="course_name" required>
                            </div>
                            <div class="form-group">
                                <label>Issue Date</label>
                                <input type="date" class="form-control" name="issue_date" value="<?php echo date('Y-m-d'); ?>" required>
                            </div>
                            <input type="hidden" name="action" value="issue">
                            <button type="submit" class="btn btn-primary btn-block">Generate Certificate</button>
                        </form>
                    </div>

                    <!-- VERIFY CERTIFICATE -->
                    <div id="verify" class="tab-pane fade">
                        <?php if ($verify_result): ?>
                            <?php if ($verify_result['valid']): ?>
                                <div class="alert alert-success">
                                    <h5>✅ CERTIFICATE IS VALID AND AUTHENTIC!</h5>
                                    <p><strong>Certificate Code:</strong> <?php echo $verify_result['cert_code']; ?></p>
                                    <p><strong>Student:</strong> <?php echo $verify_result['student_name']; ?></p>
                                    <p><strong>Email:</strong> <?php echo $verify_result['student_email']; ?></p>
                                    <p><strong>Course:</strong> <?php echo $verify_result['course_name']; ?></p>
                                    <p><strong>Date:</strong> <?php echo $verify_result['issue_date']; ?></p>
                                    <hr>
                                    <p class="text-success"><strong>✓ Hash verified - Certificate has NOT been tampered with</strong></p>
                                </div>
                            <?php else: ?>
                                <div class="alert alert-danger">
                                    <h5>❌ CERTIFICATE IS INVALID!</h5>
                                    <p>Hash not found in database or certificate may have been tampered with</p>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <div class="form-group">
                                <label>Enter Certificate Hash</label>
                                <textarea class="form-control" name="cert_hash" rows="4" placeholder="Paste SHA-256 hash" required></textarea>
                            </div>
                            <input type="hidden" name="action" value="verify">
                            <button type="submit" class="btn btn-success btn-block">Verify Certificate</button>
                        </form>
                    </div>

                    <!-- CERTIFICATE LIST -->
                    <div id="list" class="tab-pane fade">
                        <?php
                        $result = $conn->query('SELECT cert_code, student_name, student_email, course_name, issue_date FROM certificates ORDER BY created_at DESC');
                        if ($result->num_rows > 0):
                        ?>
                            <table class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Certificate Code</th>
                                        <th>Student Name</th>
                                        <th>Email</th>
                                        <th>Course</th>
                                        <th>Date</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php while ($row = $result->fetch_assoc()): ?>
                                        <tr>
                                            <td><code><?php echo $row['cert_code']; ?></code></td>
                                            <td><?php echo $row['student_name']; ?></td>
                                            <td><?php echo $row['student_email']; ?></td>
                                            <td><?php echo $row['course_name']; ?></td>
                                            <td><?php echo $row['issue_date']; ?></td>
                                        </tr>
                                    <?php endwhile; ?>
                                </tbody>
                            </table>
                        <?php else: ?>
                            <p class="text-muted">No certificates issued yet</p>
                        <?php endif; ?>
                    </div>

                </div>
            </div>
        </div>
    </div>

<?php endif; ?>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
