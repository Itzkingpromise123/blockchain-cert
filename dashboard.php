<?php
require 'config.php';
session_start();

if(!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$user_id = $_SESSION['user_id'];
$role = $_SESSION['role'];
$username = $_SESSION['username'];

// Handle Issue Certificate
$issue_message = '';
if($_POST && isset($_POST['action']) && $_POST['action'] === 'issue_cert') {
    $student_name = $_POST['student_name'];
    $student_email = $_POST['student_email'];
    $course_name = $_POST['course_name'];
    $issue_date = $_POST['issue_date'];
    
    $cert_code = 'CERT-' . strtoupper(uniqid());
    $cert_hash = generateCertificateHash($student_name, $student_email, $course_name, $issue_date);
    
    try {
        $stmt = $conn->prepare('INSERT INTO certificates (user_id, cert_code, student_name, student_email, course_name, cert_hash, issue_date) VALUES (?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([$user_id, $cert_code, $student_name, $student_email, $course_name, $cert_hash, $issue_date]);
        $issue_message = '<div class="alert alert-success"><i class="fas fa-check-circle"></i> Certificate issued successfully! Code: <strong>' . $cert_code . '</strong></div>';
    } catch (PDOException $e) {
        $issue_message = '<div class="alert alert-danger"><i class="fas fa-times-circle"></i> Error: ' . $e->getMessage() . '</div>';
    }
}

// Get all certificates
try {
    $stmt = $conn->prepare('SELECT * FROM certificates ORDER BY created_at DESC');
    $stmt->execute();
    $all_certificates = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $all_certificates = [];
}

// Get user certificates (for students)
try {
    $stmt = $conn->prepare('SELECT * FROM certificates WHERE user_id = ? ORDER BY created_at DESC');
    $stmt->execute([$user_id]);
    $user_certificates = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $user_certificates = [];
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard - Blockchain Certificate System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode.js/1.5.3/qrcode.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            padding: 15px 30px;
        }
        
        .navbar-brand {
            display: flex;
            align-items: center;
            font-size: 18px;
            font-weight: 700;
        }
        
        .navbar-brand img {
            height: 40px;
            margin-right: 10px;
            border-radius: 50%;
            background: white;
            padding: 3px;
        }
        
        .datetime-display {
            background: rgba(255,255,255,0.1);
            padding: 8px 15px;
            border-radius: 8px;
            font-size: 13px;
            color: white;
        }
        
        .sidebar {
            background: white;
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            width: 250px;
            padding-top: 80px;
            box-shadow: 2px 0 8px rgba(0,0,0,0.1);
            overflow-y: auto;
        }
        
        .main-content {
            margin-left: 250px;
            padding: 30px;
            padding-top: 100px;
        }
        
        .nav-link {
            color: #666;
            padding: 15px 30px;
            border-left: 4px solid transparent;
            transition: all 0.3s;
            font-weight: 500;
            cursor: pointer;
        }
        
        .nav-link:hover,
        .nav-link.active {
            background: #f0f0f0;
            color: #667eea;
            border-left-color: #667eea;
        }
        
        .section {
            display: none;
        }
        
        .section.active {
            display: block;
        }
        
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 20px;
            font-weight: 600;
            font-size: 16px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 8px;
            padding: 10px 25px;
            font-weight: 600;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(102, 126, 234, 0.3);
        }
        
        .form-control,
        .form-control-select {
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            padding: 10px 15px;
            transition: all 0.3s;
        }
        
        .form-control:focus,
        .form-control-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .table {
            font-size: 13px;
        }
        
        .table thead {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        
        .qr-code {
            width: 150px;
            height: 150px;
            margin: 10px auto;
            border: 2px solid #ddd;
            padding: 5px;
            border-radius: 8px;
            background: white;
        }
        
        .cert-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .cert-code {
            font-family: monospace;
            background: #f0f0f0;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
        }
        
        .role-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .role-badge.admin {
            background: #ffe5e5;
            color: #c33;
        }
        
        .role-badge.student {
            background: #e5f3ff;
            color: #0066cc;
        }
        
        .role-badge.verifier {
            background: #e5ffe5;
            color: #00aa00;
        }
        
        .stat-box {
            background: white;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 15px;
        }
        
        .stat-number {
            font-size: 28px;
            font-weight: 700;
            color: #667eea;
        }
        
        .stat-label {
            font-size: 12px;
            color: #999;
            text-transform: uppercase;
            margin-top: 5px;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                height: auto;
                position: relative;
                padding-top: 0;
            }
            
            .main-content {
                margin-left: 0;
                padding-top: 30px;
            }
        }
    </style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar navbar-dark fixed-top">
    <div class="navbar-brand">
        <i class="fas fa-graduation-cap" style="font-size: 30px;"></i>
        <div style="margin-left: 10px;">
            <div style="font-size: 16px; font-weight: 700;">NASARAWA UNIVERSITY</div>
            <div style="font-size: 11px; opacity: 0.9;">Blockchain Certificate System</div>
        </div>
    </div>
    
    <div class="datetime-display">
        <div><i class="fas fa-calendar"></i> <span id="date"></span></div>
        <div><i class="fas fa-clock"></i> <span id="time"></span></div>
    </div>
    
    <div style="margin-left: auto;">
        <span style="margin-right: 20px;"><span class="role-badge <?php echo $role; ?>"><?php echo strtoupper($role); ?></span> | <strong><?php echo htmlspecialchars($username); ?></strong></span>
        <a href="logout.php" class="btn btn-light btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </div>
</nav>

<!-- SIDEBAR -->
<div class="sidebar">
    <div style="padding: 20px; text-align: center; border-bottom: 1px solid #e0e0e0; margin-bottom: 10px;">
        <h6 style="color: #667eea; font-weight: 700;">MENU</h6>
    </div>
    
    <div class="nav-link active" onclick="showSection('dashboard')">
        <i class="fas fa-th-large"></i> Dashboard
    </div>
    
    <?php if($role === 'admin'): ?>
        <div class="nav-link" onclick="showSection('issue')">
            <i class="fas fa-certificate"></i> Issue Certificate
        </div>
        <div class="nav-link" onclick="showSection('certificates')">
            <i class="fas fa-list"></i> View Certificates
        </div>
        <div class="nav-link" onclick="showSection('users')">
            <i class="fas fa-users"></i> Manage Users
        </div>
    <?php elseif($role === 'student'): ?>
        <div class="nav-link" onclick="showSection('mycerts')">
            <i class="fas fa-file-certificate"></i> My Certificates
        </div>
    <?php elseif($role === 'verifier'): ?>
        <div class="nav-link" onclick="showSection('verify')">
            <i class="fas fa-check-circle"></i> Verify Certificate
        </div>
    <?php endif; ?>
    
    <hr style="margin: 20px 0;">
    
    <div class="nav-link" onclick="location.href='logout.php'">
        <i class="fas fa-sign-out-alt"></i> Logout
    </div>
</div>

<!-- MAIN CONTENT -->
<div class="main-content">
    
    <!-- DASHBOARD SECTION -->
    <div id="dashboard" class="section active">
        <h2 style="margin-bottom: 30px; color: #333; font-weight: 700;">
            <i class="fas fa-chart-line"></i> Welcome, <?php echo htmlspecialchars($username); ?>!
        </h2>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number"><?php echo count($all_certificates); ?></div>
                    <div class="stat-label">Total Certificates</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number"><?php echo count($user_certificates); ?></div>
                    <div class="stat-label">My Certificates</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number">100%</div>
                    <div class="stat-label">Authenticity Rate</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-box">
                    <div class="stat-number"><span class="role-badge <?php echo $role; ?>"><?php echo strtoupper($role); ?></span></div>
                    <div class="stat-label">Your Role</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <i class="fas fa-info-circle"></i> System Information
            </div>
            <div class="card-body">
                <p><strong>System:</strong> Blockchain-Based Certificate Verification Platform</p>
                <p><strong>Institution:</strong> Nasarawa University</p>
                <p><strong>Purpose:</strong> Secure digital certificate issuance and verification using blockchain technology</p>
                <p><strong>Security:</strong> SHA-256 Hashing | Tamper-Proof Records | QR Code Verification</p>
            </div>
        </div>
    </div>
    
    <!-- ISSUE CERTIFICATE SECTION (ADMIN ONLY) -->
    <div id="issue" class="section">
        <h2 style="margin-bottom: 30px; color: #333; font-weight: 700;">
            <i class="fas fa-certificate"></i> Issue New Certificate
        </h2>
        
        <?php echo $issue_message; ?>
        
        <div class="card">
            <div class="card-header">
                <i class="fas fa-pen-fancy"></i> Certificate Details
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label><strong>Student Name</strong></label>
                                <input type="text" class="form-control" name="student_name" placeholder="Enter student full name" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label><strong>Student Email</strong></label>
                                <input type="email" class="form-control" name="student_email" placeholder="Enter student email" required>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label><strong>Course/Degree Name</strong></label>
                                <input type="text" class="form-control" name="course_name" placeholder="e.g., Bachelor of Science in Computer Science" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label><strong>Issue Date</strong></label>
                                <input type="date" class="form-control" name="issue_date" value="<?php echo date('Y-m-d'); ?>" required>
                            </div>
                        </div>
                    </div>
                    
                    <input type="hidden" name="action" value="issue_cert">
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="fas fa-plus-circle"></i> Issue Certificate
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <!-- VIEW CERTIFICATES SECTION (ADMIN) -->
    <div id="certificates" class="section">
        <h2 style="margin-bottom: 30px; color: #333; font-weight: 700;">
            <i class="fas fa-list"></i> All Certificates
        </h2>
        
        <div class="card">
            <div class="card-header">
                <i class="fas fa-database"></i> Certificate Records (<?php echo count($all_certificates); ?> total)
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Certificate ID</th>
                                <th>Student Name</th>
                                <th>Course</th>
                                <th>Issue Date</th>
                                <th>Hash (First 16)</th>
                                <th>QR Code</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach($all_certificates as $cert): ?>
                            <tr>
                                <td><span class="cert-code"><?php echo substr($cert['cert_code'], 0, 12); ?></span></td>
                                <td><?php echo htmlspecialchars($cert['student_name']); ?></td>
                                <td><?php echo htmlspecialchars($cert['course_name']); ?></td>
                                <td><?php echo htmlspecialchars($cert['issue_date']); ?></td>
                                <td><code><?php echo substr($cert['cert_hash'], 0, 16); ?>...</code></td>
                                <td><button class="btn btn-sm btn-info" onclick="showQR('<?php echo htmlspecialchars($cert['cert_hash']); ?>')"><i class="fas fa-qrcode"></i> View</button></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- MY CERTIFICATES SECTION (STUDENT) -->
    <div id="mycerts" class="section">
        <h2 style="margin-bottom: 30px; color: #333; font-weight: 700;">
            <i class="fas fa-file-certificate"></i> My Certificates
        </h2>
        
        <?php if(empty($user_certificates)): ?>
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i> You don't have any certificates yet.
            </div>
        <?php else: ?>
            <?php foreach($user_certificates as $cert): ?>
            <div class="cert-card">
                <div class="row">
                    <div class="col-md-8">
                        <p><strong>Certificate Code:</strong> <span class="cert-code"><?php echo htmlspecialchars($cert['cert_code']); ?></span></p>
                        <p><strong>Course:</strong> <?php echo htmlspecialchars($cert['course_name']); ?></p>
                        <p><strong>Issue Date:</strong> <?php echo htmlspecialchars($cert['issue_date']); ?></p>
                        <p><strong>Hash:</strong> <code style="font-size: 10px;"><?php echo htmlspecialchars($cert['cert_hash']); ?></code></p>
                    </div>
                    <div class="col-md-4" style="text-align: center;">
                        <button class="btn btn-sm btn-info" onclick="showQR('<?php echo htmlspecialchars($cert['cert_hash']); ?>', '<?php echo htmlspecialchars($cert['cert_code']); ?>')">
                            <i class="fas fa-qrcode"></i> View QR Code
                        </button>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
    
    <!-- VERIFY CERTIFICATE SECTION (VERIFIER) -->
    <div id="verify" class="section">
        <h2 style="margin-bottom: 30px; color: #333; font-weight: 700;">
            <i class="fas fa-check-circle"></i> Verify Certificate
        </h2>
        
        <div class="card">
            <div class="card-header">
                <i class="fas fa-search"></i> Enter Certificate Hash
            </div>
            <div class="card-body">
                <form method="POST" id="verifyForm">
                    <div class="form-group">
                        <label><strong>Certificate Hash (SHA-256)</strong></label>
                        <textarea class="form-control" id="cert_hash" name="cert_hash" rows="4" placeholder="Paste the full SHA-256 hash here" required></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="fas fa-check"></i> Verify Certificate
                    </button>
                </form>
            </div>
        </div>
        
        <div id="verifyResult" style="margin-top: 30px;"></div>
    </div>
    
    <!-- MANAGE USERS SECTION (ADMIN ONLY) -->
    <div id="users" class="section">
        <h2 style="margin-bottom: 30px; color: #333; font-weight: 700;">
            <i class="fas fa-users"></i> System Users
        </h2>
        
        <div class="card">
            <div class="card-header">
                <i class="fas fa-user-tie"></i> User Management
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i> User management features coming soon. Current users can be managed via database directly.
                </div>
                <p><strong>Roles:</strong></p>
                <ul>
                    <li><strong>Admin:</strong> Can issue, view, and manage all certificates</li>
                    <li><strong>Student:</strong> Can view and access their own certificates</li>
                    <li><strong>Verifier:</strong> Can verify certificate authenticity</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<!-- QR CODE MODAL -->
<div class="modal fade" id="qrModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Certificate QR Code</h5>
                <button type="button" class="close" data-dismiss="modal"></button>
            </div>
            <div class="modal-body text-center">
                <div id="qrcode" class="qr-code"></div>
                <p id="qrHash" style="word-break: break-all; font-size: 11px; color: #999; margin-top: 15px;"></p>
            </div>
        </div>
    </div>
</div>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js"></script>

<script>
    // Update Date and Time
    function updateDateTime() {
        const now = new Date();
        const date = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        const time = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        
        document.getElementById('date').textContent = date;
        document.getElementById('time').textContent = time;
    }
    
    setInterval(updateDateTime, 1000);
    updateDateTime();
    
    // Show Section
    function showSection(sectionId) {
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        document.getElementById(sectionId).classList.add('active');
        
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        event.target.closest('.nav-link').classList.add('active');
    }
    
    // Show QR Code
    function showQR(hash, code = '') {
        $('#qrcode').html('');
        new QRCode(document.getElementById('qrcode'), {
            text: hash,
            width: 200,
            height: 200
        });
        
        document.getElementById('qrHash').textContent = hash;
        $('#qrModal').modal('show');
    }
    
    // Verify Certificate via AJAX
    document.getElementById('verifyForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const hash = document.getElementById('cert_hash').value;
        
        fetch('verify_api.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'cert_hash=' + encodeURIComponent(hash)
        })
        .then(r => r.json())
        .then(data => {
            if(data.valid) {
                document.getElementById('verifyResult').innerHTML = `
                    <div class="alert alert-success">
                        <h5><i class="fas fa-check-circle"></i> Certificate is VALID!</h5>
                        <p><strong>Student:</strong> ${data.student_name}</p>
                        <p><strong>Course:</strong> ${data.course_name}</p>
                        <p><strong>Date:</strong> ${data.issue_date}</p>
                    </div>
                `;
            } else {
                document.getElementById('verifyResult').innerHTML = `
                    <div class="alert alert-danger">
                        <h5><i class="fas fa-times-circle"></i> Certificate NOT FOUND or INVALID!</h5>
                    </div>
                `;
            }
        });
    });
</script>

</body>
</html>
