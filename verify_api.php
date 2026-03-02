<?php
require 'config.php';
header('Content-Type: application/json');

if($_POST && isset($_POST['cert_hash'])) {
    $hash = trim($_POST['cert_hash']);
    
    try {
        $stmt = $conn->prepare('SELECT * FROM certificates WHERE cert_hash = ?');
        $stmt->execute([$hash]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if($result) {
            echo json_encode([
                'valid' => true,
                'student_name' => $result['student_name'],
                'course_name' => $result['course_name'],
                'issue_date' => $result['issue_date'],
                'cert_code' => $result['cert_code']
            ]);
        } else {
            echo json_encode(['valid' => false]);
        }
    } catch (Exception $e) {
        echo json_encode(['valid' => false, 'error' => $e->getMessage()]);
    }
} else {
    echo json_encode(['valid' => false]);
}
?>
