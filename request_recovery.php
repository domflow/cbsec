<?php
// request_recovery.php
header('Content-Type: application/json');

$raw = file_get_contents('php://input');
$req = json_decode($raw, true);
$email = trim($req['email'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  echo json_encode(['success'=>false,'error'=>'invalid_email']); exit;
}

// DEMO: generate a 6-digit OTP (in production you'd send it via email/SMS)
$otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

// For demo purposes, just log it to a file
$logPath = __DIR__ . '/data/otp_demo.json';
$all = file_exists($logPath) ? json_decode(file_get_contents($logPath), true) : [];
$all[$email] = ['otp'=>$otp, 'created_at'=>time()];
file_put_contents($logPath, json_encode($all, JSON_PRETTY_PRINT));

// Return success (client will prompt user to enter it)
echo json_encode(['success'=>true,'message'=>'OTP generated (check server log for demo)', 'otp'=>$otp]);
