<?php
// demo_action.php
header('Content-Type: application/json');
require_once __DIR__ . '/audit_log.php'; // reuse audit logger + nonce validator

$raw = file_get_contents('php://input');
$req = json_decode($raw, true);

$email = trim($req['email'] ?? '');
$nonce = trim($req['nonce'] ?? '');
$otp   = trim($req['otp'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  audit_log('demo_action', $email, 'fail', ['error'=>'invalid_email']);
  echo json_encode(['success'=>false,'error'=>'invalid_email']); exit;
}

// validate nonce
$v = validate_and_consume_nonce($nonce, $email);
if (!$v['ok']) {
  audit_log('demo_action', $email, 'fail', ['error'=>$v['error'], 'nonce'=>$nonce]);
  echo json_encode(['success'=>false,'error'=>$v['error']]); exit;
}

// validate OTP (demo: accept "123456" only)
if ($otp !== '123456') {
  audit_log('demo_action', $email, 'fail', ['error'=>'invalid_otp', 'nonce'=>$nonce]);
  echo json_encode(['success'=>false,'error'=>'invalid_otp']); exit;
}

// pretend success
audit_log('demo_action', $email, 'success', ['nonce'=>$nonce, 'otp'=>$otp]);
echo json_encode(['success'=>true,'message'=>'Demo action completed successfully']);
