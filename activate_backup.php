<?php
header('Content-Type: application/json');
require_once __DIR__ . '/audit_log.php';

$raw = file_get_contents('php://input');
$req = json_decode($raw, true);

$email = trim($req['email'] ?? '');
$nonce = trim($req['nonce'] ?? '');
$checksum = $req['metadata']['checksum'] ?? null;

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  audit_log('activate', $email, 'fail', ['error'=>'invalid_email']); 
  echo json_encode(['success'=>false,'error'=>'invalid_email']); exit;
}
$v = validate_and_consume_nonce($nonce, $email);
if (!$v['ok']) {
  audit_log('activate', $email, 'fail', ['error'=>$v['error'], 'nonce'=>$nonce]);
  echo json_encode(['success'=>false, 'error'=>$v['error']]); exit;
}

// Demo: pretend success (your real logic here)
audit_log('activate', $email, 'success', ['nonce'=>$nonce, 'checksum'=>$checksum]);
echo json_encode(['success'=>true]);
