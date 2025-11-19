<?php
header('Content-Type: application/json');

$raw = file_get_contents('php://input');
$req = json_decode($raw, true);
$email = trim($req['email'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  echo json_encode(['success'=>false, 'error'=>'invalid_email']); exit;
}

$nonce = bin2hex(random_bytes(16));
$expires_at = time() + 300; // 5 minutes

$storePath = 'data/nonces.json';
$all = file_exists($storePath) ? json_decode(file_get_contents($storePath), true) : [];
$all[$nonce] = ['email'=>$email, 'expires_at'=>$expires_at, 'used'=>false, 'created_at'=>time()];
file_put_contents($storePath, json_encode($all, JSON_PRETTY_PRINT));

echo json_encode(['success'=>true, 'nonce'=>$nonce, 'expires_at'=>$expires_at]);
