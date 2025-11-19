<?php
// audit_log.php
function audit_log($action, $email, $outcome, $extra = []) {
  $entry = [
    'ts' => time(),
    'action' => $action,
    'email' => $email,
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
  ] + $extra + ['outcome' => $outcome];
  file_put_contents('data/audit.log', json_encode($entry) . PHP_EOL, FILE_APPEND);
}

function validate_and_consume_nonce($nonce, $email) {
  $storePath = 'data/nonces.json';
  $all = file_exists($storePath) ? json_decode(file_get_contents($storePath), true) : [];
  if (!isset($all[$nonce])) return ['ok'=>false, 'error'=>'nonce_not_found'];
  $rec = $all[$nonce];
  if ($rec['used']) return ['ok'=>false, 'error'=>'nonce_used'];
  if ($rec['expires_at'] < time()) return ['ok'=>false, 'error'=>'nonce_expired'];
  if (strcasecmp($rec['email'], $email) !== 0) return ['ok'=>false, 'error'=>'nonce_email_mismatch'];
  // consume
  $rec['used'] = true;
  $all[$nonce] = $rec;
  file_put_contents($storePath, json_encode($all, JSON_PRETTY_PRINT));
  return ['ok'=>true];
}
