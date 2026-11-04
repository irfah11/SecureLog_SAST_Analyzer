<?php
require_once __DIR__.'/../Engine_Process/Scanner/PHPScanner.php';
$source=file_get_contents(__DIR__.'/fixtures/extended_php_logging/login_encrypted_complete_context.php');
$run=static fn($code)=>scanPHP('login.php',$code,[],true,false);
$assert=static function($ok,$label){if(!$ok) throw new RuntimeException($label);echo "PASS: $label\n";};
$assert(array_column($run($source),'status')===['PASS','PASS','PASS'],'Complete context survives JSON, secretbox, nonce framing and base64');
$overwrite=str_replace('$encrypted = sodium_crypto_secretbox', '$record = "No context"; $encrypted = sodium_crypto_secretbox',$source);
$assert($run($overwrite)[0]['status']==='N/A','Plaintext overwrite invalidates earlier context');
$mixed=str_replace('$payload . PHP_EOL','$payload . $_POST["extra"] . PHP_EOL',$source);
$assert($run($mixed)[0]['status']!=='PASS','Unknown appended data cannot inherit context');
$missing=str_replace("'reason' => 'INVALID_CREDENTIALS'", "'unused' => 'INVALID_CREDENTIALS'",$source);
$assert($run($missing)[0]['status']==='FAIL','Missing required context still fails after encryption');
$late=str_replace('$payload = base64_encode', '$record = "Changed after encryption"; $payload = base64_encode',$source);
$assert($run($late)[0]['status']==='PASS','Later plaintext overwrite does not change already encrypted data');
$unknown=str_replace('$payload = base64_encode', 'mutate($record); $payload = base64_encode',$source);
$assert($run($unknown)[0]['status']==='N/A','Unknown side effects invalidate alias proof');
$reference=str_replace('$payload = base64_encode', '$alias =& $record; $alias = "Changed"; $payload = base64_encode',$source);
$assert($run($reference)[0]['status']==='N/A','Reference alias is not trusted');
$future=str_replace('$record = json_encode', '$payload = $record; $record = json_encode',$source);
// Normal encrypted flow later overwrites payload; unrelated early assignment must not poison it.
$assert($run($future)[0]['status']==='PASS','Sequential reassignment uses the current payload origin');
