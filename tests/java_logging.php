<?php
require_once __DIR__.'/../Engine_Process/Scanner/JavaScanner.php';
$source=file_get_contents(__DIR__.'/fixtures/java_logging/CompleteJavaLogging.java');
$run=static fn($s)=>scanJava('CompleteJavaLogging.java',$s);
$assert=static function($ok,$label){if(!$ok) throw new RuntimeException($label);echo "PASS: $label\n";};
$rows=$run($source);
$assert(array_column($rows,'check')===['Security Logging','Log Storage','Log Encryption'],'Exactly three Java checks');
$assert(array_column($rows,'status')===['PASS','PASS','PASS'],'Event context survives Map, bytes, AEAD encryption and base64 to actual file');
$assert(array_column($run(str_replace('security.txt','security.json',$source)),'status')===['PASS','FAIL','PASS'],'Actual non-txt destination fails project policy');
$plain=str_replace('Files.writeString(Path.of("security.txt"), payload,','Files.writeString(Path.of("security.txt"), record.toString(),',$source);
$assert(array_column($run($plain),'status')===['PASS','PASS','FAIL'],'Unrelated encryption does not protect plaintext actually written');
$unknown=str_replace('Cipher.ENCRYPT_MODE','Cipher.DECRYPT_MODE',$source);
$assert($run($unknown)[2]['status']==='FAIL','Decryption output is not encrypted log data');
$unknown=str_replace('cipher.init(Cipher.ENCRYPT_MODE, key, parameters);','',$source);
$assert($run($unknown)[2]['status']==='N/A','Uninitialized cipher does not pass');
$missing=str_replace('"reason", "INVALID_CREDENTIALS"','"unused", "INVALID_CREDENTIALS"',$source);
$assert($run($missing)[0]['status']==='FAIL','Missing user context fails Security Logging');
$overwritten=str_replace('String payload =','encrypted = unknownBytes(); String payload =',$source);
$assert($run($overwritten)[2]['status']==='N/A','Payload overwrite invalidates encryption evidence');
$assert($run('class Empty {}')===[],'No event does not invent missing-logging failures');
$assert($run('// if (!authenticate(u,p)) { logger.error("bad"); }')===[],'Comment event ignored');
$assert($run('String text = "if (!authenticate(u,p)) { logger.error(\\"bad\\"); }";')===[],'Escaped string event ignored');
$assert(count($run('if (authenticate(u,p)) { logger.info("ok"); } else { logger.error("bad"); }'))===6,'Authentication success and failed else both reviewed');
foreach (['!user.hasRole("admin")','!user.hasRole("customer")','!validateEmail(email)'] as $condition) {
    $rows=$run('if ('.$condition.') { return; }');
    $assert(count($rows)===3 && $rows[0]['status']==='FAIL','Unlogged access or validation event detected without hardcoded role');
}
$assert($run('if (!authenticate(u,p)) { if (enabled) { logger.warn("bad"); } }')[0]['status']==='N/A','Conditional logging cannot imply full coverage');
$assert($run('if (!authenticate(u,p)) { return; logger.warn("dead"); }')[0]['status']==='FAIL','Dead logging after return does not pass');
$assert($run('try { work(); } catch (Exception e) { throw e; }')[0]['status']==='N/A','Propagated exception remains unknown at caller');
$mutated=str_replace('byte[] plaintext =','Object ignored = mutate(record); byte[] plaintext =',$source);
$assert($run($mutated)[0]['status']!=='PASS','Unknown function assignment cannot preserve mutable context proof');
$alias=str_replace('byte[] encrypted =','Cipher alias = cipher; alias.init(Cipher.DECRYPT_MODE, key, parameters); byte[] encrypted =',$source);
$assert($run($alias)[2]['status']==='N/A','Cipher aliases cannot preserve outdated encrypt-mode evidence');
$access=str_replace(['!isAuthenticated(authenticated)','"claimed_identity", username,'],
    ['!user.hasRole("customer")','"actor_id", request.getUserPrincipal().getName(), "target", "admin_panel",'],$source);
$access=str_replace('"actor_type", "unauthenticated",','',$access);
$assert(array_column($run($access),'status')===['PASS','PASS','PASS'],'Access-denial context with server-established actor reaches encrypted sink');
$spoof=str_replace('request.getUserPrincipal().getName()','request.getParameter("user_id")',$access);
$assert($run($spoof)[0]['status']==='FAIL','Request parameter cannot establish authenticated identity');
require_once __DIR__.'/../Engine_Process/Scanner/DatabaseRuleScanner.php';
$custom=[['RuleID'=>42,'RuleCode'=>'JAVA_RAW_SECRET','RuleName'=>'Potential secret logging','Language'=>'JAVA','Status'=>'ACTIVE',
    'MatchType'=>'SIMPLE_PATTERN','Pattern'=>'/logger\.info\(password\)/','SecondaryPattern'=>null,'Severity'=>'HIGH',
    'CWEID'=>'CWE-532','Description'=>'Review sensitive input.','Recommendation'=>'Remove secrets.']];
$assert(count(securelogScanDatabaseRules($custom,'java','Test.java','logger.info(password);'))===1,'Java custom rules remain compatible with built-in analyzer');
$assert($run('if (!authenticate(u,p)) { System.err.println("Failed"); }')[0]['status']==='N/A','System error logging is recognized without invented user context');
$assert($run('if (!authenticate(u,p)) { logger.info("Cipher.doFinal(password)"); }')[2]['status']==='FAIL','Cipher API text inside a logged string does not prove encryption');
