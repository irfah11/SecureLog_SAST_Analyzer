<?php
require_once __DIR__ . '/../Engine_Process/Scanner/PHPScanner.php';
$assert = static function(bool $ok,string $message): void {
    if (!$ok) throw new RuntimeException($message);
    echo "PASS: $message\n";
};
$run = static fn(string $body): array => scanPHP('service.php', '<?php try { work(); } catch (Throwable $e) {' . $body . '}');
foreach (['throw $e;', 'throw new RuntimeException("Failed", 0, $e);', '/* propagated */ throw $e;'] as $body) {
    $rows = $run($body);
    $assert(count($rows) === 4 && array_column($rows,'status') === ['N/A','N/A','N/A','N/A'], 'Immediate propagation delegates handling without invented PASS');
    $assert(str_contains($rows[0]['description'],'Caller-side') && str_contains($rows[3]['description'],'caller logging sink'), 'Propagation explanations distinguish unresolved caller handling');
}
$assert($run('return false;')[0]['status'] === 'FAIL','Swallowed failure is not automatically excused as propagation');
$assert($run('if ($retry) { throw $e; } return false;')[0]['status'] === 'FAIL','Conditional throw does not prove every path propagates');
$assert($run('$callback = function() { throw new Exception(); };')[0]['status'] === 'FAIL','Nested callback throw is not immediate catch propagation');
$assert($run('error_log("Failed"); throw $e;')[0]['status'] === 'PASS','Local logging followed by throw retains logging evidence');
$code = '<?php function encrypt_archive($p,$k,$iv) { return openssl_encrypt($p,"aes-256-gcm",$k,0,$iv); }
function decrypt_archive($p,$k,$iv) { return openssl_decrypt($p,"aes-256-gcm",$k,0,$iv); }
try { work(); } catch (Throwable $e) { throw $e; }';
$rows = scanPHP('vault.php',$code);
$assert($rows[3]['status'] === 'N/A' && str_contains($rows[3]['description'],'openssl_encrypt')
    && str_contains($rows[3]['description'],'openssl_decrypt'), 'Crypto capability observations do not imply event encryption PASS');
$assert(securelogPhpCryptoApiEvidence('<?php /* openssl_encrypt($x); */ $s="openssl_decrypt($x)";') === [], 'Comments and strings are not crypto API calls');
$assert(securelogPhpCryptoApiEvidence('<?php $x->openssl_encrypt($data);') === [], 'Unbound method name is not an OpenSSL API call');
$code = '<?php try { work(); } catch(Throwable $e) { error_log("Failed"); }';
$base = scanPHP('vault.php',$code);
$withDecrypt = scanPHP('vault.php',$code . ' function archive_decode($p,$k,$iv) { return openssl_decrypt($p,"aes-256-gcm",$k,0,$iv); }');
$assert(array_column($base,'status') === array_column($withDecrypt,'status'), 'Unrelated decryption cannot upgrade log encryption');
