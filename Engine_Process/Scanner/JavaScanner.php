<?php
require_once __DIR__ . '/ScannerEngine.php';

/** Bounded Java source analysis. Never executes or compiles uploaded code.
 * Only supported straight-line event bodies are proven; class binding,
 * external configuration, arbitrary serializers and wrapper calls remain unknown.
 */
function securelogJavaLex(string $source, bool $strings = true): string
{
    $pattern = <<<'REGEX'
~//[^\r\n]*|/\*[\s\S]*?\*/|"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'~
REGEX;
    return preg_replace_callback($pattern, static function($m) use ($strings) {
        return $strings || str_starts_with($m[0], '//') || str_starts_with($m[0], '/*')
            ? preg_replace('/[^\r\n]/', ' ', $m[0]) : $m[0];
    }, $source);
}
function securelogJavaMask(string $source): string { return securelogJavaLex($source); }
function securelogJavaClose(string $code, int $start, string $open, string $close): ?int
{
    $depth=0;
    for ($i=$start,$n=strlen($code);$i<$n;$i++) {
        if ($code[$i]===$open) $depth++;
        if ($code[$i]===$close && --$depth===0) return $i;
    }
    return null;
}
function securelogJavaSplit(string $text, string $delimiter): array
{
    $mask=securelogJavaMask($text); $depth=0; $start=0; $parts=[];
    for ($i=0,$n=strlen($mask);$i<$n;$i++) {
        if (str_contains('([{',$mask[$i])) $depth++;
        elseif (str_contains(')]}',$mask[$i])) $depth--;
        elseif ($mask[$i]===$delimiter && $depth===0) { $parts[]=trim(substr($text,$start,$i-$start)); $start=$i+1; }
    }
    $parts[]=trim(substr($text,$start));
    return array_values(array_filter($parts, static fn($part)=>$part!==''));
}
/** Return arguments only for an entire expression matching the named call. */
function securelogJavaArgs(string $expression,string $name): ?array
{
    $expression=trim($expression); $mask=securelogJavaMask($expression);
    if (!preg_match('/^'.preg_quote($name,'/').'\s*\(/',$mask,$match)) return null;
    $open=strlen($match[0])-1; $close=securelogJavaClose($mask,$open,'(',')');
    return $close===strlen($expression)-1 ? securelogJavaSplit(substr($expression,$open+1,$close-$open-1),',') : null;
}
function securelogJavaLiteral(string $expression): ?string
{
    $expression=trim($expression);
    // Escape-containing paths/keys need a full Java string decoder: remain unknown.
    return preg_match('/^"([^"\\\\]*)"$/s',$expression,$match) ? $match[1] : null;
}
function securelogJavaUnknown(): array { return ['kind'=>'unknown','context'=>null,'path'=>null]; }
/** Track the actual expression supplied to a sink, not unrelated file keywords. */
function securelogJavaValue(string $expression,array $states,array $ciphers,int $depth=0): array
{
    $unknown=securelogJavaUnknown(); $expression=trim($expression);
    if ($depth>10) return $unknown;
    if (preg_match('/^[A-Za-z_]\w*$/',$expression)) return $states[$expression]??$unknown;
    $literal=securelogJavaLiteral($expression);
    if ($literal!==null) return ['kind'=>'plain','context'=>null,'path'=>$literal];
    foreach (['Path.of','Paths.get'] as $factory) {
        $args=securelogJavaArgs($expression,$factory);
        if ($args!==null) return count($args)===1 ? ['kind'=>'unknown','context'=>null,'path'=>securelogJavaLiteral($args[0])] : $unknown;
    }
    $args=securelogJavaArgs($expression,'Map.of');
    if ($args!==null) {
        if (count($args)%2!==0 || count($args)>20) return $unknown;
        $context=[];
        for ($i=0;$i<count($args);$i+=2) {
            $key=securelogJavaLiteral($args[$i]);
            if ($key===null || isset($context[$key])) return $unknown;
            $context[$key]=$args[$i+1];
        }
        return ['kind'=>'plain','context'=>$context,'path'=>null];
    }
    // Data-format conversions preserve context; they are not encryption.
    foreach (['Base64.getEncoder().encodeToString'] as $conversion) {
        $args=securelogJavaArgs($expression,$conversion);
        if ($args!==null) return count($args)===1 ? securelogJavaValue($args[0],$states,$ciphers,$depth+1) : $unknown;
    }
    if (preg_match('/^([A-Za-z_]\w*)\.doFinal\s*\(/',$expression,$match)) {
        $args=securelogJavaArgs($expression,$match[1].'.doFinal');
        if ($args===null || count($args)!==1) return $unknown;
        $value=securelogJavaValue($args[0],$states,$ciphers,$depth+1);
        if (($ciphers[$match[1]]??null)==='encrypt-aead') { $value['kind']='encrypted'; return $value; }
        // Decryption does not protect data subsequently written to a log.
        if (($ciphers[$match[1]]??null)==='decrypt') { $value['kind']='plain'; return $value; }
        return $unknown;
    }
    foreach (['.getBytes(StandardCharsets.UTF_8)','.getBytes()','.toString()'] as $suffix) {
        if (str_ends_with($expression,$suffix)) return securelogJavaValue(substr($expression,0,-strlen($suffix)),$states,$ciphers,$depth+1);
    }
    return $unknown;
}
function securelogJavaContext(?array $context,string $event): array
{
    if ($context===null) return ['N/A','Logging exists, but the payload context uses an unsupported expression or format.'];
    $required=['timestamp','event','source_ip','result','reason'];
    $required[]=$event==='Authentication Failure'?'claimed_identity':($event==='Input Validation Failure'?'field':($event==='Authentication Success'?'action':'target'));
    $missing=[];
    foreach ($required as $key) if (!isset($context[$key]) || in_array(trim($context[$key]),['null','""'],true)) $missing[]=$key;
    $anonymous=($context['actor_type']??'')==='"unauthenticated"';
    if ($event!=='Authentication Failure' && !$anonymous && (!isset($context['actor_id']) || trim($context['actor_id'])==='null')) $missing[]='actor_id';
    if ($missing) return ['FAIL','Structured log context omits required attributes: '.implode(', ',$missing).'.'];
    $expected=$event==='Authentication Success'?['SUCCESS','OK']:['FAILURE','FAIL','DENIED','ERROR'];
    $result=securelogJavaLiteral($context['result']);
    if ($result===null) return ['N/A','The result is dynamic and could not be verified.'];
    if (!in_array($result,$expected,true)) return ['FAIL','The recorded result contradicts the detected event.'];
    foreach (['actor_id','actor_role'] as $identityField) {
        if (isset($context[$identityField]) && str_contains($context[$identityField],'getParameter(')) return ['FAIL','Authenticated identity or role must not come directly from a request parameter.'];
    }
    if (!preg_match('/^(?:Instant\.now\(\)|OffsetDateTime\.now\(\))(?:\.toString\(\))?$/',$context['timestamp'])
        || !preg_match('/^[A-Za-z_]\w*\.getRemoteAddr\(\)$/',$context['source_ip'])) return ['N/A','Timestamp or request-source provenance uses an unsupported expression.'];
    if ($event!=='Authentication Failure' && !$anonymous) {
        if (str_contains($context['actor_id'],'getParameter(')) return ['FAIL','Authenticated identity must not come directly from a request parameter.'];
        if (!preg_match('/^(?:[A-Za-z_]\w*\.getUserPrincipal\(\)\.getName\(\)|[A-Za-z_]\w*\.getAttribute\("(?:user_id|UserID)"\))$/',$context['actor_id'])) return ['N/A','Server-established actor identity could not be verified.'];
    }
    return ['PASS','Recognized event context reaches the logging call. Static structure is verified; runtime values and identity correctness still require testing.'];
}
function securelogJavaEventChecks(string $body,string $event): array
{
    $clean=securelogJavaLex($body,false); $mask=securelogJavaMask($clean);
    $unknown=[['N/A','Logging path coverage or payload binding uses unsupported control flow.'],['N/A','The event log destination could not be verified.'],['N/A','Encryption of this event log could not be verified.']];
    if (preg_match('/\b(?:if|switch|for|while|try|catch|synchronized)\b|\?|&&|\|\||\bnew\b[^;]*\{/',$mask)) return $unknown;
    $states=[]; $ciphers=[]; $sinks=[]; $custom=false; $propagates=false;
    foreach (securelogJavaSplit($clean,';') as $statement) {
        $masked=trim(securelogJavaMask($statement));
        if (preg_match('/^(return|throw)\b/',$masked,$termination)) { $propagates=$termination[1]==='throw'; break; }
        if (preg_match('/^([A-Za-z_]\w*)\.init\s*\(/',$masked,$match)) {
            $args=securelogJavaArgs($statement,$match[1].'.init');
            $current=$ciphers[$match[1]]??null;
            $ciphers[$match[1]]=($args[0]??'')==='Cipher.ENCRYPT_MODE' && $current==='aead' && count($args)>=3 ? 'encrypt-aead'
                : ((($args[0]??'')==='Cipher.DECRYPT_MODE')?'decrypt':'unknown');
            continue;
        }
        if (preg_match('/^(?:(?:final\s+)?(?:Map\s*<[^;]+>|[\w.]+(?:\[\])?)\s+)?([A-Za-z_]\w*)\s*=\s*(?!=)([\s\S]+)$/',$statement,$match)) {
            $variable=$match[1]; $expression=trim($match[2]);
            $cipher=securelogJavaArgs($expression,'Cipher.getInstance');
            if ($cipher!==null) {
                $algorithm=isset($cipher[0])?securelogJavaLiteral($cipher[0]):null;
                $ciphers[$variable]=in_array($algorithm,['AES/GCM/NoPadding','ChaCha20-Poly1305'],true)?'aead':'unknown';
                $states[$variable]=securelogJavaUnknown();
            } else {
                $value=securelogJavaValue($expression,$states,$ciphers);
                // Unknown constructors/calls may mutate referenced data. Cipher
                // aliases can change another receiver's mode: do not retain proof.
                if ($value['kind']==='unknown' && $value['context']===null && $value['path']===null) {
                    $states=[]; $ciphers=[];
                }
                $states[$variable]=$value;
                unset($ciphers[$variable]);
            }
            continue;
        }
        $args=securelogJavaArgs($statement,'Files.write');
        if ($args===null) $args=securelogJavaArgs($statement,'Files.writeString');
        if ($args!==null && count($args)>=2) {
            $sinks[]=['value'=>securelogJavaValue($args[1],$states,$ciphers),
                'path'=>securelogJavaValue($args[0],$states,$ciphers)['path']];
            continue;
        }
        $args=securelogJavaArgs($statement,'System.err.println');
        if ($args!==null) {
            $sinks[]=['value'=>isset($args[0])?securelogJavaValue($args[0],$states,$ciphers):securelogJavaUnknown(),'path'=>null];
            continue;
        }
        if (preg_match('/^(logger|log)\.(info|warn|warning|error|severe|debug|log)\s*\(/',$masked,$match)) {
            $args=securelogJavaArgs($statement,$match[1].'.'.$match[2]);
            $payload=$args===null?null:($args[count($args)-1]??null);
            $sinks[]=['value'=>$payload===null?securelogJavaUnknown():securelogJavaValue($payload,$states,$ciphers),'path'=>null];
            continue;
        }
        if (preg_match('/\b(?:audit\w*|log\w*|recordEvent)\s*\(/i',$masked)) $custom=true;
        // Unknown calls/mutations may change referenced objects: discard evidence.
        if ($masked!=='') { $states=[]; $ciphers=[]; }
    }
    if (!$sinks) return [[$custom||$propagates?'N/A':'FAIL',$propagates?'Exception propagation delegates handling to a caller which has not been verified.':($custom?'Custom logger implementation is unresolved.':'No supported logging call was found on the reachable event path.')],$unknown[1],$unknown[2]];
    if (count($sinks)!==1) return $unknown; // Do not arbitrarily choose one of multiple sinks.
    $sink=$sinks[0]; $path=$sink['path']; $kind=$sink['value']['kind'];
    return [securelogJavaContext($sink['value']['context'],$event),
        [$path===null?'N/A':(preg_match('/\.txt$/i',$path)?'PASS':'FAIL'),$path===null?'Logging destination is external or dynamic; it could not be verified.':(preg_match('/\.txt$/i',$path)?'The actual logging call uses an explicit .txt destination (SecureLog policy).':'The actual logging destination does not meet the SecureLog .txt policy.')],
        [$kind==='encrypted'?'PASS':($kind==='plain'?'FAIL':'N/A'),$kind==='encrypted'?'Recognized initialized AEAD Cipher.doFinal output reaches the log write. Cryptographic parameters and key management still require review.':($kind==='plain'?'The actual logging call receives data proven plaintext by supported expressions.':'The payload encryption flow could not be verified.')]];
}
function scanJava(string $fileName,string $content): array
{
    $code=securelogJavaMask($content); $events=[]; $results=[];
    preg_match_all('/\b(if|catch)\s*\(/',$code,$matches,PREG_OFFSET_CAPTURE);
    foreach ($matches[0] as $index=>[$text,$at]) {
        $open=$at+strlen($text)-1; $close=securelogJavaClose($code,$open,'(',')'); if ($close===null) continue;
        $condition=trim(substr($code,$open+1,$close-$open-1));
        $start=$close+1; while(isset($code[$start]) && ctype_space($code[$start])) $start++;
        if (($code[$start]??'')!=='{') continue;
        $end=securelogJavaClose($code,$start,'{','}'); if ($end===null) continue;
        $kind=null;
        if ($matches[1][$index][0]==='catch') $kind='Exception Handling';
        else {
            $negative=str_starts_with($condition,'!'); $predicate=$negative?ltrim(substr($condition,1)):$condition;
            foreach (['authenticate','authenticateUser','verifyLogin','isAuthenticated'] as $auth) {
                if (securelogJavaArgs($predicate,$auth)!==null) $kind=$negative?'Authentication Failure':'Authentication Success';
            }
            if ($kind===null && $negative && preg_match('/^(?:[A-Za-z_]\w*\.)?(hasRole|hasPermission|isAuthorized|canAccess)\s*\(/',$predicate,$p)) {
                $name=trim(substr($predicate,0,strpos($predicate,'(')));
                if (securelogJavaArgs($predicate,$name)!==null) $kind='Access Control Failure';
            }
            if ($kind===null && $negative) foreach (['isValid','validateInput','validateEmail'] as $validator) {
                if (securelogJavaArgs($predicate,$validator)!==null) $kind='Input Validation Failure';
            }
        }
        if ($kind===null) continue;
        $events[]=['name'=>$kind,'line'=>substr_count(substr($code,0,$at),"\n")+1,'body'=>substr($content,$start+1,$end-$start-1)];
        if (in_array($kind,['Authentication Failure','Authentication Success'],true)) {
            $else=$end+1; while(isset($code[$else]) && ctype_space($code[$else])) $else++;
            if (preg_match('/\Gelse\s*\{/A',$code,$m,0,$else)) {
                $elseOpen=$else+strlen($m[0])-1; $elseEnd=securelogJavaClose($code,$elseOpen,'{','}');
                if ($elseEnd!==null) $events[]=['name'=>$kind==='Authentication Success'?'Authentication Failure':'Authentication Success',
                    'line'=>substr_count(substr($code,0,$else),"\n")+1,'body'=>substr($content,$elseOpen+1,$elseEnd-$elseOpen-1)];
            }
        }
    }
    foreach ($events as $index=>$event) {
        $checks=securelogJavaEventChecks($event['body'],$event['name']);
        foreach (['Security Logging','Log Storage','Log Encryption'] as $position=>$name) {
            [$status,$description]=$checks[$position];
            $standard=$position===0?($status==='FAIL' && str_contains($description,'context')?'CWE-223':'CWE-778'):'SecureLog Policy';
            $rule=$position===0?($standard==='CWE-223'?22301:77806):($position===1?90001:90002);
            $row=createFinding($status==='FAIL'?$rule:null,$name,$status==='FAIL'?'MEDIUM':'INFO',$fileName,$event['line'],
                $event['name'].': '.$description,'Review supported event paths, context, destinations and payloads. Do not log credentials or tokens.',$status,$standard);
            $row['event_key']='java-'.$index; $row['event_name']=$event['name']; $row['event_line']=$event['line']; $results[]=$row;
        }
    }
    return $results;
}
