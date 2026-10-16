<?php
/** Private processing metadata and grouped presentation; no source-code storage. */
function securelogSaveCoverage(int $scanId, int $userId, array $files, array $events, string $outcome): bool
{
    if ($scanId <= 0 || $userId <= 0) return false;
    $directory = __DIR__ . '/../Dashboard/logs/scan_coverage';
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) return false;
    $payload = json_encode(['version' => 1, 'scan_id' => $scanId, 'user_id' => $userId,
        'outcome' => $outcome, 'files' => array_values($files), 'events' => $events], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($payload === false) return false;
    $temporary = tempnam($directory, 'coverage-');
    if ($temporary === false) return false;
    $saved = file_put_contents($temporary, $payload, LOCK_EX) !== false
        && rename($temporary, $directory . '/' . $scanId . '.json');
    if (is_file($temporary)) unlink($temporary);
    return $saved;
}

/** Caller must first authorize the scan through its owner-scoped DB query. */
function securelogLoadCoverage(int $scanId, int $ownerId): ?array
{
    if ($scanId <= 0 || $ownerId <= 0) return null;
    $path = __DIR__ . '/../Dashboard/logs/scan_coverage/' . $scanId . '.json';
    if (!is_file($path)) return null;
    $content = @file_get_contents($path);
    $coverage = $content === false ? null : json_decode($content, true);
    if (!is_array($coverage) || ($coverage['version'] ?? null) !== 1
        || (int) ($coverage['scan_id'] ?? 0) !== $scanId
        || (int) ($coverage['user_id'] ?? 0) !== $ownerId
        || !is_array($coverage['files'] ?? null) || !is_array($coverage['events'] ?? null)) return null;
    return $coverage;
}

function securelogPresentation(array $rows, ?array $coverage): array
{
    $files = [];
    $counts = ['FAIL' => 0, 'PASS' => 0, 'N/A' => 0, 'SYSTEM' => 0];
    $legacy = [];
    $eventMap = $coverage['events'] ?? [];
    foreach ($rows as $row) {
        $file = (string) ($row['FilePath'] ?? 'Unknown file');
        $status = strtoupper(trim((string) ($row['Status'] ?? 'N/A')));
        if (!in_array($status, ['FAIL', 'PASS', 'N/A'], true)) $status = 'N/A';
        $row['Status'] = $status;
        $system = ($row['Standard'] ?? '') === 'SecureLog System' || ($row['VulnerabilityName'] ?? '') === 'Scan Validation';
        $counts[$system ? 'SYSTEM' : $status]++;
        $files[$file] ??= ['path' => $file, 'events' => [], 'failed' => 0, 'notes' => []];
        if ($system) { $files[$file]['notes'][] = $row; continue; }
        $metadata = $eventMap[(string) ($row['ResultID'] ?? '')] ?? null;
        if (is_array($metadata) && ($metadata['file'] ?? '') === $file) {
            $key = (string) $metadata['key'];
            $label = (string) $metadata['name'];
            $line = (int) $metadata['line'];
        } else {
            // Old PHP rows are stored as Logging then dependent checks. Keep
            // separate anchors even when two events share a source line.
            if (($row['VulnerabilityName'] ?? '') === 'Security Logging') {
                $legacy[$file] = ($legacy[$file] ?? 0) + 1;
            }
            $key = 'legacy-' . ($legacy[$file] ?? 0);
            $label = 'Recorded event checks';
            $description = (string) ($row['Description'] ?? '');
            foreach (['Authentication Failure', 'Access Control Failure', 'Exception Handling'] as $candidate) {
                if (stripos($description, $candidate) !== false) { $label = $candidate; break; }
            }
            $line = (int) ($row['LineNumber'] ?? 0);
        }
        $files[$file]['events'][$key] ??= ['name' => $label, 'line' => $line, 'rows' => [], 'failed' => 0, 'counts' => ['FAIL' => 0, 'PASS' => 0, 'N/A' => 0]];
        $files[$file]['events'][$key]['rows'][] = $row;
        $files[$file]['events'][$key]['counts'][$status]++;
        if ($status === 'FAIL') {
            $files[$file]['events'][$key]['failed']++;
            $files[$file]['failed']++;
        }
    }
    $ranks = ['FAIL' => 0, 'PASS' => 1, 'N/A' => 2];
    foreach ($files as &$file) {
        foreach ($file['events'] as &$event) {
            usort($event['rows'], static fn(array $a, array $b): int => $ranks[$a['Status']] <=> $ranks[$b['Status']]);
        }
        unset($event);
        $file['rows'] = [];
        foreach ($file['events'] as $event) array_push($file['rows'], ...$event['rows']);
        usort($file['rows'], static fn(array $a, array $b): int => $ranks[$a['Status']] <=> $ranks[$b['Status']]);
        uasort($file['events'], static fn(array $a, array $b): int => ($b['failed'] <=> $a['failed']) ?: ($a['line'] <=> $b['line']));
    }
    unset($file);
    uasort($files, static fn(array $a, array $b): int => ($b['failed'] <=> $a['failed']) ?: strcmp($a['path'], $b['path']));
    return ['files' => $files, 'counts' => $counts,
        'events' => array_sum(array_map(static fn(array $file): int => count($file['events']), $files)),
        'coverage' => $coverage];
}

function securelogPresentationEscape(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}


// Existing result labels, shared by the page and rendering checks.
function getCheckName(array $row): string

{

    $name = strtolower(

        trim(

            (string)($row['VulnerabilityName'] ?? '')

        )

    );



    $standard = strtoupper(

        trim(

            (string)($row['Standard'] ?? '')

        )

    );



    /*

    |--------------------------------------------------------------------------

    | Security Logging — CWE-778

    |--------------------------------------------------------------------------

    */



    if (

        $standard === 'CWE-778'

        ||

        strpos($name, 'authentication') !== false

        ||

        strpos($name, 'access control') !== false

        ||

        strpos($name, 'exception') !== false

        ||

        strpos($name, 'security logging') !== false

    ) {

        return 'Security Logging';

    }





    /*

    |--------------------------------------------------------------------------

    | Log Neutralization — CWE-117

    |--------------------------------------------------------------------------

    */



    if (

        $standard === 'CWE-117'

        ||

        strpos($name, 'neutral') !== false

        ||

        strpos($name, 'log injection') !== false

    ) {

        return 'Log Neutralization';

    }





    /*

    |--------------------------------------------------------------------------

    | Log Storage — SecureLog Policy

    |--------------------------------------------------------------------------

    */



    if (

        strpos($name, 'storage') !== false

        ||

        strpos($name, 'txt') !== false

        ||

        strpos($name, 'format') !== false

    ) {

        return 'Log Storage';

    }





    /*

    |--------------------------------------------------------------------------

    | Log Protection — SecureLog Policy

    |--------------------------------------------------------------------------

    */



    if (

        strpos($name, 'protection') !== false

        ||

        strpos($name, 'encrypt') !== false

        ||

        strpos($name, 'protected') !== false

    ) {

        return 'Log Protection';

    }





    /*

    |--------------------------------------------------------------------------

    | Fallback

    |--------------------------------------------------------------------------

    */



    if (!empty($row['VulnerabilityName'])) {

        return $row['VulnerabilityName'];

    }



    return 'Security Analysis';

}





/*

|--------------------------------------------------------------------------

| Helper: Status

|--------------------------------------------------------------------------

*/



function getStatus(array $row): string

{

    $status = strtoupper(

        trim(

            (string)($row['Status'] ?? '')

        )

    );



    if (

        $status !== 'PASS'

        &&

        $status !== 'FAIL'

        &&

        $status !== 'N/A'

    ) {

        return 'N/A';

    }



    return $status;

}





/*

|--------------------------------------------------------------------------

| Helper: Improve Detail Text

|--------------------------------------------------------------------------

*/



function getDetail(array $row): string

{

    $description = trim(

        (string)($row['Description'] ?? '')

    );



    if ($description !== '') {

        return $description;

    }



    $status = getStatus($row);

    $check = getCheckName($row);



    /*

    |--------------------------------------------------------------------------

    | Fallback descriptions

    |--------------------------------------------------------------------------

    */



    if ($check === 'Security Logging') {



        if ($status === 'PASS') {

            return 'Required security events are logged.';

        }



        if ($status === 'FAIL') {

            return 'Insufficient security logging detected.';

        }



        return 'Security logging could not be evaluated.';

    }





    if ($check === 'Log Neutralization') {



        if ($status === 'PASS') {

            return 'Logged external input is properly neutralized.';

        }



        if ($status === 'FAIL') {

            return 'Logged external input is not properly neutralized.';

        }



        return 'Not evaluated because no security logging operation exists for this event.';

    }





    if ($check === 'Log Storage') {



        if ($status === 'PASS') {

            return 'Approved .txt log storage detected.';

        }



        if ($status === 'FAIL') {

            return 'Log is not stored using the approved .txt storage policy.';

        }



        return 'Not evaluated because no security logging operation exists for this event.';

    }





    if ($check === 'Log Protection') {



        if ($status === 'PASS') {

            return 'Log data protection or encryption was detected.';

        }



        if ($status === 'FAIL') {

            return 'Log data is not encrypted or otherwise protected.';

        }



        return 'Not evaluated because no security logging operation exists for this event.';

    }





    return 'No additional information is available.';

}





/*

|--------------------------------------------------------------------------

| Helper: Status CSS

|--------------------------------------------------------------------------

*/



function getStatusClass(string $status): string

{

    switch ($status) {



        case 'PASS':

            return 'status-pass';



        case 'FAIL':

            return 'status-fail';



        default:

            return 'status-na';

    }

}





/*

|--------------------------------------------------------------------------

| Helper: Status Icon

|--------------------------------------------------------------------------

*/



function getStatusIcon(string $status): string

{

    switch ($status) {



        case 'PASS':

            return 'fa-circle-check';



        case 'FAIL':

            return 'fa-circle-xmark';



        default:

            return 'fa-circle-minus';

    }

}



