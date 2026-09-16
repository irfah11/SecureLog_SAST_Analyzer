<?php

/*
|--------------------------------------------------------------------------
| SecureLog - Scan Process
|--------------------------------------------------------------------------
|
| Responsibilities:
|
| 1. Validate authenticated developer
| 2. Validate programming language
| 3. Validate uploaded source-code files
| 4. Create scan record
| 5. Route each file to correct language scanner
| 6. Save PASS / FAIL / N/A analysis results
| 7. Redirect to scan result page
|
| IMPORTANT:
| Vulnerability/security detection DOES NOT belong here.
| Detection logic belongs inside Engine_Process/Scanner/.
|
*/

session_start();

require_once __DIR__ . '/connection.php';


/*
|--------------------------------------------------------------------------
| LOAD SCANNER MODULES
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/Scanner/ScannerEngine.php';
require_once __DIR__ . '/Scanner/PHPScanner.php';
require_once __DIR__ . '/Scanner/JavaScanner.php';
require_once __DIR__ . '/Scanner/JavaScriptScanner.php';
require_once __DIR__ . '/Scanner/CScanner.php';


/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
*/

if (
    !isset($_SESSION['user_id'])
    && !isset($_SESSION['UserID'])
) {
    die('Please login before starting a scan.');
}


/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/

$currentUserId = (int) (
    $_SESSION['user_id']
    ?? $_SESSION['UserID']
    ?? 0
);

if ($currentUserId <= 0) {
    die('Invalid user session.');
}


/*
|--------------------------------------------------------------------------
| CONFIGURATION
|--------------------------------------------------------------------------
*/

const MAX_SOURCE_FILE_SIZE = 2 * 1024 * 1024;
const MAX_FILES_PER_SCAN = 50;


/*
|--------------------------------------------------------------------------
| LANGUAGE CONFIGURATION
|--------------------------------------------------------------------------
*/

$languageConfiguration = [

    'php' => [
        'display_name' => 'PHP',
        'extensions' => ['php']
    ],

    'java' => [
        'display_name' => 'Java',
        'extensions' => ['java']
    ],

    'javascript' => [
        'display_name' => 'JavaScript',
        'extensions' => ['js']
    ],

    'c' => [
        'display_name' => 'C',
        'extensions' => ['c', 'h']
    ]

];


/*
|--------------------------------------------------------------------------
| NORMALIZE LANGUAGE
|--------------------------------------------------------------------------
*/

function normalizeLanguage(string $language): string
{
    $language = strtolower(trim($language));

    return match ($language) {

        'php' => 'php',

        'java' => 'java',

        'javascript',
        'java script',
        'js' => 'javascript',

        'c',
        'c language' => 'c',

        default => ''
    };
}


/*
|--------------------------------------------------------------------------
| SAFE FILE NAME
|--------------------------------------------------------------------------
*/

function cleanUploadedFileName(string $fileName): string
{
    $fileName = basename($fileName);

    $fileName = preg_replace(
        '/[^a-zA-Z0-9._\-]/',
        '_',
        $fileName
    );

    return $fileName ?: 'unknown_file';
}


/*
|--------------------------------------------------------------------------
| CREATE SCAN RECORD
|--------------------------------------------------------------------------
*/

function createScan(
    mysqli $conn,
    int $userId,
    string $projectName,
    string $language,
    int $totalFiles
): int {

    $statement = $conn->prepare(
        "
        INSERT INTO scans
        (
            UserID,
            ProjectName,
            ProgrammingLanguage,
            total_files
        )
        VALUES (?, ?, ?, ?)
        "
    );

    if (!$statement) {
        throw new RuntimeException(
            'Unable to prepare scan record.'
        );
    }

    $statement->bind_param(
        'issi',
        $userId,
        $projectName,
        $language,
        $totalFiles
    );

    if (!$statement->execute()) {

        $error = $statement->error;

        $statement->close();

        throw new RuntimeException(
            'Unable to create scan: ' . $error
        );
    }

    $scanId = (int) $conn->insert_id;

    $statement->close();

    return $scanId;
}


/*
|--------------------------------------------------------------------------
| SAVE ANALYSIS RESULT
|--------------------------------------------------------------------------
|
| Scanner result structure:
|
| [
|     'status'               => PASS / FAIL / N/A
|     'rule_id'              => CWE rule ID or NULL
|     'standard'             => CWE-778 / CWE-117 / SecureLog Policy
|     'vulnerability_name'   => Check name
|     'severity'             => INFO / LOW / MEDIUM / HIGH / CRITICAL
|     'file_path'            => source file
|     'line_number'          => line number
|     'matched_code'         => optional matched source
|     'description'          => analysis detail
|     'recommendation'       => remediation
| ]
|
*/

function saveFinding(
    mysqli $conn,
    int $scanId,
    array $finding
): void {

    /*
    |--------------------------------------------------------------------------
    | RULE ID
    |--------------------------------------------------------------------------
    |
    | IMPORTANT:
    |
    | PASS and N/A do NOT require a RuleID.
    |
    | Therefore:
    |
    | FAIL CWE-778 -> 77801 etc.
    | FAIL CWE-117 -> 11701 etc.
    | PASS         -> NULL
    | N/A          -> NULL
    |
    | This removes the old "RuleID = 0" problem.
    |
    */

    $ruleId = null;

    if (
        array_key_exists('rule_id', $finding)
        && $finding['rule_id'] !== null
        && $finding['rule_id'] !== ''
    ) {
        $ruleId = (int) $finding['rule_id'];
    }


    /*
    |--------------------------------------------------------------------------
    | STATUS
    |--------------------------------------------------------------------------
    */

    $status = strtoupper(
        trim(
            (string) (
                $finding['status']
                ?? 'FAIL'
            )
        )
    );

    $allowedStatuses = [
        'PASS',
        'FAIL',
        'N/A'
    ];

    if (!in_array($status, $allowedStatuses, true)) {
        $status = 'FAIL';
    }


    /*
    |--------------------------------------------------------------------------
    | STANDARD
    |--------------------------------------------------------------------------
    */

    $standard = trim(
        (string) (
            $finding['standard']
            ?? ''
        )
    );

    if ($standard === '') {
        $standard = null;
    }


    /*
    |--------------------------------------------------------------------------
    | CHECK / VULNERABILITY NAME
    |--------------------------------------------------------------------------
    */

    $vulnerabilityName = trim(
        (string) (
            $finding['vulnerability_name']
            ?? $finding['check']
            ?? 'Security Analysis'
        )
    );


    /*
    |--------------------------------------------------------------------------
    | SEVERITY
    |--------------------------------------------------------------------------
    */

    $severity = strtoupper(
        trim(
            (string) (
                $finding['severity']
                ?? 'INFO'
            )
        )
    );

    $allowedSeverity = [
        'INFO',
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL'
    ];

    if (!in_array($severity, $allowedSeverity, true)) {
        $severity = 'INFO';
    }


    /*
    |--------------------------------------------------------------------------
    | FILE PATH
    |--------------------------------------------------------------------------
    */

    $filePath = trim(
        (string) (
            $finding['file_path']
            ?? 'Unknown'
        )
    );


    /*
    |--------------------------------------------------------------------------
    | LINE NUMBER
    |--------------------------------------------------------------------------
    */

    $lineNumber = (int) (
        $finding['line_number']
        ?? 0
    );


    /*
    |--------------------------------------------------------------------------
    | MATCHED CODE
    |--------------------------------------------------------------------------
    */

    $matchedCode = trim(
        (string) (
            $finding['matched_code']
            ?? ''
        )
    );

    if ($matchedCode === '') {
        $matchedCode = null;
    }


    /*
    |--------------------------------------------------------------------------
    | DESCRIPTION
    |--------------------------------------------------------------------------
    */

    $description = trim(
        (string) (
            $finding['description']
            ?? 'No description provided.'
        )
    );


    /*
    |--------------------------------------------------------------------------
    | RECOMMENDATION
    |--------------------------------------------------------------------------
    */

    $recommendation = trim(
        (string) (
            $finding['recommendation']
            ?? ''
        )
    );

    if ($recommendation === '') {
        $recommendation = null;
    }


    /*
    |--------------------------------------------------------------------------
    | INSERT RESULT
    |--------------------------------------------------------------------------
    */

    $statement = $conn->prepare(
        "
        INSERT INTO scan_results
        (
            ScanID,
            RuleID,
            Status,
            Standard,
            VulnerabilityName,
            Severity,
            FilePath,
            LineNumber,
            MatchedCode,
            Description,
            Remediation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "
    );

    if (!$statement) {
        throw new RuntimeException(
            'Unable to prepare scan result: '
            . $conn->error
        );
    }


    /*
    |--------------------------------------------------------------------------
    | BIND PARAMETERS
    |--------------------------------------------------------------------------
    |
    | i = ScanID
    | i = RuleID (NULL allowed)
    | s = Status
    | s = Standard
    | s = VulnerabilityName
    | s = Severity
    | s = FilePath
    | i = LineNumber
    | s = MatchedCode
    | s = Description
    | s = Recommendation
    |
    */

    $statement->bind_param(
        'iisssssisss',
        $scanId,
        $ruleId,
        $status,
        $standard,
        $vulnerabilityName,
        $severity,
        $filePath,
        $lineNumber,
        $matchedCode,
        $description,
        $recommendation
    );

    if (!$statement->execute()) {

        $error = $statement->error;

        $statement->close();

        throw new RuntimeException(
            'Unable to save scan result: '
            . $error
        );
    }

    $statement->close();
}


/*
|--------------------------------------------------------------------------
| CREATE SYSTEM / VALIDATION RESULT
|--------------------------------------------------------------------------
|
| Upload errors are NOT CWE vulnerabilities.
|
| Therefore:
|
| RuleID   = NULL
| Status   = N/A
| Standard = SecureLog System
|
*/

function createSystemFinding(
    string $fileName,
    string $message
): array {

    return [

        'status' =>
            'N/A',

        'rule_id' =>
            null,

        'standard' =>
            'SecureLog System',

        'vulnerability_name' =>
            'Scan Validation',

        'severity' =>
            'INFO',

        'file_path' =>
            $fileName,

        'line_number' =>
            0,

        'matched_code' =>
            '',

        'description' =>
            $message,

        'recommendation' =>
            ''

    ];
}


/*
|--------------------------------------------------------------------------
| ROUTE SOURCE FILE TO CORRECT SCANNER
|--------------------------------------------------------------------------
*/

function routeToScanner(
    string $language,
    string $fileName,
    string $content
): array {

    return match ($language) {

        'php' =>
            scanPHP(
                $fileName,
                $content
            ),

        'java' =>
            scanJava(
                $fileName,
                $content
            ),

        'javascript' =>
            scanJavascript(
                $fileName,
                $content
            ),

        'c' =>
            scanC(
                $fileName,
                $content
            ),

        default =>
            [
                createSystemFinding(
                    $fileName,
                    'No scanner is available for the selected programming language.'
                )
            ]
    };
}


/*
|--------------------------------------------------------------------------
| REQUEST MUST BE POST
|--------------------------------------------------------------------------
*/

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {

    header(
        'Location: index.php'
    );

    exit();
}


/*
|--------------------------------------------------------------------------
| READ SELECTED LANGUAGE
|--------------------------------------------------------------------------
*/

$requestedLanguage =
    $_POST['language']
    ?? '';

$language =
    normalizeLanguage(
        $requestedLanguage
    );

if (
    $language === ''
    || !isset(
        $languageConfiguration[$language]
    )
) {
    die(
        'Invalid or unsupported programming language.'
    );
}


/*
|--------------------------------------------------------------------------
| PROJECT NAME
|--------------------------------------------------------------------------
*/

$projectName = trim(
    $_POST['project_name']
    ?? $_POST['projectName']
    ?? ''
);

if ($projectName === '') {

    $projectName =
        'SecureLog_Scan_'
        . date('Ymd_His');
}


/*
|--------------------------------------------------------------------------
| PROJECT NAME SANITIZATION
|--------------------------------------------------------------------------
*/

$projectName = preg_replace(
    '/[^a-zA-Z0-9_\-. ]/',
    '',
    $projectName
);

$projectName = trim(
    $projectName
);

if ($projectName === '') {

    $projectName =
        'SecureLog_Scan_'
        . date('Ymd_His');
}


/*
|--------------------------------------------------------------------------
| CHECK FILE INPUT
|--------------------------------------------------------------------------
*/

if (
    !isset($_FILES['source_code'])
    || !isset(
        $_FILES['source_code']['name']
    )
) {
    die(
        'No source-code file was uploaded.'
    );
}


/*
|--------------------------------------------------------------------------
| NORMALIZE MULTIPLE FILE UPLOAD
|--------------------------------------------------------------------------
*/

$fileNames =
    $_FILES['source_code']['name'];

$tmpNames =
    $_FILES['source_code']['tmp_name'];

$fileSizes =
    $_FILES['source_code']['size'];

$fileErrors =
    $_FILES['source_code']['error'];


/*
|--------------------------------------------------------------------------
| CONVERT SINGLE UPLOAD TO ARRAY
|--------------------------------------------------------------------------
*/

if (!is_array($fileNames)) {

    $fileNames =
        [$fileNames];

    $tmpNames =
        [$tmpNames];

    $fileSizes =
        [$fileSizes];

    $fileErrors =
        [$fileErrors];
}


/*
|--------------------------------------------------------------------------
| REMOVE EMPTY FILE ENTRIES
|--------------------------------------------------------------------------
*/

$validUploadIndexes = [];

foreach (
    $fileNames as $index => $name
) {

    if (
        trim(
            (string) $name
        ) !== ''
    ) {
        $validUploadIndexes[] =
            $index;
    }
}


$totalSubmittedFiles =
    count(
        $validUploadIndexes
    );


if ($totalSubmittedFiles === 0) {

    die(
        'Please select at least one source-code file.'
    );
}


/*
|--------------------------------------------------------------------------
| MAXIMUM FILE COUNT
|--------------------------------------------------------------------------
*/

if (
    $totalSubmittedFiles
    > MAX_FILES_PER_SCAN
) {

    die(
        'Maximum '
        . MAX_FILES_PER_SCAN
        . ' files are allowed per scan.'
    );
}


/*
|--------------------------------------------------------------------------
| CREATE SCAN
|--------------------------------------------------------------------------
*/

try {

    $scanId =
        createScan(
            $conn,
            $currentUserId,
            $projectName,
            $languageConfiguration[$language]['display_name'],
            $totalSubmittedFiles
        );

} catch (Throwable $exception) {

    error_log(
        'SecureLog Scan Error: '
        . $exception->getMessage()
    );

    die(
        'Unable to create scan record.'
    );
}


/*
|--------------------------------------------------------------------------
| EXPECTED EXTENSIONS
|--------------------------------------------------------------------------
*/

$expectedExtensions =
    $languageConfiguration[$language]['extensions'];

$displayLanguage =
    $languageConfiguration[$language]['display_name'];


/*
|--------------------------------------------------------------------------
| PROCESS FILES
|--------------------------------------------------------------------------
*/

foreach (
    $validUploadIndexes as $index
) {

    /*
    |--------------------------------------------------------------------------
    | FILE INFORMATION
    |--------------------------------------------------------------------------
    */

    $originalFileName =
        (string) (
            $fileNames[$index]
            ?? ''
        );

    $fileName =
        cleanUploadedFileName(
            $originalFileName
        );

    $tmpName =
        (string) (
            $tmpNames[$index]
            ?? ''
        );

    $fileSize =
        (int) (
            $fileSizes[$index]
            ?? 0
        );

    $uploadError =
        (int) (
            $fileErrors[$index]
            ?? UPLOAD_ERR_NO_FILE
        );


    /*
    |--------------------------------------------------------------------------
    | CHECK PHP UPLOAD ERROR
    |--------------------------------------------------------------------------
    */

    if (
        $uploadError
        !== UPLOAD_ERR_OK
    ) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The file could not be uploaded. Upload error code: '
                . $uploadError
                . '.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | VERIFY TEMPORARY UPLOAD
    |--------------------------------------------------------------------------
    */

    if (
        $tmpName === ''
        || !is_uploaded_file($tmpName)
    ) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The uploaded file could not be verified by the server.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | FILE SIZE VALIDATION
    |--------------------------------------------------------------------------
    */

    if ($fileSize <= 0) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The uploaded source-code file is empty.'
            )
        );

        continue;
    }


    if (
        $fileSize
        > MAX_SOURCE_FILE_SIZE
    ) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The uploaded source-code file exceeds the maximum size of 2 MB.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | GET FILE EXTENSION
    |--------------------------------------------------------------------------
    */

    $fileExtension =
        strtolower(
            pathinfo(
                $fileName,
                PATHINFO_EXTENSION
            )
        );


    /*
    |--------------------------------------------------------------------------
    | LANGUAGE / EXTENSION MATCH
    |--------------------------------------------------------------------------
    */

    if (
        !in_array(
            $fileExtension,
            $expectedExtensions,
            true
        )
    ) {

        $allowedText =
            implode(
                ', .',
                $expectedExtensions
            );

        $allowedText =
            '.' . $allowedText;

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                "File skipped. The selected language is {$displayLanguage}, but this file has the extension .{$fileExtension}. Expected: {$allowedText}."
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | READ SOURCE CODE
    |--------------------------------------------------------------------------
    */

    $content =
        file_get_contents(
            $tmpName
        );

    if (
        $content === false
        || trim($content) === ''
    ) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The uploaded source-code file is empty or could not be read.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | ROUTE TO LANGUAGE SCANNER
    |--------------------------------------------------------------------------
    */

    try {

        $findings =
            routeToScanner(
                $language,
                $fileName,
                $content
            );

    } catch (Throwable $exception) {

        error_log(
            'SecureLog Scanner Error ['
            . $fileName
            . ']: '
            . $exception->getMessage()
        );

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The scanner encountered an internal error while analyzing this file.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | VALIDATE SCANNER RESPONSE
    |--------------------------------------------------------------------------
    */

    if (!is_array($findings)) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'The scanner returned an invalid result.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | EMPTY SCANNER RESPONSE
    |--------------------------------------------------------------------------
    |
    | IMPORTANT:
    |
    | In the new architecture, a scanner should normally return
    | PASS / FAIL / N/A results.
    |
    | Therefore an empty array means the scanner did not provide
    | enough information to evaluate the file.
    |
    | We DO NOT create RuleID 0 anymore.
    |
    */

    if (empty($findings)) {

        saveFinding(
            $conn,
            $scanId,
            createSystemFinding(
                $fileName,
                'SecureLog analyzed the file, but the scanner returned no security check results.'
            )
        );

        continue;
    }


    /*
    |--------------------------------------------------------------------------
    | SAVE SCANNER RESULTS
    |--------------------------------------------------------------------------
    */

    foreach (
        $findings as $finding
    ) {

        if (!is_array($finding)) {
            continue;
        }


        /*
        |--------------------------------------------------------------------------
        | TRUST UPLOADED FILE NAME
        |--------------------------------------------------------------------------
        */

        $finding['file_path'] =
            $fileName;


        /*
        |--------------------------------------------------------------------------
        | NORMALIZE STATUS
        |--------------------------------------------------------------------------
        */

        $findingStatus =
            strtoupper(
                trim(
                    (string) (
                        $finding['status']
                        ?? 'FAIL'
                    )
                )
            );

        if (
            !in_array(
                $findingStatus,
                ['PASS', 'FAIL', 'N/A'],
                true
            )
        ) {
            $findingStatus =
                'FAIL';
        }

        $finding['status'] =
            $findingStatus;


        /*
        |--------------------------------------------------------------------------
        | PASS / N/A MUST NOT HAVE CWE RULE ID
        |--------------------------------------------------------------------------
        |
        | Rule IDs identify detected rules/weaknesses.
        |
        | Example:
        |
        | FAIL CWE-778
        |     RuleID = 77801
        |
        | FAIL CWE-117
        |     RuleID = 11701
        |
        | PASS
        |     RuleID = NULL
        |
        | N/A
        |     RuleID = NULL
        |
        */

        if (
            $findingStatus === 'PASS'
            || $findingStatus === 'N/A'
        ) {
            $finding['rule_id'] =
                null;
        }


        /*
        |--------------------------------------------------------------------------
        | SAVE RESULT
        |--------------------------------------------------------------------------
        */

        try {

            saveFinding(
                $conn,
                $scanId,
                $finding
            );

        } catch (Throwable $exception) {

            error_log(
                'SecureLog Save Result Error ['
                . $fileName
                . ']: '
                . $exception->getMessage()
            );

            /*
             * Continue with other findings/files instead
             * of terminating the entire batch scan.
             */
            continue;
        }
    }
}


/*
|--------------------------------------------------------------------------
| REDIRECT TO RESULT PAGE
|--------------------------------------------------------------------------
*/

header(
    'Location: index.php?scan_id='
    . urlencode(
        (string) $scanId
    )
);

exit();