<?php



session_start();

$currentUserId = (int) ($_SESSION['UserID'] ?? $_SESSION['user_id'] ?? 0);
$userRole = strtolower(trim((string) ($_SESSION['role'] ?? '')));
if ($currentUserId <= 0) {
    header('Location: ../Registration/login.php');
    exit;
}
if (!in_array($userRole, ['admin', 'developer'], true)) {
    http_response_code(403);
    exit('Access denied.');
}

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/ScanPresentation.php';
$presentation = securelogPresentation([], null);



$results = null;

$scan_info = null;

$scan_id = null;



/*

|--------------------------------------------------------------------------

| Load Current Scan

|--------------------------------------------------------------------------

*/



if (isset($_GET['scan_id'])) {



    $scan_id = filter_input(

        INPUT_GET,

        'scan_id',

        FILTER_VALIDATE_INT

    );



    if (!$scan_id || $scan_id <= 0) {
        http_response_code(400);
        exit('Invalid scan ID.');
    }

    if ($scan_id && $scan_id > 0) {



        /*

        |--------------------------------------------------------------------------

        | Scan Information

        |--------------------------------------------------------------------------

        */



        if ($userRole === 'admin') {
            $scanStatement = $conn->prepare(
                'SELECT * FROM scans WHERE ScanID = ? LIMIT 1'
            );
            $scanStatement->bind_param('i', $scan_id);
        } else {
            $scanStatement = $conn->prepare(
                'SELECT * FROM scans WHERE ScanID = ? AND UserID = ? LIMIT 1'
            );
            $scanStatement->bind_param('ii', $scan_id, $currentUserId);
        }



        $scanStatement->execute();



        $scanResult = $scanStatement->get_result();



        $scan_info = $scanResult->fetch_assoc();



        $scanStatement->close();

        // Do not query findings until the scan is visible to this identity.
        // Missing and inaccessible scans share a response to avoid ID discovery.
        if (!$scan_info) {
            http_response_code(404);
            exit('Scan report not found.');
        }





        /*

        |--------------------------------------------------------------------------

        | Scan Results

        |--------------------------------------------------------------------------

        */



        $resultStatement = $conn->prepare(

            "

            SELECT

                ResultID,

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

            FROM scan_results

            WHERE ScanID = ?

            ORDER BY ResultID ASC

            "

        );



        $resultStatement->bind_param(

            "i",

            $scan_id

        );



        $resultStatement->execute();



        $results = $resultStatement->get_result();
        $resultRows = [];
        while ($resultRow = $results->fetch_assoc()) $resultRows[] = $resultRow;
        $resultStatement->close();
        $coverage = securelogLoadCoverage((int) $scan_id, (int) $scan_info['UserID']);
        $presentation = securelogPresentation($resultRows, $coverage);


    }

}





/*

|--------------------------------------------------------------------------

| Helper: Display Check Name

|--------------------------------------------------------------------------

|

| Scanner/database may store detailed vulnerability names such as:

|

| Authentication Failure Without Logging

| Access Control Failure Without Logging

| Exception Without Logging

|

| But the main scanner UI groups them into the four SecureLog checks.

|

*/



?>



<!DOCTYPE html>

<html lang="en">



<head>



    <meta charset="UTF-8">



    <meta

        name="viewport"

        content="width=device-width, initial-scale=1.0"

    >



    <title>Scanner - SAST Tool</title>



    <link

        rel="stylesheet"

        href="https\://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"

    >



    <link

        href="https\://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"

        rel="stylesheet"

    >





    <style>



        :root {



            --bg-main: #020817;

            --bg-sidebar: #071426;



            --bg-card: #07111f;

            --bg-card-2: #081827;



            --border: rgba(59, 130, 246, 0.18);

            --border-light: rgba(148, 163, 184, 0.15);



            --text-main: #f8fafc;

            --text-muted: #93a4b8;



            --primary: #0d6efd;

            --primary-2: #2563eb;



            --success: #22c55e;

            --danger: #ff4d67;

            --warning: #94a3b8;



            --secondary: #172334;

        }





        * {

            box-sizing: border-box;

        }





        body {



            margin: 0;



            min-height: 100vh;



            font-family: 'Inter', sans-serif;



            background:

                radial-gradient(

                    circle at top left,

                    rgba(37, 99, 235, 0.08),

                    transparent 30%

                ),

                var(--bg-main);



            color: var(--text-main);



            display: flex;

        }





        /*

        |--------------------------------------------------------------------------

        | Sidebar

        |--------------------------------------------------------------------------

        */



        .sidebar,

        .side-bar,

        .sidebar-user,

        nav,

        aside {



            background:

                var(--bg-sidebar) !important;

        }





        /*

        |--------------------------------------------------------------------------

        | Main Content

        |--------------------------------------------------------------------------

        */



        .content {



            margin-left: 300px;



            padding: 34px 28px;



            width:

                calc(100% - 300px);



            min-height: 100vh;



            background:

                radial-gradient(

                    circle at 40% 0%,

                    rgba(14, 165, 233, 0.05),

                    transparent 35%

                ),

                var(--bg-main);

        }





        .scanner-wrapper {



            max-width: 1150px;

        }





        .content h1 {



            font-size: 1.35rem;



            font-weight: 800;



            color: #ffffff;



            margin:

                0 0 22px 0;



            letter-spacing: -0.3px;

        }





        /*

        |--------------------------------------------------------------------------

        | Scanner Grid

        |--------------------------------------------------------------------------

        */



        .scanner-grid {



            display: grid;



            grid-template-columns:

                380px 1fr;



            gap: 18px;



            align-items: stretch;

        }





        /*

        |--------------------------------------------------------------------------

        | Card

        |--------------------------------------------------------------------------

        */



        .card {



            background:

                rgba(7, 17, 31, 0.92);



            border:

                1px solid var(--border);



            border-radius: 10px;



            padding: 22px;



            box-shadow:

                0 18px 35px

                rgba(0, 0, 0, 0.28);

        }





        .card h3 {



            font-size: 0.96rem;



            font-weight: 800;



            color: #ffffff;



            margin:

                0 0 22px 0;



            display: flex;



            align-items: center;



            gap: 8px;

        }





        .card h3 i.upload-icon {



            color: #0d6efd;



            font-size: 1.1rem;

        }





        .card h3 i.result-icon {



            color: var(--success);



            font-size: 1.1rem;

        }





        /*

        |--------------------------------------------------------------------------

        | Form

        |--------------------------------------------------------------------------

        */



        label {



            display: block;



            color: #cbd5e1;



            font-size: 0.75rem;



            font-weight: 500;



            margin-bottom: 7px;

        }





        .form-select {



            width: 100%;



            height: 40px;



            border-radius: 7px;



            border:

                1px solid

                var(--border-light);



            background: #050d19;



            color: #ffffff;



            padding:

                0 12px;



            outline: none;



            font-size: 0.82rem;



            margin-bottom: 17px;

        }





        .form-select:focus {



            border-color:

                rgba(

                    37,

                    99,

                    235,

                    0.75

                );



            box-shadow:

                0 0 0 3px

                rgba(

                    37,

                    99,

                    235,

                    0.12

                );

        }





        /*

        |--------------------------------------------------------------------------

        | Upload Box

        |--------------------------------------------------------------------------

        */



        .upload-box {



            height: 150px;



            border:

                1.5px dashed

                rgba(

                    37,

                    99,

                    235,

                    0.65

                );



            border-radius: 8px;



            background:

                rgba(

                    3,

                    10,

                    23,

                    0.75

                );



            display: flex;



            align-items: center;



            justify-content: center;



            text-align: center;



            cursor: pointer;



            margin-bottom: 17px;



            transition:

                all 0.25s ease;

        }





        .upload-box:hover,

        .upload-box.dragover {



            border-color: #38bdf8;



            background:

                rgba(

                    37,

                    99,

                    235,

                    0.08

                );

        }





        .upload-inner i {



            color: #0d6efd;



            font-size: 2rem;



            margin-bottom: 14px;

        }





        .upload-inner p {



            color: #dbeafe;



            font-size: 0.82rem;



            margin:

                0 0 8px 0;

        }





        .upload-inner span {



            color: #2f8cff;



            font-size: 0.75rem;

        }





        /*

        |--------------------------------------------------------------------------

        | Buttons

        |--------------------------------------------------------------------------

        */



        .btn {



            width: 100%;



            height: 40px;



            border: none;



            border-radius: 7px;



            color: #ffffff;



            font-weight: 800;



            font-size: 0.78rem;



            display: flex;



            align-items: center;



            justify-content: center;



            gap: 7px;



            cursor: pointer;



            text-decoration: none;



            transition:

                all 0.25s ease;

        }





        .btn:hover {



            transform:

                translateY(-1px);



            filter:

                brightness(1.08);

        }





        .btn-primary {



            background:

                linear-gradient(

                    90deg,

                    #0d6efd,

                    #006dff

                );



            box-shadow:

                0 12px 25px

                rgba(

                    13,

                    110,

                    253,

                    0.25

                );



            margin-bottom: 14px;

        }





        .btn-secondary {



            background: #172334;



            color: #ffffff;

        }





        .btn-success {



            width: auto;



            height: 34px;



            padding:

                0 14px;



            background: #16a34a;



            font-size: 0.75rem;

        }





        /*

        |--------------------------------------------------------------------------

        | Result Card

        |--------------------------------------------------------------------------

        */



        .result-card {



            min-height: 405px;

        }





        .result-header {



            display: flex;



            justify-content:

                space-between;



            align-items: center;



            gap: 15px;

        }





        .result-header h3 {



            margin-bottom: 0;

        }





        hr {



            border: 0;



            border-top:

                1px solid

                var(--border-light);



            margin:

                18px 0 0 0;

        }





        .result-body {



            min-height: 300px;



            max-height: 420px;



            overflow-y: auto;

        }





        /*

        |--------------------------------------------------------------------------

        | Empty State

        |--------------------------------------------------------------------------

        */



        .empty-state {



            height: 285px;



            display: flex;



            align-items: center;



            justify-content: center;



            text-align: center;



            color: #93c5fd;

        }





        .empty-state i {



            width: 52px;



            height: 52px;



            border-radius: 50%;



            background:

                rgba(

                    37,

                    99,

                    235,

                    0.35

                );



            display: inline-flex;



            align-items: center;



            justify-content: center;



            font-size: 1.35rem;



            color: #93c5fd;



            margin-bottom: 13px;

        }





        .empty-state strong {



            display: block;



            color: #ffffff;



            font-size: 0.78rem;



            margin-bottom: 8px;

        }





        .empty-state p {



            color: #60a5fa;



            font-size: 0.75rem;



            margin: 0;

        }





        /*

        |--------------------------------------------------------------------------

        | Result Table

        |--------------------------------------------------------------------------

        */



        .analysis-table {



            width: 100%;



            border-collapse: collapse;



            margin-top: 18px;



            color: #dbeafe;

        }





        .analysis-table th {



            background:

                rgba(

                    15,

                    23,

                    42,

                    0.85

                );



            color: #93c5fd;



            font-size: 0.70rem;



            text-transform: uppercase;



            letter-spacing: 0.5px;



            padding: 13px 12px;



            text-align: left;



            border-bottom:

                1px solid

                var(--border-light);

        }





        .analysis-table td {



            padding: 14px 12px;



            border-bottom:

                1px solid

                rgba(

                    148,

                    163,

                    184,

                    0.08

                );



            color: #cbd5e1;



            font-size: 0.76rem;



            vertical-align: top;



            line-height: 1.45;

        }





        /*

        |--------------------------------------------------------------------------

        | Table Column Width

        |--------------------------------------------------------------------------

        */



        .status-column {



            width: 115px;

        }





        .check-column {



            width: 165px;

        }





        /*

        |--------------------------------------------------------------------------

        | Status

        |--------------------------------------------------------------------------

        */



        .status {



            display: inline-flex;



            align-items: center;



            gap: 7px;



            font-weight: 800;



            white-space: nowrap;

        }





        .status i {



            font-size: 0.95rem;

        }





        .status-pass {



            color: #34d399;

        }





        .status-fail {



            color: #fb7185;

        }





        .status-na {



            color: #94a3b8;

        }





        /*

        |--------------------------------------------------------------------------

        | Check Name

        |--------------------------------------------------------------------------

        */



        .check-name {



            color: #f8fafc;



            font-weight: 700;

        }





        /*

        |--------------------------------------------------------------------------

        | Detail

        |--------------------------------------------------------------------------

        */



        .detail-text {



            color: #cbd5e1;



            line-height: 1.55;

        }





        /*

        |--------------------------------------------------------------------------

        | Optional Metadata

        |--------------------------------------------------------------------------

        */



        .result-meta {



            display: flex;



            flex-wrap: wrap;



            gap: 7px;



            margin-top: 7px;

        }





        .meta-badge {



            display: inline-flex;



            align-items: center;



            padding: 3px 7px;



            border-radius: 4px;



            background: #0f172a;



            color: #93c5fd;



            font-size: 0.63rem;



            font-weight: 600;

        }





        /*

        |--------------------------------------------------------------------------

        | Responsive

        |--------------------------------------------------------------------------

        */



        @media (max-width: 992px) {



            .content {



                margin-left: 0;



                width: 100%;



                padding:

                    25px 18px;

            }





            .scanner-grid {



                grid-template-columns:

                    1fr;

            }





            .scanner-wrapper {



                max-width: 100%;

            }

        }





        @media (max-width: 700px) {



            .analysis-table th,

            .analysis-table td {



                padding:

                    10px 8px;

            }





            .status-column {



                width: 90px;

            }





            .check-column {



                width: 130px;

            }





            .result-meta {



                display: none;

            }

        }



        .scan-modes { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:16px; }
        .mode-button { border:1px solid #334155; background:#0b1728; color:#b7c9df; padding:11px;
                       border-radius:8px; cursor:pointer; font:inherit; font-size:.75rem; }
        .mode-button.selected { background:#102b50; border-color:#3b82f6; color:white; font-weight:700; }
        .hidden-upload { position:absolute; width:1px; height:1px; opacity:0; overflow:hidden; }
        .upload-summary { color:#93a4b8; font-size:.73rem; line-height:1.6; margin:0 0 15px; }
        .upload-error { color:#fecaca; background:#450a0a; border:1px solid #991b1b;
                        padding:10px; border-radius:6px; font-size:.74rem; margin-bottom:12px; }
        .upload-box:focus-visible { outline:2px solid #60a5fa; outline-offset:3px; }

.logging-reminder { color:#acbdd0; background:#102238; border-left:3px solid #3c9de5; padding:10px 12px; font-size:.76rem; line-height:1.6; margin:12px 0 18px; }
.scan-overview { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; }
.scan-overview>div { padding:10px; background:#102238; border:1px solid #263b52; border-radius:6px; }
.scan-overview strong { display:block; font-size:1.3rem; color:#f3f7fc; }
.scan-overview span { color:#acbdd0; font-size:.7rem; }
.scan-guidance { color:#acbdd0; font-size:.76rem; line-height:1.65; margin:12px 0; }
.scan-file,.scan-coverage { border:1px solid #263b52; border-radius:7px; margin:12px 0; background:#07162b; }
.scan-file>summary,.scan-coverage>summary { cursor:pointer; color:#e6edf6; padding:12px; font-weight:600; font-size:.8rem; }
.scan-file>summary:focus-visible,.scan-coverage>summary:focus-visible { outline:2px solid #69bfff; outline-offset:2px; }
.scan-file-content { padding:0 10px 10px; }
.scan-count { display:block; color:#acbdd0; font-size:.7rem; font-weight:400; margin:5px 0 0 16px; }
.scan-count.has-fail { color:#ffacb7; }
.scan-path { overflow-wrap:anywhere; word-break:break-word; }
.scan-message { color:#acbdd0; font-size:.8rem; line-height:1.6; background:#102238; padding:12px; margin:10px 0; border-radius:6px; }
.scan-message p { margin:6px 0 0; }
.scan-coverage { padding:0 12px 12px; }
.scan-coverage>summary { padding-left:0; }
.scan-file-content .analysis-table { table-layout:fixed; width:100%; }
.scan-file-content .analysis-table th:first-child { width:19%; }
.scan-file-content .analysis-table th:nth-child(2) { width:25%; }
.scan-file-content .analysis-table td,.coverage-table td { overflow-wrap:anywhere; }
@media(max-width:650px) { .scan-overview { grid-template-columns:repeat(2,minmax(0,1fr)); } .scan-file-content .analysis-table { table-layout:auto; } }

</style>



</head>





<body>





<?php



include '../Sidebar/sidebaruser.php';



?>





<div class="content">



    <div class="scanner-wrapper">





        <h1>

            Logging Analysis Scanner (Project & Batch Mode)

        </h1>





        <div class="scanner-grid">





            <!-- =====================================================

                 UPLOAD CARD

                 ===================================================== -->



            <div class="card upload-card">





                <h3>



                    <i

                        class="fas fa-cloud-upload-alt upload-icon"

                    ></i>



                    Source Code Upload



                </h3>





                <form id="scan-form" action="scan_process.php" method="POST" enctype="multipart/form-data">
                    <label for="project-name">Project Name</label>
                    <input id="project-name" name="project_name" class="form-select" type="text" maxlength="120"
                           placeholder="e.g. FinalYearProject" required>

                    <label for="language-select">Programming Language</label>
                    <select name="language" id="language-select" class="form-select" required>
                        <option value="php" selected>PHP</option>
                        <option value="java">Java</option>
                        <option value="javascript">JavaScript</option>
                        <option value="c">C</option>
                    </select>

                    <label>Upload Method</label>
                    <div class="scan-modes">
                        <button type="button" class="mode-button selected" data-mode="batch">Batch Files</button>
                        <button type="button" class="mode-button" data-mode="folder">Project Folder</button>
                    </div>
                    <input type="hidden" name="upload_mode" id="upload-mode" value="batch">
                    <div class="upload-box" id="upload-box" role="button" tabindex="0">
                        <div class="upload-inner">
                            <i class="fas fa-folder-open"></i>
                            <p id="file-text">Click to select source files</p>
                            <span id="upload-hint">Or drag and drop files here</span>
                        </div>
                    </div>
                    <input type="file" id="file-input" name="source_code[]" multiple
                           accept=".php,.java,.js,.c,.h" class="hidden-upload">
                    <input type="file" id="folder-input" webkitdirectory directory multiple class="hidden-upload">
                    <input type="file" id="prepared-files" name="source_code[]" multiple disabled class="hidden-upload">
                    <div id="relative-paths"></div>
                    <p id="upload-summary" class="upload-summary">Max 200 files, 5 MB each, 50 MB total.</p>
                    <p class="logging-reminder"><i class="fas fa-info-circle" aria-hidden="true"></i>
                        Not every file requires security logging. SecureLog checks supported security events and their logging paths.
                        Files without detected events appear in Scan Coverage. Include logger files when scanning a project.</p>
                    <p id="upload-error" class="upload-error" role="alert" hidden></p>
                    <button type="submit" class="btn btn-primary" id="scan-submit">
                        <i class="fas fa-play"></i> Start Engine Analysis
                    </button>
                    <a href="index.php" class="btn btn-secondary">
                        <i class="fas fa-redo"></i> Clear / New Scan
                    </a>
                </form>





            </div>





            <!-- =====================================================

                 RESULT CARD

                 ===================================================== -->



            <div class="card result-card">





                <div class="result-header">





                    <h3>



                        <i

                            class="fas fa-poll result-icon"

                        ></i>



                        Analysis Result



                        <?php



                        if ($scan_info) {



                            echo ' - ' .

                                htmlspecialchars(

                                    $scan_info['ProjectName']

                                    ?? ''

                                );

                        }



                        ?>



                    </h3>





                    <?php if ($scan_id && $scan_id > 0): ?>





                        <a

                            href="Download_report.php?scan_id=<?= (int)$scan_id ?>&amp;format=pdf"

                            class="btn btn-success"

                            target="_blank"

                        >



                            <i

                                class="fas fa-file-pdf"

                            ></i>



                            PDF



                        </a>





                    <?php endif; ?>





                </div>





                <hr>





                <div class="result-body">
                    <?php require __DIR__ . '/scan_results_view.php'; ?>






                </div>





            </div>





        </div>





    </div>





</div>





<script>
(() => {
    'use strict';
    const $ = id => document.getElementById(id);
    const form = $('scan-form'), box = $('upload-box'), batch = $('file-input');
    const folder = $('folder-input'), prepared = $('prepared-files');
    const paths = $('relative-paths'), mode = $('upload-mode'), language = $('language-select');
    const title = $('file-text'), summary = $('upload-summary'), error = $('upload-error');
    const project = $('project-name'), submit = $('scan-submit');
    const maxFiles = 200, maxFile = 5 * 1024 * 1024, maxTotal = 50 * 1024 * 1024;
    const extensions = {php:['php'], java:['java'], javascript:['js'], c:['c','h']};
    const ignored = new Set(['vendor','node_modules','.git','.idea','.vscode','dist','build',
                             'coverage','encrypted_logs','keys','logs','cache','.next']);
    let valid = false;

    function warn(message) { error.textContent = message; error.hidden = !message; }
    function clearPrepared() { prepared.value = ''; paths.replaceChildren(); valid = false; }
    function changeMode(next) {
        mode.value = next;
        document.querySelectorAll('.mode-button').forEach(b => b.classList.toggle('selected', b.dataset.mode === next));
        batch.disabled = next !== 'batch';
        prepared.disabled = next !== 'folder';
        batch.value = ''; folder.value = ''; clearPrepared(); warn('');
        title.textContent = next === 'folder' ? 'Click to select a project folder' : 'Click to select source files';
        $('upload-hint').textContent = next === 'folder'
            ? 'Only matching source files will be uploaded' : 'Or drag and drop files here';
        summary.textContent = 'Max 200 files, 5 MB each, 50 MB total.';
    }
    document.querySelectorAll('.mode-button').forEach(b => b.addEventListener('click', () => changeMode(b.dataset.mode)));
    function openPicker() { (mode.value === 'folder' ? folder : batch).click(); }
    box.addEventListener('click', openPicker);
    box.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPicker(); }
    });
    function eligible(file, path) {
        const parts = path.split('/');
        if (parts.some(part => ignored.has(part.toLowerCase()) || !part || part === '..' || part === '.')) return false;
        const name = parts[parts.length - 1].toLowerCase();
        if (name === 'email_config.php' || name === 'connection.php') return false;
        const ext = name.includes('.') ? name.split('.').pop() : '';
        return extensions[language.value].includes(ext);
    }
    function validateFiles(files) {
        if (!files.length) return 'No eligible files found for the selected language.';
        if (files.length > maxFiles) return 'This project has ' + files.length + ' eligible files; limit is 200. Select a smaller folder.';
        if (files.some(f => f.size === 0 || f.size > maxFile)) return 'Files must be non-empty and no larger than 5 MB each.';
        if (files.reduce((n, f) => n + f.size, 0) > maxTotal) return 'Total upload exceeds 50 MB.';
        return '';
    }
    function prepareFolder() {
        clearPrepared(); warn('');
        const files = [...folder.files];
        const eligibleFiles = files.map(file => {
            const full = file.webkitRelativePath || file.name;
            const parts = full.replaceAll('\\', '/').split('/');
            return {file, path: parts.length > 1 ? parts.slice(1).join('/') : file.name};
        }).filter(x => eligible(x.file, x.path));

        // A single empty or oversized file must not block an entire project scan.
        const skippedEmpty = eligibleFiles.filter(x => x.file.size === 0);
        const skippedLarge = eligibleFiles.filter(x => x.file.size > maxFile);
        const selected = eligibleFiles.filter(x => x.file.size > 0 && x.file.size <= maxFile);
        const skipped = skippedEmpty.length + skippedLarge.length;

        if (!selected.length) {
            warn('No valid source files found. ' + skippedEmpty.length +
                 ' empty and ' + skippedLarge.length + ' over 5 MB were skipped.');
            summary.textContent = 'Max 200 files, 5 MB each, 50 MB total.';
            return;
        }
        if (selected.length > maxFiles) {
            warn(selected.length + ' valid files found; maximum is 200 per scan. Select a smaller folder.');
            return;
        }
        const totalBytes = selected.reduce((n, x) => n + x.file.size, 0);
        if (totalBytes > maxTotal) {
            warn('Valid source files total ' + (totalBytes / 1048576).toFixed(2) +
                 ' MB, exceeding the 50 MB scan limit. Select a smaller folder.');
            return;
        }
        if (typeof DataTransfer === 'undefined') {
            warn('Use Chrome or Edge for project folder uploads.');
            return;
        }

        const dt = new DataTransfer();
        selected.forEach(({file, path}) => {
            dt.items.add(file);
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'relative_paths[]';
            input.value = path;
            paths.appendChild(input);
        });
        prepared.files = dt.files;
        valid = prepared.files.length === selected.length;
        if (!valid) {
            clearPrepared();
            warn('Could not prepare folder files. Try Chrome or Edge.');
            return;
        }
        const root = files[0]?.webkitRelativePath?.split('/')[0] || 'Project';
        if (!project.value.trim()) project.value = root;
        title.textContent = selected.length + ' valid source files ready';
        const skippedMessage = skipped
            ? ' · Skipped: ' + skippedEmpty.length + ' empty, ' + skippedLarge.length + ' over 5 MB'
            : ' · No files skipped';
        summary.textContent = root + '/ · ' + selected.length + ' files · ' +
                              (totalBytes / 1048576).toFixed(2) + ' MB' + skippedMessage;
    }
    function prepareBatch() {
        valid = false; warn('');
        const files = [...batch.files];
        const problem = validateFiles(files) ||
            (files.every(f => eligible(f, f.name)) ? '' : 'Files do not match the selected language.');
        if (problem) { warn(problem); return; }
        valid = true;
        title.textContent = files.length + ' source files selected';
        summary.textContent = 'Batch mode · ' + files.length + ' files ready to scan.';
    }
    folder.addEventListener('change', prepareFolder);
    batch.addEventListener('change', prepareBatch);
    language.addEventListener('change', () => {
        if (mode.value === 'folder' && folder.files.length) prepareFolder();
        if (mode.value === 'batch' && batch.files.length) prepareBatch();
    });
    box.addEventListener('dragover', e => { e.preventDefault(); box.classList.add('dragover'); });
    box.addEventListener('dragleave', () => box.classList.remove('dragover'));
    box.addEventListener('drop', e => {
        e.preventDefault(); box.classList.remove('dragover');
        if (mode.value === 'folder') { warn('Click the upload box to select a project folder.'); return; }
        batch.files = e.dataTransfer.files; prepareBatch();
    });
    form.addEventListener('submit', e => {
        if (!valid || (mode.value === 'folder' && prepared.files.length !== paths.children.length)) {
            e.preventDefault(); warn('Please select valid source files before scanning.'); return;
        }
        submit.disabled = true; submit.textContent = 'Uploading and scanning…';
    });
    changeMode('batch');
})();
</script>





</body>



</html>
