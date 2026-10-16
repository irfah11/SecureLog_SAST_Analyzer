# SecureLog validation baseline

Date: 16 October 2026 (Asia/Kuala_Lumpur)

Status: original fixtures inspected, expected results awaiting user confirmation.
The original Tests 01-13 have NOT been executed in this review.

## 1. Access-control boundary

Changed `Engine_Process/index.php` to require a positive authenticated identity
and the admin/developer role before database access. Developers retrieve scans
using both ScanID and their session UserID; admins may retrieve any scan.
Findings are queried only after the scan passes that check. Missing and
inaccessible scans return the same 404 response. Invalid IDs return 400.

Changed `Engine_Process/scan_process.php` to reject anonymous and disallowed
roles before database/upload work. Both endpoints prefer session UserID, with
user_id retained as a compatibility fallback, matching Download_report.php.

Read-only HTTP validation: `php tests/scan_access_http.php` passed 18 assertions
against a temporary loopback PHP server using temporary test sessions and one
existing database scan. Covered anonymous redirects, guest denial, owner access,
other-developer denial, admin access, legacy session support, zero identity,
malformed IDs, and report ownership denial. No database records were changed.

Static inspection also found developer filtering in History/index.php and
dashboard_Developer.php, ownership checks in Download_report.php, and admin guards
in user/rule management and vault pages. These observations do not establish
that every application route is secure. Login/session issuance, inactive-account
revocation, CSRF, web-server file protections and destructive actions require
separate tests. Dashboard/Scan/allScans.php and scandetails.php are empty files.

## 2. Original scanner test expectations

Fixture root: `C:/xampp/htdocs/SecureLog_TestSuite02/`.
Source files remain unchanged. Folder tests are separate projects, with paths
relative to each test folder. Do not combine all fixtures into one project:
many deliberately reuse function names.

For each supported event the check order is:
Security Logging / Log Neutralization / Log Storage / Log Protection.
Helper files without events contribute coverage, not extra finding rows.
PASS means verified within supported static patterns, not guaranteed runtime
delivery or a declaration that the whole application is secure.

| Test | Expected checks | Evidence and qualification |
| --- | --- | --- |
| 01 procedural | PASS / PASS / N/A / N/A | Failed password verification unconditionally calls error_log with a constant message. Destination is environment-configured. |
| 02 OOP logger | PASS / PASS / N/A / N/A | Direct logger->warning call with a constant message. PASS relies on the supported logger API convention; receiver implementation is not verified. |
| 03 custom logger | PASS / N/A / N/A / N/A | Same-file recordSecurityEvent implementation writes to error_log. Wrapper argument flow is not verified. |
| 04 nested conditions | PASS / PASS / N/A / N/A | Both locked and unlocked failure branches log constant messages before returning. |
| 05 exception handling | PASS / PASS / N/A / N/A | Catch block logs a constant message. Evaluates exception handling, not a separate inferred login-failure event. |
| 06 wrong branch | FAIL / N/A / N/A / N/A | Failed authentication returns before the success log. |
| 07 fake logger | FAIL / N/A / N/A / N/A | Same-file wrapper returns true and has no sink. |
| 08 cross-file function | PASS / N/A / N/A / N/A | login.php includes SecurityLogger.php; recordSecurityEvent calls error_log. Scan both files together. |
| 09 unreachable log | FAIL / N/A / N/A / N/A | Failure path returns before the log statement. |
| 10 conditional log | FAIL / N/A / N/A / N/A | enableLogging=false leaves a reachable unlogged failure path. |
| 11 valid log | PASS / PASS / N/A / N/A | Failure path directly logs a constant message. |
| 12 cross-file class | Semantic target: PASS / N/A / N/A / N/A for the failure event in AuthService.php | Logger::securityEvent has a real sink, but class-qualified cross-file binding is unsupported. Record N/A as an unresolved case if returned; do not count it as a successful verification or change the target to fit implementation. login.php's !$auth->authenticate(...) is outside the current authentication-pattern detector. |
| 13 original folder | Invalid fixture; no Logging PASS expected | login.php includes test13_logger.php, but supplied helper is logger.php. Missing require_once prevents normal execution. The scanner should not silently substitute a different filename. Expect four unresolved checks for the detected failure event; do not score this fixture as a validated secure example. |

### Test 13 decision required before execution

Keep the originals unchanged. Proposed follow-up fixtures in the writable project:

1. Original case: verify no false PASS for the missing include.
2. Filename-corrected copy: change only the include to logger.php. Its logger
   calls error_log only when json_encode succeeds. The current resolver does not
   establish that wrapper's complete path/argument behavior, so Logging remains
   unresolved. The helper contains an if statement and is conservatively excluded
   by the current cross-file definition collector.
3. Separate unconditional-wrapper control: a matching include and wrapper with
   error_log($message) on every path. Expected PASS / N/A / N/A / N/A.

The caller in the supplied case uses fixed ASCII strings and null; a richer
argument-aware analyzer could prove more about that particular json_encode call.
The current scanner cannot. Do not label the original logger vulnerable solely
because its encoding-failure branch exists, or claim it is verified without
following the arguments.

## 3. Evaluation method

Freeze fixture contents and expected results before running. Save file hashes,
scanner revision/diff, test mode, event line, expected and actual checks, and
descriptions. Run scanner functions on source strings only; never include or
execute the untrusted fixtures. Test persistence/upload/report integration
separately from detection so insertion errors are not mistaken for detector errors.

Use each security event and check as the evaluation unit, not an entire file or
the total number of result rows. Preserve distinct events; do not globally dedupe
all Security Logging rows to force a scan to have four results.

For CWE-778, vulnerability-positive means an event has a demonstrable missing
logging path. TP = vulnerable event reported FAIL; FP = verified logged event
reported FAIL; FN = vulnerable event reported PASS; TN = logged event reported
PASS. Report unresolved N/A cases separately, along with coverage:

- Resolved-only precision = TP / (TP + FP).
- Resolved-only recall = TP / (TP + FN).
- Decision coverage = resolved labelled events / all valid labelled events.
- Effective recall = TP / all labelled vulnerable events, including unresolved
  vulnerable events in that denominator.

Undefined ratios must be reported as undefined, not 100%. Exclude invalid Test 13
from valid-example denominators, while retaining it as a negative robustness
test. Do not mix storage-policy findings into CWE-778 accuracy.

These fixtures do not establish CWE-117 sensitivity: most messages are constants.
Add independently labelled input-to-log examples, including raw CR/LF input,
neutralized input, assignment propagation and wrappers, before claiming log-
injection detection accuracy. Add unseen examples before making general claims.

## 4. Current unsupported or approximate behavior

- Authentication-event discovery supports selected syntax patterns, not arbitrary
  business logic, custom object authentication methods or all PHP constructs.
- Recognized logger method names/receivers are conventions, not proof of the
  runtime object's implementation or successful log delivery.
- Cross-file resolution follows leading unconditional literal includes, including
  __DIR__ concatenation, using verified uploaded source strings only. It does not
  execute uploaded PHP, read include targets from disk, resolve dynamic paths,
  Composer autoloading or arbitrary include placement.
- Imported class/namespace/trait/interface definitions and files containing
  conditional/loop constructs are conservatively excluded. Method binding and
  conditional declaration analysis require additional work.
- Include traversal is bounded to 12 levels; wrapper resolution to 6 levels;
  control-flow exploration is bounded. Cycles and ambiguous definitions must not
  be treated as proof of logging.
- Wrapper parameter-to-sink neutralization and encryption propagation are not
  verified. N/A is appropriate until evidence is available.
- A .txt suffix is a project storage policy, not proof of security or an OWASP
  requirement. Static code cannot generally establish filesystem permissions,
  external log retention, monitoring, alert delivery or protected archive state.
- Java, JavaScript and C modules exist, but use separate simpler heuristics. The
  PHP tests do not validate equivalent analysis quality in those languages.

## 5. Report alignment notes

Source: Final Psm CB23041_v2.pdf; PDF remains unchanged pending validated results.
Printed page numbers below differ from PDF viewer page indices.

- Abstract, objectives (p.14) and development method (p.33): describe PHP analysis
  as token-assisted rule analysis with regex event recognition, bounded path
  assessment and limited wrapper/include resolution. It is not regex-only or a
  complete interprocedural analyzer.
- Scope/limitations (pp.15-16,37): code contains PHP, Java, JavaScript and C modules.
  Clearly distinguish implemented modules from empirically validated language
  support. Do not claim identical capabilities across languages.
- Evaluation objective (p.14) and UAT (pp.82-84): UAT demonstrates usability and
  workflow acceptance. Add separate labelled detection evaluation and measured
  results. Existing Pass/Fail placeholders are not completed evidence.
- Security requirements (pp.36-37): replace unconditional guarantees with testable
  controls and bounded claims. Static findings do not directly prevent runtime
  log manipulation. Encryption alone is not a general integrity guarantee;
  authenticated encryption can detect protected-archive modification when its
  verification and key assumptions hold.
- Use consistent OWASP Top 10:2025 category wording throughout. Separate CWE-778,
  CWE-117, storage policy and log-protection policy; distinguish source analysis
  from SecureLog's own activity logging and vault features.
- Conclusion (p.87): claim only capabilities supported by implementation and
  recorded tests. Keep proposed enhancements separate from completed outcomes.

Suggested scope statement:

> SecureLog is a web-based static analysis prototype for selected security
> logging weaknesses. Its PHP analyzer combines token-based source inspection,
> rule-based event recognition and bounded path and wrapper analysis. Findings
> distinguish detected weaknesses, verified checks within supported patterns,
> and cases requiring further inspection. Additional language modules use
> separate heuristics and require their own evaluation.

## 6. Next gate

Confirm the table and the three-part Test 13 treatment before executing the
original suite. Then record actual findings, investigate mismatches, calculate
metrics, and prepare the report changes around those results. Additional feature
development remains deferred.
