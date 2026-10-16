# Test 13: Cross-file structured JSON logger

Upload `login.php` and `logger.php` together in a project-folder scan.
Do not execute uploaded fixture code as part of scanning.

The failed-password branch calls the typed `log_activity()` function in
`logger.php`. The helper encodes the event, user ID and description as JSON,
then calls `error_log()` only when encoding succeeds.

The original suite referenced `test13_logger.php`; this copy references the
actual `logger.php` filename.

Observed scanner result: Security Logging = N/A (external wrapper could not
be verified); Log Neutralization, Log Storage and Log Protection = N/A.
This exposes a verification limitation for this wrapper. It is not a verified
logging pass. Logging is conditional on successful JSON encoding, so the test
does not establish that every authentication failure is logged.

No scanner implementation changes were made for this test.
