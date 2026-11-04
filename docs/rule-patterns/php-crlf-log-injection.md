# Candidate rule: direct request input in PHP error_log

Saved for manual creation through Add Rule. Not activated or installed.

| Field | Value |
|---|---|
| Rule Code | PHP_LOG_RAW_INPUT |
| Rule Name | Potential Log Injection from Direct Request Input |
| Language | PHP |
| Detection Type | Custom Detection |
| Weakness Category | Log Injection |
| Match Type | SIMPLE_PATTERN |
| CWE ID | CWE-117 |
| Severity | MEDIUM (proposed triage priority) |
| OWASP Category | A09: Security Logging and Monitoring Failures (2021 option currently offered by the form) |

Primary Pattern (copy the single line, including ~ delimiters):

```regex
~\berror_log\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\s*\[\s*['"][A-Za-z_][A-Za-z0-9_]*['"]\s*\]|(?:'[^'\r\n]*'|"[^"\r\n]*")\s*\.\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['"][A-Za-z_][A-Za-z0-9_]*['"]\s*\])\s*[,)]~
```

Secondary Pattern: leave empty.

Description:

```text
Potential log injection: request input is passed directly to error_log() on one source line. Review whether upstream validation and the logging format adequately neutralize control characters and delimiters. This pattern does not prove exploitable CR/LF injection.
```

Recommendation:

```text
Encode logged data for the actual output format. For plain line-oriented logs, neutralize CR/LF and relevant delimiters before logging. Prefer structured logging with appropriate encoding. Do not log passwords or tokens.
```

## Match examples

```php
error_log($_POST['username']);
error_log('LOGIN_FAILED user=' . $_GET['username']);
```

## No-match examples

```php
$safeUsername = str_replace(["\r", "\n"], '_', $_POST['username']);
error_log($safeUsername);
error_log(json_encode(['username' => $_POST['username']]));
```

No match is not proof of safety. These examples demonstrate the pattern's limited scope.

## Limitations

- This detects a direct raw-input logging pattern, not the literal characters CR/LF in an attack payload.
- The current custom matcher operates on source lines, not tokens or data flow.
- Comments/string examples can match. Multiline calls, aliases, custom wrappers and upstream validation are not analyzed.
- It does not check all log sinks, delimiters or downstream parser behavior.
- The built-in PHP analyzer already assesses neutralization; this custom rule can duplicate an existing finding.
- Do not use a rule searching for str_replace alone as proof of a weakness or safety.
- Suggested future UI category: Log Neutralization / Log Injection. Until then, CUSTOM is more accurate than SENSITIVE_LOGGING; choose Custom Detection when entering this rule.

Reference: https://cwe.mitre.org/data/definitions/117.html
