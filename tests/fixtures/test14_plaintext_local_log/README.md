# Test 14: Explicit plaintext TXT destination

Upload `login.php` to the PHP scanner. Do not deploy or execute this fixture.
Scanning it does not create `auth.txt`.

Code evidence:
- Authentication failure calls `error_log` before returning.
- Message is constant; no user input reaches the log message.
- `error_log` mode 3 appends to `__DIR__ . '/auth.txt'`.
- This write uses plaintext; no encryption is applied in this function.
- Destination is beside the PHP source. If deployed in a web-served folder,
  web access depends on server configuration; this source cannot prove access.

Observed scanner output:
| Check | Result |
| --- | --- |
| Security Logging | PASS |
| Log Neutralization | PASS |
| Log Storage | N/A |
| Log Protection | N/A |

The scanner does not resolve this explicit destination expression, so its
storage/protection results are inconclusive despite the visible write target.
The destination meets the project's TXT-extension policy, but that alone does
not establish a safe location or encryption.

Validation: PHP syntax check passed; isolated scanPHP analysis completed.
