# Extended PHP logging review

Upload each PHP fixture separately and enable **Extended PHP logging review**.
Uploaded code is analyzed, never executed. Do not browse the fixture PHP URLs.

| Fixture | Security Logging | Log Neutralization | Log Storage | Log Encryption |
|---|---|---|---|---|
| validation_with_context.php | PASS | PASS | N/A | N/A |
| access_missing_context.php | FAIL (missing context) | PASS | N/A | N/A |
| login_wrapper_context.php | PASS | N/A | N/A | N/A |

Each recognized event produces four checks. Context is assessed within Security Logging,
not a separate finding. Retention is outside the source-only scan. Custom ACTIVE rules
may add findings. Context failure does not suppress analysis of an existing logging sink.
PASS describes recognized static evidence, not runtime values or overall application security.

## Supported scope

- Opt-in checkbox is checked for new uploads. Untick to preserve the four-check baseline.
- `scanPHP($file, $source, $sources, true)` enables this mode for programmatic calls.
- Authentication: existing failure vocabulary plus direct positive `password_verify`,
  `authenticate`, `authenticateUser`, `loginUser`, `verifyLogin`, `Auth::attempt` predicates.
  Immediate else branches are also examined. Other frameworks/boolean expressions need review.
- Validation: explicitly failing `filter_var` predicates using a `FILTER_VALIDATE_*`
  constant; `in_array` / `preg_match` predicates with direct GET/POST/REQUEST input.
  This is not exhaustive discovery of all server validation or all application login flows.
- Context: direct literal arrays sent through `error_log(json_encode([...]))` or supported
  logger context arguments. Keys use the demonstrated flat schema. Other schemas, dynamic
  payloads and aliases remain unknown. Plain-function wrappers with a single call statement
  can bind literal caller context or add supported attributes themselves. Static included
  wrappers use only definitions accepted by include resolution. Class/namespace binding,
  parameter reassignment, references, defaults and variadics remain unsupported. This context
  binding does not establish separate neutralization/encryption flow through wrappers.
- Required base fields: event, result, reason, source_ip. Event-specific fields:
  claimed_identity for failed login; actor_id + action for successful login;
  actor_id + target for access denial; actor_id + field for validation failure.
  Explicit actor_type='unauthenticated' replaces actor_id for anonymous access/validation.
- Server-established session identity is recognized independently of role name.
  Client-provided actor_id/actor_role cannot establish authenticated identity.
- Missing explicit timestamp is N/A, because runtime logging may add one.
- Retention is not a scan result. No uploaded retention
  declaration is accepted as proof; no runtime log rotation, deletion or archiving is changed.

## Deployment retention verification (manual)

1. Agree the required retention duration from the application's investigation needs and policies.
2. Inspect the effective logging/rotation/archive/backup configuration for that destination.
3. Verify permissions and integrity for current and archived logs.
4. In a controlled environment, rotate a dated test event and retrieve it from the archive.
5. Verify retrieval throughout the required period and document deletion/backup behavior.

No universal minimum number of days is imposed by this scanner. A runtime retrieval test
and deployment evidence are necessary before making a retention claim.
