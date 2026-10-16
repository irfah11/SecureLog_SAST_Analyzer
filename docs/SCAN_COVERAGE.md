# Grouped results and scan coverage

New scans store processing metadata in
`Dashboard/logs/scan_coverage/<ScanID>.json`. No database schema change is required.
The parent log directory is excluded from Git and denied web access by its
existing .htaccess. Direct access to the coverage directory was verified to
return HTTP 403 on the local Apache server.

Metadata contains the scan/owner IDs, submitted file paths, processing states,
returned/saved check counts, and saved ResultID-to-event mappings. It does not
contain source code. Only load it after the scan has passed the existing database
ownership/role check. The loader also verifies the saved scan and owner IDs.
Writes use a temporary file and rename; failure leaves the scan results intact
and records a server error. Coverage remains unavailable rather than inferred.

PHP results now carry event identifiers, names and event-start lines through the
save process. These are presentation fields, not changed detection criteria.
Multiple events on the same line have different identifiers. Dependent checks
remain grouped with their event even if their finding lines differ.

Files and events with FAIL checks appear first and open by default. Other files
and events start collapsed. Checks inside a group are ordered FAIL, PASS, N/A.
The existing descriptions, rules, severity and finding lines remain visible.
System/validation messages are not included in security-check counts.

Coverage separates files analyzed with checks, files analyzed without a supported
event, unsupported extensions, validation rejections and scanner failures. A
dashboard/helper without a supported event adds no finding row. It does not
establish that logging is unnecessary or that the file is secure. Frontend-
excluded/unsubmitted files are not part of coverage.

Old scans have no coverage snapshot and explicitly disclose that limitation.
Their groups are reconstructed from the saved Security Logging anchors and
result order. For older non-PHP results, these are check groups, not a claimed
complete event inventory. Run a new scan for per-file coverage and explicit PHP
event mappings. The report module retains the saved check data and its existing
interpretation; this change concerns the scanner page and scan metadata.

Validation: `php tests/scan_presentation.php` checks grouping, ordering, no-event
files, same-line events, escaping, old scans and owner-bound coverage persistence.
It uses synthetic source strings and removes its unique metadata file afterward.
The optional output path creates a synthetic HTML browser preview; remove that
preview after reviewing. Scanner regression tests and read-only HTTP access/PDF
tests remain applicable.
