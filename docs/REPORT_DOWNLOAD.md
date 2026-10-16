# Scan report and PDF download

The scanner's PDF button downloads a compact `SecureLog-Scan-<ScanID>.pdf` directly.
The History page's View Report action opens the readable report preview, which
also has a Download PDF action. Both formats use the same saved scan/results.

Routes:

- Preview: `Engine_Process/Download_report.php?scan_id=<ScanID>`
- PDF attachment: `Engine_Process/Download_report.php?scan_id=<ScanID>&format=pdf`
- Full preview: add `&detail=full` to the preview route.
- Full PDF: add `&detail=full` to the PDF route. Its filename ends in `-full.pdf`.

The compact report is the default for both preview and download. It retains every
failed check's severity, file, line, standard and saved result reference in a
compact table. General remediation is listed once per check type. PASS and N/A
are aggregated by check/standard; they are not silently treated as resolved.
The full report preserves each explanation, saved remediation and source snippet.
The preview links allow switching between compact and full modes. There is no
fixed page cap or hidden failure limit; page count depends on the scan contents.

Developers can access their own scans; admins can access all scans. Anonymous
requests redirect to login; other roles receive 403. Missing or inaccessible
scans return the same 404. Reports use private no-store response headers.

## Contents and interpretation

The report includes scan metadata, counts, highest failed-check severity,
severity-ordered failed checks, saved source evidence when available, saved or
fallback recommendations, individual PASS/N/A reasons, processing notes, and
static-analysis limitations. Stable references include the scan and result IDs.

Only FAIL rows count as failed checks. Policy failures are distinguished from
CWE failures. Validation/system notes are separate from security-check counts.
No report claim implies that PASS or an empty result proves the application safe.

The scan table does not reliably record a final processing outcome for older
scans. The report displays the saved status, including Pending, rather than
silently relabelling it Completed. With zero rows it explains that no security
checks were saved; completion should be confirmed separately in the activity log.
The report uses only the stored MatchedCode field for snippets. It does not read
submitted file paths from disk. Source revision hashes are not currently stored;
users should keep the report with the matching source revision.

## Runtime dependency

PDF rendering uses `dompdf/dompdf ~3.1.0` (locked to 3.1.6) installed through
Composer. PHP DOM and mbstring are required; the current XAMPP runtime has both.
Run `composer install` after checking out the updated composer.json/lock.
Remote resource fetching, embedded PHP and PDF JavaScript are disabled. Text is
escaped; the PDF uses bundled fonts, A4 pagination and scan/page footers.
PDF bytes are generated in memory; no public report archive is created.

## Verification

- `php tests/report_compact.php`: compact/default behavior, every failed result
  reference retained, aggregated counts, full-detail availability and PDF output.
  The synthetic 29 FAIL / 37 PASS / 142 N/A case renders to three compact pages.
- `php tests/report_rendering.php`: full report content, counts, escaping, source
  evidence, missing evidence, N/A reasons, empty scans and multi-page PDF checks.
  An optional output-directory argument saves synthetic PDFs for visual review.
- `php tests/scan_access_http.php`: read-only HTTP checks against local MySQL
  and a temporary loopback server. Uses temporary test sessions and an existing
  scan; does not insert scans, change accounts or modify database records.
  Verifies preview/PDF response, attachment/cache headers and owner/admin access.
- Synthetic PDFs were rendered with Poppler and inspected. Searchable text,
  page numbers and content bounds were checked for ordinary, empty and long
  reports. Synthetic examples are not evidence of an actual uploaded scan.
