# Open Redirect Candidate Finder for Burp Suite

Open Redirect Candidate Finder is a passive Burp Suite extension built with Java 17 and the Montoya API. It highlights requests and client-side code that deserve manual open-redirect review while keeping detection separate from confirmation.

The extension never sends an HTTP request automatically. **Send to Repeater** only creates a Repeater tab; the tester decides whether and when to send it.

## What it detects

- Common redirect parameters in URL, body, and other non-cookie parameter locations.
- URL-like redirect values, including repeatedly URL-encoded absolute and scheme-relative destinations.
- `3xx` responses with a `Location` header, with higher priority when the supplied parameter appears in the redirect target.
- Client-side navigation sinks such as `location.assign`, `location.replace`, router navigation, and meta refresh.
- Client-side sources such as `location.search`, `location.hash`, `document.referrer`, `postMessage`, and browser storage.
- Nearby source/sink pairs as higher-priority DOM redirect candidates.
- JavaScript source-map references without fetching them.

These are candidates, not confirmed vulnerabilities. The extension does not inject payloads, follow redirects, fetch source maps, or assert exploitability.

## Features

- Reviews existing Proxy history in a background thread and inspects new Proxy responses.
- Uses **Target Scope only** by default.
- Shows the original request and response beside each finding.
- Supports search, severity filters, review states, host/marker ignore lists, and configurable parameter/source/sink lists.
- Sends a selected request to Repeater for controlled manual testing.
- Exports redacted JSON or spreadsheet-safe CSV.
- Persists reviewed and false-positive fingerprints in the Burp project when project persistence is available.
- Releases its background scanner when the extension unloads.

## Requirements

- A current Burp Suite Community or Professional release compatible with Montoya API 2026.4.
- JDK 17 or newer to build the extension.

## Build

The Gradle wrapper and all required wrapper files are included.

Linux or macOS:

```bash
./gradlew clean test jar
```

Windows:

```powershell
.\gradlew.bat clean test jar
```

The loadable JAR is created at:

```text
build/libs/open-redirect-candidate-finder-2.0.0.jar
```

GitHub Actions runs all tests and publishes this JAR as a directly downloadable workflow artifact. For public distribution, attach the tested file to a versioned GitHub Release instead of committing `build/`.

## Install in Burp Suite

1. Open **Extensions > Installed**.
2. Click **Add**.
3. Choose extension type **Java**.
4. Select `build/libs/open-redirect-candidate-finder-2.0.0.jar`.
5. Review the **Output** and **Errors** tabs, then open **Redirect Candidates**.

## Suggested workflow

1. Add only authorized targets to **Target > Scope**.
2. Browse the application normally. The extension scans recent history when loaded and analyzes new Proxy responses.
3. Start with **HIGH** candidates where a supplied value appears in a `Location` header or a client-side source is close to a navigation sink.
4. Inspect the request, response, and evidence. Use **Send to Repeater** and choose a safe test value under your engagement rules.
5. Verify the final browser behavior, URL parsing, allowlist logic, and whether a redirect reaches an attacker-controlled origin.
6. Mark each item Reviewed or False positive, or ignore a noisy host/marker.
7. Export JSON or CSV when you need a review log.

## Configuration

The **Settings** tab controls:

- Target Scope filtering.
- Maximum textual response size from 1 to 100 MB.
- Redirect parameter names.
- Client-side navigation sinks.
- Client-side input sources.

Applying settings clears the current in-memory results and rescans Proxy history. Ignored hosts and markers are stored in Burp preferences and can be cleared with **Restore defaults**, followed by **Apply and rescan**.

## Safety, privacy, and limitations

- No active request is sent in the background.
- Only existing response bodies are inspected; gzip and deflate are decoded within the configured size limit.
- Export evidence redacts common `Authorization`, `Cookie`, and `Set-Cookie` values, but you should still review files before sharing them.
- Literal source/sink proximity is a triage signal, not JavaScript data-flow proof.
- A reflected `Location` value still needs manual validation because normalization, allowlists, and browser parsing affect exploitability.
- Use the extension only on systems you are authorized to test.

## الاستخدام السريع بالعربية

1. ابنِ المشروع بالأمر `./gradlew clean test jar`.
2. من Burp افتح **Extensions > Installed > Add** واختر **Java**، ثم حمّل `build/libs/open-redirect-candidate-finder-2.0.0.jar`.
3. أضف الهدف المصرح به إلى **Target Scope**.
4. راجع تبويب **Redirect Candidates** وابدأ بنتائج HIGH.
5. زر **Send to Repeater** لا يرسل الطلب؛ هو فقط ينشئ تبويبًا للمراجعة والاختبار اليدوي.
6. النتائج مرشحات للمراجعة وليست إثباتًا تلقائيًا لثغرة Open Redirect.

## License

MIT. See [LICENSE](LICENSE).
