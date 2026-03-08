# Burp Extension Handoff

## Purpose

This document is a practical handoff for the next agent working on the native Burp Suite Professional addon in this repository.

The Python CLI remains intact and is still the reference implementation. The Java addon in `burp-extension/` is being brought toward feature parity.

---

## Current branch / build status

- Working branch: `cursor/native-burp-suite-extension-129e`
- Repo root: `/workspace`
- Burp addon module: `/workspace/burp-extension`

### Current build command

```bash
cd /workspace/burp-extension
./gradlew clean fatJar test
```

### Current artifact

```bash
/workspace/burp-extension/build/libs/GraphQLHunterBurp.jar
```

### Current status

The addon is **well beyond MVP** and now includes:
- native Java/Montoya packaging
- Burp tab UI
- request import from Burp context menu
- auth configuration/validation foundation
- request importer foundation
- discovery foundation
- reporting foundation
- a broad scanner set in Java

The main remaining work is **fidelity, polish, and parity validation**, not basic scaffolding.

---

## Important repo files

### Burp addon entrypoint
- `burp-extension/src/main/java/burp/GraphQLHunterExtension.java`

### Core transport / request logic
- `burp-extension/src/main/java/graphqlhunter/GraphQLHunterCore.java`

### Scanner orchestration and scanner implementations
- `burp-extension/src/main/java/graphqlhunter/GraphQLHunterScanners.java`

### UI
- `burp-extension/src/main/java/graphqlhunter/ui/GraphQLHunterTab.java`

### Config loading
- `burp-extension/src/main/java/graphqlhunter/config/ConfigurationLoader.java`
- `burp-extension/src/main/resources/graphqlhunter/config/payloads.yaml`
- `burp-extension/src/main/resources/graphqlhunter/config/auth.yaml`

### Auth foundation
- `burp-extension/src/main/java/graphqlhunter/auth/AuthManager.java`
- `burp-extension/src/main/java/graphqlhunter/auth/AuthProvider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/BearerTokenProvider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/ApiKeyProvider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/StaticHeadersProvider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/ScriptedProvider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/CookieSessionProvider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/OAuth2Provider.java`
- `burp-extension/src/main/java/graphqlhunter/auth/flow/*`

### Import / discovery / reporting
- `burp-extension/src/main/java/graphqlhunter/importer/RequestImporter.java`
- `burp-extension/src/main/java/graphqlhunter/importer/ImportedRequest.java`
- `burp-extension/src/main/java/graphqlhunter/discovery/AutoDiscover.java`
- `burp-extension/src/main/java/graphqlhunter/discovery/DiscoveryResult.java`
- `burp-extension/src/main/java/graphqlhunter/reporting/ReportingService.java`
- `burp-extension/src/main/java/graphqlhunter/reporting/ReportSummary.java`

### Persisted state model
- `burp-extension/src/main/java/graphqlhunter/GraphQLHunterModels.java`
- `burp-extension/src/main/java/graphqlhunter/GraphQLHunterPersistence.java`

### Reference Python implementation
- `graphql-hunter.py`
- `lib/graphql_client.py`
- `lib/introspection.py`
- `lib/request_importer.py`
- `lib/auto_discover.py`
- `lib/reporter.py`
- `lib/html_reporter.py`
- `lib/auth/*`
- `scanners/*`

---

## What is already implemented in Java

## UI / workflow

- Request editor:
  - URL
  - method
  - query
  - variables
  - headers
- Scan profile controls:
  - profile
  - safe mode
  - delay
- Auth workspace:
  - mode
  - profile
  - auth vars
  - static headers
  - imported auth headers
  - auth validation result
- Import & discovery workspace:
  - pasted import content
  - import format selection
  - imported request selection/application
  - discovery notes
  - discovery analysis/application
- Export actions:
  - JSON
  - HTML

## Auth

- static headers
- imported headers
- bearer
- API key
- scripted auth foundation
- cookie-session auth foundation
- OAuth foundation for:
  - client credentials
  - refresh token
  - auth code
  - device code
- auth validation workflow
- redaction helpers

## Request import

- cURL
- raw HTTP
- JSON
- YAML
- Postman collection
- auto-detect

## Discovery

- notes/text-based extraction for:
  - URL
  - credentials
  - tokens
  - auth-related headers
- request-collection-driven discovery
- basic recommendations

## Reporting

- summary/risk rollup foundation
- JSON export
- basic HTML export

## Java scanner coverage currently present

- introspection
- info disclosure
- auth exposure differential
- batching
- injection (lightweight)
- DoS
- aliasing
- circular query
- XSS
- JWT
- rate limiting
- CSRF
- file upload surface review
- mutation fuzzer review

---

## What is still missing / weak

These are the most important next tasks.

## 1. Full-fidelity parity gaps

### Transport/runtime fidelity
- multipart upload execution parity is still incomplete
- replay generation is much closer to the Python CLI now, but multipart and batch-specific edge cases still need work
- proxy-specific parity is not fully addressed
- some deeper auth retry/refresh semantics and external auth-config ergonomics remain lighter than Python, though auth validation now uses an isolated anonymous baseline instead of sharing the authenticated session

### Scanner fidelity
- some Java scanners are present but still lighter than the Python versions
- especially worth improving:
  - deeper boolean-differential injection sophistication beyond the current conservative list-count heuristic
  - file upload exploitation depth
  - deeper CSRF token/cookie handling depth beyond the current origin and token-presence checks
  - mutation fuzzer behavior depth

### Reporting fidelity
- HTML/JSON export is materially closer to the Python CLI now, including filters, structured redaction, replay snippets, and real executed/skipped/failed scanner metadata

### UX polish
- pasted imports now carry auth headers forward, discovery can promote token-only notes into usable headers, and runtime-only secrets are exposed in the UI, but the workspace still needs refinement
- no richer GraphQL message editor/view integration yet
- no multi-target/history UX yet

### Validation / confidence
- no formal parity harness yet that compares Java results to Python results against the same fixtures

---

## Suggested next execution order

If continuing immediately, the best order is:

1. **Strengthen scanner fidelity**
   - deeper boolean-differential injection parity
   - deeper JWT expiry / auth-behavior parity
   - deeper file upload / CSRF / mutation parity

2. **Add parity validation harness**
   - fixture-based comparison between Python and Java outputs

3. **Polish import/discovery/export UX**

---

## Tests already added

Current Java tests cover:
- core request parsing / operation building
- scanner behavior
- configuration loading
- auth foundation
- auth flow runner
- importer behavior
- discovery behavior
- reporting behavior
- DoS/content/protection scanner groups

Key test files:
- `burp-extension/src/test/java/graphqlhunter/GraphQLHunterCoreTest.java`
- `burp-extension/src/test/java/graphqlhunter/GraphQLHunterScannersTest.java`
- `burp-extension/src/test/java/graphqlhunter/GraphQLHunterDosScannersTest.java`
- `burp-extension/src/test/java/graphqlhunter/GraphQLHunterContentScannersTest.java`
- `burp-extension/src/test/java/graphqlhunter/GraphQLHunterMutationAndProtectionScannersTest.java`
- `burp-extension/src/test/java/graphqlhunter/config/ConfigurationLoaderTest.java`
- `burp-extension/src/test/java/graphqlhunter/auth/AuthFoundationTest.java`
- `burp-extension/src/test/java/graphqlhunter/auth/flow/FlowRunnerTest.java`
- `burp-extension/src/test/java/graphqlhunter/importer/RequestImporterTest.java`
- `burp-extension/src/test/java/graphqlhunter/discovery/AutoDiscoverTest.java`
- `burp-extension/src/test/java/graphqlhunter/reporting/ReportingServiceTest.java`

---

## Recent commits for context

Most relevant recent commits:

- `44705e1` — Update Burp parity documentation
- `9928454` — Add Burp protection scanners
- `9ad035b` — Add Burp content scanners
- `2a47894` — Add Burp OAuth provider foundation
- `4eda238` — Add Burp DoS family scanners
- `5addf55` — Add Burp import and export workspace
- `b742f2d` — Add Burp discovery and reporting foundations
- `32db82a` — Add Burp request importer foundation
- `f993b4e` — Add Burp auth validation workflow
- `b46d47e` — Add scripted and cookie auth providers
- `2c8af83` — Add Burp auth flow runner foundation
- `4a35e50` — Add Burp auth configuration panel
- `1ef1484` — Add Burp auth manager foundation
- `0cd93f7` — Add Burp scan configuration foundation

---

## Practical instructions for the next agent

1. Read:
   - `README.md`
   - `BURP_EXTENSION_ASSESSMENT.md`
   - this file
2. Build and test first:
   ```bash
   cd /workspace/burp-extension
   ./gradlew clean fatJar test
   ```
3. Inspect:
   - `GraphQLHunterScanners.java`
   - `GraphQLHunterTab.java`
   - `GraphQLHunterCore.java`
4. Continue with:
   - reporting fidelity
   - scanner fidelity
   - issue publication
   - parity harness

---

## Notes / cautions

- The Python CLI is the source of truth for parity decisions.
- Do not regress the current build or tests.
- The addon is now large enough that fidelity changes should be accompanied by targeted tests.
- Keep committing and pushing in small logical chunks.
