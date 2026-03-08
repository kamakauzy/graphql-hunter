# Burp Suite Extension - Feasibility Assessment

## Overview

This document assesses the complexity and effort required to port GraphQL Hunter functionality into a Burp Suite extension.

> **Status update (March 2026):** the repository now includes a native Burp Suite Professional addon module in `burp-extension/`. The implementation has moved beyond the initial MVP and now includes native request import workspaces, auth setup/validation foundations, discovery/reporting foundations, and a materially broader scanner set in Java. The rest of this document still explains why complete CLI-equivalent polish and behavior matching remain substantial engineering work.

## Complexity Rating: **MEDIUM to HARD** (3-6 months for full feature parity)

---

## Architecture Overview

### Current GraphQL Hunter Architecture
- **Language**: Python 3
- **Core Components**:
  - GraphQL Client (HTTP requests)
  - 11 Security Scanners (modular)
  - Auth Manager (handles various auth flows)
  - Request Importer (Postman, cURL, JSON, YAML)
  - Auto-Discovery (pattern recognition)
  - Reporter (console + HTML output)

### Burp Extension Architecture
- **Language Options**:
  - **Java** (native, recommended)
  - **Python via Jython** (limited, slower)
  - **Python via Montoya API** (newer, better Python support)
- **Burp APIs**:
  - `IBurpExtender` - Main extension interface
  - `IHttpListener` - Proxy traffic interception
  - `IScannerCheck` - Active/passive scanning
  - `IMessageEditorTab` - Custom request/response views
  - `IContextMenuFactory` - Right-click menu items
  - `ITab` - Custom UI tabs

---

## Feature Porting Complexity

### ✅ **EASY** (1-2 weeks each)

#### 1. GraphQL Request Detection
- **Effort**: Low
- **Implementation**: 
  - `IHttpListener` to detect GraphQL requests
  - Parse JSON body for `query`, `variables`, `operationName`
  - Identify GraphQL endpoints automatically
- **Burp Integration**: Passive scanner check

#### 2. Basic Introspection Scanner
- **Effort**: Low-Medium
- **Implementation**:
  - Port `IntrospectionScanner` logic
  - Use Burp's HTTP client to send introspection queries
  - Parse SDL schema from responses
- **Burp Integration**: Active scanner check

#### 3. GraphQL Request/Response View
- **Effort**: Low
- **Implementation**:
  - `IMessageEditorTab` to show formatted GraphQL queries
  - Syntax highlighting for GraphQL
  - Variable editor
- **Burp Integration**: Custom tab in Repeater/Proxy

#### 4. Request Import (Basic)
- **Effort**: Medium
- **Implementation**:
  - Port `RequestImporter` logic
  - `IContextMenuFactory` to import from clipboard/file
  - Convert to Burp `IHttpRequestResponse`
- **Burp Integration**: Right-click menu item

---

### ⚠️ **MEDIUM** (2-4 weeks each)

#### 5. Security Scanners (All 11)
- **Effort**: Medium-High
- **Implementation**:
  - Port each scanner class
  - Convert to `IScannerCheck` interface
  - Handle Burp's request/response model
  - Integrate with Burp's issue reporting
- **Scanners to Port**:
  1. Introspection Scanner ✅
  2. Info Disclosure Scanner
  3. Auth Bypass Scanner
  4. Injection Scanner (SQL, NoSQL, Command)
  5. DoS Scanner
  6. Batching Scanner
  7. Aliasing Scanner
  8. Circular Query Scanner
  9. Mutation Fuzzer
  10. XSS Scanner
  11. JWT Scanner

**Challenges**:
- Burp's scanner API requires specific issue format
- Need to convert findings to Burp's `IScanIssue`
- Threading/synchronization for concurrent scans
- Burp's rate limiting vs. our aggressive scanning

#### 6. Authentication Manager
- **Effort**: Medium
- **Implementation**:
  - Port `AuthManager` and provider classes
  - Store auth tokens in Burp's session handling
  - Integrate with Burp's cookie jar
  - Handle token refresh automatically
- **Burp Integration**: 
  - Custom session handling
  - Cookie management
  - Header injection

#### 7. Auto-Discovery Feature
- **Effort**: Medium
- **Implementation**:
  - Port `AutoDiscover` logic
  - UI for notes/file input
  - Auto-configure Burp session/auth
- **Burp Integration**: Custom tab with file upload

---

### 🔴 **HARD** (1-2 months each)

#### 8. Full UI Integration
- **Effort**: High
- **Implementation**:
  - Custom `ITab` for main interface
  - Scanner configuration UI (Swing)
  - Results viewer
  - Progress indicators
  - Settings panel
- **Challenges**:
  - Java Swing UI (different from CLI)
  - Burp's UI threading model
  - Integration with Burp's theme system

#### 9. Real-Time Scanning Integration
- **Effort**: High
- **Implementation**:
  - Passive scanning on proxy traffic
  - Active scanning integration
  - Background scanning tasks
  - Results aggregation
- **Challenges**:
  - Burp's scanning lifecycle
  - Performance impact on proxy
  - Threading and concurrency

#### 10. Advanced Features
- **Effort**: High
- **Features**:
  - Intruder payloads for GraphQL
  - Sequencer integration for tokens
  - Collaborator integration
  - Custom scan profiles
  - Report generation (HTML/JSON)

---

## Implementation Approaches

### Option 1: Pure Java (Recommended)
**Pros**:
- Native Burp performance
- Full API access
- Better integration
- Easier distribution

**Cons**:
- Rewrite all Python code to Java
- No code reuse
- Longer development time

**Effort**: 4-6 months

### Option 2: Python via Montoya API
**Pros**:
- Reuse existing Python code
- Modern API
- Better Python support

**Cons**:
- Requires Burp Suite Professional
- Jython limitations
- Performance overhead

**Effort**: 3-4 months

### Option 3: Hybrid Approach
**Pros**:
- Java for UI/Burp integration
- Python for core logic (via subprocess/API)
- Best of both worlds

**Cons**:
- Complex architecture
- Inter-process communication
- Deployment complexity

**Effort**: 3-5 months

---

## Recommended Implementation Plan

### Phase 1: Foundation (4-6 weeks)
1. ✅ GraphQL request detection
2. ✅ Basic introspection scanner
3. ✅ GraphQL request/response view
4. ✅ Simple context menu items

### Phase 2: Core Scanners (6-8 weeks)
1. Port 5-6 most critical scanners
2. Integrate with Burp's scanner
3. Issue reporting
4. Basic configuration UI

### Phase 3: Advanced Features (4-6 weeks)
1. Auth manager integration
2. Request import
3. Auto-discovery
4. Remaining scanners

### Phase 4: Polish (2-4 weeks)
1. UI improvements
2. Documentation
3. Testing
4. Performance optimization

**Total Estimated Time**: 4-6 months for full feature parity

---

## Key Technical Challenges

### 1. **Language Barrier**
- **Current**: Python 3 with modern libraries
- **Burp**: Java or Jython (limited libraries)
- **Solution**: Rewrite core logic or use hybrid approach

### 2. **Request/Response Model**
- **Current**: Custom `GraphQLClient` with `requests` library
- **Burp**: `IHttpRequestResponse`, `IRequestInfo`, `IResponseInfo`
- **Solution**: Adapter layer to convert between models

### 3. **Scanner Integration**
- **Current**: Sequential scanning with custom reporter
- **Burp**: `IScannerCheck` with specific lifecycle
- **Solution**: Refactor scanners to Burp's interface

### 4. **Authentication Handling**
- **Current**: Custom `AuthManager` with session management
- **Burp**: Built-in session handling + cookie jar
- **Solution**: Integrate with Burp's session management

### 5. **UI Development**
- **Current**: CLI with HTML reports
- **Burp**: Java Swing UI
- **Solution**: Complete UI rewrite in Swing

### 6. **Threading & Concurrency**
- **Current**: Sequential or simple threading
- **Burp**: Complex threading model for proxy/scanner
- **Solution**: Careful thread management

---

## Code Reusability Analysis

### ✅ **Highly Reusable** (80-90% reusable)
- Scanner logic (business logic)
- GraphQL query parsing
- Schema analysis
- Pattern matching (auto-discovery)
- Payload generation

### ⚠️ **Partially Reusable** (40-60% reusable)
- HTTP client (needs adapter)
- Auth flows (needs Burp integration)
- Request importer (needs Burp model conversion)

### ❌ **Not Reusable** (0-20% reusable)
- CLI interface
- HTML reporter (needs Burp issue format)
- Console output
- File I/O (different in Burp)

---

## Minimum Viable Product (MVP)

**Goal**: Core GraphQL security testing in Burp

**Features**:
1. ✅ Detect GraphQL requests in proxy
2. ✅ GraphQL request/response view
3. ✅ Introspection scanner
4. ✅ 3-4 critical scanners (DoS, Injection, Auth Bypass)
5. ✅ Basic issue reporting

**Effort**: 6-8 weeks

**Value**: Immediate GraphQL security testing in Burp workflow

---

## Comparison: Standalone vs. Burp Extension

### Standalone Tool (Current)
**Pros**:
- ✅ Full control over execution
- ✅ No Burp dependency
- ✅ Easy to distribute
- ✅ Can run in CI/CD
- ✅ Better for automation

**Cons**:
- ❌ Separate tool to learn
- ❌ Manual request capture
- ❌ No integration with other Burp tools

### Burp Extension
**Pros**:
- ✅ Integrated workflow
- ✅ Automatic request capture
- ✅ Works with Intruder, Repeater, etc.
- ✅ Familiar interface for Burp users
- ✅ Real-time scanning

**Cons**:
- ❌ Burp dependency
- ❌ More complex development
- ❌ Java/Jython limitations
- ❌ Harder to automate

---

## Recommendations

### Short Term (MVP)
1. **Start with MVP** (6-8 weeks)
   - GraphQL detection
   - Basic scanners
   - Simple UI
   - Issue reporting

2. **Validate demand**
   - Release MVP to community
   - Gather feedback
   - Prioritize features

### Medium Term (Full Feature)
1. **Port remaining scanners** (2-3 months)
2. **Add auth management** (1 month)
3. **Improve UI** (1 month)
4. **Add advanced features** (1-2 months)

### Long Term (Enhancement)
1. **Intruder integration**
2. **Custom payloads**
3. **Collaborator support**
4. **Advanced reporting**

---

## Estimated Effort Summary

| Component | Complexity | Effort | Reusability |
|-----------|-----------|--------|-------------|
| GraphQL Detection | Easy | 1 week | 0% (new) |
| Introspection Scanner | Easy | 1 week | 70% |
| Request/Response View | Easy | 1 week | 20% |
| Core Scanners (11) | Medium | 6-8 weeks | 80% |
| Auth Manager | Medium | 2-3 weeks | 50% |
| Request Import | Medium | 2 weeks | 60% |
| Auto-Discovery | Medium | 2 weeks | 70% |
| UI Development | Hard | 4-6 weeks | 10% |
| Scanner Integration | Hard | 3-4 weeks | 30% |
| Testing & Polish | Medium | 2-3 weeks | 0% |

**Total**: 4-6 months for full feature parity

---

## Conclusion

Creating a Burp Suite extension is **feasible but non-trivial**. The core scanning logic is highly reusable, but significant work is needed for:

1. **Language conversion** (Python → Java/Jython)
2. **UI development** (CLI → Swing)
3. **Burp API integration** (custom models → Burp models)
4. **Scanner lifecycle** (custom → Burp's interface)

**Recommendation**: Start with an MVP (6-8 weeks) to validate the approach and gather feedback, then iterate based on user needs.

That recommendation has now been followed in this repository: the MVP addon exists under `burp-extension/`, and it has since moved beyond the original scaffold with broader scanner coverage, concurrent rate-limit probing, JWT `alg:none` and expired-token acceptance checks, query-only time-based and conservative boolean-differential injection probes, richer report exports, improved auth/runtime-secret handling, isolated anonymous auth validation, external auth-config loading, native Burp issue publication, real scan coverage metadata, CSRF header-suppression correctness, string-surface upload runtime probes, multipart upload execution with nested-target and oversize probing, passive request capture with recent-history tracking, richer Burp request/response editor integration, and stronger request-fidelity carry-forward for batch and multipart traffic. The Python CLI still remains the standalone source of truth. Reaching full feature parity with the CLI would still require additional work across fuller multipart replay/import handling, deeper auth workflows, richer UI, and tighter Burp-native integrations.

The standalone tool remains valuable for automation and CI/CD, while the Burp extension would serve users who prefer integrated workflows.
