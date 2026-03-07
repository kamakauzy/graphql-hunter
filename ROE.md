# Rules of Engagement

1. Preserve the existing Python CLI and library behavior unless a change is strictly required for compatibility.
2. Implement the Burp Suite Professional extension as an additive module under `burp-extension/`.
3. Prefer safe-by-default scanning behavior inside Burp; never enable noisy or destructive checks automatically.
4. Keep secrets and environment-specific values out of source control and persisted state where possible.
5. Maintain reproducible builds for the Burp extension and verify that the native `.jar` can be built locally.
6. Update existing project documentation when user-visible behavior or build/install steps change.
7. Keep changes reviewable: use small commits, avoid force pushes, and preserve backwards compatibility for the current Python workflow.
