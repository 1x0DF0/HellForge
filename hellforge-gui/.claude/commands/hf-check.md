Run a fast compile check and clippy lint pass across both HellForge crates without producing release binaries.

Steps:
1. Run `cargo check` in `/Users/leog/HellForge/hellforge-build` and capture any errors.
2. Run `cargo check` in `/Users/leog/HellForge/hellforge-gui` and capture any errors.
3. Run `cargo clippy -- -D warnings` in both crates (same order).
4. Summarize: report which crates are clean and list any errors or warnings that need attention. Keep the summary short — one line per finding is enough.
