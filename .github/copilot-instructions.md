# Project Guidelines

## Build and Test

- Build (debug): `cargo build`
- Build (release): `cargo build --release`
- Run tests: `cargo test`
- Lint: `cargo clippy`
- Format: `cargo fmt`
- Run TUI mode (default): `cargo run`
- Run CLI mode: `cargo run -- --cli`

## Architecture

- Command implementations are organized by module under `src/` (for example: `cat.rs`, `grep.rs`, `chmod.rs`).
- The async pipeline abstraction is in `src/pipeline.rs`.
- App entrypoint and command dispatch live in `src/main.rs`.
- Public module exports are in `src/lib.rs`.
- Windows-specific behavior is guarded with `#[cfg(windows)]` or `#[cfg(target_os = "windows")]`.

## Conventions

- Keep new command logic in a dedicated `src/<command>.rs` module.
- If adding a reusable command module, export it from `src/lib.rs` and wire CLI/TUI routing in `src/main.rs` as needed.
- Prefer `io::Result`-based error propagation in command and pipeline code.
- For Windows FFI work, keep `unsafe` blocks tightly scoped and ensure handles/resources are cleaned up reliably.
- When adding platform-specific features or tests, guard them with `#[cfg(...)]` so non-Windows environments do not break.

## Key References

- Project overview and command scope: `README.md`
- Contribution and PR expectations: `CONTRIBUTION.md`
- Windows internals and FFI guidance: `WINDOWS_INTERNALS.md`

## Agent Behavior in This Repo

- Make focused, minimal edits that preserve existing patterns and module structure.
- Do not introduce broad refactors unless explicitly requested.
- Run relevant checks for touched code (`cargo test`, and `cargo clippy` when practical).
- When behavior is already documented in repo docs, link to that doc instead of duplicating large sections.
- ALways start in Plan Mode, and only execute when you have a clear, actionable plan.
- Always ask questions if you are unsure about the intent of a change or how to implement it, if you have doubts, strraight away ask for clarification, do not make assumptions.
- Always update the memory with new information you learn about the project, and refer to that memory when making decisions.
