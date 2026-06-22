Build both HellForge crates in release mode and verify the binaries land in the right place.

Steps:
1. Run `cargo build --release` in `/Users/leog/HellForge/hellforge-build` to produce `hfbuild`.
2. Run `cargo build --release` in `/Users/leog/HellForge/hellforge-gui` to produce the `hellforge` GUI binary.
3. The GUI expects `hfbuild` to sit next to it at runtime (`std::env::current_exe().parent().join("hfbuild")`). After both builds succeed, report the paths of both release binaries so the user knows where they are.
4. If either build fails, show the relevant compiler errors and stop — do not attempt to copy or run anything.
