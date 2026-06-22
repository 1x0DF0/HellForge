Add a new msfvenom payload string to the PAYLOAD_TYPES list in src/types.rs.

The user will provide the payload string as an argument (e.g. `windows/x64/shell_bind_tcp`).
If no argument is given, ask the user for the full msfvenom payload string before proceeding.

Steps:
1. Read `src/types.rs` and locate the `PAYLOAD_TYPES` constant.
2. Check that the payload string is not already in the list. If it is, tell the user and stop.
3. Append the new entry inside the `&[...]` block, maintaining the existing formatting (one string per line, trailing comma).
4. If the payload contains "bind" or "reverse" it will automatically work with the `needs_conn` gate — no other changes needed. If it doesn't match either pattern and requires connection options, flag that to the user.
5. Confirm the edit was applied and show the updated list.
