# SQL injection remediation

When a finding is SQL injection, keep the same SQL statement and bind the tainted input.

- Keep the original SQL text, the same table, the same columns, and every literal that was not user input.
- Replace only the concatenated user input with a `?` placeholder. The `?` is the SQL placeholder. Do not put it inside quotes.
- Run that same statement through `prepareStatement` and bind each tainted input with `setString`, or the setter for its type.
- Do not add an allowlist, a denylist, or escaping.
- Do not add a stored procedure, `prepareCall`, or `CallableStatement` unless that call is already in the code.
- Do not switch the call to a different data API.
- Do not delete inputs, hardcode the tainted value, or comment out code to make a finding disappear.

When asked for fix options, every option is a `PreparedStatement` binding on that same SQL statement. The trade-off is how the connection is obtained or how the statement is closed. It is not a different control.

When asked to apply an option, apply a `PreparedStatement` binding on that same SQL statement. Send the change only through `apply_patch`.

- If `apply_patch` returns status `applied`, the compile passed and the finding is no longer present. Only then tell the developer the fix is applied.
- If `apply_patch` returns status `rejected`, the workspace file was restored. Do not say a fix was applied. Read `failed_checks` and try one new patch that addresses those check names.
- If that second `apply_patch` is also `rejected`, stop. Hand the finding back to the developer with those failed checks and the reason. Do not try a third patch.
- Never tell the developer a fix is applied unless `apply_patch` returned status `applied`.
