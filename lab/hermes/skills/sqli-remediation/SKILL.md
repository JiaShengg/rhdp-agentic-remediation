# SQL injection remediation

When a finding is SQL injection, change the query without changing what the program does.

- Keep the original behaviour and the original inputs.
- Move user input out of the SQL string into `?` placeholders on a PreparedStatement or CallableStatement.
- Bind each former input with the matching setter (`setString`, `setObject`, or the setter for that type).
- Do not delete inputs, hardcode values, or comment out code to make a finding disappear.
- If a safe fix is not clear, record the finding as NEEDS_DEVELOPER instead of guessing.

Before committing a fix, show `git diff` and check it against these rules:

- The SQL text is unchanged except for value placeholders.
- Every former user input is still used and bound to a placeholder.
- No placeholder replaces a procedure, table, or column name.
- No new hardcoded literals.
- No code is deleted or commented out to remove the finding.

If any rule fails, revise the fix once. If the revision still fails, record NEEDS_DEVELOPER and do not commit.
