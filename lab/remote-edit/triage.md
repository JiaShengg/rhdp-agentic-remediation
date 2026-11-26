# Triage

When deciding whether a finding is a true or false positive:

- Cite the file and line numbers that support the decision.
- State where the input comes from and whether it reaches the sink unchanged.
- When a branch depends on a constant expression, evaluate it explicitly, show the result, and follow only the branch that runs.
- Only change code when the finding is a true positive.
- If the evidence does not support either decision, record NEEDS_DEVELOPER.
- Call record_decision with the decision and the reason.
