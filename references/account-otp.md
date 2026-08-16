# AgentMail account registration and OTP capture

Load this reference only when an engagement needs a test email for signup OTP or
verification-link capture. Use AgentMail, not a real human mailbox.

**Resource guard:** free tier = 3 inboxes / 3,000 emails per month across the
organization. Treat it as a budget, not a pool:

- Create one inbox per target (`agentmail alias add <target> <inbox_id>`), never
  one per attempt. Reuse it across the engagement.
- Poll with `agentmail watch <alias> --interval 5 --output <run>/otp.jsonl`
  (continuous) or `agentmail otp <alias> --from <sender>` (one-shot). Polling
  is a GET; sending mail consumes the monthly quota.
- Only send mail when the target flow requires it. Prefer passing the inbox to
  the target so the target sends the OTP.
- Delete the inbox at engagement end: `agentmail delete <inbox>`.
- Do not auto-provision during P2 recon. Account scope and RoE still require
  explicit engagement approval.

Full CLI, OTP extraction, watch/exec triggers, and pitfalls live in the
`agentmail` skill. Every OTP read belongs under the engagement evidence ledger;
never store it in global memory or in the VHS skill tree.
