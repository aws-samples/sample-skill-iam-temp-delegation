# Domain Reference Documents

These are the domain skill docs that provide context for the reviewer analysis (Stage 3). Load them based on the bundle's content:

- `docs/domain-general.md` — General delegation review (always load)
- `docs/domain-delegation-system.md` — Delegation platform execution model and threat model (always load)
- `docs/domain-ec2-tag.md` — EC2 tag-based access (when ec2: actions present)
- `docs/domain-billing-transfer.md` — Organizations billing (when organizations: actions present)
- `docs/domain-principaltag-boundary.md` — PrincipalTag boundaries (when a boundary is present in the bundle)

Additional procedural guides:

- `docs/procedure-reviewer.md` — Detection patterns and constraints for Stage 3 analysis
- `docs/procedure-verifier.md` — Verification procedure for Stage 4 falsification

Submission workflow (load only when user asks to package/submit):

- `references/procedure-submit.md` — Disposition tracking and submission packaging workflow. Do NOT load during reviews.

Fix workflow (load when user asks to fix/address findings):

- `references/procedure-fix.md` — Guidance for editing policies in the registry after review. Load when user asks to fix or address findings.

All docs are within this skill package under `docs/` and `references/`.
