# 🔍 Nimbus Guard: Pull Request

## Summary
<!-- Briefly describe what this PR changes or fixes -->

## Checklist
- [ ] Code builds locally (`python -m scanner.runner`)
- [ ] Docker image builds (`docker build -t nimbus-guard:latest .`)
- [ ] Terraform validates (`terraform validate`)
- [ ] CI passes via OIDC (Nimbus Guard scan runs automatically)

## CI Scan
- Nimbus Guard runs automatically in **GitHub Actions**.
- Reports generated:
  - `nimbus-guard-report.md`
  - `nimbus-guard-report.html`
  - `nimbus-guard-report.json`
- Build **fails on HIGH/CRITICAL findings** (exit ≠ 0).

📎 **Artifacts:** View in the Actions run → Artifacts → `nimbus-guard-report.*`

## Reviewer Notes
- [ ] Verified scan artifacts attached
- [ ] Reviewed severity gate results
- [ ] Reviewed code + Terraform changes

