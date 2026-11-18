# Security notes

- Analysis is local and does not execute extension code.
- A low score is not a safety verdict; code can be harmful without broad
  permissions, and a high score can support a legitimate feature.
- Manifest semantics differ across browsers and versions. Verify conclusions
  against current browser documentation before making a deployment decision.
- Do not paste proprietary manifests unless authorized.
