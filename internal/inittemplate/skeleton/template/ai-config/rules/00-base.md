# How to develop THIS template

The rules below are addressed to the AI assistant and the person who develops the TEMPLATE itself
(this repository), not a project generated from it.

## Conditions and setting groups

- Express a new behavior option as a setting group in `template.manifest.yaml`,
  NOT hardcoded. Types: `toggle`, `select`, `multiselect`, `string`, `int`.
- In `files/` templates branch via helpers: `{{ if is "variant" "advanced" }}`
  (select/toggle/string/int) and `{{ if has "brokers" "kafka" }}` (multiselect).
- Fine-grained inclusions — via conditional path segments `__if_<group>__` /
  `__if_<group>=<value>__` or in-file markers `tplater:if` /
  `tplater:begin`…`tplater:end`.
- Put choice-dependent refinement in nested `options[].settings` —
  this way it is asked/active only with the selected option.

## Files globs when adding a vertical

- Connect a new vertical's directory via a `files` rule: `paths` — "include when
  true", `remove` — "delete when true". Condition — exactly one of `when`/`anyOf`.
- Keep the `files/` tree renderable in ALL combinations: any `{{ … }}` must
  parse independently of setting values (a branch may be inactive but
  syntactically valid).

## Tests and publishing

- Before publishing run `tplaiter lint-template` — it renders all edge-case
  setting combinations and checks NOTES, generators, ai-config, and playbooks.
- Version with tags (SemVer): `git tag v0.1.0`. For multi-repo the tag is
  `<template-name>/vX.Y.Z`.
- ai-config: new module — file `modules/NN-*.json` + `rules/NN-*.md` +
  `docs/NN-*.md`; module gating is set by the `when` field in terms of setting groups.
