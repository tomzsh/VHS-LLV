# GraphQL integration for VHS

This is the local VHS integration point for GraphQL-specific assessment work.
It connects the existing `references/attack-playbooks/graphql.md` methodology to
GraphQL Cop without changing the upstream repository or installing a global
Python package.

## Installed tool

- Tool: GraphQL Cop
- Source: `https://github.com/dolevf/graphql-cop`
- Local source: `~/tools/graphql-cop`
- Isolated interpreter: `~/tools/graphql-cop/venv/bin/python`
- Launcher: `scripts/graphql_cop.sh`
- Version verified locally: `1.15`
- Override root: `VHS_GRAPHQL_COP_HOME`

The venv installs the tool's runtime dependencies in isolation. `PYTHONPATH` is
cleared by the launcher so a target run cannot accidentally import packages from
the Hermes process or the system interpreter.

## Readiness check

```bash
python3 scripts/check_tools.py --profile active-safe --verify --json \
  | jq '.agents.graphql, .verification["graphql-cop"]'
```

`graphql-cop` is optional. A missing install must never make the general VHS
recon pipeline fail; `check_tools.py` reports it as unavailable instead.

## Explicit execution only

GraphQL Cop is not wired into the default orchestrator DAG. It sends active
requests, including checks for introspection, batching, aliases, field
duplication, directives, and depth-related behavior. Run it only against an
endpoint that is already authorized, in scope, and covered by the engagement's
allowed methods.

```bash
umask 077
bash scripts/graphql_cop.sh \
  --engagement ./engagement \
  -t 'https://api.example.com/graphql' \
  -o json \
  > ./engagement/graphql-cop.json
```

For an approved test identity, pass headers as separate `-H` arguments. Do not
put long-lived credentials in the command history; use a short-lived token and
redact it before preserving evidence.

```bash
bash scripts/graphql_cop.sh \
  --engagement ./engagement \
  -t 'https://api.example.com/graphql' \
  -H '{"Authorization":"Bearer REDACTED"}' \
  -o json \
  > ./engagement/graphql-cop-authenticated.json
```

The output is scanner evidence/hypothesis input, not a confirmed finding. Map
interesting results into `hypothesis-ledger.csv`, then validate with baseline,
mutation, negative-control, and cleanup steps in P4.

## Integration contract

1. `--engagement` is mandatory; the launcher enforces P0, the testing window,
   permission mode, and `ScopePolicy` before starting GraphQL Cop.
2. The endpoint must be an explicitly supplied URL, not an unfiltered crawler
   candidate.
3. The GraphQL playbook citation belongs in the P3 test matrix, for example:
   `notes="playbook: graphql"`.
4. GraphQL Cop output is stored under the engagement directory and reviewed
   before it enters the evidence ledger.
5. Credentials and raw sensitive responses are never committed or copied into
   the VHS skill directory.

This integration complements the `api-security-testing` skill's GraphQL
methodology; it does not replace that skill's authorization, evidence, or
severity guidance.
