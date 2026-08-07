# Module — Cloud, AI & Supply Chain

Use only for authorized accounts, projects, repositories, tenants, and resources. A discovered vendor or open bucket name is not permission to interact.

## Cloud and SaaS trust boundaries

Map:

- account, organization, project, subscription, region, and environment;
- identities, roles, service accounts, workload identities, and trust policies;
- public/private endpoints, gateways, load balancers, and serverless functions;
- object stores, databases, queues, caches, registries, and secret stores;
- control plane versus data plane;
- tenant management, support, billing, audit, and break-glass paths.

Create hypotheses for:

- public access inconsistent with intended policy;
- cross-account or cross-tenant trust;
- confused-deputy conditions;
- overly broad workload permissions;
- user-controlled resource identifiers or callback destinations;
- stale, orphaned, or environment-crossing resources.

Do not use discovered credentials or query unrelated resources.

## Secrets and configuration

Review approved sources for:

- hard-coded or generated secrets;
- secrets in build artifacts, source maps, logs, examples, tickets, and caches;
- environment separation;
- secret rotation and revocation;
- public identifiers misclassified as secrets;
- signing material and credential propagation.

For an exposed secret, do not authenticate with it unless explicit validation permission exists. Prefer format, location, scope metadata, revocation status from the owner, and hash correlation.

## CI/CD and software supply chain

Model:

- fork and pull-request trust;
- workflow triggers and token permissions;
- artifact, cache, package, and release provenance;
- protected branches, environments, approvals, and deploy identities;
- mutable tags, dependency confusion, typosquatting, install scripts;
- build-time versus runtime secrets;
- self-hosted runners and untrusted input;
- SBOM, signature, attestation, and rollback.

Use local or sandbox reproduction. Do not publish malicious packages, poison shared caches, or trigger unauthorized deployments.

## Observability and operations

Check authorized surfaces for:

- dashboards, metrics, traces, logs, profiling, health, debug, and admin endpoints;
- log injection or misleading structured fields;
- sensitive request/response capture;
- query authorization and tenant filters;
- alert, webhook, and incident-action permissions.

Do not inject high-volume logs or access unrelated tenant telemetry.

## AI, LLM, RAG, and agents

Map:

- system/developer/user prompts and precedence;
- retrieval sources, tenant filters, chunk metadata, and indexing;
- memory scope, retention, deletion, and cross-session isolation;
- tools, connectors, credentials, approval gates, and action authority;
- model output sinks such as HTML, SQL, shell, email, ticket, or transaction;
- model/provider boundaries, training use, logging, and redaction;
- file, image, URL, and multimodal ingestion;
- autonomous loops, budgets, retries, and stop controls.

Test invariants such as:

- untrusted content cannot override higher-priority policy;
- retrieved content remains tenant-bound;
- model text is never treated as authorization;
- every tool call is re-authorized against the requesting user and current context;
- high-impact actions require explicit confirmation;
- secrets are not exposed through prompt, memory, retrieval, logs, or tool output;
- output is contextually encoded before reaching an execution sink.

Use synthetic documents and researcher-owned tenants. Do not send sensitive production data to external models or attempt real-world harmful actions.

## AI-specific evidence

Record:

- model and version when known;
- system configuration relevant to the behavior;
- sampling parameters and number of trials;
- exact synthetic input;
- tool and retrieval context;
- success rate and negative controls;
- whether the behavior was model nondeterminism, deterministic policy failure, or unsafe downstream execution.

One surprising model response is not automatically a security finding. Tie it to a violated boundary and reproducible impact.
