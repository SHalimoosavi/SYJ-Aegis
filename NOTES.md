
## Phase 3 Detection Heuristics

AI-Firewall is intentionally conservative. It uses Python `ast` within each file/function and does not perform cross-function or cross-file taint tracking. Findings describe observable static patterns, not proven runtime behavior.

### Prompt security
- Hardcoded prompt secrets: inspect string literals assigned to variables whose names contain `prompt`, `instruction`, or `system`. The existing Phase 1 `secrets.RULES` patterns are applied to the literal value; placeholder values are ignored using the same placeholder logic. Evidence points to the assignment line.
- LLM-call recognition: the Phase 3 list recognizes concrete call-name patterns such as `client.responses.create`, `client.chat.completions.create`, `client.completions.create`, `openai.ChatCompletion.create`, `anthropic.messages.create`, `llm.invoke`, `llm.predict`, and `model.generate_content`, plus documented method suffixes for chat/completion/response/message creation. This is pattern recognition, not a claim of complete framework support.
- Prompt-injection exposure: within one function, an LLM prompt-like argument is considered exposed when it is an f-string, string concatenation, direct variable, or simple container expression containing a function parameter or a `request.*` / `req.*` attribute. Evidence records the input origin and LLM call site in the finding description. Cross-function propagation is not attempted. Severity is `HIGH`; confidence is `MEDIUM`.

### Data exposure
- PII literals are limited to regex matches for email addresses and phone-number-like strings.
- PII variables use a documented naming heuristic covering names such as `email`, `phone`, `ssn`, `customer_id`, `client_id`, `user_id`, `address`, `postal_code`, and related variants.
- A finding is emitted only when the PII-like literal/variable is passed directly as an argument in the same function to a recognized logging call (`logging.*`, `logger.*`, or `log.*`), recognized LLM call, or recognized network call from the Phase 2 network patterns.
- Confidence is `LOW` for PII literal matches and `MEDIUM` for PII-looking variable names. The heuristic does not claim that every matching value is personal data.

### RAG security
- Vector-store usage is detected from import statements whose top-level package is one of: `chromadb`, `pinecone`, `weaviate`, `qdrant`, `faiss`, `pgvector`, or `milvus`. Aegis does not import or install these packages.
- Retrieval call names are limited to `similarity_search`, `query`, `retrieve`, and `get_relevant_documents`.
- In a function containing a retrieval call, authorization/tenant/filter-looking evidence is considered present when names, attributes, or string literals contain tokens such as `auth`, `tenant`, `permission`, `access`, `acl`, `filter`, `user_id`, `customer_id`, `org_id`, `organization_id`, or `role`.
- If no such indicator is visible in that same function, the finding says exactly: `Access filtering: UNCLEAR. Potential risk: Retrieved content may cross authorization boundaries.` Severity is `HIGH`, confidence is `LOW`, and the issue is review-oriented rather than a claim that isolation is broken.

### Output security
- Dangerous sinks are limited to `subprocess.*`, `os.system`, `os.popen`, `eval`, `exec`, `cursor-like .execute(...)` when the SQL argument is an f-string or `.format(...)` expression, and `open(..., "w"/"a"/"x"/"+")`.
- An LLM output is identified only when a recognized LLM call is directly assigned to a local variable in the same function.
- If that variable is then passed directly, or through an f-string/concatenation/container expression, to a dangerous sink in the same function, emit `AEGIS-AI-017` with `CRITICAL` severity and `MEDIUM` confidence. The finding is a `REVIEW REQUIRED` style warning and does not claim the sink will definitely execute harmful behavior.
