# Aegis Agent Guardrails

- Treat release status as **NOT SEALED** unless `python scripts/verify.py verify` succeeds with
  every required gate passing.
- Fail closed on gate ambiguity: missing/malformed coverage evidence, failure markers in gate output,
  or non-zero exits must block release claims.
- Do not claim authentication, PKI signatures, cryptographic non-repudiation, durable persistence,
  ROS/runtime execution safety, or hardware safety unless explicitly implemented and tested.
