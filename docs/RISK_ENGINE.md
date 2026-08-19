# Risk Engine

The Risk Engine is deterministic and runs in `backend/risk/engine.py`. The LLM never decides priority. Each finding receives a score from 0 to 100 based on:

- severity base;
- internet exposure;
- asset criticality;
- confidence;
- CVE/exploitability signal;
- age and recurrence.

The factors are stored in `findings.risk_factors` so the UI and Iron AI can explain the result. Organization score is an aggregate posture indicator, not a claim that the company is absolutely secure. Snapshots are created through `POST /api/security/snapshot` and queried through `GET /api/security/trend`.
