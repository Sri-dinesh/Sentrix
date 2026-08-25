# Sentrix

*Self-learning network intrusion detection with autonomous, confidence-calibrated threat containment.*

Sentrix fuses three independent signal families — anomaly detection scores (PyTorch Autoencoder), supervised classifier confidence margins (XGBoost), and statistical concept drift indicators (PSI / KS tests) — into a single calibrated trust score. That calibrated score drives tiered, autonomous containment decisions (Mininet / Open vSwitch / Ryu SDN) with automated LLM-generated incident playbooks (Ollama) and a safety-gated model adaptation loop.

## Architecture

- **Frontend**: Next.js (App Router), Tailwind CSS v4 (`@theme`), shadcn/ui, TanStack Query, Zustand, Clerk.
- **Backend API**: FastAPI (Python 3.11+), SQLAlchemy, Alembic, Clerk JWKS Token Verification.
- **Database & Storage**: Supabase (Postgres & Object Storage for model checkpoints).
- **Task Queue & Cache**: Redis & Celery (playbook generation & model retraining).
- **ML & Analytics**: PyTorch (Autoencoder), XGBoost (Classifier), Scikit-Learn (Scaling & Drift metrics).
- **SDN Simulation**: Mininet, Open vSwitch, Ryu OpenFlow Controller.
- **Local LLM**: Ollama (`llama3.1:8b` / `mistral`).
