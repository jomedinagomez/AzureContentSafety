## Azure AI Content Safety tester

This repo contains:
- `notebooks/demo_pipeline.ipynb`: the original end-to-end notebook demo.
- `src/azure_content_safety/guards.py`: reusable safety helpers (blocklists, moderation, PII, Prompt Shields, pipeline).
- `app_streamlit.py`: a small Streamlit app to test each function.

## Prerequisites

- Python 3.10+ recommended
- Azure resources:
	- Azure AI Content Safety
	- Azure AI Language
	- Azure OpenAI

## Configure environment

Create a `.env` file in the repo root (or set environment variables another way):

Required:
- `MSFT_FOUNDRY_ENDPOINT` (shared Azure AI Services endpoint for Content Safety + Language)
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_DEPLOYMENT`
- `AZURE_OPENAI_API_VERSION`

Optional (only needed if you are not using Entra ID auth via `DefaultAzureCredential`):
- `CONTENT_SAFETY_ENDPOINT` / `LANGUAGE_ENDPOINT` (only if they live on different regions; otherwise inherit `MSFT_FOUNDRY_ENDPOINT`)
- `CONTENT_SAFETY_KEY`
- `LANGUAGE_KEY`
- `AZURE_OPENAI_KEY`

Optional knobs:
- `CONTENT_SAFETY_API_VERSION` (defaults to `2024-09-01`)
- `SAFETY_SEVERITY_THRESHOLD` (defaults to `2`)

## Run (PowerShell)

From the repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
python -m streamlit run .\app_streamlit.py
```

If you installed packages with `--user` (common on locked-down machines), PowerShell may not find the `streamlit` executable.
Using `python -m streamlit ...` avoids needing to add the user Scripts directory to `PATH`.

## Notes

- The app prefers Entra ID via `DefaultAzureCredential`. If that fails, it falls back to API keys.
- Blocklist seeding uses the Content Safety GA blocklist REST API version `2024-09-01` and supports regex items via `isRegex`.
