# Azure AI Content Safety Tester

> **DISCLAIMER**: This repository contains sample test data that includes **hateful, violent, sexually explicit, self-harm, and other sensitive content** for the sole purpose of testing Azure AI Content Safety services. This content is used exclusively to validate the detection capabilities of safety APIs and does not reflect the views or values of the authors. Handle with care and ensure compliance with your organization's policies.

A comprehensive toolkit for testing and demonstrating [Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/) capabilities, including harmful content detection, jailbreak/prompt injection shields, PII redaction, custom blocklists, and protected material detection.

---

## Project Structure

```
AzureContentSafety/
├── app/
│   ├── app_streamlit.py       # Interactive Streamlit UI for testing evaluators
│   ├── sample_test_cases.jsonl # Pre-built test scenarios (includes sensitive content)
│   └── .streamlit/
│       └── config.toml        # Streamlit theme configuration
├── src/
│   └── azure_content_safety/
│       ├── __init__.py
│       └── guards.py          # Reusable safety helpers and pipeline logic
├── notebooks/
│   └── demo_pipeline.ipynb    # End-to-end notebook demonstration
├── requirements.txt           # Python dependencies
└── .env.example               # Environment variable template
```

---

## Features

| Evaluator | Description | API |
|-----------|-------------|-----|
| **Harmful Content** | Detects Violence, Hate, Sexual, Self-Harm with severity scores (0-6) | Content Safety `text:analyze` |
| **Jailbreak Detection** | Prompt Shields for user attacks and document exploits | Content Safety `text:shieldPrompt` |
| **PII Redaction** | 100+ entity types with synthetic replacement, masking, or entity labels | Azure AI Language PII |
| **Custom Blocklists** | Exact match and regex patterns for business-specific terms | Content Safety Blocklists |
| **Protected Material** | Detects copyrighted lyrics, news, recipes, code with citations | Content Safety `text:detectProtectedMaterial` |
| **Unified Pipeline** | Runs all checks in sequence with aggregated results | Custom orchestration |

---

## Prerequisites

- **Python 3.10+** recommended
- **Azure Resources**:
  - [Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/overview)
  - [Azure AI Language](https://learn.microsoft.com/en-us/azure/ai-services/language-service/overview) (for PII)
  - [Azure OpenAI](https://learn.microsoft.com/en-us/azure/ai-services/openai/overview) (optional, for LLM integration demos)

---

## Configuration

Create a `.env` file in the repo root (see `.env.example`):

### Required
```env
MSFT_FOUNDRY_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com
AZURE_OPENAI_ENDPOINT=https://<your-aoai>.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-10-21
```

### Optional (for separate endpoints or API key auth)
```env
CONTENT_SAFETY_ENDPOINT=https://<separate-cs>.cognitiveservices.azure.com
CONTENT_SAFETY_KEY=<your-key>
LANGUAGE_ENDPOINT=https://<separate-lang>.cognitiveservices.azure.com
LANGUAGE_KEY=<your-key>
AZURE_OPENAI_KEY=<your-key>
```

### Tuning
```env
CONTENT_SAFETY_API_VERSION=2024-09-01
SAFETY_SEVERITY_THRESHOLD=2
```

> **Note**: The app prefers **Entra ID authentication** via `DefaultAzureCredential`. API keys are used as fallback only.

---

## Quick Start

### Option 1: PowerShell (Windows)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
python -m streamlit run .\app\app_streamlit.py
```

### Option 2: Bash (Linux/macOS)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
python -m streamlit run app/app_streamlit.py
```

> **Tip**: Use `python -m streamlit ...` to avoid PATH issues with user-installed packages.

---

## Notebook Demo

The `notebooks/demo_pipeline.ipynb` provides an end-to-end walkthrough of all safety evaluators with code examples and inline results.

```powershell
# Launch Jupyter
jupyter notebook notebooks/demo_pipeline.ipynb
```

---

## Test Cases

The `app/sample_test_cases.jsonl` file contains pre-built test scenarios covering:
- Clean baseline text
- Jailbreak attempts (DAN, developer override, ignore instructions)
- PII samples (SSN, credit cards, emails, addresses)
- Harmful content (violence, hate, self-harm, sexual)
- Blocklist triggers (credentials, internal terms)
- Protected material (song lyrics, source code)

Load these from the Streamlit sidebar dropdown for quick testing.

---

## Related Documentation

- [Azure AI Content Safety Overview](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/overview)
- [Prompt Shields Concepts](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
- [Protected Material Detection](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/protected-material)
- [PII Detection with Azure AI Language](https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/overview)
- [Custom Blocklists](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/how-to/use-blocklist)

---

## Azure AI Content Safety Capabilities Overview

This section provides a detailed overview of Azure AI Content Safety capabilities, useful for comparison with other platforms (e.g., Google Model Armor).

### Core Moderation Capabilities
| Capability | Description |
|------------|-------------|
| **Text Moderation** | Detects harmful text across multiple categories |
| **Image Moderation** | Detects harmful images (not covered in this demo) |
| **Multimodal** | Handles text + image combinations (e.g., memes) |

### Harm Categories & Severity
- **Standard Categories**: Hate, Violence, Self-harm, Sexual
- **Severity Levels**: 0 (Safe) → 2 (Low) → 4 (Medium) → 6 (High)
- **Configurable Thresholds**: Per-category sensitivity tuning

### Advanced AI Safety
| Feature | Description |
|---------|-------------|
| **Jailbreak / Prompt Injection** | Detects attempts to bypass rules (DAN, indirect attacks, document exploits) |
| **Groundedness Detection** | Detects factually unsupported or hallucinated content |
| **Protected Material** | Detects copyrighted text (lyrics, news, recipes) and code with source citations |

### PII / Data Loss Prevention
Azure uses **AI Language service** (NLP/ML-based) for PII detection:
- **100+ entity types**: SSN, credit cards, emails, Azure secrets, medical records, etc.
- **Context-aware**: Understands "John" in names vs. emails vs. addresses
- **4 redaction modes**:
  - `SyntheticReplacement` – Replaces with realistic fake data
  - `CharacterMask` – Replaces with `*****`
  - `EntityMask` – Replaces with `[PERSON]`, `[EMAIL]`, etc.
  - `NoMask` – Detects but doesn't redact
- **Confidence thresholds** and **domain filtering** (e.g., PHI-only mode)

> **Note**: Azure Content Safety regex blocklists are for *content moderation*, NOT PII detection. Use Azure AI Language for PII.

### Custom Blocklists
- **Pattern Types**: Exact match and regex patterns
- **Capacity**: Up to 10,000 terms per blocklist
- **Regex Support**: Via `isRegex` property (128-1000 char limit per item)
- **Use Cases**: Obfuscated words, leetspeak, internal terminology, credential patterns

### Custom Categories (Not in this demo)
- Train custom classifiers with your own labeled examples
- Useful for business-specific topics not covered by standard categories

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Important Notes

- **Sensitive Test Data**: The sample test cases intentionally contain harmful content for API validation. Do not use in production without review.
- **Authentication**: Entra ID (`DefaultAzureCredential`) is recommended over API keys for security.
- **Blocklist Seeding**: Uses Content Safety GA API (`2024-09-01`) with regex support via `isRegex`.
- **Protected Material**: Uses GA API (`2024-09-01`) for text; Code detection requires preview API (`2024-09-15-preview`).


