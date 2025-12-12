import os
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import requests
from azure.ai.contentsafety import BlocklistClient, ContentSafetyClient
from azure.ai.contentsafety.models import AnalyzeTextOptions, TextCategory
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential, TokenCredential
from azure.identity import DefaultAzureCredential
from openai import AzureOpenAI


CONTENT_SAFETY_GA_BLOCKLIST_API_VERSION = "2024-09-01"


@dataclass(frozen=True)
class Settings:
    content_safety_endpoint: str
    content_safety_key: Optional[str]
    content_safety_api_version: str

    language_endpoint: str
    language_key: Optional[str]

    azure_openai_endpoint: str
    azure_openai_key: Optional[str]
    azure_openai_deployment: str
    azure_openai_api_version: str

    safety_severity_threshold: int

    blocklist_names: List[str]
    blocklist_seed_exact: List[str]
    blocklist_seed_regex: List[str]

    pii_categories_to_redact: List[str]


def load_settings(*, env: Optional[Dict[str, str]] = None) -> Settings:
    env = env or os.environ

    msft_foundry_endpoint = (env.get("MSFT_FOUNDRY_ENDPOINT") or "").strip()

    content_safety_endpoint = (env.get("CONTENT_SAFETY_ENDPOINT") or msft_foundry_endpoint).strip()
    if not content_safety_endpoint:
        raise RuntimeError("CONTENT_SAFETY_ENDPOINT or MSFT_FOUNDRY_ENDPOINT is required")

    language_endpoint = (env.get("LANGUAGE_ENDPOINT") or msft_foundry_endpoint).strip()
    if not language_endpoint:
        raise RuntimeError("LANGUAGE_ENDPOINT or MSFT_FOUNDRY_ENDPOINT is required")

    azure_openai_endpoint = (env.get("AZURE_OPENAI_ENDPOINT") or "").strip()
    if not azure_openai_endpoint:
        raise RuntimeError("AZURE_OPENAI_ENDPOINT is required")

    azure_openai_deployment = (env.get("AZURE_OPENAI_DEPLOYMENT") or "").strip()
    if not azure_openai_deployment:
        raise RuntimeError("AZURE_OPENAI_DEPLOYMENT is required")

    azure_openai_api_version = (env.get("AZURE_OPENAI_API_VERSION") or "").strip()
    if not azure_openai_api_version:
        raise RuntimeError("AZURE_OPENAI_API_VERSION is required")

    content_safety_api_version = (env.get("CONTENT_SAFETY_API_VERSION") or "2024-09-01").strip()

    safety_severity_threshold = int((env.get("SAFETY_SEVERITY_THRESHOLD") or "2").strip())

    blocklist_names = [
        name.strip()
        for name in (env.get("BLOCKLIST_NAMES") or "demo-blocklist-a,demo-blocklist-b").split(",")
        if name.strip()
    ]

    # Enhanced blocklist with more comprehensive examples
    default_exact_items = (
        "secret_project_x,internal_use_only,confidential_data,"
        "classified_info,restricted_access,do_not_share,proprietary_code,"
        "admin_credentials,root_password,master_key,nuclear_codes"
    )
    blocklist_seed_exact = [
        s.strip()
        for s in (env.get("BLOCKLIST_SEED_EXACT") or default_exact_items).split(",")
        if s.strip()
    ]

    # Allow regex list via JSON array (preferred) or comma-separated.
    raw_regex = (env.get("BLOCKLIST_SEED_REGEX") or "").strip()
    if raw_regex.startswith("["):
        blocklist_seed_regex = [str(x) for x in json.loads(raw_regex)]
    elif raw_regex:
        blocklist_seed_regex = [s.strip() for s in raw_regex.split(",") if s.strip()]
    else:
        # Regex patterns for Azure Content Safety blocklist
        # Azure uses RE2-like regex which doesn't support backtracking
        # Avoid: nested quantifiers, backreferences, lookaheads/lookbehinds
        # Use: character classes, simple quantifiers, alternation
        blocklist_seed_regex = [
            r"p[a@]ssw[o0]rd[ \t]*[=:][ \t]*[A-Za-z0-9!@#$%^&*]{8,}",
            r"[a@]pi[_-]?key[ \t]*[=:][ \t]*[A-Za-z0-9_-]{12,}",
            r"s[e3]cret[_-]?key[ \t]*[=:][ \t]*[A-Za-z0-9_-]{12,}",
            r"[a@]uth[_-]?token[ \t]*[=:][ \t]*[A-Za-z0-9_-]{16,}",
            r"[a@]ccess[_-]?t[o0]ken[ \t]*[=:][ \t]*[A-Za-z0-9_-]{16,}",
            r"connection[_-]?string[ \t]*[=:][ \t]*Server=[A-Za-z0-9.-]+;Database=[A-Za-z0-9_-]+;User=[A-Za-z0-9_-]+;Password=[A-Za-z0-9!@#$%^&*]{6,}",
            r"[Pp]rivate[_-]?key[ \t]*[=:][ \t]*[A-Za-z0-9_-]{16,}",
            r"[Ss]sh[_-]?key[ \t]*[=:][ \t]*[A-Za-z0-9_-]{16,}",
            r"[Bb]earer[ \t]+[A-Za-z0-9._=-]{20,}",
            r"aws[_-]?key[ \t]*[=:][ \t]*[A-Za-z0-9_-]{16,}",
        ]

    # All PII categories - comprehensive list from Azure AI Language
    # If you want to redact ALL PII, leave this list empty or set to []
    # For selective redaction, specify only the sensitive categories
    pii_categories_to_redact = []  # Empty list = redact ALL detected PII entities

    return Settings(
        content_safety_endpoint=content_safety_endpoint,
        content_safety_key=(env.get("CONTENT_SAFETY_KEY") or None),
        content_safety_api_version=content_safety_api_version,
        language_endpoint=language_endpoint,
        language_key=(env.get("LANGUAGE_KEY") or None),
        azure_openai_endpoint=azure_openai_endpoint,
        azure_openai_key=(env.get("AZURE_OPENAI_KEY") or None),
        azure_openai_deployment=azure_openai_deployment,
        azure_openai_api_version=azure_openai_api_version,
        safety_severity_threshold=safety_severity_threshold,
        blocklist_names=blocklist_names,
        blocklist_seed_exact=blocklist_seed_exact,
        blocklist_seed_regex=blocklist_seed_regex,
        pii_categories_to_redact=pii_categories_to_redact,
    )


def _safe_token_or_key(
    credential: TokenCredential,
    *,
    key_value: Optional[str],
    scope: str,
) -> Tuple[Optional[TokenCredential], Optional[str]]:
    try:
        credential.get_token(scope)
        return credential, None
    except Exception:
        if not key_value:
            raise
        return None, key_value


def build_default_credential() -> DefaultAzureCredential:
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def build_clients(
    settings: Settings,
    *,
    credential: Optional[DefaultAzureCredential] = None,
) -> Dict[str, Any]:
    credential = credential or build_default_credential()
    cs_scope = "https://cognitiveservices.azure.com/.default"

    cs_token_cred, cs_key = _safe_token_or_key(credential, key_value=settings.content_safety_key, scope=cs_scope)
    if cs_token_cred:
        cs_client = ContentSafetyClient(settings.content_safety_endpoint, cs_token_cred)
        blocklist_client = BlocklistClient(settings.content_safety_endpoint, cs_token_cred)
    else:
        cs_client = ContentSafetyClient(settings.content_safety_endpoint, AzureKeyCredential(cs_key))
        blocklist_client = BlocklistClient(settings.content_safety_endpoint, AzureKeyCredential(cs_key))

    lang_token_cred, lang_key = _safe_token_or_key(credential, key_value=settings.language_key, scope=cs_scope)
    if lang_token_cred:
        language_client = TextAnalyticsClient(endpoint=settings.language_endpoint, credential=lang_token_cred)
    else:
        language_client = TextAnalyticsClient(endpoint=settings.language_endpoint, credential=AzureKeyCredential(lang_key))

    aoai_token_provider: Optional[Callable[[], str]] = None
    aoai_api_key: Optional[str] = None
    try:
        credential.get_token(cs_scope)

        def aoai_token_provider() -> str:
            return credential.get_token(cs_scope).token

    except Exception:
        aoai_api_key = settings.azure_openai_key
        if not aoai_api_key:
            raise RuntimeError("AOAI auth not configured: neither Entra token nor AZURE_OPENAI_KEY available")

    aoai_client = AzureOpenAI(
        azure_endpoint=settings.azure_openai_endpoint,
        azure_ad_token_provider=aoai_token_provider,
        api_key=aoai_api_key,
        api_version=settings.azure_openai_api_version,
    )

    return {
        "credential": credential,
        "cs_client": cs_client,
        "blocklist_client": blocklist_client,
        "language_client": language_client,
        "aoai_client": aoai_client,
        "cs_scope": cs_scope,
    }


def _cs_auth_headers(settings: Settings, credential: TokenCredential, cs_scope: str) -> Dict[str, str]:
    try:
        token = credential.get_token(cs_scope).token
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    except Exception:
        if not settings.content_safety_key:
            raise RuntimeError("Content Safety auth failed: neither AAD token nor CONTENT_SAFETY_KEY available")
        return {"Ocp-Apim-Subscription-Key": settings.content_safety_key, "Content-Type": "application/json"}


def ensure_blocklist_exists(
    settings: Settings,
    credential: TokenCredential,
    *,
    blocklist_name: str,
    description: str = "Demo blocklist created from app",
    api_version: str = CONTENT_SAFETY_GA_BLOCKLIST_API_VERSION,
    timeout_s: int = 10,
) -> Dict[str, Any]:
    base = settings.content_safety_endpoint.rstrip("/")
    url = f"{base}/contentsafety/text/blocklists/{blocklist_name}?api-version={api_version}"
    resp = requests.patch(
        url,
        headers=_cs_auth_headers(settings, credential, "https://cognitiveservices.azure.com/.default"),
        json={"description": description},
        timeout=timeout_s,
    )
    resp.raise_for_status()
    return {"status_code": resp.status_code, "body": (resp.json() if resp.text else {})}


def delete_blocklist(
    settings: Settings,
    credential: TokenCredential,
    *,
    blocklist_name: str,
    api_version: str = CONTENT_SAFETY_GA_BLOCKLIST_API_VERSION,
    timeout_s: int = 10,
) -> Dict[str, Any]:
    """Delete a blocklist if it exists. Ignores 404 errors."""
    base = settings.content_safety_endpoint.rstrip("/")
    url = f"{base}/contentsafety/text/blocklists/{blocklist_name}?api-version={api_version}"
    headers = _cs_auth_headers(settings, credential, "https://cognitiveservices.azure.com/.default")

    resp = requests.delete(url, headers=headers, timeout=timeout_s)
    if resp.status_code == 404:
        return {"status": "missing", "blocklist_name": blocklist_name}

    resp.raise_for_status()
    return {"status": "deleted", "blocklist_name": blocklist_name}


def cleanup_blocklists(
    settings: Settings,
    credential: TokenCredential,
    *,
    blocklist_names: Optional[Sequence[str]] = None,
    api_version: str = CONTENT_SAFETY_GA_BLOCKLIST_API_VERSION,
    timeout_s: int = 10,
) -> List[Dict[str, Any]]:
    """Remove existing blocklists so the app can reseed from a clean slate."""
    names = list(blocklist_names or settings.blocklist_names)
    results: List[Dict[str, Any]] = []
    for name in names:
        try:
            result = delete_blocklist(
                settings,
                credential,
                blocklist_name=name,
                api_version=api_version,
                timeout_s=timeout_s,
            )
        except requests.exceptions.HTTPError as exc:
            error_detail = ""
            try:
                error_detail = exc.response.json()
            except Exception:
                error_detail = exc.response.text if exc.response else str(exc)
            result = {
                "status": "error",
                "blocklist_name": name,
                "detail": error_detail,
            }
        results.append(result)
    return results


def add_block_items(
    settings: Settings,
    credential: TokenCredential,
    *,
    blocklist_name: str,
    exact_items: Optional[Sequence[str]] = None,
    regex_items: Optional[Sequence[str]] = None,
    api_version: str = CONTENT_SAFETY_GA_BLOCKLIST_API_VERSION,
    timeout_s: int = 10,
) -> Dict[str, Any]:
    exact_items = list(exact_items or [])
    regex_items = list(regex_items or [])

    items: List[Dict[str, Any]] = []
    for text in exact_items:
        items.append({"description": "exact match", "text": text})
    for pattern in regex_items:
        items.append({"description": "regex pattern", "text": pattern, "isRegex": True})

    if not items:
        return {"status": "skipped", "reason": "no items"}

    base = settings.content_safety_endpoint.rstrip("/")
    url = f"{base}/contentsafety/text/blocklists/{blocklist_name}:addOrUpdateBlocklistItems?api-version={api_version}"
    
    try:
        resp = requests.post(
            url,
            headers=_cs_auth_headers(settings, credential, "https://cognitiveservices.azure.com/.default"),
            json={"blocklistItems": items},
            timeout=timeout_s,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        error_detail = ""
        try:
            error_detail = resp.json()
        except:
            error_detail = resp.text
        raise RuntimeError(f"Failed to add items to blocklist '{blocklist_name}': {e}. Response: {error_detail}")

    data = resp.json() if resp.text else {}
    added_items = [
        {
            "id": item.get("blocklistItemId"),
            "text": item.get("text"),
            "is_regex": item.get("isRegex"),
            "description": item.get("description"),
        }
        for item in data.get("blocklistItems", [])
    ]
    return {"status": "added", "blocklist_name": blocklist_name, "items": added_items}


def seed_blocklists(settings: Settings, credential: TokenCredential) -> List[Dict[str, Any]]:
    """
    Seeds blocklists with different content based on their names:
    - demo-blocklist-a: Exact match terms (internal/confidential terms)
    - demo-blocklist-b: Regex patterns (credential patterns with character class variations)
    """
    results: List[Dict[str, Any]] = []
    for name in settings.blocklist_names:
        created = ensure_blocklist_exists(settings, credential, blocklist_name=name)
        
        # Split blocklists by type for better organization
        if "a" in name.lower():
            # Blocklist A: Exact match terms only (internal/confidential terms)
            added = add_block_items(
                settings,
                credential,
                blocklist_name=name,
                exact_items=settings.blocklist_seed_exact,
                regex_items=[],  # No regex patterns for blocklist A
            )
        elif "b" in name.lower():
            # Blocklist B: Regex patterns only (credential/secret patterns)
            added = add_block_items(
                settings,
                credential,
                blocklist_name=name,
                exact_items=[],  # No exact items for blocklist B
                regex_items=settings.blocklist_seed_regex,
            )
        else:
            # Other blocklists: Use both exact and regex
            added = add_block_items(
                settings,
                credential,
                blocklist_name=name,
                exact_items=settings.blocklist_seed_exact,
                regex_items=settings.blocklist_seed_regex,
            )
        
        results.append({"blocklist_name": name, "created": created, "added": added})
    return results


def analyze_text_safety(
    cs_client: ContentSafetyClient,
    *,
    text: str,
    severity_threshold: int,
    blocklist_names: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    blocklist_names = list(blocklist_names or [])
    request = AnalyzeTextOptions(
        text=text,
        categories=[TextCategory.HATE, TextCategory.SELF_HARM, TextCategory.SEXUAL, TextCategory.VIOLENCE],
        blocklist_names=blocklist_names,
    )

    t0 = time.perf_counter()
    response = cs_client.analyze_text(request)
    latency_ms = (time.perf_counter() - t0) * 1000
    
    unsafe_categories: List[Dict[str, Any]] = []
    for category in response.categories_analysis:
        if category.severity >= severity_threshold:
            unsafe_categories.append({"category": str(category.category), "severity": category.severity})

    return {
        "safe": len(unsafe_categories) == 0,
        "flagged_categories": unsafe_categories,
        "threshold": severity_threshold,
        "latency_ms": latency_ms,
    }


def check_blocklists(
    cs_client: ContentSafetyClient,
    *,
    text: str,
    blocklist_names: Sequence[str],
) -> Dict[str, Any]:
    matches: List[Dict[str, Any]] = []
    latency_ms = 0.0

    if blocklist_names:
        options = AnalyzeTextOptions(
            text=text,
            categories=[TextCategory.HATE, TextCategory.VIOLENCE, TextCategory.SELF_HARM, TextCategory.SEXUAL],
            blocklist_names=list(blocklist_names),
            halt_on_blocklist_hit=True,
        )
        t0 = time.perf_counter()
        result = cs_client.analyze_text(options)
        latency_ms = (time.perf_counter() - t0) * 1000
        
        if result and result.blocklists_match:
            for item in result.blocklists_match:
                matches.append(
                    {
                        "type": "content_safety_blocklist",
                        "blocklist": item.blocklist_name,
                        "value": item.blocklist_item_id,
                        "text": item.blocklist_item_text,
                    }
                )

    return {"matched": bool(matches), "matches": matches, "detected": bool(matches), "latency_ms": latency_ms}


def detect_pii(
    language_client: TextAnalyticsClient,
    *,
    text: str,
    pii_categories_to_redact: Sequence[str],
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    response = language_client.recognize_pii_entities([text], language="en")
    latency_ms = (time.perf_counter() - t0) * 1000
    
    result = response[0]

    if result.is_error:
        return {"has_pii": False, "error": result.error.message, "latency_ms": latency_ms}

    pii_entities: List[Dict[str, Any]] = []
    sensitive_pii_found = False

    pii_categories_set = set(pii_categories_to_redact)
    for entity in result.entities:
        pii_entities.append(
            {
                "text": entity.text,
                "category": entity.category,
                "confidence_score": entity.confidence_score,
            }
        )
        if entity.category in pii_categories_set:
            sensitive_pii_found = True

    final_text = result.redacted_text if sensitive_pii_found else text

    return {
        "has_pii": sensitive_pii_found,
        "all_entities": pii_entities,
        "redacted_text": final_text,
        "sensitive_categories": list(pii_categories_to_redact),
        "latency_ms": latency_ms,
    }


def detect_jailbreak(
    settings: Settings,
    credential: TokenCredential,
    *,
    text: str,
) -> Dict[str, Any]:
    base_endpoint = settings.content_safety_endpoint.rstrip("/")
    url = f"{base_endpoint}/contentsafety/text:shieldPrompt?api-version={settings.content_safety_api_version}"

    try:
        token = credential.get_token("https://cognitiveservices.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    except Exception:
        if not settings.content_safety_key:
            raise
        headers = {"Ocp-Apim-Subscription-Key": settings.content_safety_key, "Content-Type": "application/json"}

    payload = {"userPrompt": text, "documents": []}

    try:
        t0 = time.perf_counter()
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        latency_ms = (time.perf_counter() - t0) * 1000
        resp.raise_for_status()
        data = resp.json()
        user_analysis = data.get("userPromptAnalysis", {})
        return {"detected": bool(user_analysis.get("attackDetected", False)), "analysis": user_analysis, "via": "prompt-shields", "latency_ms": latency_ms}
    except Exception as e:
        suspicious_patterns = ["ignore previous instructions", "dan mode", "developer mode", "jailbreak"]
        lowered = text.lower()
        for pattern in suspicious_patterns:
            if pattern in lowered:
                return {"detected": True, "details": f"Jailbreak pattern detected: '{pattern}'", "via": "heuristic", "latency_ms": 0}
        return {"detected": False, "warning": f"Prompt Shields API fallback used: {e}", "via": "heuristic", "latency_ms": 0}


def detect_protected_material(*, text: str) -> Dict[str, Any]:
    return {"detected": False, "via": "stub", "latency_ms": 0}


def run_all_checks(
    settings: Settings,
    clients: Dict[str, Any],
    *,
    text: str,
    stage: str = "input",
) -> Dict[str, Any]:
    cs_client: ContentSafetyClient = clients["cs_client"]
    language_client: TextAnalyticsClient = clients["language_client"]
    credential: TokenCredential = clients["credential"]

    results: Dict[str, Any] = {
        "stage": stage,
        "text_preview": (text[:100] + "...") if len(text) > 100 else text,
        "blocked": False,
        "block_reason": None,
        "checks": [],
        "total_latency_ms": 0.0,
    }

    t0 = time.perf_counter()
    blocklist_result = check_blocklists(cs_client, text=text, blocklist_names=settings.blocklist_names)
    latency = (time.perf_counter() - t0) * 1000
    results["checks"].append({"check": "blocklist", "latency_ms": latency, "result": blocklist_result})
    results["total_latency_ms"] += latency
    if blocklist_result.get("detected") and not results["blocked"]:
        results["blocked"] = True
        results["block_reason"] = "Blocklist match"

    t0 = time.perf_counter()
    safety_result = analyze_text_safety(
        cs_client,
        text=text,
        severity_threshold=settings.safety_severity_threshold,
        blocklist_names=settings.blocklist_names,
    )
    latency = (time.perf_counter() - t0) * 1000
    results["checks"].append({"check": "content_safety", "latency_ms": latency, "result": safety_result})
    results["total_latency_ms"] += latency
    if not safety_result.get("safe", False) and not results["blocked"]:
        results["blocked"] = True
        results["block_reason"] = "Harmful content detected"

    t0 = time.perf_counter()
    jailbreak_result = detect_jailbreak(settings, credential, text=text)
    latency = (time.perf_counter() - t0) * 1000
    results["checks"].append({"check": "jailbreak", "latency_ms": latency, "result": jailbreak_result})
    results["total_latency_ms"] += latency
    if jailbreak_result.get("detected") and not results["blocked"]:
        results["blocked"] = True
        results["block_reason"] = "Jailbreak/prompt injection detected"

    t0 = time.perf_counter()
    pii_result = detect_pii(language_client, text=text, pii_categories_to_redact=settings.pii_categories_to_redact)
    latency = (time.perf_counter() - t0) * 1000
    results["checks"].append({"check": "pii", "latency_ms": latency, "result": pii_result})
    results["total_latency_ms"] += latency
    results["pii_detected"] = pii_result.get("has_pii", False)
    results["redacted_text"] = pii_result.get("redacted_text", text)

    t0 = time.perf_counter()
    protected_result = detect_protected_material(text=text)
    latency = (time.perf_counter() - t0) * 1000
    results["checks"].append({"check": "protected_material", "latency_ms": latency, "result": protected_result})
    results["total_latency_ms"] += latency
    if protected_result.get("detected") and not results["blocked"]:
        results["blocked"] = True
        results["block_reason"] = "Protected material detected"

    return results


def middleware_pipeline(settings: Settings, clients: Dict[str, Any], *, user_prompt: str) -> Dict[str, Any]:
    aoai_client: AzureOpenAI = clients["aoai_client"]

    pipeline_log: Dict[str, Any] = {"input": user_prompt, "steps": []}

    t0 = time.perf_counter()
    input_check_result = run_all_checks(settings, clients, text=user_prompt, stage="input")
    pipeline_log["steps"].append({"step": "input_checks", "latency_ms": (time.perf_counter() - t0) * 1000, "result": input_check_result})

    if input_check_result["blocked"]:
        return {
            "status": "blocked",
            "stage": "input",
            "message": f"Input blocked: {input_check_result['block_reason']}",
            "details": input_check_result,
            "log": pipeline_log,
        }

    llm_input = input_check_result.get("redacted_text", user_prompt)

    t0 = time.perf_counter()
    try:
        response = aoai_client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": llm_input},
            ],
        )
        llm_response_text = response.choices[0].message.content
        pipeline_log["steps"].append({"step": "llm_call", "latency_ms": (time.perf_counter() - t0) * 1000, "result": "success"})
    except Exception as e:
        pipeline_log["steps"].append({"step": "llm_call", "latency_ms": (time.perf_counter() - t0) * 1000, "result": "error", "error": str(e)})
        return {"status": "error", "message": f"LLM call failed: {str(e)}", "log": pipeline_log}

    t0 = time.perf_counter()
    output_check_result = run_all_checks(settings, clients, text=llm_response_text, stage="output")
    pipeline_log["steps"].append({"step": "output_checks", "latency_ms": (time.perf_counter() - t0) * 1000, "result": output_check_result})

    if output_check_result["blocked"]:
        return {
            "status": "blocked",
            "stage": "output",
            "message": f"Output blocked: {output_check_result['block_reason']}",
            "details": output_check_result,
            "log": pipeline_log,
        }

    final_output = output_check_result.get("redacted_text", llm_response_text)

    return {
        "status": "success",
        "original_response": llm_response_text,
        "final_response": final_output,
        "input_pii_redacted": input_check_result.get("pii_detected", False),
        "output_pii_redacted": output_check_result.get("pii_detected", False),
        "log": pipeline_log,
    }
