import json
import os
import sys
from typing import Any, Dict

import streamlit as st
from dotenv import load_dotenv

# Load environment variables from .env file before anything else
load_dotenv(".env")

# Make ./src importable when running `streamlit run app_streamlit.py`
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from azure_content_safety.guards import (  # noqa: E402
    analyze_text_safety,
    build_clients,
    build_default_credential,
    cleanup_blocklists,
    check_blocklists,
    detect_jailbreak,
    detect_pii,
    detect_protected_material,
    load_settings,
    run_all_checks,
    seed_blocklists,
)


def _as_pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def load_sample_test_cases() -> Dict[str, str]:
    """Load sample test cases from JSONL file."""
    sample_cases = {}
    jsonl_path = os.path.join(ROOT_DIR, "sample_test_cases.jsonl")
    
    try:
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    case = json.loads(line)
                    # Format as pretty JSON string for display
                    sample_cases[case["name"]] = json.dumps({"messages": case["messages"]}, indent=2)
    except FileNotFoundError:
        st.warning(f"⚠️ Sample test cases file not found: {jsonl_path}")
        # Fallback to a simple example
        sample_cases["Clean Text (Baseline)"] = json.dumps({
            "messages": [
                {"role": "user", "content": "What is the capital of France?"}
            ]
        }, indent=2)
    except Exception as e:
        st.error(f"Error loading sample test cases: {e}")
        sample_cases["Error"] = "Failed to load samples"
    
    return sample_cases


# Load sample test cases from external file
SAMPLE_TEST_CASES = load_sample_test_cases()


@st.cache_resource
def _init() -> Dict[str, Any]:
    settings = load_settings()
    credential = build_default_credential()
    cleanup_results = cleanup_blocklists(settings, credential)
    seed_results = seed_blocklists(settings, credential)
    clients = build_clients(settings, credential=credential)
    return {
        "settings": settings,
        "clients": clients,
        "credential": credential,
        "blocklist_cleanup": cleanup_results,
        "blocklist_seed": seed_results,
    }


st.set_page_config(
    page_title="Azure Content Safety Tester",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'About': "Test Azure AI Content Safety evaluators individually"
    }
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .stAlert {
        border-radius: 8px;
        border-left: 4px solid;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.5rem;
    }
    .status-card {
        padding: 1rem;
        border-radius: 8px;
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        margin: 1rem 0;
    }
    h1 {
        padding-bottom: 1rem;
        border-bottom: 2px solid #0078D4;
        margin-bottom: 1rem;
    }
    h3 {
        margin-top: 1.5rem;
        margin-bottom: 0.5rem;
    }
    .input-card {
        background-color: #f8f9fa;
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid #dee2e6;
        margin-bottom: 1rem;
    }
    div[data-testid="stTabs"] {
        margin-top: 1rem;
    }
    footer {
        text-align: center;
        padding: 2rem 0;
        color: #6c757d;
        font-size: 0.875rem;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.title("Azure AI Content Safety Tester")
st.markdown("Test individual safety evaluators with real-time latency metrics")

# Initialize settings first
try:
    state = _init()
    settings = state["settings"]
    clients = state["clients"]
    credential = state["credential"]
    startup_cleanup = state.get("blocklist_cleanup", [])
    startup_seed = state.get("blocklist_seed", [])
except Exception as e:
    st.error(":red[**App configuration is incomplete**]")
    st.code(str(e))
    st.stop()

# Sidebar configuration
with st.sidebar:
    st.header("Sample Test Cases")
    st.caption("Pre-populated examples for testing")
    
    # Sample test case selector in sidebar
    sample_case = st.selectbox(
        "Load Sample",
        options=["(Custom text)"] + list(SAMPLE_TEST_CASES.keys()),
        index=0,
        label_visibility="collapsed",
    )
    
    if sample_case != "(Custom text)":
        st.success(f"Loaded: {sample_case}")
    
    st.divider()
    
    st.header("Configuration")
    msft_base = os.getenv('MSFT_FOUNDRY_ENDPOINT', '').strip()
    cs_env = os.getenv('CONTENT_SAFETY_ENDPOINT', '').strip() or msft_base
    lang_env = os.getenv('LANGUAGE_ENDPOINT', '').strip() or msft_base
    env_status = ":green[READY]" if cs_env and lang_env else ":orange[INCOMPLETE]"
    st.markdown(f"**Environment Status:** {env_status}")
    with st.expander("View details", expanded=False):
        st.code(
            "\n".join(
                [
                    f"MSFT_FOUNDRY_ENDPOINT={':green[SET]' if msft_base else ':red[MISSING]'}",
                    f"CONTENT_SAFETY_ENDPOINT={':green[SET]' if os.getenv('CONTENT_SAFETY_ENDPOINT') else (':blue[USING MSFT_FOUNDRY]' if msft_base else ':red[MISSING]')}",
                    f"LANGUAGE_ENDPOINT={':green[SET]' if os.getenv('LANGUAGE_ENDPOINT') else (':blue[USING MSFT_FOUNDRY]' if msft_base else ':red[MISSING]')}",
                    "(Keys optional with Entra ID)",
                ]
            )
        )
    
    st.divider()
    
    st.markdown("**Blocklists**")
    if settings.blocklist_names:
        for bl in settings.blocklist_names[:3]:
            st.caption(f"• {bl}")
        if len(settings.blocklist_names) > 3:
            st.caption(f"• +{len(settings.blocklist_names) - 3} more")
    else:
        st.caption("None configured")
    
    st.caption("GA API 2024-09-01 with regex support")

    if startup_cleanup or startup_seed:
        with st.expander("Startup blocklist refresh", expanded=False):
            if startup_cleanup:
                deleted = sum(1 for r in startup_cleanup if r.get("status") == "deleted")
                missing = sum(1 for r in startup_cleanup if r.get("status") == "missing")
                st.caption(f"Cleanup: {deleted} deleted, {missing} already missing")
                errors = [r for r in startup_cleanup if r.get("status") == "error"]
                if errors:
                    st.error("One or more blocklists failed to delete")
                    st.json(errors)
            if startup_seed:
                st.caption("Seed results:")
                st.json(startup_seed)

    if st.button("Seed Blocklists", use_container_width=True):
        with st.spinner("Seeding blocklists..."):
            try:
                results = seed_blocklists(settings, credential)
                st.success("Seed complete")
                with st.expander("View results"):
                    st.json(results)
            except Exception as e:
                st.error("Seeding failed")
                st.code(str(e))

# Main input section
st.markdown("### Input Text")

# Set default text based on sidebar selection (from session state)
if sample_case == "(Custom text)":
    default_text = "My email is test@example.com. Tell me about secret_project_x"
else:
    default_text = SAMPLE_TEST_CASES[sample_case]

text = st.text_area(
    "Enter text to evaluate",
    height=150,
    value=default_text,
    placeholder="Enter the text you want to check for safety issues...",
    label_visibility="collapsed",
    key=f"text_input_{sample_case}"
)

# Evaluator selection
st.markdown("### Select Evaluator")
evaluator = st.selectbox(
    "Choose which safety check to run",
    options=[
        "All checks (unified)",
        "Blocklist",
        "Content Safety (Hate/Violence/SelfHarm/Sexual)",
        "Jailbreak Detection",
        "PII Detection",
        "Protected Material",
    ],
    index=0,
    label_visibility="collapsed",
)

if st.button("Run Evaluation", type="primary", use_container_width=True):
    st.markdown("---")
    with st.spinner(f"Running {evaluator}..."):
        try:
            if evaluator == "All checks (unified)":
                result = run_all_checks(settings, clients, text=text, stage="input")
                
                # Create tabs for results
                tab1, tab2, tab3, tab4 = st.tabs(["Status", "Details", "Raw JSON", "About"])
                
                with tab1:
                    # Status header - collect all failures
                    blocked = result.get('blocked')
                    failed_checks = []
                    
                    for check in result.get('checks', []):
                        check_result = check.get('result', {})
                        check_name = check.get('check', 'unknown').replace('_', ' ').title()
                        
                        if check.get('check') == 'blocklist' and check_result.get('detected'):
                            failed_checks.append(f"{check_name}: Blocklist match")
                        elif check.get('check') == 'content_safety' and not check_result.get('safe', True):
                            failed_checks.append(f"{check_name}: Harmful content detected")
                        elif check.get('check') == 'jailbreak' and check_result.get('detected'):
                            failed_checks.append(f"{check_name}: Prompt injection detected")
                        elif check.get('check') == 'protected_material' and check_result.get('detected'):
                            failed_checks.append(f"{check_name}: Protected material detected")
                    
                    if blocked:
                        st.error(f":red[**BLOCKED**] — {len(failed_checks)} violation(s) detected")
                        for failure in failed_checks:
                            st.warning(f"• {failure}")
                    else:
                        st.success(":green[**PASSED**] — All checks completed successfully")
                    
                    # Metrics row
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Latency", f"{result.get('total_latency_ms', 0):.1f} ms")
                    with col2:
                        st.metric("Checks Run", len(result.get('checks', [])))
                    with col3:
                        pii_status = "Yes" if result.get('pii_detected') else "No"
                        st.metric("PII Detected", pii_status)
                    
                    # Show which checks were run
                    st.markdown("**Checks Executed:**")
                    check_names = [check.get('check', 'unknown').replace('_', ' ').title() for check in result.get('checks', [])]
                    st.write(" → ".join(check_names))
                
                with tab2:
                    # Redacted text
                    st.markdown("**Redacted Text:**")
                    st.text_area("", value=result.get("redacted_text", text), height=200, key="redacted", label_visibility="collapsed")
                    
                    # Check details
                    if result.get('checks'):
                        st.markdown("**Check Details:**")
                        for check in result['checks']:
                            check_name = check.get('check', 'unknown').replace('_', ' ').title()
                            check_result = check.get('result', {})
                            
                            # Determine status from result
                            status = ":green[PASSED]"
                            if check.get('check') == 'blocklist' and check_result.get('detected'):
                                status = ":red[BLOCKED]"
                            elif check.get('check') == 'content_safety' and not check_result.get('safe', True):
                                status = ":red[BLOCKED]"
                            elif check.get('check') == 'jailbreak' and check_result.get('detected'):
                                status = ":red[BLOCKED]"
                            elif check.get('check') == 'pii' and check_result.get('has_pii'):
                                status = ":orange[PII FOUND]"
                            elif check.get('check') == 'protected_material' and check_result.get('detected'):
                                status = ":red[BLOCKED]"
                            
                            with st.expander(f"{check_name} — {status}"):
                                st.json(check)
                
                with tab3:
                    st.json(result)
                
                with tab4:
                    st.markdown("**Unified Content Safety Pipeline**")
                    st.markdown("""
                    This evaluator runs **all safety checks** to provide comprehensive analysis.
                    
                    **Execution Model:**
                    - **Sequential Execution**: Checks run one after another in order
                    - **Complete Analysis**: All checks run regardless of blocking status
                    - **First Blocker Reported**: If multiple violations exist, the first detected violation is reported as the block reason
                    
                    > **Production Note**: For high-throughput applications, consider **parallelizing** these checks 
                    > using async/await or concurrent execution to reduce total latency. The current sequential 
                    > implementation prioritizes simplicity and debugging visibility.
                    
                    ---
                    
                    **Checks Performed (in order):**
                    
                    **1. Blocklist Matching**
                    - Exact term matching and regex patterns
                    - Detects credentials, secrets, restricted terms
                    
                    **2. Content Safety (Hate/Violence/SelfHarm/Sexual)**
                    - Severity levels 0-6 (default threshold: 4)
                    - **Level 0**: Safe - Professional/journalistic context
                    - **Level 2**: Low - Prejudiced views, stereotyping
                    - **Level 4**: Medium - Insulting language, harmful instructions
                    - **Level 6**: High - Explicit harmful content, radicalization
                    
                    **3. Jailbreak Detection (Prompt Shields)**
                    - Detects prompt injection attempts
                    - Identifies instruction override patterns
                    
                    **4. PII Detection**
                    - Identifies personally identifiable information
                    - Redacts sensitive categories (SSN, credit cards, etc.)
                    - Non-blocking: Always runs for redaction purposes
                    
                    **5. Protected Material**
                    - Detects copyrighted content (stub implementation)
                    """)

            elif evaluator == "Blocklist":
                result = check_blocklists(
                    clients["cs_client"],
                    text=text,
                    blocklist_names=settings.blocklist_names,
                )
                
                # Create tabs for results
                tab1, tab2, tab3, tab4 = st.tabs(["Status", "Details", "Raw JSON", "About"])
                
                with tab1:
                    if result.get("detected"):
                        st.error(":red[**BLOCKED**] — Matched blocklist entry")
                    else:
                        st.success("🟢 **PASSED** — No blocklist matches")
                    
                    st.metric("⏱️ API Latency", f"{result.get('latency_ms', 0):.2f} ms")
                
                with tab2:
                    if result.get("matches"):
                        st.markdown("**Blocklist Matches:**")
                        
                        # Create CSV data
                        import io
                        csv_buffer = io.StringIO()
                        csv_buffer.write("Blocklist,Matched Text,Match Type\n")
                        
                        for match in result["matches"]:
                            blocklist = match.get('blocklist', 'unknown')
                            text = match.get('text', '').replace('"', '""')  # Escape quotes for CSV
                            match_type = "Regex" if match.get('kind') == 'regex' else "Exact"
                            csv_buffer.write(f'"{blocklist}","{text}","{match_type}"\n')
                            
                            # Display in UI
                            st.warning(f"**{blocklist}** ({match_type}): `{match.get('text')}`")
                        
                        # Download button
                        csv_data = csv_buffer.getvalue()
                        st.download_button(
                            label="Download Matches as CSV",
                            data=csv_data,
                            file_name="blocklist_matches.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                    else:
                        st.info("No matches found")
                
                with tab3:
                    st.json(result)
                
                with tab4:
                    st.markdown("**Blocklist Evaluation**")
                    st.markdown("""
                    Blocklists provide exact-match and regex-based content filtering.
                    
                    **Match Types:**
                    - **Exact Match**: Full term matching (case-insensitive)
                    - **Regex Patterns**: Pattern-based detection (credentials, secrets)
                    
                    **Detection Logic:**
                    - Text is scanned against all configured blocklists
                    - Any match results in immediate blocking
                    - No severity levels - binary pass/fail
                    
                    **Common Use Cases:**
                    - Credential patterns (passwords, API keys, tokens)
                    - Restricted internal terms (project codenames, confidential data)
                    - Custom harmful patterns specific to your domain
                    
                    **API Version:** GA 2024-09-01 with regex support
                    """)

            elif evaluator == "Content Safety (Hate/Violence/SelfHarm/Sexual)":
                result = analyze_text_safety(
                    clients["cs_client"],
                    text=text,
                    severity_threshold=settings.safety_severity_threshold,
                    blocklist_names=settings.blocklist_names,
                )
                
                # Create tabs for results
                tab1, tab2, tab3, tab4 = st.tabs(["Status", "Details", "Raw JSON", "About"])
                
                with tab1:
                    if not result.get("safe"):
                        st.error(":red[**UNSAFE**] — Harmful content detected")
                    else:
                        st.success("🟢 **SAFE** — No harmful content detected")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Threshold", result.get('threshold', 0))
                    with col2:
                        st.metric("⏱️ API Latency", f"{result.get('latency_ms', 0):.2f} ms")
                
                with tab2:
                    if result.get("flagged_categories"):
                        st.markdown("##### ⚠️ Flagged Categories")
                        for cat in result["flagged_categories"]:
                            st.warning(f"**{cat['category']}** — Severity: {cat['severity']}")
                    else:
                        st.info("No harmful content detected")
                
                with tab3:
                    st.json(result)
                
                with tab4:
                    st.markdown("##### ⚠️ Content Safety Harm Categories")
                    st.markdown("""
                    Azure AI Content Safety detects harmful content across 4 categories.
                    
                    **Harm Categories:**
                    - **Hate**: Discriminatory language targeting identity groups (race, gender, religion, etc.)
                    - **Sexual**: Explicit sexual content, pornography, non-consensual acts
                    - **Violence**: Content describing physical harm, weapons, killing
                    - **Self-Harm**: Content promoting suicide, self-injury, eating disorders
                    
                    **Severity Levels (0-6):**
                    
                    | Level | Risk | Description |
                    |-------|------|-------------|
                    | **0** | Safe | Professional/scientific/journalistic context |
                    | **2** | Low | Prejudiced views, stereotyping, offensive language |
                    | **4** | Medium | Insulting/mocking language, harmful instructions |
                    | **6** | High | Explicit harmful content, radicalization, abuse |
                    
                    **Current Threshold:** Level {threshold} (configurable)
                    
                    **Recommendation:** Microsoft recommends starting with level 4 for balanced protection.
                    """.format(threshold=settings.safety_severity_threshold))

            elif evaluator == "Jailbreak Detection":
                result = detect_jailbreak(
                    settings=settings,
                    credential=credential,
                    text=text,
                )
                
                # Create tabs for results
                tab1, tab2, tab3, tab4 = st.tabs(["Status", "Details", "Raw JSON", "About"])
                
                with tab1:
                    if result.get("detected"):
                        st.error(":red[**JAILBREAK DETECTED**] — Prompt injection attempt")
                    else:
                        st.success("🟢 **SAFE** — No jailbreak detected")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Detection Method", result.get('via', 'unknown'))
                    with col2:
                        st.metric("⏱️ API Latency", f"{result.get('latency_ms', 0):.2f} ms")
                
                with tab2:
                    if result.get("analysis"):
                        st.markdown("**Analysis Details:**")
                        st.json(result.get("analysis"))
                    else:
                        st.info("No additional details available")
                
                with tab3:
                    st.json(result)
                
                with tab4:
                    st.markdown("**Jailbreak Detection (Prompt Shields)**")
                    st.markdown("""
                    Detects prompt injection attacks that attempt to override AI safety guardrails.
                    
                    **Detection Methods:**
                    - **Prompt Shields API**: Azure AI Content Safety's specialized jailbreak detector
                    - **Heuristic Fallback**: Pattern-based detection for common bypass attempts
                    
                    **Common Jailbreak Patterns:**
                    - **Ignore Instructions**: "Ignore all previous instructions and..."
                    - **Role-Playing**: "Pretend you are DAN (Do Anything Now)..."
                    - **Developer Override**: "As a developer/admin, bypass safety filters..."
                    - **Hypothetical Scenarios**: "In a fictional world where rules don't apply..."
                    - **Encoding Tricks**: Base64, ROT13, or other obfuscation attempts
                    
                    **Detection Logic:**
                    - Binary result: :red[Detected] or :green[Safe]
                    - No severity levels - any jailbreak attempt is blocked
                    - Returns analysis details when available
                    
                    **Use Case:** Essential for AI chatbots and LLM applications to prevent safety bypass
                    """)

            elif evaluator == "PII Detection":
                result = detect_pii(
                    clients["language_client"],
                    text=text,
                    pii_categories_to_redact=settings.pii_categories_to_redact,
                )
                
                # Create tabs for results
                tab1, tab2, tab3, tab4 = st.tabs(["Status", "Details", "Raw JSON", "About"])
                
                with tab1:
                    if result.get("has_pii"):
                        st.warning("⚠️ **SENSITIVE PII FOUND**")
                    else:
                        st.success("🟢 **NO SENSITIVE PII** — Safe to proceed")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        entity_count = len(result.get("all_entities", []))
                        st.metric("Entities Detected", entity_count)
                    with col2:
                        st.metric("⏱️ API Latency", f"{result.get('latency_ms', 0):.2f} ms")
                
                with tab2:
                    # Detected entities
                    if result.get("all_entities"):
                        st.markdown("**Detected Entities:**")
                        for ent in result["all_entities"]:
                            sensitive = ":red[●]" if ent['category'] in settings.pii_categories_to_redact else ":gray[○]"
                            st.write(f"{sensitive} **{ent['category']}**: `{ent['text']}`")
                    else:
                        st.info("No PII entities detected")
                    
                    # Redacted text
                    st.markdown("**Redacted Text:**")
                    st.text_area("", value=result.get("redacted_text", text), height=150, key="pii_redacted", label_visibility="collapsed")
                
                with tab3:
                    st.json(result)
                
                with tab4:
                    st.markdown("**PII Detection (Personally Identifiable Information)**")
                    st.markdown("""
                    Detects and redacts sensitive personal information using Azure AI Language's advanced entity recognition.
                    
                    **Comprehensive Coverage (150+ Entity Types)**
                    
                    Azure AI Language PII detection supports entities across multiple categories and 100+ countries/regions.
                    
                    ---
                    
                    **Financial Information:**
                    - Credit card numbers (Visa, Mastercard, Amex, Discover)
                    - Bank account numbers (US, International)
                    - IBAN (International Banking Account Number)
                    - SWIFT codes and BIC codes
                    - ABA routing numbers
                    - Sort codes (UK banking)
                    - CVV (Card Verification Value)
                    - Bitcoin/cryptocurrency wallet addresses
                    
                    **🆔 Government & National IDs:**
                    - Social Security Numbers (US, Canada, South Korea)
                    - Driver's license numbers (US, Australia, Canada, UK, and 20+ countries)
                    - Passport numbers (US, UK, Australia, and 30+ countries)
                    - National ID cards (Argentina, Austria, Belgium, Brazil, and 50+ countries)
                    - Tax identification numbers (TIN, NIF, VAT numbers globally)
                    - Medicare/Medicaid IDs (US, Australia)
                    
                    **Contact & Location:**
                    - Email addresses (all formats)
                    - Phone numbers (international formats with country codes)
                    - Physical addresses (street, city, state, zip code)
                    - IP addresses (IPv4, IPv6)
                    - GPS coordinates and geolocation data
                    - Airport codes, cities, states, zip codes
                    
                    **Healthcare & Protected Health Information (PHI):**
                    - Medical record numbers
                    - Health insurance numbers
                    - Prescription numbers
                    - Medical device identifiers
                    - Health service numbers (Canada, UK, Australia)
                    
                    **Credentials & Authentication:**
                    - Passwords and passphrases
                    - API keys and access tokens
                    - Azure connection strings (Storage, SQL, IoT, Redis, Service Bus)
                    - Azure Document DB auth keys
                    - Azure SAS tokens
                    - SQL Server connection strings
                    - SSH keys and private keys
                    
                    **Vehicle & Transportation:**
                    - VIN (Vehicle Identification Numbers)
                    - License plate numbers
                    - Driver's license numbers
                    
                    **Personal Information:**
                    - Person names (first, middle, last, full names)
                    - Date of birth
                    - Age
                    - Biometric data
                    - Personal identification numbers
                    
                    **Business & Organizations:**
                    - Organization names
                    - Business registration numbers
                    - Company tax IDs
                    - EU VAT numbers
                    - Professional license numbers
                    
                    ---
                    
                    **Detection Logic:**
                    
                    1. **Entity Recognition**: Uses ML models trained on 100+ languages
                    2. **Confidence Scoring**: Each entity has a confidence score (0.0-1.0)
                    3. **Contextual Analysis**: Understands context to reduce false positives
                    4. **Redaction**: Replaces detected PII with `[EntityType]` placeholders
                    5. **Customizable**: Specify which categories to redact or detect only
                    
                    **Current Configuration:**
                    - **Redaction Mode**: ALL categories (maximum privacy protection)
                    - Empty `pii_categories_to_redact` list = redact everything detected
                    
                    ---
                    
                    **Use Cases:**
                    
                    - **Compliance**: GDPR (EU), CCPA (California), HIPAA (Healthcare), PIPEDA (Canada)
                    - **Data Privacy**: Anonymize logs, customer support tickets, feedback forms
                    - **Content Moderation**: Remove PII from user-generated content before storage
                    - **Data Sharing**: Clean datasets before sharing with third parties
                    - **Audit & Logging**: Prevent PII from entering application logs
                    - **AI Training**: Sanitize training data to protect privacy
                    
                    ---
                    
                    **API Details:**
                    - **Service**: Azure AI Language Text Analytics
                    - **API Version**: v3.1 (GA - Generally Available)
                    - **Language Support**: English primary (additional languages supported with varying accuracy)
                    - **Rate Limits**: 1000 requests/minute (configurable)
                    - **Max Text Size**: 5,120 characters per document
                    
                    **Documentation:**
                    - [PII Entity Categories](https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information/concepts/entity-categories)
                    - [Quickstart Guide](https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information/quickstart)
                    """)

            elif evaluator == "Protected Material":
                result = detect_protected_material(text=text)
                
                # Create tabs for results
                tab1, tab2, tab3, tab4 = st.tabs(["Status", "Details", "Raw JSON", "About"])
                
                with tab1:
                    if result.get("detected"):
                        st.error(":red[**PROTECTED MATERIAL DETECTED**]")
                    else:
                        st.info("🟢 **SAFE** (stub implementation)")
                    
                    st.metric("⏱️ API Latency", f"{result.get('latency_ms', 0):.2f} ms")
                
                with tab2:
                    st.info("This is a stub implementation. No detailed analysis available.")
                    st.caption("Integrate with Azure AI Content Safety Protected Material API for production use.")
                
                with tab3:
                    st.json(result)
                
                with tab4:
                    st.markdown("##### ©️ Protected Material Detection")
                    st.markdown("""
                    Detects copyrighted content, lyrics, articles, and code snippets.
                    
                    **⚠️ Note: This is currently a stub implementation.**
                    
                    **What It Will Detect (When Implemented):**
                    - **Text**: Copyrighted book excerpts, articles, song lyrics
                    - **Code**: Protected code snippets with licensing restrictions
                    - **Media Citations**: References to copyrighted material
                    
                    **Detection Logic:**
                    - Binary result: Protected material detected or not
                    - No severity levels
                    - Returns matched citations and sources when available
                    
                    **Integration Steps:**
                    1. Enable Azure AI Content Safety Protected Material API in your subscription
                    2. Update `detect_protected_material()` in `guards.py` with API calls
                    3. Add appropriate error handling and rate limiting
                    
                    **Use Case:** Essential for content platforms, publishing, code repositories to avoid copyright violations
                    
                    **API:** Azure AI Content Safety Protected Material Detection
                    """)

        except Exception as e:
            st.error(f":red[**Evaluation Failed**]: {evaluator}")
            st.exception(e)

# Footer
st.markdown("---")
st.markdown("""
<footer>
    <p><strong>Azure AI Content Safety Tester</strong></p>
    <p>Built with Azure AI Content Safety, Azure AI Language, and Streamlit</p>
    <p style="font-size: 0.75rem; margin-top: 0.5rem;">
        Using API versions: Content Safety GA 2024-09-01 | Text Analytics v3.1
    </p>
</footer>
""", unsafe_allow_html=True)

