# Azure AI Content Safety vs. Google Model Armor - Comparison Demo Plan

## 1. Core Moderation Capabilities
- **Text Moderation**: Compare detection of harmful text.
- **Image Moderation**: Compare detection of harmful images.
- **Multimodal Moderation**: Compare handling of text + image combinations (e.g., memes).

## 2. Harm Categories
- **Standard Categories**: Hate, Violence, Self-harm, Sexual.
- **Severity Levels**: Compare how each service scores severity (Safe, Low, Medium, High).

## 3. Advanced AI Safety
- **Jailbreak / Prompt Injection**: Compare detection of attempts to bypass rules (e.g., DAN, indirect attacks).
- **Hallucination / Groundedness**: Compare ability to detect factually unsupported content.
- **Protected Material**: Compare detection of copyrighted text and code.

## 4. Security & Privacy
- **PII / DLP**: 
  - **Azure**: Uses AI Language service (NLP/ML-based) with 100+ entity types (SSN, credit cards, Azure secrets, etc.)
    - Context-aware detection (understands "John" in names vs. emails)
    - 4 redaction modes: SyntheticReplacement (new), CharacterMask, EntityMask, NoMask
    - Confidence thresholds and domain filtering (PHI-only mode)
  - **Google**: Integrated DLP via Sensitive Data Protection
  - **Note**: Azure Content Safety regex blocklists are for *content moderation*, NOT PII detection
  - **Demo Focus**: Test context-aware detection (e.g., "John" in different contexts), synthetic replacement quality
- **Malware / Phishing**: Compare detection of malicious URLs and files.

## 5. Integration & Deployment
- **Architecture**: API-based (Azure) vs. Firewall/Proxy (Google).
- **Model Support**: Integration with Azure OpenAI vs. Model Agnostic support.

## 6. Customization
- **Blocklists**: 
  - **Pattern Types**: Both support exact match and regex patterns
  - **Azure**: Up to 10,000 terms, `isRegex` property, built-in profanity lists, 128-1000 char limit per item
  - **Google**: Regex support via Model Armor policies
  - **Demo Focus**: Test complex regex patterns (e.g., obfuscated words, leetspeak)
- **Custom Categories**: 
  - **Azure**: Train custom categories with your own examples for business-specific topics
  - **Google**: Custom sensitive data types via DLP integration
- **Sensitivity Tuning**: 
  - **Azure**: Per-category threshold adjustment (Safe/Low/Medium/High)
  - **Google**: Confidence threshold tuning across policies
