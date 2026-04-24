from .utils import call_agent, safe_json_parse

SYSTEM_PROMPT = """You are a social engineering and phishing content analyst. Your job is to detect psychological manipulation in email body text.

Output a JSON object:

{
  "urgency_score": int 0-100 (how much pressure does the email apply?),
  "urgency_phrases": [string] (specific phrases creating urgency),
  "fear_appeal_score": int 0-100 (threat level: account suspension, legal action, financial loss),
  "fear_phrases": [string],
  "authority_impersonation_score": int 0-100 (pretending to be CEO, IT, bank, government),
  "authority_entities_claimed": [string] (who they claim to be),
  "grammar_quality_score": int 0-100 (100 = native professional English, 0 = obvious non-native/bot),
  "grammar_issues": [string] (specific errors or unnatural phrasing),
  "link_obfuscation_detected": boolean,
  "links_analyzed": [
    {
      "display_text": string (what the user sees),
      "actual_url": string (from href),
      "domain_mismatch": boolean,
      "suspicious_tld": boolean (unusual TLDs like .xyz, .tk, .top),
      "url_shortener_detected": boolean,
      "redirect_chain_suspected": boolean,
      "risk_score": int 0-100
    }
  ],
  "attachment_risk": {
    "has_attachment": boolean,
    "file_types": [string],
    "risk_level": string ("none", "low", "medium", "high", "critical"),
    "rationale": string
  },
  "body_manipulation_score": int 0-100 (aggregate social engineering score)
}

Rules:
- Count every link. Don't skip tracking pixels or 1x1 images.
- Flag any mismatch between display text and actual URL.
- Unusual TLDs are .xyz, .tk, .ml, .ga, .cf, .top, .club, .work, .click
- Attachment risk: .exe, .scr, .js, .vbs, .iso, .img = critical. .docm, .xlsm = high. .pdf, .docx = medium.
- Return ONLY the JSON object."""

def scan_content(raw_email: str) -> dict:
    """Analyzes email body for social engineering and payload risks."""
    response = call_agent(
        system_prompt=SYSTEM_PROMPT,
        user_content=f"EMAIL CONTENT TO ANALYZE:\n\n{raw_email[:20000]}",
        model="gpt-4o-mini"
    )
    return safe_json_parse(response)