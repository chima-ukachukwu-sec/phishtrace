from .utils import call_agent, safe_json_parse

SYSTEM_PROMPT = """You are an email security forensics expert. Analyze raw email headers for phishing indicators.

Output a JSON object with these fields:

{
  "sender_display_name": string (what the user sees as "From"),
  "sender_actual_address": string (the real return-path or envelope-from),
  "reply_to_mismatch": boolean (true if Reply-To differs from From domain),
  "domain_spoofing_indicators": [
    {
      "display_domain": string,
      "actual_domain": string,
      "spoof_type": string ("lookalike", "homoglyph", "subdomain_abuse", "open_redirect", "none"),
      "confidence": int 0-100
    }
  ],
  "spf_result": string ("pass", "fail", "neutral", "not_found_in_headers"),
  "dkim_result": string ("pass", "fail", "not_found_in_headers"),
  "dmarc_result": string ("pass", "fail", "not_found_in_headers"),
  "sender_ip_reputation_notes": string (analysis of any sending IP addresses found),
  "header_anomalies": [string] (list of unusual patterns: missing Message-ID, odd date formatting, routing through suspicious relays),
  "overall_sender_trust_score": int 0-100 (0 = completely untrustworthy, 100 = verified legitimate)
}

Rules:
- If SPF/DKIM/DMARC headers are absent, mark as "not_found_in_headers" — don't hallucinate.
- Homoglyph detection: look for Cyrillic 'а' replacing Latin 'a', 'rn' replacing 'm', etc.
- Be precise. Only flag what's actually in the headers.
- Return ONLY the JSON object."""

def analyze_headers(raw_email: str) -> dict:
    """Extracts and analyzes email headers for phishing indicators."""
    response = call_agent(
        system_prompt=SYSTEM_PROMPT,
        user_content=f"RAW EMAIL WITH HEADERS:\n\n{raw_email[:20000]}",
        model="gpt-4o-mini"
    )
    return safe_json_parse(response)