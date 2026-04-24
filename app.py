import streamlit as st
import plotly.graph_objects as go
from agents import analyze_headers, scan_content, generate_report

# ──────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────
st.set_page_config(
    page_title="PhishTrace | AI Phishing Forensics",
    page_icon="🎣",
    layout="wide"
)

# ──────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────
with st.sidebar:
    st.title("🎣 PhishTrace")
    st.caption("AI-Powered Phishing Email Forensics")
    st.divider()
    st.markdown("""
    **How it works:**
    1. Paste a suspicious email (with headers)
    2. AI analyzes sender identity
    3. AI scans for manipulation tactics
    4. AI scans links and attachments
    5. Get a forensic report + severity score
    
    **Pro tip:** Include full email headers for best results.
    In Gmail: ⋮ → Show original → Copy all.
    In Outlook: File → Properties → Internet headers.
    """)
    st.divider()
    st.caption("Built by a Cybersecurity Master's Graduate")
    st.markdown("[GitHub Repo](https://github.com/chima-ukachukwu-sec/phishtrace)")
    
    st.divider()
    st.markdown("### Sample Phishing Emails")
    st.markdown("Need something to test?")
    st.markdown("- Forward a suspicious email to yourself")
    st.markdown("- Check your spam folder")
    st.markdown("- [Phishing examples (Wikipedia)](https://en.wikipedia.org/wiki/Phishing#Examples)")

# ──────────────────────────────────────
# MAIN CONTENT
# ──────────────────────────────────────
st.title("PhishTrace")
st.subheader("AI Forensics for Suspicious Emails")

st.markdown("""
Paste the **complete email** below — including all headers. 
The AI will analyze sender identity, scan for manipulation, inspect links, and generate a forensic report.
""")

raw_email = st.text_area(
    "Paste email here (with headers)",
    height=250,
    placeholder="Paste the full email source here...\n\nIn Gmail: Open email → ⋮ → Show original → Copy all\nIn Outlook: File → Properties → Internet headers",
    help="Include full headers for best results. Headers contain SPF, DKIM, DMARC records."
)

# ── SAMPLE EMAIL BUTTON ──
with st.expander("📩 Don't have a phishing email? Use this sample"):
    st.markdown("Click below to auto-fill a real phishing example:")
    sample_email = """Delivered-To: user@gmail.com
Received: by 2002:a05:6512:3b87:b0:52e:9d4f:3c8b with SMTP id abc123;
        Tue, 15 Apr 2025 03:42:17 -0700 (PDT)
Return-Path: <bounce@mail.track-orders247.xyz>
Received: from mail.track-orders247.xyz (unknown [103.224.182.253])
        by mx.google.com with ESMTP id xyz789
        for <user@gmail.com>;
        Tue, 15 Apr 2025 03:42:15 -0700 (PDT)
From: "Amazon Security" <account-alert@amaz0n-secure.com>
Reply-To: <support@track-orders247.xyz>
Subject: URGENT: Your Amazon Account Has Been Suspended
Message-ID: <20250415104215.ABC123@track-orders247.xyz>
Date: Tue, 15 Apr 2025 10:42:15 +0000

Dear Valued Customer,

We have detected unusual activity on your Amazon account and it has been temporarily suspended for your protection.

You have 24 hours to verify your account information before your account is permanently closed and all pending orders are cancelled.

Click here to verify your account immediately:
https://www.amazon.com.account-verify.tk/login.php?redirect=secure

If you do not verify within 24 hours, your account will be permanently disabled and your payment methods will be removed.

Thank you,
Amazon Security Team"""
    
    if st.button("Use Sample Email", type="secondary"):
        st.session_state.sample_email = sample_email
        st.rerun()

# Pre-fill from session state if sample was clicked
if "sample_email" in st.session_state:
    raw_email = st.session_state.sample_email

if raw_email:
    # ── AGENT CHAIN EXECUTION ──
    if "header_analysis" not in st.session_state:
        st.session_state.header_analysis = None
        st.session_state.content_scan = None
        st.session_state.forensic_report = None
    
    if st.button("🔍 Analyze Email", type="primary", use_container_width=True):
        # Agent 1: Header Analysis
        with st.spinner("🕵️ Agent 1: Analyzing email headers..."):
            st.session_state.header_analysis = analyze_headers(raw_email)
            sender_score = st.session_state.header_analysis.get("overall_sender_trust_score", 0)
            st.success(f"Sender trust score: {sender_score}/100")
        
        # Agent 2: Content Scan
        with st.spinner("🔎 Agent 2: Scanning for manipulation tactics..."):
            st.session_state.content_scan = scan_content(raw_email)
            body_score = st.session_state.content_scan.get("body_manipulation_score", 0)
            st.success(f"Body manipulation score: {body_score}/100")
        
        # Agent 3: Forensic Report
        with st.spinner("📋 Agent 3: Generating forensic report..."):
            st.session_state.forensic_report = generate_report(
                st.session_state.header_analysis,
                st.session_state.content_scan
            )
            severity = st.session_state.forensic_report.get("severity_label", "Unknown")
            st.success(f"Verdict: {severity}")
    
    # ── RESULTS DISPLAY ──
    if st.session_state.forensic_report:
        st.divider()
        
        report = st.session_state.forensic_report
        headers = st.session_state.header_analysis
        content = st.session_state.content_scan
        
        # Severity Banner
        severity = report.get("severity_label", "Unknown")
        severity_score = report.get("overall_severity_score", 0)
        
        if severity in ["Confirmed Threat", "Likely Phishing"]:
            banner_color = "red"
            emoji = "🚨"
        elif severity == "Suspicious":
            banner_color = "orange"
            emoji = "⚠️"
        else:
            banner_color = "green"
            emoji = "✅"
        
        st.markdown(f"## {emoji} Verdict: {severity}")
        st.progress(severity_score / 100, text=f"Severity Score: {severity_score}/100")
        
        st.divider()
        
        # Tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Executive Summary", "🕵️ Sender Analysis", "🔎 Content Scan", "🛡️ Action Plan"])
        
        with tab1:
            st.subheader("Executive Summary")
            st.markdown(f"""
            <div style="background-color: #1e1e1e; padding: 20px; border-radius: 10px; border-left: 5px solid {banner_color};">
                <p style="font-size: 16px; line-height: 1.6; color: #e0e0e0;">{report.get('executive_summary', 'N/A')}</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.divider()
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Attack Classification", report.get("attack_vector_classification", "N/A"))
            col2.metric("Confidence", f"{report.get('confidence_level', 0)}%")
            col3.metric("False Positive Risk", report.get("false_positive_risk", "N/A"))
            col4.metric("Sender Trust Score", f"{headers.get('overall_sender_trust_score', 'N/A')}/100")
            
            # Severity gauge chart
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=severity_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Overall Threat Severity"},
                delta={'reference': 50, 'increasing': {'color': "red"}},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "red" if severity_score > 60 else "orange" if severity_score > 30 else "green"},
                    'steps': [
                        {'range': [0, 30], 'color': "rgba(0,255,0,0.1)"},
                        {'range': [30, 60], 'color': "rgba(255,165,0,0.1)"},
                        {'range': [60, 100], 'color': "rgba(255,0,0,0.1)"}
                    ],
                    'threshold': {
                        'line': {'color': "white", 'width': 2},
                        'thickness': 0.75,
                        'value': severity_score
                    }
                }
            ))
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            st.subheader("Sender Identity Analysis")
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Display Name:**")
                st.code(headers.get("sender_display_name", "N/A"))
                st.markdown("**Actual Address:**")
                st.code(headers.get("sender_actual_address", "N/A"))
                st.markdown("**Reply-To Mismatch:**")
                st.warning("⚠️ Yes — reply goes to different domain") if headers.get("reply_to_mismatch") else st.success("No mismatch detected")
            
            with col_b:
                st.markdown("**Authentication Results:**")
                spf = headers.get("spf_result", "N/A")
                dkim = headers.get("dkim_result", "N/A")
                dmarc = headers.get("dmarc_result", "N/A")
                
                spf_icon = "✅" if spf == "pass" else "❌" if spf == "fail" else "⚠️"
                dkim_icon = "✅" if dkim == "pass" else "❌" if dkim == "fail" else "⚠️"
                dmarc_icon = "✅" if dmarc == "pass" else "❌" if dmarc == "fail" else "⚠️"
                
                st.markdown(f"{spf_icon} **SPF:** {spf}")
                st.markdown(f"{dkim_icon} **DKIM:** {dkim}")
                st.markdown(f"{dmarc_icon} **DMARC:** {dmarc}")
            
            st.divider()
            st.markdown("**Domain Spoofing Indicators:**")
            spoofing = headers.get("domain_spoofing_indicators", [])
            if spoofing:
                for s in spoofing:
                    if s.get("spoof_type") != "none":
                        st.error(f"🔴 **{s.get('spoof_type', 'Unknown').upper()}**: Display domain `{s.get('display_domain', 'N/A')}` → Actual domain `{s.get('actual_domain', 'N/A')}` (Confidence: {s.get('confidence', 0)}%)")
            else:
                st.success("No domain spoofing detected.")
            
            st.divider()
            st.markdown("**Header Anomalies:**")
            anomalies = headers.get("header_anomalies", [])
            if anomalies:
                for a in anomalies:
                    st.warning(f"⚠️ {a}")
            else:
                st.success("No header anomalies detected.")
        
        with tab3:
            st.subheader("Content & Payload Analysis")
            
            col_c, col_d, col_e = st.columns(3)
            col_c.metric("Urgency Score", f"{content.get('urgency_score', 'N/A')}/100")
            col_d.metric("Fear Appeal Score", f"{content.get('fear_appeal_score', 'N/A')}/100")
            col_e.metric("Authority Impersonation", f"{content.get('authority_impersonation_score', 'N/A')}/100")
            
            st.divider()
            
            # Urgency phrases
            st.markdown("**🚨 Urgency Phrases Detected:**")
            urgency_phrases = content.get("urgency_phrases", [])
            if urgency_phrases:
                for phrase in urgency_phrases:
                    st.warning(f"• {phrase}")
            else:
                st.success("No urgent language detected.")
            
            # Fear phrases
            st.markdown("**😨 Fear Appeal Phrases Detected:**")
            fear_phrases = content.get("fear_phrases", [])
            if fear_phrases:
                for phrase in fear_phrases:
                    st.error(f"• {phrase}")
            else:
                st.success("No fear-based manipulation detected.")
            
            # Authority claims
            st.markdown("**👔 Authority Entities Claimed:**")
            authorities = content.get("authority_entities_claimed", [])
            if authorities:
                for auth in authorities:
                    st.info(f"• Claims to be: {auth}")
            else:
                st.success("No authority impersonation detected.")
            
            st.divider()
            
            # Links Analysis
            st.markdown("**🔗 Link Analysis:**")
            links = content.get("links_analyzed", [])
            if links:
                for link in links:
                    risk = link.get("risk_score", 0)
                    icon = "🔴" if risk > 60 else "🟡" if risk > 30 else "🟢"
                    st.markdown(f"""
                    {icon} **Display:** `{link.get('display_text', 'N/A')}`  
                    → **Actual URL:** `{link.get('actual_url', 'N/A')}`  
                    → Domain Mismatch: {'⚠️ Yes' if link.get('domain_mismatch') else '✅ No'} | Suspicious TLD: {'⚠️ Yes' if link.get('suspicious_tld') else '✅ No'} | URL Shortener: {'⚠️ Yes' if link.get('url_shortener_detected') else '✅ No'} | **Risk Score: {risk}/100**
                    """)
            else:
                st.success("No links found in email.")
            
            st.divider()
            
            # Attachment Risk
            st.markdown("**📎 Attachment Risk:**")
            attachment = content.get("attachment_risk", {})
            if attachment.get("has_attachment"):
                risk_level = attachment.get("risk_level", "unknown")
                if risk_level in ["high", "critical"]:
                    st.error(f"⚠️ **{risk_level.upper()} RISK**: {attachment.get('rationale', '')}")
                    st.markdown(f"File types: {', '.join(attachment.get('file_types', []))}")
                else:
                    st.info(f"Risk Level: {risk_level} — {attachment.get('rationale', '')}")
            else:
                st.success("No attachments detected.")
            
            # Grammar Quality
            st.divider()
            st.markdown("**📝 Grammar Quality:**")
            grammar_score = content.get("grammar_quality_score", 0)
            st.progress(grammar_score / 100, text=f"Grammar Quality: {grammar_score}/100 (100 = native professional English)")
            grammar_issues = content.get("grammar_issues", [])
            if grammar_issues:
                for issue in grammar_issues:
                    st.caption(f"• {issue}")
        
        with tab4:
            st.subheader("Action Plan")
            
            st.markdown("### ⚡ Immediate Actions (For Recipient)")
            immediate = report.get("immediate_actions", [])
            if immediate:
                for i, action in enumerate(immediate, 1):
                    st.error(f"**{i}.** {action}")
            else:
                st.info("No immediate actions needed.")
            
            st.divider()
            
            st.markdown("### 🛡️ IT Remediation Steps (For Security Team)")
            remediation = report.get("it_remediation_steps", [])
            if remediation:
                for i, step in enumerate(remediation, 1):
                    st.warning(f"**{i}.** {step}")
            else:
                st.info("No remediation steps needed.")
            
            st.divider()
            
            st.markdown("### 🦠 Indicators of Compromise (IOCs)")
            iocs = report.get("indicators_of_compromise", [])
            if iocs:
                for ioc in iocs:
                    st.code(ioc)
                st.caption("Share these IOCs with your security team for threat hunting.")
            else:
                st.info("No specific IOCs identified.")
        
        # ── DOWNLOAD REPORT ──
        st.divider()
        report_text = f"""
=== PHISHTRACE FORENSIC REPORT ===

VERDICT: {severity}
SEVERITY SCORE: {severity_score}/100
CONFIDENCE: {report.get('confidence_level', 'N/A')}%

=== EXECUTIVE SUMMARY ===
{report.get('executive_summary', 'N/A')}

=== ATTACK CLASSIFICATION ===
{report.get('attack_vector_classification', 'N/A')}

=== INDICATORS OF COMPROMISE ===
{chr(10).join(report.get('indicators_of_compromise', ['None identified']))}

=== IMMEDIATE ACTIONS ===
{chr(10).join(report.get('immediate_actions', ['None needed']))}

=== IT REMEDIATION STEPS ===
{chr(10).join(report.get('it_remediation_steps', ['None needed']))}

=== GENERATED BY PHISHTRACE ===
https://phishtrace.streamlit.app
"""
        st.download_button(
            label="📥 Download Full Forensic Report (.txt)",
            data=report_text,
            file_name="phishtrace_report.txt",
            mime="text/plain",
            use_container_width=True
        )
        
        # ── DISCLAIMER ──
        st.divider()
        st.caption("⚠️ **Disclaimer:** PhishTrace provides AI-generated educational content to help identify potential phishing emails. It is NOT a substitute for enterprise-grade email security solutions. Always consult your organization's security team before taking action on suspicious emails.")

else:
    # ── EMPTY STATE ──
    st.info("👆 Paste a suspicious email above to begin forensic analysis.")
    
    st.divider()
    st.markdown("""
    ### What this tool does:
    
    | Agent | Function |
    |---|---|
    | 🕵️ **Header Analyzer** | Examines SPF, DKIM, DMARC, domain spoofing, sender reputation |
    | 🔎 **Content Scanner** | Detects urgency tactics, fear appeals, authority impersonation, link obfuscation, attachment risks |
    | 📋 **Forensic Reporter** | Generates severity score, executive summary, IOCs, and action plan |
    
    Built with a **3-agent AI chain** — cybersecurity threat-modeling applied to email forensics.
    """)