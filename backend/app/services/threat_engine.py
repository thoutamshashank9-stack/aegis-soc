"""
Threat Detection Engine and Explainable Risk Scoring.
Combines:
1. Rule-based static email analysis
2. ML classification probability
3. URL & domain threat signals
4. Authentication verification (SPF, DKIM, DMARC)
5. Header anomalies (Reply-To mismatch, display name spoofing)
6. Suspicious attachment inspection
7. Explainable 0-100 normalized risk score calculation
"""
import re
from typing import Dict, Any, List

# Phishing and Social Engineering Keyword Patterns
URGENCY_KEYWORDS = [
    r'\bimmediate(?:ly)?\b', r'\baction required\b', r'\baccount suspended\b',
    r'\bwithin 24 hours\b', r'\bcritical security\b', r'\bwire transfer\b',
    r'\bpayroll\b', r'\btermination\b', r'\bverify your account\b',
    r'\bseed phrase\b', r'\bsecret recovery\b', r'\breset your password\b',
    r'\bunauthorized access\b', r'\bpermanent closure\b', r'\burgent\b'
]

FINANCIAL_KEYWORDS = [
    r'\bbank account\b', r'\bcredit card\b', r'\bssn\b', r'\bsocial security\b',
    r'\bdirect deposit\b', r'\bbank password\b', r'\brefund of \$\b',
    r'\bwire transfer\b', r'\binvoice attached\b', r'\brouting number\b'
]


class ThreatEngine:

    @staticmethod
    def analyze_threats(
        email_data: Dict[str, Any],
        url_analyses: List[Dict[str, Any]],
        attachment_analyses: List[Dict[str, Any]],
        ml_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Runs the hybrid rule + ML threat detection engine."""
        findings: List[Dict[str, str]] = []
        raw_score = 0

        auth = email_data.get("authentication", {})
        spf = auth.get("spf", "unknown").lower()
        dkim = auth.get("dkim", "unknown").lower()
        dmarc = auth.get("dmarc", "unknown").lower()

        # 1. Authentication Analysis
        if spf in ["fail", "softfail", "permerror"]:
            pts = 20 if spf == "fail" else 12
            raw_score += pts
            findings.append({
                "indicator": f"SPF Authentication Failure ({spf.upper()})",
                "severity": "high",
                "reason": "The sending mail server is not authorized in the sender domain's SPF DNS record.",
                "evidence": f"Authentication-Results SPF: {spf}"
            })
        elif spf == "pass":
            raw_score -= 5

        if dkim in ["fail", "permerror"]:
            raw_score += 15
            findings.append({
                "indicator": "DKIM Cryptographic Signature Failure",
                "severity": "high",
                "reason": "The email message body or headers were modified in transit or signed with invalid keys.",
                "evidence": f"Authentication-Results DKIM: {dkim}"
            })
        elif dkim == "pass":
            raw_score -= 5

        if dmarc in ["fail", "reject"]:
            raw_score += 15
            findings.append({
                "indicator": "DMARC Alignment Policy Failure",
                "severity": "high",
                "reason": "The sender domain failed DMARC alignment check; potential spoofing campaign.",
                "evidence": f"Authentication-Results DMARC: {dmarc}"
            })
        elif dmarc == "pass":
            raw_score -= 5

        # 2. Header Anomaly & Spoofing Analysis
        sender_email = email_data.get("sender_email", "")
        sender_display = email_data.get("sender_display", "")
        reply_to = email_data.get("reply_to", "")
        return_path = email_data.get("return_path", "")

        # Display Name Impersonation
        if sender_display and sender_email:
            for trusted_brand in ["paypal", "microsoft", "google", "apple", "support", "security", "it admin"]:
                if trusted_brand in sender_display.lower() and trusted_brand not in sender_email.lower():
                    raw_score += 25
                    findings.append({
                        "indicator": "Display Name Spoofing / Brand Impersonation",
                        "severity": "critical",
                        "reason": f"Display name poses as '{sender_display}' but the actual transmitting email address is '{sender_email}'.",
                        "evidence": f"From header: {email_data.get('sender')}"
                    })
                    break

        # Reply-To / Return-Path Mismatch
        if reply_to and reply_to != "not_available" and sender_email:
            if sender_email.lower() not in reply_to.lower() and reply_to.lower() not in sender_email.lower():
                raw_score += 20
                findings.append({
                    "indicator": "Reply-To Address Mismatch",
                    "severity": "high",
                    "reason": "Replies will be routed to a destination address different from the sender address.",
                    "evidence": f"From: {sender_email} vs Reply-To: {reply_to}"
                })

        if return_path and return_path != "not_available" and sender_email:
            clean_rp = return_path.strip("<> ").lower()
            if sender_email.lower() != clean_rp and not clean_rp.endswith("bounce"):
                raw_score += 10
                findings.append({
                    "indicator": "Return-Path Envelope Mismatch",
                    "severity": "medium",
                    "reason": "Envelope Return-Path does not match From address; common in spoofed or relayed attacks.",
                    "evidence": f"From: {sender_email} vs Return-Path: {return_path}"
                })

        # 3. URL Threat Indicators
        suspicious_urls = [u for u in url_analyses if u.get("is_suspicious")]
        if suspicious_urls:
            raw_score += min(len(suspicious_urls) * 15, 35)
            for s_url in suspicious_urls:
                for ind in s_url.get("indicators", []):
                    findings.append({
                        "indicator": f"Suspicious URL: {ind['rule'].replace('_', ' ').title()}",
                        "severity": ind["severity"],
                        "reason": ind["description"],
                        "evidence": s_url["url"]
                    })

        # 4. Attachment Threat Indicators
        for att in attachment_analyses:
            if att.get("is_dangerous"):
                raw_score += 25
                findings.append({
                    "indicator": "High-Risk Executable Attachment",
                    "severity": "critical",
                    "reason": f"Attachment '{att['filename']}' carries an executable or script format.",
                    "evidence": f"File: {att['filename']} ({att['size_bytes']} bytes), SHA-256: {att['sha256'][:16]}..."
                })
            elif att.get("is_archive"):
                raw_score += 10
                findings.append({
                    "indicator": "Compressed Archive Attachment",
                    "severity": "medium",
                    "reason": f"Attachment '{att['filename']}' is an archive file commonly used to evade static scanner inspection.",
                    "evidence": f"File: {att['filename']}"
                })

        # 5. Phishing Language & Social Engineering Signals
        content = f"{email_data.get('subject', '')}\n{email_data.get('body_text', '')}"
        
        urgency_matches = []
        for pat in URGENCY_KEYWORDS:
            if re.search(pat, content, re.IGNORECASE):
                urgency_matches.append(pat.replace(r'\b', ''))

        if urgency_matches:
            raw_score += 15
            findings.append({
                "indicator": "Social Engineering: High Urgency / Coercive Language",
                "severity": "medium",
                "reason": "Email employs pressure tactics, countdowns, or threats of suspension to induce hasty user action.",
                "evidence": f"Matched patterns: {', '.join(urgency_matches[:4])}"
            })

        fin_matches = []
        for pat in FINANCIAL_KEYWORDS:
            if re.search(pat, content, re.IGNORECASE):
                fin_matches.append(pat.replace(r'\b', ''))

        if fin_matches:
            raw_score += 15
            findings.append({
                "indicator": "Financial / Credential Request Patterns",
                "severity": "high",
                "reason": "Email solicits sensitive banking credentials, wire transfers, direct deposits, or authentication secrets.",
                "evidence": f"Matched terms: {', '.join(fin_matches[:3])}"
            })

        # 6. ML Model Signal Integration
        ml_pred = ml_result.get("prediction", "unknown")
        ml_conf = ml_result.get("confidence", 0.0)
        
        if ml_pred == "phishing":
            ml_impact = int(25 * ml_conf)
            raw_score += ml_impact
            findings.append({
                "indicator": f"ML Model Phishing Classification (Confidence: {ml_conf*100:.1f}%)",
                "severity": "high" if ml_conf > 0.75 else "medium",
                "reason": "Supervised NLP classifier detected lexical patterns and semantic features consistent with known phishing campaigns.",
                "evidence": f"Model: {ml_result.get('model_name', 'TF-IDF LogisticRegression')}, Probs: {ml_result.get('probabilities')}"
            })
        elif ml_pred == "spam":
            raw_score += int(15 * ml_conf)
            findings.append({
                "indicator": f"ML Model Spam Classification (Confidence: {ml_conf*100:.1f}%)",
                "severity": "medium",
                "reason": "Classifier detected bulk marketing / spam vocabulary structures.",
                "evidence": f"Model: {ml_result.get('model_name', 'TF-IDF LogisticRegression')}"
            })
        elif ml_pred == "legitimate":
            # Attenuate score for clean NLP
            raw_score -= int(10 * ml_conf)

        # 7. Normalize Risk Score (0 - 100 range)
        final_score = max(0, min(100, raw_score))

        # Risk Level Categorization
        if final_score >= 80:
            risk_level = "CRITICAL"
        elif final_score >= 60:
            risk_level = "HIGH"
        elif final_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Generate Explainable Executive Summary
        if not findings:
            executive_summary = "The email exhibits standard operational characteristics with verified or benign envelope structures and clean body contents. No significant threat indicators were identified."
        else:
            reasons_summary = [f['indicator'] for f in findings[:3]]
            executive_summary = (
                f"Assessed as {risk_level} risk (score: {final_score}/100). "
                f"Primary indicators observed include: {'; '.join(reasons_summary)}. "
                f"Available evidence suggests caution when interacting with links or attachments."
            )

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "findings": findings,
            "executive_summary": executive_summary,
            "signals_evaluated": {
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
                "suspicious_url_count": len(suspicious_urls),
                "attachment_count": len(attachment_analyses),
                "ml_prediction": ml_pred,
                "ml_confidence": ml_conf
            }
        }
