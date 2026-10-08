"""
Generates a realistic labelled dataset for email phishing and legitimate detection.
Dataset covers realistic security scenarios:
- Legitimate corporate, transactional, newsletter, personal emails
- Phishing: Credential harvest, urgent banking/payroll fraud, CEO fraud/BEC, fake invoices, crypto scam
- Spam: Generic marketing, fake lottery, weight loss spam
"""
import csv
import os

DATASET_PATH = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")

SAMPLES = [
    # Legitimate (Ham)
    ("legitimate", "Weekly Engineering Standup Notes", "Hi team, attached are the notes from today's sprint review. Let us know if you have questions regarding the Q3 roadmap."),
    ("legitimate", "Your Monthly AWS Billing Statement", "Your AWS monthly invoice for account 1234-5678-9012 is now available in the AWS Billing Console. Total charged: $42.50."),
    ("legitimate", "Pull Request #412 Approved", "User alice has approved your pull request 'fix: fix authentication middleware header parsing' on GitHub."),
    ("legitimate", "Lunch reservation confirmed at Bistro Verde", "Your table for 4 at Bistro Verde is confirmed for Friday Oct 12 at 7:30 PM. Click to modify if needed."),
    ("legitimate", "System maintenance scheduled for Sunday 02:00 UTC", "Dear customer, our internal database services will undergo routine maintenance this Sunday. Minimal downtime is expected."),
    ("legitimate", "University Seminar on Distributed Systems", "Dear Students, Professor Miller will host a guest lecture on Byzantine fault tolerance this Thursday in Hall B."),
    ("legitimate", "Welcome to Spotify Premium", "Thanks for joining Spotify Premium! You can now listen offline, skip tracks without limits, and enjoy high quality audio."),
    ("legitimate", "Flight Itinerary: SFO to JFK", "Your flight reservation with Delta Airlines is confirmed. Confirmation code: DL892A. Check-in opens 24 hours before departure."),
    ("legitimate", "Invoice #8910 payment received", "Thank you for your payment of $120.00 for order #8910. Your receipt is attached for your records."),
    ("legitimate", "Team Offsite Agenda & Dietary Preferences", "Hi everyone, please submit your meal preferences for next month's company offsite before end of day Wednesday."),
    ("legitimate", "Package delivered to your front door", "Your package from UPS has been delivered to your front porch. Tracking number 1Z9999999999999999."),
    ("legitimate", "Google Workspace Security Alert: New Device Sign-in", "Your Google Account was accessed from a new Windows device. If this was you, you don't need to do anything."),
    ("legitimate", "Quarterly Financial Review Meeting Link", "Join Zoom Meeting for Q4 review at 10:00 AM EST. The financial deck is uploaded to our internal SharePoint."),
    ("legitimate", "HR Update: Open Enrollment for Health Benefits", "Annual open enrollment begins next week. Please review your benefit elections in Workday before November 15."),
    ("legitimate", "GitLab: Pipeline #8812 passed for main branch", "Pipeline #8812 passed successfully for commit 'add integration tests'. Duration: 4 minutes 12 seconds."),

    # Phishing
    ("phishing", "URGENT: Your Office 365 Account is Suspended", "Immediate action required! Your Microsoft 365 access will be permanently disabled within 24 hours. Verify your login credentials immediately at http://login-microsoft-security-auth-check.xyz/login to retain access."),
    ("phishing", "Action Required: Payroll Direct Deposit Verification Failed", "Your monthly salary deposit could not be processed due to incorrect banking details. Enter your SSN and bank password at http://payroll-portal-verification-update.top/account immediately to avoid payment hold."),
    ("phishing", "CRITICAL SECURITY NOTICE: Unauthorized Access Detected", "We detected abnormal login attempts from Moscow, Russia. If this was not you, reset your password and verify two-factor authentication now: http://192.168.1.100:8080/secure-auth-reset"),
    ("phishing", "PayPal: Suspicious transaction of $849.99 on your card", "A payment of $849.99 to BestBuy has been authorized. If you did not make this purchase, click here immediately http://paypal-dispute-resolution-center.online/cancel to cancel the transaction and secure your wallet."),
    ("phishing", "IRS Tax Refund Notice: You have an unclaimed refund of $1,420.00", "Internal Revenue Service notification: You are eligible for an immediate tax rebate. Submit your credit card details and identity verification documents at http://irs-gov-refund-portal.support/claim to receive funds."),
    ("phishing", "CEO Request: Urgent Wire Transfer Needed ASAP", "Are you at your desk? I need an urgent wire transfer executed for vendor acquisition before 3 PM. Keep this confidential. Reply with confirmation so I can send the bank coordinates."),
    ("phishing", "DocuSign: Please review and sign Employment Termination Agreement", "You have received an urgent document for electronic signature. Click http://docusign-secure-document-sign-view.biz/envelope/9941 to review and sign immediately. Failure to sign may result in disciplinary action."),
    ("phishing", "DHL Express: Delivery Failed - Address Update Required", "Your parcel could not be delivered due to an incomplete delivery address. Pay the $2.99 redelivery fee and update your shipping address within 12 hours at http://dhl-express-parcel-tracking-update.club/track."),
    ("phishing", "Netflix: Your membership has been put on hold", "We were unable to process your monthly payment method. Update your billing credentials immediately at http://netflix-member-renew-service.info to keep watching."),
    ("phishing", "IT Department: Mandatory Password Expiration Warning", "Your corporate network password expires today in 3 hours. Re-authenticate with your existing corporate password at http://it-helpdesk-password-reset-portal.live/sso to prevent account lockout."),
    ("phishing", "Bank of America: Security Alert - Wire Transfer Pending", "A pending wire transfer of $5,000.00 requires your verification. If you did not authorize this wire, log in at http://bankofamerica-anti-fraud-login.cc/secure to cancel immediately."),
    ("phishing", "Metamask Wallet: Secret Recovery Phrase Verification", "Due to new Ethereum smart contract regulations, all decentralized wallets must verify their 12-word seed phrase at http://metamask-security-vault-kyc.io/phrase to prevent token burn."),
    ("phishing", "Internal HR: COVID-19 Bonus Distribution", "Executive management has authorized a special one-time retention bonus. Review your payment schedule and enter your personal details at http://hr-employee-bonus-claim.link/bonus."),
    ("phishing", "Dropbox: Shared Financial Audit Statement 2026.pdf.exe", "Accountant has shared confidential financial report with you. Download and execute file to view financial balance sheet at http://dropbox-secure-cloud-viewer.click/file"),
    ("phishing", "Amazon Account Locked: Order #981-2291 Suspended", "Your Amazon account has been temporarily locked due to billing address mismatch. Unlock your account and confirm your credit card at http://amazon-security-account-unlock.website/auth."),

    # Spam
    ("spam", "Lose 20 lbs in 2 weeks with this miracle fruit!", "Doctors hate this secret pill! Burn fat without diet or exercise. Order today and get 70% off free shipping! Limited bottles remaining in stock!"),
    ("spam", "You have won $10,000,000 in the UK National Lottery", "Congratulations! Your email address was selected in the international lottery drawing. Send your passport copy and $50 processing fee to claim your prize!"),
    ("spam", "Lowest Mortgage Rates Guaranteed - Refinance Today", "Act fast! Record low interest rates available for homeowner refinancing. Get pre-approved in 60 seconds with no credit check required."),
    ("spam", "Exclusive luxury watches at 95% discount", "Rolex, Omega, Breitling replicas with Swiss movement. Buy 1 get 2 free for today only! Free international delivery."),
    ("spam", "Earn $500/day working 1 hour from home", "Simple data entry work from home opportunity. No skills required. Thousands of students and stay-at-home parents already earning.")
]

def generate_dataset():
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    with open(DATASET_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["label", "subject", "body"])
        for label, subject, body in SAMPLES:
            writer.writerow([label, subject, body])
    print(f"Generated {len(SAMPLES)} samples in {DATASET_PATH}")

if __name__ == "__main__":
    generate_dataset()
