import smtplib

EMAIL = "eyesofegale01@gmail.com"
APP_PASSWORD = "ssjvagchbiwfralc"

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL, APP_PASSWORD)
    print("✅ Gmail SMTP Login Success")
except Exception as e:
    print("❌ SMTP Error:", e)
