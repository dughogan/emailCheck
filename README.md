# **Email Verification Tool**

## **Description**

The Email Verification Tool is a Python script designed to analyze `.eml` files for potential red flags that indicate phishing or spamming activities. It scans through various parts of the email structure and provides a legitimacy score ranging from 0 to 100, where 100 means the email passed all red flag checks. IT's recommended additional tools be used to measure email validation since it can be quite a nuanced analysis at times.

## **How To Use**

1. **Clone** this repository to your local machine.
2. **Open** a terminal and navigate to the project folder.
3. **Run** the script by typing `python main.py` or `python3 main.py` depending on your Python installation.
4. The program will **prompt** you to enter the path to the `.eml` file you wish to investigate.
5. Once entered, the program will execute the red flag checks and display a score.

## **Red Flag Checks**

The tool checks for the following red flags:

### **SPF Neutral Test**
- **Why it matters**: SPF (Sender Policy Framework) is used to prevent email spoofing. A neutral test result may indicate that the email could be spoofed.

### **Unfamiliar IP Addresses**
- **Why it matters**: Unfamiliar or private/reserved IPs in the email header may be a sign of malicious activity.

### **Inconsistent Timing and Timezones**
- **Why it matters**: Inconsistency in timing and time zones between server hops may indicate that the email was rerouted through various locations to mask its origin.

### **Generic or Unusual Server Names**
- **Why it matters**: Names like `server1`, `server2`, etc., in the email header may indicate that the email is passing through a temporary or malicious server.

### **Number of Transfers Between Servers**
- **Why it matters**: A high number of server transfers can indicate that the email is being rerouted multiple times, possibly to mask its true origin.

### **X-Gmail-Fetch-Info**
- **Why it matters**: The presence of this header can be a sign that the email was fetched by a Gmail account, which could be unusual depending on the context.

### **Content Type Check for multipart/alternative**
- **Why it matters**: The `multipart/alternative` content type can be used to serve different versions of the email to bypass spam filters.

### **Unusual Sender Domain**
- **Why it matters**: Domains with words like "store" or "shop" may be attempting to imitate legitimate businesses.

## **Score Interpretation**

- `0-20`: **Highly suspicious**, likely a scam or phishing email.
- `21-40`: **Suspicious**, proceed with caution.
- `41-60`: **Moderate**, may require further verification.
- `61-80`: **Likely safe**, but stay cautious.
- `81-100`: **Highly likely** to be a legitimate email.
