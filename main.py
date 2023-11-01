import email
import os
from email.header import decode_header
from datetime import datetime
import re
from ipaddress import ip_address


def check_spf_neutral(lines):
    for line in lines:
        if "Received-SPF: neutral" in line:
            return True
    return False


def check_unfamiliar_ip(lines):
    for line in lines:
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
        if ip_match:
            ip = ip_address(ip_match.group())
            if ip.is_private or ip.is_reserved:
                return True
    return False


def check_inconsistent_timing(lines):
    dates = []
    for line in lines:
        if line.startswith("Date:"):
            try:
                date_str = line.split(":", 1)[1].strip()
                date_obj = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
                dates.append(date_obj)
            except Exception as e:
                print(f"Could not parse date: {e}")
                continue
    if len(dates) >= 2:
        return dates[-1] < dates[-2]
    return False


def check_generic_server_names(lines):
    for line in lines:
        if "Received: from" in line:
            server_name = line.split(" ")[2]
            if re.match(r"server\d+", server_name):
                return True
    return False


def check_num_transfers(lines):
    count = 0
    for line in lines:
        if "Received: from" in line:
            count += 1
    return count > 5


def check_x_gmail_fetch(lines):
    for line in lines:
        if "X-Gmail-Fetch-Info" in line:
            return True
    return False


def check_content_type(lines):
    for line in lines:
        if "Content-Type: multipart/alternative" in line:
            return True
    return False


def check_unusual_sender_domain(lines):
    for line in lines:
        if "From:" in line:
            parts = line.split('@')
            if len(parts) > 1:
                domain = parts[1].strip()
                if "store" in domain or "shop" in domain:
                    return True
    return False


def analyze_eml_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    total_checks = 0
    passed_checks = 0
    checks = {
        "SPF neutral test": check_spf_neutral,
        #"Unfamiliar IP addresses": check_unfamiliar_ip,
        "Inconsistent timing and timezones": check_inconsistent_timing,
        "Generic or unusual server names": check_generic_server_names,
        "Number of transfers between servers": check_num_transfers,
        #"X-Gmail-Fetch-Info": check_x_gmail_fetch,
        #"Content type check for multipart/alternative": check_content_type,
        "Unusual sender domain": check_unusual_sender_domain,
    }

    for check_name, check_func in checks.items():
        total_checks += 1
        if not check_func(lines):
            print(f"{check_name}: Passed")
            passed_checks += 1
        else:
            print(f"{check_name}: Failed")

    score = (passed_checks / total_checks) * 100
    return score


if __name__ == '__main__':
    while True:
        eml_file_path = input("Please enter the path to the .eml file to investigate (or type 'exit' to quit): ")

        if eml_file_path.lower() == 'exit':
            print("Exiting the program.")
            break

        if not os.path.exists(eml_file_path):
            print(f"{eml_file_path} does not exist!")
        else:
            score = analyze_eml_file(eml_file_path)
            print(f"\nThe email has a legitimacy score of {score:.2f}/100.")
