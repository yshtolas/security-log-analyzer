import ipaddress
import sys

FAILED_LOGIN_THRESHOLD = 3

def analyze_log(log_file_name):
    
    failed_attempts = {}
    failed_usernames = {}

    try:
        with open(log_file_name, "r") as file:

            for line in file:
                
                if "failed password" in line.lower():
                    sep_words = line.split()

                    username = None

                    if "for" in sep_words:
                        user_position = sep_words.index("for")

                        if user_position + 1 < len(sep_words):

                            if (
                                user_position + 3 < len(sep_words) 
                                and sep_words[user_position + 1] == "invalid" 
                                and sep_words[user_position + 2] == "user" 
                                and sep_words[user_position + 3] != "from"
                            ):
                                username = sep_words[user_position + 3]

                            elif sep_words[user_position + 1] != "invalid" and sep_words[user_position + 1] != "from":
                                username = sep_words[user_position + 1]
                    
                    if "from" in sep_words:
                        position = sep_words.index("from")
                        
                        if position + 1 < len(sep_words):
                            ip_address = sep_words[position + 1]

                            try:
                                ipaddress.ip_address(ip_address)
                            except ValueError:
                                continue

                            failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1

                            if username is not None:
                                failed_usernames[username] = failed_usernames.get(username, 0) + 1
                                    

    except FileNotFoundError:
        print(f"ERROR: {log_file_name} not found.")
        sys.exit(1)

    return failed_attempts, failed_usernames

def display_results(failed_attempts, failed_usernames):

    print("Failed login attempts:")
    for ip, count in failed_attempts.items():
        word = "attempt" if count == 1 else "attempts"
        print(f" - {ip}: {count} failed {word}")

    if not failed_attempts:
        print("No failed login attempts found.")

    print("\nFailed login attempts by username:")

    for username, count in failed_usernames.items():
        word = "attempt" if count == 1 else "attempts"
        print(f" - {username}: {count} failed {word}")

    if not failed_usernames:
        print("No valid usernames found.")

    print(f"Total failed login attempts: {sum(failed_attempts.values())}")

    suspicious_count = 0

    for ip, count in failed_attempts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            print(f"WARNING: Suspicious login activity detected from {ip}")
            suspicious_count += 1

    if suspicious_count == 0:
        print("No suspicious activity detected.")

    print(f"Total suspicious IP addresses: {suspicious_count}")

    return suspicious_count

def generate_report(failed_attempts, failed_usernames, suspicious_count):

    with open("security_report.txt", "w") as report:
    
        report.write("Security Log Analysis Report\n\n")

        report.write("=== Failed Login Attempts ===\n")
        for ip, count in failed_attempts.items():
            word = "attempt" if count == 1 else "attempts"
            report.write(f" - {ip}: {count} failed {word}\n")

        if not failed_attempts:
            report.write("No failed login attempts found.\n")

        report.write("\n=== Failed Login Attempts by Username ===\n")
        for username, count in failed_usernames.items():
            word = "attempt" if count == 1 else "attempts"
            report.write(f" - {username}: {count} failed {word}\n")

        if not failed_usernames:
            report.write("No valid usernames found.\n")
        
        report.write("\n=== Suspicious Activity ===\n")
        for ip, count in failed_attempts.items():
            if count >= FAILED_LOGIN_THRESHOLD:
                report.write(f"WARNING: Suspicious login activity detected from {ip}\n")

        if suspicious_count == 0:
            report.write("No suspicious activity detected.\n")

        report.write("\n=== Summary ===\n")
        report.write(f"Total failed login attempts: {sum(failed_attempts.values())}\n")
        report.write(f"Total suspicious IP addresses: {suspicious_count}\n")

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("ERROR: Please provide a log filename.")
        sys.exit(1)

    if len(sys.argv) > 2:
        print("ERROR: Please provide only one log filename.")
        sys.exit(1)

    log_file_name = sys.argv[1]

    failed_attempts, failed_usernames = analyze_log(log_file_name)

    suspicious_count = display_results(failed_attempts, failed_usernames)

    generate_report(failed_attempts, failed_usernames, suspicious_count)