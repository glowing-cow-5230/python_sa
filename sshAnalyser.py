import re
from collections import defaultdict
import ipaddress
import csv

# Define the log file path
log_file_path = "auth.log"

# Define unusual IP ranges in CIDR notation
unusual_ip_ranges = ['179.39.0.0/16', '52.32.226.0/24'] 
unusual_hours = range(0, 6)  # Example: 12 AM to 6 AM
unusual_hour_logins = defaultdict(int)

# Convert CIDR blocks to ipaddress.IPv4Network objects for easy checking
unusual_networks = [ipaddress.ip_network(cidr) for cidr in unusual_ip_ranges]

# Initialize counters and storage
# Use defaultdict to initialise any new keys to 0
invalid_login_ip = defaultdict(int)
invalid_login_user = defaultdict(int)
successful_login_ip = defaultdict(int)
successful_login_user = defaultdict(int)
preauth_disconnect_ip = defaultdict(int)
unusual_ips = set()

# Compile regex patterns to search for specific log events

# -- Invalid User Event --
# An ssh server may log invalid username attempts
# Exmaple invalid user event: Jan 11 10:22:56 ip-172-31-1-163 sshd[2363]: Invalid user ubnt from 179.39.2.133
# Below regex will extract the match groups 'user' and 'ip'
invalid_user_pattern = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)')

# -- Successful Login (publickey) Event --
# An ssh server may log successful authentication using an accepted method, such as publickey authentication
# Exmaple login event: Jan 11 12:07:15 ip-172-31-1-163 sshd[2434]: Accepted publickey for ubuntu from 208.167.254.47 port 49268 ssh2: RSA 0a:78:92:3c:c8:27:13:d3:f7:ee:d5:ac:75:45:31:5c
# Below regex will extract the match groups 'user' and 'ip'
# -----------------------
# -- Student Code Here --
# -----------------------
# See [1] below: Optional regex approach to extracting the Successful Login (publickey) Event
success_pk_pattern = re.compile(r'-- Student Regex Here --')

# -- Preauth Failure Event--
# An ssh server may disconnect a client after a timeout if they do not supply a password (pre-authenticated)
# Received disconnect from 121.18.238.114: 11:  [preauth]
# Below regex will extract the match group 'ip''
preauth_pattern = re.compile(r'Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[preauth\]')


# Check if the supplied IP address is in the IP range provided by the CIDR
# returns true if in one of the ranges, false if not
def is_ip_unusual(ip_address):
    ip_obj = ipaddress.ip_address(ip_address)
    for network in unusual_networks:
        if ip_obj in network:
            return True
    return False


# Open the log file and check for matches
with open(log_file_path, 'r') as log_file:
    for line in log_file:

        # Check if the line matches any of the desired regex cases
        match_invalid_user = invalid_user_pattern.search(line)
        match_pk = success_pk_pattern.search(line)
        match_preauth = preauth_pattern.search(line)

        # If there are regex matches for invalid users, process the event
        if (match_invalid_user):
            ip = match_invalid_user.group('ip')
            user = match_invalid_user.group('user')

            # store the ip in the invalid_login_ip Dictionary
            # invalid_login_ip = {'ip1':count1, 'ip2':count2, etc}
            invalid_login_ip[ip] += 1

            # store the user in the invalid_login_user Dictionary
            # invalid_login_user = {'alice':1, 'bob':2, etc}
            invalid_login_user[user] += 1
            if is_ip_unusual(ip):
                unusual_ips.add(ip)

        # If there are regex matches for preauth disconnects, process the event
        elif (match_preauth):
            ip = match_preauth.group('ip')
            # store the ip in the preauth_disconnect_ip Dictionary
            # preauth_disconnect_ip = {'ip1':count1, 'ip2':count2, etc}
            preauth_disconnect_ip[ip] += 1

            # use the is_ip_unusual(ip_address) function to check if the ip is in the unusual_ip_ranges
            if is_ip_unusual(ip):
                # if it is, add the ip to the unusual_ips Set object (see https://www.w3schools.com/python/python_sets.asp)
                unusual_ips.add(ip)

        # -----------------------
        # -- Student Code Here --
        # -----------------------
        # [1] Students must construct their own logic to match a successful publickey authentication event
        #     Student can either modify the regex above or can use other logic of their own choosing to filter
        #     their way down to appropriate events
        #     e.g. 
        #       elif "publickey" in line:
        #           if "Some other string" in line:
        #               ip = extract_ip(line)
        #
        elif (match_pk):
            # [2] Students should create own logic to extract the ip and user from the event
            ip = "0.0.0.0"
            user = "placeholder"
            successful_login_ip[ip] += 1
            successful_login_user[user] += 1

            if is_ip_unusual(ip):
                unusual_ips.add(ip)

            # [3] Students should create own logic to extract the timestamp from the event
            time = "99:99:99"
            hour = int(time.split(":")[0])
            if hour in unusual_hours:
                unusual_hour_logins[user] += 1


# Print analysis results
print("SSH Log Analysis Results:")

# Print the total number of attempted invalid logins
# -----------------------
# -- Student Code Here --
# -----------------------
#
# [4] Write your own logic to sum the total invalid user attempts
#     store the result in 'total_invalid_user_attempts' as an int
total_invalid_user_attempts = 0
print(f"Total Invalid Login Attempts: {total_invalid_user_attempts}")

# Print the ip of the highest number of attempts
most_invalid_ip = ""
most_invalid_ip_count = 0
# -----------------------
# -- Student Code Here --
# -----------------------
#
# [5] Write your own logic to determine which source ip attempted the most logins
#     store the result in 'most_invalid_ip' as a string
#     store the number of attempts from this ip in 'most_invalid_ip_count' as an int
print(f"Most Invalid Login Attempts (IP): {most_invalid_ip} with {most_invalid_ip_count} attempts.")

# Print the highest attempted username
most_invalid_user = ""
most_invalid_user_count = 0
# -----------------------
# -- Student Code Here --
# -----------------------
#
# [6] Write your own logic to determine which user name was most attempted
#     store the result in 'most_invalid_user' as a string
#     store the number of attempts against this user in 'most_invalid_user_count' as an int
print(f"Most Invalid Login Attempts (User): {most_invalid_user} with {most_invalid_user_count} attempts.")

# Print any unusual IPs
print(f"Unusual IPs: {list(unusual_ips)}")

# Print the names of successful logon users
print(f"Successful Logins By: {list(successful_login_user.keys())}")

# Print the number of unusual hour logons and total successful logins
unusual_hour_logins_count = sum(unusual_hour_logins.values())
print(f"Unusual Hour Logins: {unusual_hour_logins_count}")

# -----------------------
# -- Student Code Here --
# -----------------------
#
# [7] Write your own logic to output the total number of invalid attempts per IP to a csv file
#     The csv file should have the format:
#     ip,count
#     1.1.1.1,99
#     2.2.2.2,30
#     
#     The output file should be named "invalid_logins_by_ip.csv"
#     retain the below options for the output file (i.e. newline='', encoding='utf-8')
outfile = 'invalid_logins_by_ip.csv'
with open(outfile,'w', newline='', encoding='utf-8') as f:
    # write the output

    print(f"Output: {outfile}")