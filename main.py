import json
import sys
from sniffing import sniffing_from_file, capturing_to_file
import os

path_to_dir = sys.path[0]

# sniffing_from_file(path_to_dir + '/my_cap.cap')
# capturing_to_file(path_to_dir + '/my_cap.cap')

# cmd = 'sudo apt install tshark'
# os.system(cmd)

# here we need to call firewall functions


# to save iptables state
# cmd = 'sudo /sbin/iptables-save'

file = open(file='firewall_rules')
rule = json.load(file)
file.close()

print(rule)
denied_addr = rule['ListOfBannedIpAddr']
denied_ports = rule['ListOfBannedPorts']
denied_prefixes = rule['ListOfBannedPrefixes']

print('Denied addresses:', denied_addr)
print('Denied ports:', denied_ports)
print('Denied prefixes:', denied_prefixes)

if __name__ == '__main__':
    pass
