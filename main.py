import json
import os

# cmd = 'sudo apt install nftables'  - ???

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
