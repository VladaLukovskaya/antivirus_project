import iptc
from elevate import elevate
import sqlite3

# elevate()

conn = sqlite3.connect('malware_sites.db')
cursor = conn.cursor()


# a function that filters all the packages
def package_filter(interface, chain, action, protocol=None, source_ip=None, destination_ip=None,
                   dest_port=None):
    iptb_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain)  # chains: INPUT, OUTPUT, FORWARD
    rule = iptc.Rule()
    rule.in_interface = interface  # interfaces: lo, ens33, ens38
    action = int(action)
    if action == 1:
        target = iptc.Target(rule, 'DROP')
        rule.target = target
    elif action == 2:
        target = iptc.Target(rule, 'ACCEPT')
        rule.target = target
    elif action == 3:
        target = iptc.Target(rule, 'REJECT')
        rule.target = target
    elif action == 4:
        target = iptc.Target(rule, 'LOG')
        rule.target = target
    else:
        print('You have to choose the action.')
    if source_ip:
        rule.src = source_ip
    if destination_ip:
        rule.dst = destination_ip
    if protocol and chain == 'INPUT':
        rule.protocol = protocol
        match = iptc.Match(rule, "tcp")
        match.dport = dest_port
        rule.add_match(match)
    # if chain == 'INPUT':
    #     rule.src = source_ip
    # elif chain == 'OUTPUT':
    #     rule.dst = destination_ip
    # else:
    #     pass
    iptb_chain.insert_rule(rule)


# that function inserts new values (a malware site and its address) into table
def insert_new_record(name, address):
    cursor.execute('''INSERT INTO blocked_sites VALUES (?, ?)''', (name, address))
    conn.commit()


def new_record():
    

# insert_new_record('terrifying.site', '10.0.0.1')

# here I open the json file of blocked sites and then i print all its elements
# blocked_sites = open('blocked_addresses.json', 'r')
# print(blocked_sites)

# with open('blocked_addresses.json', 'r') as blocked_sites:
#     # addresses = list(blocked_sites)
#     for elem in blocked_sites:
#         print(elem)
#     # print(addresses)

# boo = iptc.easy.dump_table('filter')
# print(boo)
#
# package_filter(interface='ens38', chain='INPUT', action=1, protocol='tcp',
#                source_ip='192.168.134.128', dest_port='80')
#
# foo = iptc.easy.dump_table('filter')
# print(foo)

# cursor.execute('''CREATE TABLE blocked_sites (name text, address text)''')
# conn.commit()
sites = [('malware.ru', '192.168.134.128'),
         ('fishing.com', '192.168.134.135'),
         ('scanme.nmap.org', '45.33.32.156')]

# cursor.executemany("INSERT INTO blocked_sites VALUES (?,?)", sites)
# conn.commit()

for row in cursor.execute('''SELECT * FROM blocked_sites ORDER BY name'''):
    print(row)
