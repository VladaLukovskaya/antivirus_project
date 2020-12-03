import iptc
from elevate import elevate
import sqlite3

conn = sqlite3.connect('malware_sites.db')
cursor = conn.cursor()


# a function that filters all packages
def package_filter(ip, chain, action):
    iptb_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain)  # chains: INPUT, OUTPUT, FORWARD
    rule = iptc.Rule()
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
    if chain == 'INPUT':
        print('inp')
        rule.src = ip
    elif chain == 'OUTPUT':
        print('out')
        rule.dst = ip
    else:
        pass
    iptb_chain.insert_rule(rule)


# that function inserts new values (a malware site and its address) into table
def insert_new_record(name, address):
    cursor.execute('''INSERT INTO blocked_sites VALUES (?, ?)''', (name, address))
    conn.commit()


# that function shows all table entries
def show_all_records():
    for row in cursor.execute('''SELECT * FROM blocked_sites ORDER BY name'''):
        print(row)
    conn.commit()


def take_address(address_name):
    for row in cursor.execute('''SELECT address FROM blocked_sites WHERE name=(?)''', (address_name,)):
        return row[0]
    conn.commit()


def delete_records():
    cursor.execute('''DELETE FROM blocked_sites WHERE name="malware.ru"''')
    conn.commit()


sites = [('malware.ru', '192.168.134.128'),
         ('fishing.com', '192.168.134.135'),
         ('scanme.nmap.org', '45.33.32.156')]


# the first time we run this app:
# cursor.execute('''CREATE TABLE blocked_sites (name text, address text)''')
# cursor.executemany("INSERT INTO blocked_sites VALUES (?,?)", sites)
# conn.commit()
#
# show_all_records()
# delete_records()

'''Here we output table Filter from iptables, then we use packet filter 
(we write address and action that we want to do)
Then we output Filter again to see if it changed:'''
# elevate()
# show_table = iptc.easy.dump_table('filter')
# print(show_table)
#
# package_filter(ip=take_address('scanme.nmap.org'), chain='OUTPUT', action=1)
#
# print(show_table)
