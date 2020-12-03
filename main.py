import sys
from sniffing import sniffing_from_file, capturing_to_file
from firewall import package_filter, take_address
from antivirus import show_result, report_info, scanning
import os

path_to_dir = sys.path[0]

'''Sniffer'''
# to install tshark
# cmd = 'sudo apt install tshark'
# os.system(cmd)

# sniffing_from_file(path_to_dir + '/my_cap.cap')
# capturing_to_file(path_to_dir + '/my_cap.cap')

'''Firewall'''
# here we need to call firewall functions
# package_filter(ip=take_address('scanme.nmap.org'), chain='OUTPUT', action=1)

# to save iptables state
# cmd = 'sudo /sbin/iptables-save'

'''Antivirus'''
# here you write the name of file and scan it and then you will see the result of the scanning
# path_to_file = path_to_dir + '/mal.exe'
# report_info(scanning(path_to_file))
# show_result()


if __name__ == '__main__':
    pass
