import pyshark
from elevate import elevate
import netifaces
import sys

# we need a path to directory where our files will be stored:
path_to_dir = sys.path[0]


# here we capture the traffic, write it into file and print first packet (optional)
def capturing_to_file(file):
    elevate()
    print("I've just started to sniff your traffic")
    interfaces = netifaces.interfaces()  # a list of interfaces (make a function that will be output the list to user
    cap = pyshark.LiveCapture(interface=interfaces[1],
                              output_file=file)
    cap.sniff(timeout=10)
    # if len(cap) > 0:
    #     print(cap[0])


# the function prints captured traffic from file
def sniffing_from_file(file):
    print(file)
    cap1 = pyshark.FileCapture(file)
    # first_packet = cap1[0]
    # print(first_packet)
    for pkt in cap1:
        print(pkt)


# capturing_to_file(path_to_dir + '/my_cap.cap')
# sniffing_from_file(path_to_dir + '/my_cap.cap')
