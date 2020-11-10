import pyshark
from elevate import elevate
import sys

# elevate()

path = sys.path()

def capturing_to_file(path):
    cap = pyshark.LiveCapture(interface='ens33',
                              output_file=path)
    print("I've just started to sniff your traffic")
    cap.sniff(timeout=10)
    print(cap)
    # if len(cap) > 0:
    #     print(cap[0])


def sniffing_from_file(path):
    cap1 = pyshark.FileCapture(path)
    # first_packet = cap1[0]
    # print(first_packet)
    for pkt in cap1:
        print(pkt)


# capturing_to_file('/home/vlada/Documents/my_cap.cap')
sniffing_from_file('/home/vlada/Documents/my_cap.cap')
