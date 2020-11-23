
# Parse protocol data from nfdump csv
import math
import csv
import sys

class protocol_dictionary(dict):

    def __init__(self):
        self = dict()

    def add(self, key, value):
        self[key] = value

protocols = protocol_dictionary()

# Only print IP related protocols
ip_check = False
ipv6_check = False
flow_total = 0
pkt_total = 0
with open(sys.argv[1]) as fp:
   line = fp.readline()
   while line:
       if len(line.split()) > 1 and "No" not in line.split()[0]:
          current_line = line.split(",")
          name = current_line[3]
          flow_total += int(current_line[5])
          pkt_total += int(current_line[7])

          if name in protocols:
                  flow_val = int(current_line[5]) + int((protocols.get(name))[0])
                  pkt_val = int(current_line[7]) + int((protocols.get(name))[1])
                  d1 = {name: [flow_val, pkt_val]}
                  protocols.update(d1)
          elif name not in protocols:
                  protocols.add(name,[int(current_line[5]),int(current_line[7])])


       line = fp.readline()

print("protocol,flows,flow_percentage,packets,packet_percentage")
for key in protocols:
    print(key, end=",")
    print(protocols.get(key)[0], end=",")
    print('%.6f'%(protocols.get(key)[0]/flow_total), end=",")
    print(protocols.get(key)[1], end=",")
    print('%.6f'%(protocols.get(key)[1]/pkt_total))