# Parse protocol data results
# Output protocol percentages per router, unusual protocols, and unique protocols
import math
import csv

def removeItem(item_list, item):
    answer = []
    for i in item_list:
        if i!=item:
            answer.append(i)
    return answer


class protocol_dictionary(dict): 
  
    def __init__(self): 
        self = dict() 
          
    def add(self, key, value): 
        self[key] = value 

class router_dictionary(dict): 
  
    def __init__(self): 
        self = dict() 
          
    def add(self, key, value): 
        self[key] = value

# dictionary of routers, key = router name, value = dictionary of protocols
routers = router_dictionary() 
protocols = protocol_dictionary()
temp_protocols = protocol_dictionary()
#print(protocols) 


# Only print IP related protocols
ip_check = False
ipv6_check = False
first_router = True
prev_name = ""
flow_total = 0
packet_total = 0
temp_flow_total = 0
temp_packet_total = 0

with open('router_results3.txt') as fp:
   line = fp.readline()
   while line:
       current_router = ""
       current_line = line.split(",")
       if line[0] == '/':
           # add final router protocol dict if this is not the first
           if first_router == False and current_line[len(current_line)-1] != prev_name:
               d1 = {prev_name: [temp_protocols,temp_flow_total,temp_packet_total]}
               routers.update(d1)
               temp_protocols = protocol_dictionary()
               temp_protocols.clear()
               temp_flow_total = 0
               temp_packet_total = 0
           first_router = False

           
           name = current_line[len(current_line)-1]
           prev_name = name
           current_router = name
           if name not in routers:
                  # router name, protocols, flow_total, packet_total
                  routers.add(name,[protocol_dictionary(),0,0])
       elif "," in line and current_line[0] != "protocol":
           if current_line[0] in protocols and current_line[0] != None:
                  flow_total += int(current_line[1])
                  packet_total += int(current_line[3])
                  flow_val = int(current_line[1]) + int((protocols.get(current_line[0]))[0])
                  packet_val = int(current_line[3]) + int((protocols.get(current_line[0]))[1])
                  d1 = {current_line[0]: [flow_val, packet_val]}
                  protocols.update(d1)
           elif current_line[0] not in protocols:
                  protocols.add(current_line[0],[int(current_line[1]),int(current_line[3])])
                  flow_total += int(current_line[1])
                  packet_total += int(current_line[3])

           if current_line[0] in temp_protocols and current_line[0] != None:
                  temp_flow_total += int(current_line[1])
                  temp_packet_total += int(current_line[3])
                  flow_val = int(current_line[1]) + int((temp_protocols.get(current_line[0]))[0])
                  packet_val = int(current_line[3]) + int((temp_protocols.get(current_line[0]))[1])
                  d1 = {current_line[0]: [flow_val, packet_val]}
                  temp_protocols.update(d1)
           elif current_line[0] not in temp_protocols:
                  temp_protocols.add(current_line[0],[int(current_line[1]),int(current_line[3])])
                  temp_flow_total += int(current_line[1])
                  temp_packet_total += int(current_line[3])
       line = fp.readline()

if first_router == False:
    d1 = {prev_name: [temp_protocols,temp_flow_total,temp_packet_total]}
    routers.update(d1)       

print("protocol flow_total packet_total flow_percentage packet_percentage")
print("--------------------------------------------")
print("all routers")
print("--------------------------------------------")

for key in protocols:
    print(key, protocols.get(key)[0],protocols.get(key)[1], "{0:.5%}".format(protocols.get(key)[0]/flow_total),"{0:.5%}".format(protocols.get(key)[1]/packet_total))

print()
print("--------------------------------------------")
print("per router")
print("--------------------------------------------")
for key in routers:
    print(key, end="")
    for protocol in routers.get(key)[0]:
        print(protocol, routers.get(key)[0].get(protocol)[0], routers.get(key)[0].get(protocol)[1], "{0:.5%}".format(routers.get(key)[0].get(protocol)[0]/routers.get(key)[1]), "{0:.5%}".format(routers.get(key)[0].get(protocol)[1]/routers.get(key)[2]))

print()
print("--------------------------------------------")
print("unnamed protocols by router")
print("--------------------------------------------")
for key in routers:
    print(key, end="")
    for protocol in routers.get(key)[0]:
        if protocol.isdigit(): 
            print(protocol, routers.get(key)[0].get(protocol)[0], routers.get(key)[0].get(protocol)[1], "{0:.5%}".format(routers.get(key)[0].get(protocol)[0]/routers.get(key)[1]), "{0:.5%}".format(routers.get(key)[0].get(protocol)[1]/routers.get(key)[2]))

print()
print("--------------------------------------------")
print("unique protocols by router")
print("--------------------------------------------")
protocol_list = []
removed_list = []
for key in routers:
    print(key, end="")
    for protocol in routers.get(key)[0]:
            if protocol not in protocol_list and protocol not in removed_list:
                protocol_list.append(protocol)
            else:
                protocol_list = removeItem(protocol_list, protocol)
                removed_list.append(protocol)

for key in routers:
    print(key, end="")
    print_line = False
    for protocol in routers.get(key)[0]:
        if protocol in protocol_list:
            print_line = True
            print(protocol, routers.get(key)[0].get(protocol)[0], routers.get(key)[0].get(protocol)[1], "{0:.5%}".format(routers.get(key)[0].get(protocol)[0]/routers.get(key)[1]), "{0:.5%}".format(routers.get(key)[0].get(protocol)[1]/routers.get(key)[2]))
    if print_line:
        print()
print()
print("--------------------------------------------")
print("unique protocols (only appear on one router)")
print("--------------------------------------------")
for i in protocol_list:
    print(i)

