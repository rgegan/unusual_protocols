# Uncommon Protocol Statistics and Detection
This GitHub repository contains code for monitoring protocol usage with Zeek, including updated plugins for lower level protocols and scripts for logging unusual protocol events.  Some Python scripts for additional analysis are included as well.   The modified Ethernet and IP plugins create events for each new packet providing information on the protocols seen.  The various scripts are described below.  

# Zeek Scripts
**unusual_protocols.zeek**:  This is the primary script for protocol usage.  The user can set thresholds for different L4 protocols, and those protocols will be logged once the threshold is passed.  Constants in the script are used to define the behavior.  The thresholds can be defined individually in thresholds.file, or all protocols can use the same threshold value.  If desired, the protocol distribution can be logged every X packets, along with the standard deviation and entropy of the protocol counts (which could be useful for anomaly detection).   In addition, you can log new protocols when they appear for the first time.

**ethernet_protocols.zeek**: This script is similar to **unusual_protocols.zeek**, but for logging L3 protocols.     

**l7_unusual.zeek**:  This script adds a new function to **unusual_protocols.zeek**.  It logs when certain L7 protocols appear over L4 protocols besides TCP.  Currently, it checks HTTP, FTP, and SSH packets.

Note that because event are handled for each packet, some of the monitoring in these scripts could become expensive for real-time monitoring, in which case it might be more well-suited for analyzing trace files.

# Python Scripts
**nfdump_parser.py**:  This script takes an nfdump file and parses the protocol data, printing the protocols, and the number and percentage of flows/packets appearing with that protocol.

**parse_router_results.py**:  This script reads in the text file created by router_protocols_script.sh, and outputs the protocol percentages per router, unique and unnamed protocols per router, and unique protocols (appearing only on a single router).

**protocol_clustering.py**:  This script will perform density based clustering using DBSCAN based on a given protocol.  Uses the **packet_totals.log** file created by **unusual_protocols.zeek** to cluster the protocol totals with their timestamps.  The clustering parameters should be adjusted based on how ofter the distributions are logged.   
