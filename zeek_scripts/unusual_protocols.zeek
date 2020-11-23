module Unusual_protocols;

# options variables 
# log_once, True = log every time a packet with that protocol appears past threshold, False = log once past threshold
const log_once = F;
# reset period = reset the protocol logging every X hours (0 means never reset)
const reset_period = 0;
# log_all, True = log every protocol over a threshold (log_all_thresh), False = log only those specified in thresholds.file
const log_all = T;
const log_all_thresh = 1;
# log_distribution, True = writes the overall protocol count distribution to a log after set number of packets
const log_distribution = T;
const log_distr_pkts = 100000;





# file reading for protocol thresholds
# defines the protocols to check, thresholds, and if payloads are logged   
type Idx: record {
        protocol: count;
};

type Val: record {
        payload: bool;
	threshold: count;
};


global protocol_names: table[count] of string = {
	[0]="HOPOPT", [1]="ICMP", [2]="IGMP", [3]="GGP", [4]="IPv4", [5]="ST", [6]="TCP", [7]="CBT", 
	[8]="EGP", [9]="IGP", [10]="BBN-RCC-MON", [11]="NVP-II", [12]="PUP", [13]="ARGUS",[14]="EMCON", [15]="XNET", 
	[16]="CHAOS", [17]="UDP",[18]="MUX",[19]="DCN-MEAS", [20]="HMP", [21]="PRM", [22]="XNS-IDP", [23]="TRUNK-1", 
	[24]="TRUNK-2", [25]="LEAF-1", 	[26]="LEAF-2", 	[27]="RDP", [28]="IRTP", [29]="ISO-TP4", [30]="NETBLT", [31]="MFE-NSP", 
	[32]="MERIT-INP", [33]="DCCP", [34]="3PC", [35]="IDPR", [36]="XTP", [37]="DDP", [38]="IDPR-CMTP", [39]="TP++", 
	[40]="IL", [41]="IPv6", [42]="SDRP", [43]="IPv6-Route",[44]="IPv6-Frag", [45]="IDRP",[46]="RSVP",[47]="GRE", 
	[48]="DSR", [49]="BNA", [50]="ESP", [51]="AH", [52]="I-NLSP", [53]="SWIPE", [54]="NARP", [55]="MOBILE", 
	[56]="TLSP", [57]="SKIP", [58]="IPv6-ICMP", [59]="IPv6-NoNxt", [60]="IPv6-Opts", [61]="internal protocol", [62]="CFTP", [63]="local network", 
	[64]="SAT-EXPAK", [65]="KRYPTOLAN", [66]="RVD", [67]="IPPC", [68]="distributed file system", [69]="SAT-MON", [70]="VISA", [71]="IPCV", 
	[72]="CPNX", [73]="CPHB", [74]="WSN", [75]="PVP", [76]="BR-SAT-MON", [77]="SUN-ND", [78]="WB-MON", [79]="WB-EXPAK", 
	[80]="ISO-IP", [81]="VMTP", [82]="SECURE-VMTP", [83]="VINES", 	[84]="TTP/IPTM", [85]="NSFNET-IGP", [86]="DGP", [87]="TCF", 	
	[88]="EIGRP", [89]="OSPFIGP", [90]="Sprite-RPC",[91]="LARP", [92]="MTP", [93]="AX.25", [94]="IPIP", [95]="MICP", 
	[96]="SCC-SP", [97]="ETHERIP", [98]="ENCAP", [99]="private encryption scheme", [100]="GMTP",[101]="IFMP", [102]="PNNI", [103]="PIM",	    [104]="ARIS", [105]="SCPS", [106]="QNX", [107]="A/N", [108]="IPComp", [109]="SNP", [110]="Compaq-Peer", [111]="IPX-in-IP",
	[112]="VRRP", [113]="PGM", [114]="0-hop protocol", [115]="L2TP", [116]="DDX", [117]="IATP", [118]="STP", [119]="SRP",
	[120]="UTI", [121]="SMP", [122]="SM", [123]="PTP", [124]="ISIS over IPv4", [125]="FIRE", [126]="CRTP", [127]="CRUDP", 
	[128]="SSCOPMCE", [129]="IPLT", [130]="SPS", [131]="PIPE", [132]="SCTP", [133]="FC", [134]="RSVP-E2E-IGNORE", [135]="Mobility Header",
	[136]="UDPLite", [137]="MPLS-in-IP", [138]="manet", [139]="HIP", [140]="Shim6", [141]="WESP", [142]="ROHC", [143]="Ethernet",

};

global thresholds: table[count] of Val = table();



# Define threshold values
const sctp_thresh = 1;
# protocol counters
global proto_counts: vector of count;
global protos_logged: vector of bool;
global packet_count: count = 0;
global cycle_count: count = 0;
global packet_total: count = 0;

export {
    redef enum Log::ID += { LOG, LOG2 };

    type Info: record {
        ts: time        &log;
        src_ip: addr     &log;
        dst_ip: addr &log;
	protocol: count &log;
	esp: count &log;
	protocol_name: string &log;
    };

    type Totals: record {
	protocol: count &log;
	protocol_name: string &log;
	protocol_total: count &log;
    };
}

event zeek_init() &priority=5
    {
    # Read in the thresholds
    Input::add_table([$source="thresholds.file", $name="thresholds",
                      $idx=Idx, $val=Val, $destination=thresholds]);
    Input::remove("thresholds");

    # Create the stream. This adds a default filter automatically.
    Log::create_stream(Unusual_protocols::LOG, [$columns=Info, $path="unusual_protocols"]);
    # Create a stream for logging the distribution and other stats
    Log::create_stream(Unusual_protocols::LOG2, [$columns=Totals, $path="protocol_totals"]);
    # Fill the count array with 0s
    local i: count;
    i = 0;

    while (i < 255)
     {
	proto_counts += 0;
	protos_logged += F;
	i += 1;
     }
    }

event test(src: count)
{
  print "works";
}

event new_ip_protocol(src_ip: addr, dst_ip: addr, protocol: count, esp_protocol: count)
    {
	# Convert strings to addr
	local src: addr;
	local dst: addr;

        src = src_ip;
        dst = dst_ip;

	local proto_name: string = "unassigned protocol";


	packet_count += 1;

	if(protocol < 144)
	{
		proto_name = protocol_names[protocol];
	}

	local rec: Unusual_protocols::Info = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $esp=esp_protocol, $protocol_name=proto_name];
	
	local i: count;

	if (esp_protocol < 256 && esp_protocol >= 0)
        {
		if(esp_protocol < 144)
		{
			proto_name = protocol_names[esp_protocol];
		}
		else
		{
			proto_name = "unassigned protocol";
		}
                proto_counts[esp_protocol] += 1;
		rec = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $esp=esp_protocol, $protocol_name=proto_name];
        }

	i = protocol;
	
	# Update the protocol counts
	proto_counts[i] += 1;

	#print "Odd protocol found";
	#print src_ip, dst_ip, protocol, esp_protocol, proto_name;
	#print protocol_names[protocol];
	#print proto_counts;
	
	# Check for unusual behavior (thresholds to start, try clustering later, but every packet clustering won't work)
	# Also clustering doesn't make much sense, some kind of histogram analysis or changes in protocol composition instead
	
 
	if (protos_logged[protocol] == F && (protocol in thresholds || log_all == T))
        {
		if( log_all == T) 
		{
			if(proto_counts[protocol] >= log_all_thresh)
			{
				Log::write(Unusual_protocols::LOG, rec);	
				if ( log_once == T)
                        	{
                                	protos_logged[protocol] = T;
                        	}
			}
		}
                else if((proto_counts[protocol] > thresholds[protocol]$threshold))
                {
                        if(thresholds[protocol]$payload)
                        {
                                Log::write(Unusual_protocols::LOG, rec);
                        }
                        else
                        {
                                #rec = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $esp=esp_protocol];
                                Log::write(Unusual_protocols::LOG, rec);
                        }
			if ( log_once == T)
			{
				protos_logged[protocol] = T;
			}
                }
		
		#print thresholds[protocol];
		# Record unusual protocols to the log (use weird for just flows, this is per packet)
		# Add selective logging based on thresholds soon
        #	Log::write(Unusual_protocols::LOG, rec);	
		
	}
	if (packet_count >= reset_period && reset_period != 0)
	{
		local j: count = 0;
		local total_rec: Unusual_protocols::Totals;

		packet_total += packet_count;
		cycle_count += 1;
		total_rec = [$protocol=packet_total, $protocol_name="total packets, cycle number", $protocol_total=cycle_count];
		Log::write(Unusual_protocols::LOG2, total_rec);
		
		while (j < 255)
     		{
			if (proto_counts[j] > 0)
			{
				if (j < 144)
                	                total_rec = [$protocol=j, $protocol_name=protocol_names[j], $protocol_total=proto_counts[j]];
	                        else
        	                        total_rec = [$protocol=j, $protocol_name="N/A", $protocol_total=proto_counts[j]];
				Log::write(Unusual_protocols::LOG2, total_rec);
			}
			proto_counts[j] = 0;
        		protos_logged[j] = F;
     			j += 1;
		}

		#Log::write(Unusual_protocols::LOG2, total_rec);
		packet_count = 0; 
	}
	#print thresholds[10]$payload;
	#for (key,value in thresholds)
		#print key,value;
    }
