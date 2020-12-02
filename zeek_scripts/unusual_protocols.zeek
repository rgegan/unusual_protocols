module Unusual_protocols;

# options variables 
# log_once, True = log every time a packet with that protocol appears past threshold, False = log once past threshold
const log_once = T;
# log_all, True = log every protocol over a threshold (log_all_thresh), False = log only those specified in thresholds.file
const log_all = F;
const log_all_thresh = 1;
# log_distribution, True = writes the overall protocol count distribution to a log after set number of packets
const log_distribution = T;
const log_distr_pkts = 1000.0; #100000;
# reset, True = start logging protocols again in new cycles if they pass the threshold again
const reset = T;
const check_esp = T;


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


# protocol counters
global proto_counts: vector of count;
global protos_logged: vector of bool;
global protos_seen: vector of bool;
global packet_count: count = 0;
global cycle_count: count = 0;
global packet_total: count = 0;
global top_protocol: count = 0;

# test variables
global top_ent:double = 0;
global low_ent:double = 100.0;

export {
    redef enum Log::ID += { LOG, LOG2, LOG_NEW };

    type Info: record {
        ts: time        &log;
        src_ip: addr     &log;
        dst_ip: addr &log;
	protocol: count &log;
	esp: count &log;
	protocol_name: string &log;
	threshold: count &log;
	cycle_count: count &log;
    };

    type Totals: record {
	ts: time &log;
	msg_type: string &log;
	protocol: count &log;
	protocol_name: string &log;
	protocol_total: count &log;
	std_dev: double &log;
	entropy: double &log;
    };

    type New_Protocol: record {
	ts: time        &log;
        protocol: count &log;
        protocol_name: string &log;
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
    # Create a stream for logging protocols appearing for the first time
    Log::create_stream(Unusual_protocols::LOG_NEW, [$columns=New_Protocol, $path="new_protocols"]);
    # Create a stream for logging changes in the top protocol
    #Log::create_stream(Unusual_protocols::LOG_TOP, [$columns=Top_Protocol, $path="top_protocol_changes"]);

    # Fill the count array with 0s
    local i: count;
    i = 0;

    while (i < 255)
     {
	proto_counts += 0;
	protos_logged += F;
	protos_seen += F;
	i += 1;
     }
    }

event new_ip_protocol(src_ip: addr, dst_ip: addr, protocol: count, esp_protocol: count)
    {
	local thresh: count = 0;
	# Convert strings to addr
	local src: addr;
	local dst: addr;

        src = src_ip;
        dst = dst_ip;

	local proto_name: string = "unassigned protocol";

	if (log_all == T)
		thresh = log_all_thresh;
	else if (protocol in thresholds)
		thresh = thresholds[protocol]$threshold; 

	packet_count += 1;

	if(protocol < 144)
	{
		proto_name = protocol_names[protocol];
	}

	local rec: Unusual_protocols::Info = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $esp=esp_protocol, $protocol_name=proto_name, $threshold=thresh, $cycle_count=cycle_count];
	
	#local i: count;

	if (check_esp == T && esp_protocol < 256 && esp_protocol >= 0)
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
		rec = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $esp=esp_protocol, $protocol_name=proto_name, $threshold=thresh, $cycle_count=cycle_count];
        }

	#i = protocol;
	
	# Update the protocol counts
	proto_counts[protocol] += 1;
	
	# Log new protocols seen for the first time
	if(protos_seen[protocol] == F)
	{
		local new_rec: Unusual_protocols::New_Protocol;
		new_rec = [$ts=network_time(), $protocol=protocol, $protocol_name=proto_name]; 
		protos_seen[protocol] = T;
		Log::write(Unusual_protocols::LOG_NEW, new_rec);	
	}

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
	if (packet_count >= log_distr_pkts && log_distribution == T)
	{
		local top_proto:count = 0;
		local top_protocol_count: count = 0;
		local j: count = 0;
		local total_rec: Unusual_protocols::Totals;
		local distribution: table[count] of count;
		local num_protocols: count = 0;


		packet_total += packet_count;
		cycle_count += 1;
		total_rec = [$ts=network_time(), $msg_type="cycle complete", $protocol=packet_total, $protocol_name="total packets, cycle number", $protocol_total=cycle_count, $std_dev=0.0, $entropy=0.0];
		Log::write(Unusual_protocols::LOG2, total_rec);
		
		while (j < 255)
     		{
			if (proto_counts[j] > 0)
			{
				distribution[j] = proto_counts[j];
				num_protocols += 1;
				if (proto_counts[j] > top_protocol_count)
				{
					top_proto = j;
					top_protocol_count = proto_counts[j];
				}
				if (j < 144)
                	                total_rec = [$ts=network_time(), $msg_type=" ", $protocol=j, $protocol_name=protocol_names[j], $protocol_total=proto_counts[j], $std_dev=0.0, $entropy=0.0];
	                        else
        	                        total_rec = [$ts=network_time(), $msg_type=" ", $protocol=j, $protocol_name="N/A", $protocol_total=proto_counts[j], $std_dev=0.0, $entropy=0.0];
				Log::write(Unusual_protocols::LOG2, total_rec);
			}
			proto_counts[j] = 0;
			if (reset == T)
        			protos_logged[j] = F;
	
     			j += 1;
		}
		# Check if there's a change in the top protocol this cycle
		if (top_proto != top_protocol)
		{
			top_protocol = top_proto;
			if (top_protocol < 144)
                                        total_rec = [$ts=network_time(), $msg_type="New top protocol:", $protocol=top_protocol, $protocol_name=protocol_names[top_protocol], $protocol_total=proto_counts[top_protocol], $std_dev=0.0, $entropy=0.0];
                                else
                                        total_rec = [$ts=network_time(), $msg_type="New top protocol:", $protocol=top_protocol, $protocol_name="N/A", $protocol_total=proto_counts[top_protocol], $std_dev=0.0, $entropy=0.0];

			Log::write(Unusual_protocols::LOG2, total_rec);
		}

		print distribution;
		# Calculate the mean, variance, and entropy of protocol counts
		local mean:double;
		local variance:double;
		local std_dev:double; 
		local entropy:double;
		local total:double = 0;

		# Get the mean
		for ( entry in distribution )
		{
			total += distribution[entry];
		} 
		mean = total/num_protocols;		
		
		total = 0;
		# Get variance
		for ( entry in distribution )
		{
			total += (distribution[entry]-mean)*(distribution[entry]-mean);
		}
		variance = total/num_protocols;
		#print variance;
		std_dev = sqrt(variance);
		print std_dev;

		# Shannon entropy
		entropy = 0;
		for (entry in distribution)
		{
			#print distribution[entry];
			entropy += -1 * (distribution[entry]/log_distr_pkts * ln(distribution[entry]/log_distr_pkts));
		}
		print entropy;
		if (entropy > top_ent)
			top_ent = entropy;
		if (entropy < low_ent)
			low_ent = entropy;
		print top_ent,low_ent;
		# Calculate variance and entropy of protocol counts over the last X cycles
		total_rec = [$ts=network_time(), $msg_type="Statistics", $protocol=0, $protocol_name="N/A", $protocol_total=0, $std_dev=std_dev, $entropy=entropy];
		
		Log::write(Unusual_protocols::LOG2, total_rec);
		packet_count = 0; 
	}
	#print thresholds[10]$payload;
	#for (key,value in thresholds)
		#print key,value;
    }
