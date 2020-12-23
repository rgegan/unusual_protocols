module Unusual_protocols;

# options variables (can set with cmd line, but for now use consts)
# log_once, True = log every time a packet with that protocol appears past threshold, False = log once past threshold
const log_once = F;
# reset period = reset the protocol logging every X hours (0 means never reset)
const reset_period = 10000000;
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
        #payload: bool;
	threshold: count;
};


# Names taken from https://www.iana.org

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

global eth_protocol_names: table[count] of string = {

[0]="0x0000/IEEE802.3 Length Field", [25]="Experimental", [512]="0x0200/XEROX PUP", [513]="0x0201/PUP Addr Trans",
[1536]="0x0600/XEROX NS IDP", [2048]="0x0800/Internet Protocol version 4 (IPv4)", [2049]="0x0801/X.75 Internet", [2050]="0x0802/NBS Internet", 
[2051]="0x0803/ECMA Internet", [2052]="0x0804/Chaosnet", [2053]="0x0805/X.25 Level 3", [2054]="0x0806/Address Resolution Protocol (ARP)", 
[2055]="0x0807/XNS Compatability", [2056]="0x0808/Frame Relay ARP",[2076]="0x081C/Symbolics Private", [2184]="0x0888-088A/Xyplex",
[2304]="0x0900/Ungermann-Bass net debugr",[2560]="0x0A00/Xerox IEEE802.3 PUP", [2561]="0x0A01/PUP Addr Trans",[2989]="0x0BAD/Banyan VINES",
[2990]="0x0BAE/VINES Loopback", [2991]="0x0BAF/VINES Echo", [4096]="0x1000/Berkeley Trailer nego", 	[4097]="0x1001-100F/Berkeley Trailer encap/IP", [5632]="0x1600/Valid Systems",[8947]="0x22F3/TRILL",[8948]="0x22F4/L2-IS-IS",[16962]="0x4242/PCS Basic Block Protocol", 
[21000]="0x5208/BBN Simnet", [24576]="0x6000/DEC Unassigned (Exp.)", [24577]="0x6001/DEC MOP Dump/Load", [24578]="0x6002/DEC MOP Remote Console",[24579]="0x6003/DEC DECNET Phase IV Route", [24580]="0x6004/DEC LAT", [24581]="0x6005/DEC Diagnostic Protocol", [24582]="0x6006/DEC Customer Protocol", [24583]="0x6007/DEC LAVC, SCA",[24584]="0x6008-6009/DEC Unassigned", 	[24592]="0x6010-6014/3Com Corporation", 
[25944]="0x6558/Trans Ether Bridging", 	[25945]="0x6559/Raw Frame Relay", [28672]="0x7000/Ungermann-Bass download", [28674]="0x7002/Ungermann-Bass dia/loop", [28704]="0x7020-7029/LRT", [28720]="0x7030/Proteon", [28724]="0x7034/Cabletron",[32771]="0x8003/Cronus VLN", [32772]="0x8004/Cronus Direct", 
[32773]="0x8005/HP Probe", [32774]="0x8006/Nestar", [32776]="0x8008/AT&T", [32784]="0x8010/Excelan", [32787]="0x8013/SGI diagnostics", [32788]="0x8014/SGI network games", 
[32789]="0x8015/SGI reserved", 	[32790]="0x8016/SGI bounce server", [32793]="0x8019/Apollo Domain", [32814]="0x802E/Tymshare", [32815]="0x802F/Tigan, Inc.", [32821]="0x8035/Reverse Address Resolution Protocol (RARP)", [32822]="0x8036/Aeonic Systems", [32824]="0x8038/DEC LANBridge", [32825]="0x8039-803C/DEC Unassigned", [32829]="0x803D/DEC Ethernet Encryption", [32830]="0x803E/DEC Unassigned", [32831]="0x803F/DEC LAN Traffic Monitor",[32832]="0x8040-8042/DEC Unassigned", [32836]="0x8044/Planning Research Corp.", [32838]="0x8046/AT&T", [32839]="0x8047/AT&T", 
[32841]="0x8049/ExperData", [32859]="0x805B/Stanford V Kernel exp.", [32860]="0x805C/Stanford V Kernel prod.", [32861]="0x805D/Evans & Sutherland", [32864]="0x8060/Little Machines", [32866]="0x8062/Counterpoint Computers", [32869]="0x8065/Univ. of Mass. @ Amherst", [32870]="0x8066/Univ. of Mass. @ Amherst", [32871]="0x8067/Veeco Integrated Auto.", [32872]="0x8068/General Dynamics", [32873]="0x8069/AT&T", [32874]="0x806A/Autophon", [32876]="0x806C/ComDesign", [32877]="0x806D/Computgraphic Corp.", [32878]="0x806E-8077/Landmark Graphics Corp.", [32890]="0x807A/Matra", [32891]="0x807B/Dansk Data Elektronik", [32892]="0x807C/Merit Internodal", [32893]="0x807D-807F/Vitalink Communications", [32896]="0x8080/Vitalink TransLAN III", [32897]="0x8081-8083/Counterpoint Computers", 
[32923]="0x809B/Appletalk",[32924]="0x809C-809E/Datability", [32927]="0x809F/Spider Systems Ltd.", [32931]="0x80A3/Nixdorf Computers", [32932]="0x80A4-80B3/Siemens Gammasonics Inc.", [32960]="0x80C0-80C3/DCA Data Exchange Cluster", [32964]="0x80C4/Banyan Systems", [32965]="0x80C5/Banyan Systems",[32966]="0x80C6/Pacer Software", [32967]="0x80C7/Applitek Corporation", [32968]="0x80C8-80CC/Intergraph Corporation", [32973]="0x80CD-80CE/Harris Corporation", [32975]="0x80CF-80D2/Taylor Instrument", [32979]="0x80D3-80D4/Rosemount Corporation", [32981]="0x80D5/IBM SNA Service on Ether", [32989]="0x80DD/Varian Associates", [32990]="0x80DE-80DF/Integrated Solutions TRFS", [32992]="0x80E0-80E3/Allen-Bradley", [32996]="0x80E4-80F0/Datability",[33010]="0x80F2/Retix",[33011]="0x80F3/AppleTalk AARP (Kinetics)", [33012]="0x80F4-80F5/Kinetics", [33015]="0x80F7/Apollo Computer", [33023]="0x80FF/Wellfleet Communications", [33024]="0x8100/Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag) (initially Wellfleet)", [33025]="0x8101-8103/Wellfleet Communications", 
[33031]="0x8107-8109/Symbolics Private", [33072]="0x8130/Hayes Microcomputers", [33073]="0x8131/VG Laboratory Systems", [33074]="0x8132-8136/Bridge Communications", [33079]="0x8137-8138/Novell, Inc.", [33081]="0x8139-813D/KTI", [33096]="0x8148/Logicraft", [33097]="0x8149/Network Computing Devices", [33098]="0x814A/Alpha Micro", [33100]="0x814C/SNMP", 
[33101]="0x814D/BIIN", [33102]="0x814E/BIIN", [33103]="0x814F/Technically Elite Concept", [33104]="0x8150/Rational Corp",  [33149]="0x817D/XTP",[33150]="0x817E/SGI/Time Warner prop.",[33152]="0x8180/HIPPI-FP encapsulation", [33153]="0x8181/STP, HIPPI-ST", [33154]="0x8182/Reserved for HIPPI-6400", [33155]="0x8183/Reserved for HIPPI-6400", [33165]="0x818D/Motorola Computer",  [33188]="0x81A4/ARAI Bunkichi", [34523]="0x86DB/SECTRA", [34526]="0x86DE/Delta Controls", [34525]="0x86DD/Internet Protocol version 6 (IPv6)", [34527]="0x86DF/ATOMIC",  [34667]="0x876B/TCP/IP Compression", [34668]="0x876C/IP Autonomous Systems", [34669]="0x876D/Secure Data", [34824]="0x8808/IEEE Std 802.3 - Ethernet Passive Optical Network (EPON)", [34827]="0x880B/Point-to-Point Protocol (PPP)", [34828]="0x880C/General Switch Management Protocol (GSMP)", [34887]="0x8847/MPLS", [34888]="0x8848/MPLS with upstream-assigned label",[34913]="0x8861/Multicast Channel Allocation Protocol (MCAP)", 
[34915]="0x8863/PPP over Ethernet (PPPoE) Discovery Stage", [34916]="0x8864/PPP over Ethernet (PPPoE) Session Stage", [34958]="0x888E/IEEE Std 802.1X - Port-based network access control", 
[34984]="0x88A8/IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)", [34997]="0x88B5/IEEE Std 802 - Local Experimental Ethertype", 
[34998]="0x88B6/IEEE Std 802 - Local Experimental Ethertype", [34999]="0x88B7/IEEE Std 802 - OUI Extended Ethertype", 
[35015]="0x88C7/IEEE Std 802.11 - Pre-Authentication (802.11i)", [35020]="0x88CC/IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP)", 
[35045]="0x88E5/IEEE Std 802.1AE - Media Access Control Security", [35047]="0x88E7/Provider Backbone Bridging Instance tag", 
[35061]="0x88F5/IEEE Std 802.1Q - Multiple VLAN Registration Protocol (MVRP)", [35062]="0x88F6/IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP)", [35085]="0x890D/IEEE Std 802.11 - Fast Roaming Remote Request (802.11r)",[35095]="0x8917/IEEE Std 802.21 - Media Independent Handover Protocol", 
[35113]="0x8929/IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol", [35131]="0x893B/TRILL Fine Grained Labeling (FGL)",
[35136]="0x8940/IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR)", [35142]="0x8946/TRILL RBridge Channel",[35143]="0x8947/GeoNetworking as defined in ETSI EN 302 636-4-1",
[35151]="0x894F/NSH (Network Service Header)",[36864]="0x9000/Loopback", [36865]="0x9001/3Com(Bridge) XNS Sys Mgmt", 	[36866]="0x9002/3Com(Bridge) TCP-IP Sys",[36867]="0x9003/3Com(Bridge) loop detect",[39458]="0x9A22/Multi-Topology",[41197]="0xA0ED/LoWPAN encapsulation",[47082]="0xB7EA", 
[65280]="0xFF00/BBN VITAL-LanBridge cache",  [65535]="0xFFFF/Reserved",
};




# define globals
global thresholds: table[count] of Val = table();
global eth_proto_counts: table[count] of count = table();
global eth_protos_logged: table[count] of bool = table();

# Define threshold values
const sctp_thresh = 1;
# protocol counters
global proto_counts: vector of count;
global protos_logged: vector of bool;
global packet_count: count = 0;


export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time        &log;
        src_ip: addr     &log;
        dst_ip: addr &log;
	protocol: count &log;
	esp: count &log;
	protocol_name: string &log;
    };

    type Eth_Info: record {
	ts: time        &log;
        src_ip: addr     &log;
        dst_ip: addr &log;
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
    Log::create_stream(Unusual_protocols::LOG, [$columns=Eth_Info, $path="unusual_eth_protocols"]);
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


event eth_reply(src_ip: string, dst_ip: string, protocol: count)
{
        local src: addr;
        local dst: addr;
	local proto_name: string = "unlisted protocol";

	if(src_ip != "-")
	{
        	src = to_addr(src_ip);
        	dst = to_addr(dst_ip);
	}
	else
	{
		src = to_addr("255.255.255.255");
		dst = to_addr("255.255.255.255");
	}

        print src, dst, protocol;

	packet_count += 1;

	if (protocol in eth_proto_counts)
	{
		eth_proto_counts[protocol] += 1;
	}
	else
	{
		eth_proto_counts[protocol] = 1;
	}

	if (protocol in eth_protocol_names)
	{
		proto_name = eth_protocol_names[protocol];
	}

	local rec: Unusual_protocols::Eth_Info = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $protocol_name=proto_name];
	
	if (protocol in eth_proto_counts && !(protocol in eth_protos_logged) && (protocol in thresholds || log_all == T))
        {
		if( log_all == T) 
		{
			if(eth_proto_counts[protocol] >= log_all_thresh)
			{
				Log::write(Unusual_protocols::LOG, rec);	
				if ( log_once == T)
                        	{
                                	eth_protos_logged[protocol] = T;
                        	}
			}
			
		}
                else if((eth_proto_counts[protocol] > thresholds[protocol]$threshold))
                {
                        #rec = [$ts=network_time(), $src_ip=src, $dst_ip=dst, $protocol=protocol, $esp=esp_protocol];
                        Log::write(Unusual_protocols::LOG, rec);
                 
			if ( log_once == T)
			{
				eth_protos_logged[protocol] = T;
			}
		}
                
	}
	if (packet_count >= reset_period)
	{
        	eth_proto_counts = table();
        	eth_protos_logged = table();
		packet_count = 0; 
	} 
	

}

