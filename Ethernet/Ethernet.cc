// See the file "COPYING" in the main distribution directory for copyright.

#include "Ethernet.h"
#include "NetVar.h"
#include "Manager.h"

#include "Event.h"
#include "Val.h"
#include "ZeekString.h"
#include "events.bif.h"
#include "Reporter.h"

using namespace zeek::packet_analysis::Ethernet;

EthernetAnalyzer::EthernetAnalyzer()
	: zeek::packet_analysis::Analyzer("Ethernet")
	{
	}

void EthernetAnalyzer::Initialize()
	{
	Analyzer::Initialize();

	SNAPAnalyzer = LoadAnalyzer("snap_analyzer");
	NovellRawAnalyzer = LoadAnalyzer("novell_raw_analyzer");
	LLCAnalyzer = LoadAnalyzer("llc_analyzer");
	}

bool EthernetAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Make sure that we actually got an entire ethernet header before trying
	// to pull bytes out of it.
	if ( 16 >= len )
		{
		packet->Weird("truncated_ethernet_frame");
		return false;
		}

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( data[12] == 0x89 && data[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( cfplen + 14 >= len )
			{
			packet->Weird("truncated_link_header_cfp");
			return false;
			}

		data += cfplen;
		len -= cfplen;
		}

	// Get protocol being carried from the ethernet frame.
	uint32_t protocol = (data[12] << 8) + data[13];

	packet->eth_type = protocol;
	packet->l2_dst = data;
	packet->l2_src = data + 6;


	// New code here - check for IPv4
	if (packet->eth_type == 0x0800)
	{ 
		char src_ip[1024], dst_ip[1024], proto_num[32], esp_num[32];

		// Get payload after header
		uint32_t total_length = (data[16] << 8) + data[17];
		uint32_t header_length = data[14];
		char payload[2000];
		
		/*if(total_length < 1600)
		{
			int payload_count = 0;
			int start = 14+(((int)header_length - 64)*32/8);

			sprintf(payload, " ");
			if(data[start] || data[start] == 0)
				sprintf(payload + strlen(payload), "%02x", data[start]);
			for(int count=(15+(((int)header_length - 64)*32/8)); count < (14+(int)total_length); count++)
			{
				if(data[count] || data[count] == 0)
					//printf("%02x", data[count]);
					sprintf(payload + strlen(payload), "%02x", data[count]);
			}
		}
		*/
  		snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", 
                         data[26], data[27], data[28], data[29]);
		snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",
                         data[30], data[31], data[32], data[33]);
		snprintf(proto_num, sizeof(proto_num), "%u", data[23]);

		IPAddr orig = IPAddr(src_ip);
		IPAddr resp = IPAddr(dst_ip);
		
                //reporter->Info(src_ip);
		//reporter->Info(dst_ip);
		
		// Log the flow using weird.log
		if (data[23] >= 0x90 && data[23] <= 0xFC)
		{
	        	reporter->Weird(orig,resp,"Odd protocol",proto_num);
		}
		
		// Now try passing it to a script as an event
		int i = strlen(proto_num);
		//event_mgr.Enqueue(eth_reply, make_intrusive<StringVal>(new zeek::String(1, reinterpret_cast<byte_vec>("tester"),strlen("tester"))));
		EventHandlerPtr f = nullptr;

		f = eth_reply;
		if(f)
		{
			int proto_count = atoi(proto_num);
			int esp_count = 256;

			// Check for ESP protocol, then grab from the next_header field of ESP header
                        if (proto_count == 50)
                        {
                        	snprintf(esp_num, sizeof(esp_num), "%u", data[58]);
				esp_count = atoi(esp_num);
                        }
			
			mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(int(packet->eth_type)));
			//event_mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(proto_count), val_mgr->Count(esp_count));//, make_intrusive<StringVal>(dst_ip/*payload*/));//packet->Weird("Found Protocol - TCP");
			
		}
	}
	// Check for virtual lan headers (IPv4 first)
	else if (packet->eth_type == 0x8100)
	{
		// Check for IPv4 or IPv6
		uint32_t eth_type = (data[16] << 8) + data[17];
		if (eth_type == 0x0800)
		{
			char src_ip[1024], dst_ip[1024], proto_num[32], esp_num[32];
			
			// Get payload after header
                	uint32_t total_length = (data[20] << 8) + data[21];
                	uint32_t header_length = data[18];
                	char payload[2000];

                	/*if(total_length < 1600)
                	{
                        	int payload_count = 0;
                        	int start = 18+(((int)header_length - 64)*32/8);

                        	sprintf(payload, " ");
                        	if(data[start] || data[start] == 0)
                                	sprintf(payload + strlen(payload), "%02x", data[start]);
                        	for(int count=(19+(((int)header_length - 64)*32/8)); count < (18+(int)total_length); count++)
                        	{
                                	if(data[count] || data[count] == 0)
                                        	//printf("%02x", data[count]);
                                        	sprintf(payload + strlen(payload), "%02x", data[count]);
                        	}
                	}*/

                	snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",
                        	 data[30], data[31], data[32], data[33]);
                	snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",
                        	 data[34], data[35], data[36], data[37]);
                	snprintf(proto_num, sizeof(proto_num), "%u", data[27]);

                	IPAddr orig = IPAddr(src_ip);
                	IPAddr resp = IPAddr(dst_ip);

                	//reporter->Info("right here");
                	//reporter->Info(src_ip);
                	//reporter->Info(dst_ip);

                	// Log the flow using weird.log
                	if (data[27] >= 0x90 && data[27] <= 0xFC)
                	{
                        	reporter->Weird(orig,resp,"Odd protocol",proto_num);
                	}

                	// Now try passing it to a script as an event
                	int i = strlen(proto_num);
                	//event_mgr.Enqueue(eth_reply, make_intrusive<StringVal>(new zeek::String(1, reinterpret_cast<byte_vec>("tester"),strlen("tester"))));
                	EventHandlerPtr f = nullptr;

                	f = eth_reply;
                	if(f)
                	{
                        	int proto_count = atoi(proto_num);
				int esp_count = 256;

				// Check for ESP protocol, then grab from the next_header field of ESP header
				if (proto_count == 50)
				{
					snprintf(esp_num, sizeof(esp_num), "%u", data[62]);
					esp_count = atoi(esp_num);
				}

				mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(int(packet->eth_type)));
                        	//mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(proto_count), val_mgr->Count(esp_count));//, make_intrusive<StringVal>(payload));//packet->Weird("Found Protocol - TCP");

                	}
		}

		// Check for VLAN IPv6
		if (eth_type == 0x086DD)
                {
                        char src_ip[1024], dst_ip[1024], proto_num[32], esp_num[32];

			// Get payload after header
			// header length for IPv6 is always 40 bytes
			// Adding 4 for VLAN 
                	uint32_t payload_length = (data[22] << 8) + data[23];
                	char payload[2000];

                	/*if(payload_length < 1600)
                	{
                        	int payload_count = 0;
                        	int start = 58;  //(((int)header_length - 64)*32/8);

                        	sprintf(payload, " ");
                        	if(data[start] || data[start] == 0)
                                	sprintf(payload + strlen(payload), "%02x", data[start]);
                        	for(int count=59; count < (58+(int)payload_length); count++)
                        	{
                                	if(data[count] || data[count] == 0)
                                        	//printf("%02x", data[count]);
                                        	sprintf(payload + strlen(payload), "%02x", data[count]);
                        	}
                	}*/

                	snprintf(src_ip, sizeof(src_ip), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                         	 data[26], data[27], data[28], data[29],
                         	 data[30], data[31], data[32], data[33],
                         	 data[34], data[35], data[36], data[37],
                         	 data[38], data[39], data[40], data[41]);
                	snprintf(dst_ip, sizeof(dst_ip), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                        	 data[42], data[43], data[44], data[45],
                          	 data[46], data[47], data[48], data[49],
                         	 data[50], data[51], data[52], data[53],
                         	 data[54], data[55], data[56], data[57]);
                	snprintf(proto_num, sizeof(proto_num), "%u", data[24]);

                	// Don't know the proper format for IPv6 strings here
                	IPAddr orig = IPAddr(src_ip);
                	IPAddr resp = IPAddr(dst_ip);

                	//reporter->Info("right here");
                	//reporter->Info(src_ip);
			//reporter->Info(dst_ip);

                	// Log the flow using weird.log
               		if (data[24] >= 0x90 && data[24] <= 0xFC)
                	{
                        	reporter->Weird(orig,resp,"Odd protocol",proto_num);
                	}

                	// Now try passing it to a script as an event
                	int i = strlen(proto_num);
                	//event_mgr.Enqueue(eth_reply, make_intrusive<StringVal>(new zeek::String(1, reinterpret_cast<byte_vec>("tester"),strlen("tester"))));
                	EventHandlerPtr f = nullptr;

                	f = eth_reply;
        	        if(f)
                	{
                        	int proto_count = atoi(proto_num);
				int esp_count = 256;

                                // Check for ESP protocol, then grab from the next_header field of ESP header
                                if (proto_count == 50)
                                {
                                        snprintf(esp_num, sizeof(esp_num), "%u", data[82]);
                                        esp_count = atoi(esp_num);
                                }

                        	mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(int(packet->eth_type)));//packet->Weird("Found Protocol - TCP");

	                }

                }

	}
	// Check for IPv6
	else if (packet->eth_type == 0x86DD)
	{
		char src_ip[1024], dst_ip[1024], proto_num[32], esp_num[32];

		// Get payload after header
                // header length for IPv6 is always 40 bytes
                uint32_t payload_length = (data[18] << 8) + data[19];
                char payload[2000];

                /*if(payload_length < 1600)
                {
                	int payload_count = 0;
                        int start = 54;  //(((int)header_length - 64)*32/8);

                        sprintf(payload, " ");
                        if(data[start] || data[start] == 0)
                        	sprintf(payload + strlen(payload), "%02x", data[start]);
                        for(int count=55; count < (54+(int)payload_length); count++)
                        {
                        	if(data[count] || data[count] == 0)
                                	//printf("%02x", data[count]);
                                	sprintf(payload + strlen(payload), "%02x", data[count]);
                        }
                }*/



                snprintf(src_ip, sizeof(src_ip), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                         data[22], data[23], data[24], data[25],
			 data[26], data[27], data[28], data[29],
			 data[30], data[31], data[32], data[33],
			 data[34], data[35], data[36], data[37]);
                snprintf(dst_ip, sizeof(dst_ip), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                         data[38], data[39], data[40], data[41],
			 data[42], data[43], data[44], data[45],
			 data[46], data[47], data[48], data[49],
			 data[50], data[51], data[52], data[53]);
                snprintf(proto_num, sizeof(proto_num), "%u", data[20]);



		// Don't know the proper format for IPv6 strings here
                IPAddr orig = IPAddr(src_ip);
                IPAddr resp = IPAddr(dst_ip);

                //reporter->Info("right here");
                //reporter->Info(src_ip);
                //reporter->Info(dst_ip);

                // Log the flow using weird.log
                if (data[20] >= 0x90 && data[20] <= 0xFC)
                {
                        reporter->Weird(orig,resp,"Odd protocol",proto_num);
                }

                // Now try passing it to a script as an event
                int i = strlen(proto_num);
                //event_mgr.Enqueue(eth_reply, make_intrusive<StringVal>(new zeek::String(1, reinterpret_cast<byte_vec>("tester"),strlen("tester"))));
                EventHandlerPtr f = nullptr;

                f = eth_reply;
                if(f)
                {
                        int proto_count = atoi(proto_num);
			int esp_count = 256;

                        // Check for ESP protocol, then grab from the next_header field of ESP header
                        if (proto_count == 50)
                        {
                        	snprintf(esp_num, sizeof(esp_num), "%u", data[78]);
                        	esp_count = atoi(esp_num);
                        }
			
			mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(int(packet->eth_type)));
                        //mgr.Enqueue(f, make_intrusive<StringVal>(src_ip), make_intrusive<StringVal>(dst_ip), val_mgr->Count(proto_count), val_mgr->Count(esp_count));//, make_intrusive<StringVal>(payload));//packet->Weird("Found Protocol - TCP");

                }

	}
	else
	{
		EventHandlerPtr f = nullptr;
		f = eth_reply;
		if(f)
		{
			// Event for non-IP protocol
			mgr.Enqueue(f, make_intrusive<StringVal>("-"), make_intrusive<StringVal>("-"), val_mgr->Count(int(packet->eth_type)));
	
		}
	}

	// Ethernet II frames
	if ( protocol >= 1536 )
		return ForwardPacket(len - 14, data + 14, packet, protocol);

	// Other ethernet frame types
	if ( protocol <= 1500 )
		{
		if ( 16 >= len )
			{
			packet->Weird("truncated_ethernet_frame");
			return false;
			}

		// Let specialized analyzers take over for non Ethernet II frames.
		// Note that pdata remains at the start of the ethernet frame.

		AnalyzerPtr eth_analyzer = nullptr;

		if ( data[14] == 0xAA && data[15] == 0xAA)
			// IEEE 802.2 SNAP
			eth_analyzer = SNAPAnalyzer;
		else if ( data[14] == 0xFF && data[15] == 0xFF)
			// Novell raw IEEE 802.3
			eth_analyzer = NovellRawAnalyzer;
		else
			// IEEE 802.2 LLC
			eth_analyzer = LLCAnalyzer;

		if ( eth_analyzer )
			return eth_analyzer->AnalyzePacket(len, data, packet);

		return true;
		}

	// Undefined (1500 < EtherType < 1536)
	packet->Weird("undefined_ether_type");
	return false;
	}
