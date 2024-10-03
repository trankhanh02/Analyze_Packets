#include<iostream>	
#include<pcap.h>
#include <cstring>
#include <fstream>
#include <winsock2.h> 
#include <ws2tcpip.h> 
#include<vector>
#include<map>
#include<iomanip>
#include<sstream>

using namespace std;
// --------------------------0      1       2       3      4       5     6     7        8          9
vector<string> protocols = {"ETHER", "TCP", "UDP", "ICMP", "DNS", "HTTP","IP","HTTPS", "ICMPv6" ,"OTHER"};

// ĐỊNH NGHĨA CÁC HEADER
struct ether_header {
    u_char  ether_dhost[6];  // Địa chỉ MAC đích
    u_char  ether_shost[6];  // Địa chỉ MAC nguồn
    u_short ether_type;       // Loại giao thức (IPv4, ARP, v.v.)
};

struct ip {
    u_char  ip_hl:4;       // Chiều dài tiêu đề IP (tính bằng 32-bit words)
    u_char  ip_v:4;        // Phiên bản IP (IPv4 = 4)
    u_char  ip_tos;        // Loại dịch vụ
    u_short ip_len;        // Tổng chiều dài của gói tin (tính bằng byte)
    u_short ip_id;         // ID của gói tin
    u_short ip_off;        // Độ lệch (fragment offset)
    u_char  ip_ttl;        // Thời gian sống (TTL)
    u_char  ip_p;          // Giao thức (TCP, UDP, ICMP, v.v.)
    u_short ip_sum;        // Tổng kiểm tra (checksum)
    struct  in_addr ip_src; // Địa chỉ IP nguồn
    struct  in_addr ip_dst; // Địa chỉ IP đích
};

struct ip6_hdr {
    uint32_t ip6_flow;      // Dữ liệu dòng (flow label)
    uint16_t ip6_plen;      // Độ dài phần payload
    uint8_t  ip6_nxt;       // Giá trị của Next Header
    uint8_t  ip6_hlim;      // Thời gian sống (Hop Limit)
    struct in6_addr ip6_src; // Địa chỉ nguồn
    struct in6_addr ip6_dst; // Địa chỉ đích
};

struct udp_header {
    uint16_t source_port;      // Port nguồn
    uint16_t destination_port; // Port đích
    uint16_t length;           // Chiều dài toàn bộ gói UDP
    uint16_t checksum;         // Tổng kiểm tra
};

struct tcp_header {
    uint16_t source_port;        // Cổng nguồn
    uint16_t destination_port;   // Cổng đích
    uint32_t sequence_number;    // Số thứ tự
    uint32_t acknowledgment_number; // Số xác nhận
    uint8_t data_offset: 4;      // Độ dài header
    uint8_t reserved: 3;         // Dành cho tương lai
    uint8_t flags: 9;            // Các cờ điều khiển
    uint16_t window_size;        // Kích thước cửa sổ
    uint16_t checksum;           // Kiểm tra lỗi
    uint16_t urgent_pointer;     // Con trỏ khẩn cấp
};

struct dns_header {
    uint16_t id;         // Mã định danh của gói DNS
    uint16_t flags;      // Cờ và mã hoạt động của DNS
    uint16_t q_count;    // Số lượng câu hỏi trong phần truy vấn
    uint16_t ans_count;  // Số lượng câu trả lời trong phần phản hồi
    uint16_t auth_count; // Số lượng bản ghi quyền lực
    uint16_t add_count;  // Số lượng bản ghi bổ sung
};

 string ipToString(const struct in_addr &ip) {
     ostringstream oss;
    oss << (static_cast<int>(ip.s_addr & 0xFF)) << "."
        << (static_cast<int>((ip.s_addr >> 8) & 0xFF)) << "."
        << (static_cast<int>((ip.s_addr >> 16) & 0xFF)) << "."
        << (static_cast<int>((ip.s_addr >> 24) & 0xFF));
    return oss.str();
}

 string ipv6ToString(const struct in6_addr &ip6) {
    char str[INET6_ADDRSTRLEN];
    snprintf(str, sizeof(str), "%x:%x:%x:%x:%x:%x:%x:%x",
        ntohs(*(uint16_t*)&ip6.s6_addr[0]), ntohs(*(uint16_t*)&ip6.s6_addr[2]),
        ntohs(*(uint16_t*)&ip6.s6_addr[4]), ntohs(*(uint16_t*)&ip6.s6_addr[6]),
        ntohs(*(uint16_t*)&ip6.s6_addr[8]), ntohs(*(uint16_t*)&ip6.s6_addr[10]),
        ntohs(*(uint16_t*)&ip6.s6_addr[12]), ntohs(*(uint16_t*)&ip6.s6_addr[14]));
    return  string(str);
}



//in dia chi MAC
string mactoString(const u_char* mac_address)
{	stringstream write;
	for (int i =0; i< 6; i++){
		write << hex << setw(2)<< setfill('0') << (int)mac_address[i];
		if(i < 5) write << ":";
	}
	return write.str();
}
void display_src_and_dest_MAC(const u_char* srcMAC, const u_char* dstMAC, ofstream &outPut){
	stringstream write;
	write<<"ETHERNET :" <<endl;
	write << "src MAC: " << mactoString(srcMAC);
	write<<" "<<"dest MAC: " << mactoString(dstMAC);
	write <<endl;
	cout<< write.str();
	outPut << write.str();
}

void display_IPv4(struct in_addr src, struct in_addr dst, ofstream &outPut) {
    stringstream write;
	write << "IPv4" << endl;
    write << "src IP: " << ipToString(src) << "  " << "dst IP: " << ipToString(dst) << endl;
	cout<< write.str();
	outPut << write.str();
}

void display_IPv6(struct in6_addr src, struct in6_addr dst, ofstream &outPut) {
	stringstream write;
    write << "IPv6" << endl;
    write << "src IP: " << ipv6ToString(src) << "  " << "dst IP: " << ipv6ToString(dst) << endl;
	cout<< write.str();
	outPut << write.str();
}

bool isPrintableASCII(char c) {
    return (c >= 32 && c <= 126) || c == '\n' || c == '\r';
}
int indexMethod(const string line){

    if (line.find("GET ") != string::npos) return line.find("GET ");
    else if (line.find("POST ")!= string::npos) return line.find("POST ");
    else if (line.find("PUT ") != string::npos) return line.find("PUT ");
    else if (line.find("DELETE") != string::npos) return  line.find("DELETE");
    else if (line.find("PATCH ")!= string::npos) return line.find("PATCH ") ;
    else if (line.find("OPTIONS ")!= string::npos) return  line.find("OPTIONS ");
      
    return -1;
}

void getHttpInfo(const u_char* payload, int length,  ofstream& outPut) {
    // Chuyển đổi payload thành chuỗi
     string httpPayload(reinterpret_cast<const char*>(payload), length);
     string filteredPayload;

    // Lọc ra các ký tự có 
    for (char c : httpPayload) {
        if (isPrintableASCII(c)) {
            filteredPayload += c;
        }
    }

     istringstream stream(filteredPayload); // chuyển chuyển dữ liều thành dàng luồng hay từng dòng
     string line;
     string method, url1, url2, status;

    // Đọc từng dòng trong chuỗi đã lọc
    while ( getline(stream, line)) {
        // Kiểm tra phương thức HTTP
        if (indexMethod(line) != -1) // kiểm tra method
        {
            int position = indexMethod(line); // trả về vị trí method.
            if (position !=  string::npos) {
                method = line.substr(position, line.find(" ") - position); // Trích xuất phương thức
                int nextSpace = line.find(" ", position + 1); // Tìm dấu cách thứ hai
                if (nextSpace !=  string::npos) {
                    int nnSpace = line.find(" ", nextSpace + 1);
                    if (nnSpace !=  string::npos) {
                        url1 = line.substr(nextSpace + 1, nnSpace - nextSpace - 1); // Trích xuất URL
                    }
                }
            }
        }
        // Trích xuất thông tin Host
        else if (line.find("Host:") !=  string::npos) {
            int hostPosition = line.find(":"); // Tìm dấu ":"
            if (hostPosition !=  string::npos) {
                url2 = line.substr(hostPosition + 1); // Trích xuất Host
                // Xóa khoảng trắng ở đầu URL
                url2.erase(0, url2.find_first_not_of(" \n\r\t")); 
            }
        }
        // Kiểm tra mã trạng thái
        else if (line.find("HTTP/") !=  string::npos) {
            int statusPosition = line.find("HTTP/");
            if (statusPosition !=  string::npos) {
                status = line.substr(statusPosition); // Trích xuất mã trạng thái
            }
        }
    }
    // Tạo chuỗi đầu ra
     stringstream write;
    write<<"HTTP:\n";
    if (!method.empty()) {
        write << "HTTP Method: " << method <<  endl;
    }

    if (!url1.empty() || !url2.empty()) {
        write << "Host: http://" << url2 << "URL:"<< url1 <<endl;
    }
    if (!status.empty()) {
        write << status <<  endl;
    }

    // In và ghi ra file
    cout << write.str();
    outPut << write.str();
}

// cau truc cua question setion
//Tên miền: Phần www: Độ dài: len Ký tự: w, w, w
// Phần example: d0 dai: 7 Ký tự: e, x, a, m, p, l, e
// Phần com: Độ dài: 3 Ký tự: c, o, m
// Kết thúc tên miền bằng byte 0: 0
string getDomain( const u_char * packet,int &offset){
    string domain;
    int len = packet[offset];
    while( len > 0){
        const u_char * domainPart = &packet[offset+1];
        domain.append(reinterpret_cast<const char*>(domainPart), len); // VD str1 "abc"; s2 = "345";  str1.append(str2,2) = "abc34"; lay 2 ky tu  position 0;
        offset = offset + len + 1;
        len = packet[offset];
        if(len>0) domain += ".";
    }
    offset++; // bo qua ket thuc ten mien
    return domain;
}

void processPacket(const u_char* packet, vector<unsigned long long> &count, ofstream &outPut , int n = protocols.size())
{	
    int leng_iph;
	// khoi tao gia tri bien dem goi tin la 0
	for ( int i = 0; i < n; i++) {
		count.push_back(0); 
	}
	struct ether_header* ether = (struct ether_header*) packet;
	// print src MAC/ des MAC
	display_src_and_dest_MAC(ether->ether_shost, ether->ether_dhost, outPut);
	
    
    // Xử lý với IPv4
	if (ntohs(ether->ether_type)== 0x0800)
	{
		count[0]++;
		count[6]++;
		struct ip* ip_header = (struct ip*) (packet + 14);
		// In Địa chỉ IPv4;
		display_IPv4(ip_header->ip_src, ip_header->ip_dst, outPut);
        // port 6: TCP
		if (ip_header->ip_p == 6) 
		{
			leng_iph = ip_header->ip_hl * 4; // độ dài ip header
            struct tcp_header* tcp_h = (struct tcp_header*) (packet + (14 +leng_iph));
            int len_tcp_hdr = tcp_h->data_offset * 4; // độ dài cải tcp_header;
            // In src và dest port của TCP
			cout<< "TCP: " << "Src Port: " << ntohs(tcp_h->source_port) << "   " <<"Dst Port:" << ntohs(tcp_h->destination_port) <<endl;
			outPut<< "TCP: " << "Src Port: " << ntohs(tcp_h->source_port) << "   " <<"Dst Port:" << ntohs(tcp_h->destination_port) <<endl;
			count[1]++;
            // 80 HTTP, 443 HTTPS, 53 DNS
			if (ntohs(tcp_h->source_port)== 80 || ntohs(tcp_h->destination_port)== 80){
				count[5]++;
                const u_char * payload = packet + (14 + leng_iph + len_tcp_hdr);

                int total_length = ntohs(ip_header->ip_len);
                // Độ dài TCP payload
                int tcp_payload_length = total_length - (leng_iph + len_tcp_hdr);
                if(tcp_payload_length > 0)
                    // hàm trích xuất phương thức (GET, POST, v.v.), URL và mã trạng thái HTTP (nếu có).
                    getHttpInfo(payload, tcp_payload_length, outPut);
			}
			else if(ntohs(tcp_h->source_port)== 443 || ntohs(tcp_h->destination_port)== 443)
			{
				count[7]++;
			}
			else if (ntohs(tcp_h->source_port)== 53 || ntohs(tcp_h->destination_port)== 53){
				outPut<< "DNS: " << endl;
                cout << "DNS: " << endl;
                count[4]++;
                // DO dai cuar dns header la 12 bytes
                struct dns_header* dns_hdr = (struct dns_header*) packet + (14 + leng_iph + len_tcp_hdr); //len_tcp_hdr bytes la do dai
                // vi tri cua question 
                // cau tru 12byte DNS header -> question section -> Ansen question -> ..
                // question (Domain name , Type 2bytes, class 2 bytes) -> 
                //AwnQus(name ?byte, type 2 bytes, class 2 bytes, TTL: 4 bytes, date len: 2 bytes, data 4 bytes )
                int offset = 14 + leng_iph + 8 + 12; // 12bytes la do dai DNS headers
                if(ntohs(dns_hdr->q_count) > 0)
                {   for(int i = 0; i < ntohs(dns_hdr->q_count); i ++){
                        string domain = getDomain(packet, offset);
                        outPut<< "Domain: " << domain<< endl;
                        cout<< "Domain: " << domain<< endl;
                        offset += 4;
                    }
                }
                // get ip from DNS AWS Section;
                if(ntohs(dns_hdr->ans_count) > 0)
                {
                    for( int i = 0; i < dns_hdr->ans_count ; i++){
                        string anwser_domain_name = getDomain(packet, offset); // bỏ qua số byte tại Name files;
                        offset += 10; // Bỏ qua Type (2 byte), Class (2 byte), TTL (4 byte), Data length (2 byte)
                        struct in_addr addr;
                        memcpy(&addr, &packet[offset], sizeof(struct in_addr));
                        outPut << "DNS respond IP:" << ipToString(addr) << endl;
                        cout << "DNS respond IP:" << ipToString(addr) << endl;
                        offset+= 4; // bỏ qua 4 byte phần data.
                    }

                }
			}
		}
        // port 17 UDP 
        else if(ip_header->ip_p == 17) 
		{
			count[2]++;
			leng_iph = ip_header->ip_hl * 4; // độ dài ip header
			struct udp_header* udp_hdr = (struct udp_header*) packet + (14 + leng_iph );
			cout<< "UDP: " << "Src Port: " << ntohs(udp_hdr->source_port) << "   " <<"Dst Port:" << ntohs(udp_hdr->destination_port) <<endl;
			outPut<< "UDP: " << "Src Port: " << ntohs(udp_hdr->source_port) << "   " <<"Dst Port:" << ntohs(udp_hdr->destination_port) <<endl;
			if (ntohs(udp_hdr->source_port)== 53 || ntohs(udp_hdr->destination_port)== 53){
				outPut<< "DNS: " << endl;
                cout << "DNS: " << endl;
                count[4]++;
                // Độ dài DNS header là 12 bytes
                struct dns_header* dns_hdr = (struct dns_header*) packet + (14 + leng_iph + 8); // 8 bytes la do dai cua UDP hearder (co dinh)
                // vi tri cua question 
                // cau tru 12byte DNS header -> question section -> Ansen question -> ..
                // question (Domain name , Type 2bytes, class 2 bytes) -> 
                //AwnQus(name ?byte, type 2 bytes, class 2 bytes, TTL: 4 bytes, date len: 2 bytes, data 4 bytes )
                int offset = 14 + leng_iph + 8 + 12; // 12bytes la do dai DNS headers
                if(ntohs(dns_hdr->q_count) > 0)
                {   for(int i = 0; i < ntohs(dns_hdr->q_count); i ++){
                        string domain = getDomain(packet, offset);
                        outPut<< "Domain: " << domain<< endl;
                        cout<< "Domain: " << domain<< endl;
                        offset += 4; // bỏ qua 4bytes ( 2byte type và 2 bytes của class)
                    }
                }
                // get ip from DNS AWS Section;
                if(ntohs(dns_hdr->ans_count) > 0)
                {
                    for( int i = 0; i < dns_hdr->ans_count ; i++){
                        string anwser_domain_name = getDomain(packet, offset); // bỏ qua số byte tại Name files;
                        offset += 10; // Bỏ qua Type (2 byte), Class (2 byte), TTL (4 byte), Data length (2 byte)
                        struct in_addr addr;
                        memcpy(&addr, &packet[offset], sizeof(struct in_addr));
                        outPut << "DNS respond IP:" << ipToString(addr) << endl;
                        cout << "DNS respond IP:" << ipToString(addr) << endl;
                        offset+= 4; // bỏ qua 4 byte phần data.
                    }

                }
			}
		}
		
         //port 1 ICMP
        else if (ip_header->ip_p ==1)
		{
            count[3]++;

		}
        else
		{
            count[9]++;
        }
	}
	//Xử lý với IPv6
	else if (ntohs(ether->ether_type) == 0x086DD)
    {
		count[0]++;
		count[6]++;
		struct ip6_hdr* ip6_header = (struct ip6_hdr*) (packet + 14);
		// //in ipv6
		display_IPv6(ip6_header->ip6_src, ip6_header->ip6_dst, outPut);
		//  TCP: 6
		if ((ip6_header->ip6_nxt) == 6)
		{	
			
			count[1]++;
			struct tcp_header* tcp_hdr = (struct tcp_header*) packet +(14 + 40); // 14 byte do dai cua ethernet header va 40 bytes la ipv6 header
			cout<< "TCP: " << "Src Port: " << ntohs(tcp_hdr->source_port) << "   " <<"Dst Port:" << ntohs(tcp_hdr->destination_port) <<endl;
			outPut<< "TCP: " << "Src Port: " << ntohs(tcp_hdr->source_port) << "   " <<"Dst Port:" << ntohs(tcp_hdr->destination_port) <<endl;
			if (ntohs(tcp_hdr->source_port)== 80 || ntohs(tcp_hdr->destination_port)== 80)
			{
                count[5]++;
            }
			else if(ntohs(tcp_hdr->source_port)== 443 || ntohs(tcp_hdr->destination_port)== 443)
			{
				count[7]++;
			}
			else if (ntohs(tcp_hdr->source_port)== 53 || ntohs(tcp_hdr->destination_port)== 53)
			{
                count[4]++;
            }
		}
		//UDP: 17 
		else if ((ip6_header->ip6_nxt) == 17)
		{
			count[2]++;
			struct udp_header* udp6_hdr = (struct udp_header*) packet + (14+40);
			cout<< "UDP: " << "Src Port: " << ntohs(udp6_hdr->source_port) << "   " <<"Dst Port:" << ntohs(udp6_hdr->destination_port) <<endl;
			outPut<< "UDP: " << "Src Port: " << ntohs(udp6_hdr->source_port) << "   " <<"Dst Port:" << ntohs(udp6_hdr->destination_port) <<endl;
			if (ntohs(udp6_hdr->source_port)== 53 || ntohs(udp6_hdr->destination_port)== 53)
			{
                count[4]++;
            }
		}
		// ICMPv6: 58
		else if ((ip6_header->ip6_nxt) == 58)
		{
			count[8]++;
		}
		else{
			count[9]++;
		}
	}
	// ETHER OTHER
	else
	{
		count[0]++;
		count[9]++;
	}  
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap file>" << std::endl;
        return 1;
    }

    char *filename = argv[1];

	stringstream write;
	ofstream outPut;
	outPut.open("result.txt");
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char* packet;
    vector<unsigned long long> count;

	pcap_t* handle = pcap_open_offline(filename, errbuf);
	if (handle == NULL) {
		cout << " cannot open pcap file" << errbuf << endl;
		return 1;
	}
    
	unsigned long long index = 1;
	while ((packet = pcap_next(handle, &header))!= nullptr){

		cout<< endl  <<"------------------PACKET:"<<  dec <<index <<"---------------"<<endl;
		outPut << endl  <<"------------------PACKET:"<<  dec <<index <<"---------------"<<endl;
		processPacket(packet,count,outPut);
		cout << endl;
		outPut << endl;
		index++;
	}
	pcap_close(handle);

    write <<"\n COUNT PACKET: \n";
    for (int i =0; i < protocols.size(); i++){
        write << endl  << protocols[i]<< ":" << dec <<count[i] << " ";
    }
	cout <<write.str();
	outPut << write.str();
	outPut.close();
	return 0;
}