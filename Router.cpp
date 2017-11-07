#include <vector>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/if_ether.h>
//#include <net/if_dl.h>
#include <netpacket/packet.h>
#include <string.h>
//#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <thread>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>


class Router {

private:

    //map pointers to the iterfaces to the socket numbers they are bound to
    std::map<struct ifaddrs *, int> socketMap;
    std::map<std::string, std::vector<std::string> > table;
    std::vector<struct ifaddrs> interfaces;
    std::vector<int> sockets;

    //keep the initial linked list around
    struct ifaddrs *ifaddr;

    //std::vector<std::string[]> routingTable;

public:

    unsigned short checksum(unsigned short *ptr, int nbytes) {
        register long sum;
        u_short oddbyte;
        register u_short answer;
        sum = 0;
        while (nbytes > 1) {
            sum += *ptr++;
            nbytes -= 2;
        }
        if (nbytes == 1) {
            oddbyte = 0;
            *((u_char * ) & oddbyte) = *(u_char *) ptr;
            sum += oddbyte;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return (answer);
    }

    Router() {

        int packet_socket;
        //get list of interfaces (actually addresses)
        struct ifaddrs *tmp;


        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
        }

        for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next) {

            //Check if this is a packet address, there will be one per
            //interface.  There are IPv4 and IPv6 as well, but we don't care
            //about those for the purpose of enumerating interfaces. We can
            //use the AF_INET addresses in this list for example to get a list
            //of our own IP addresses
            if (tmp->ifa_addr->sa_family == AF_PACKET) {
                printf("found socket address\n");
                printf("name: %s \n", tmp->ifa_name);
                printf("family: %u \n", tmp->ifa_addr->sa_family);

                //create a packet socket on interface r?-eth1
                interfaces.push_back(*tmp);

                printf("Creating Socket on interface %s", tmp->ifa_name);

                //create a packet socket
                //AF_PACKET makes it a packet socket
                //SOCK_RAW makes it so we get the entire packet
                //could also use SOCK_DGRAM to cut off link layer header
                //ETH_P_ALL indicates we want all (upper layer) protocols
                //we could specify just a specific one
                packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                socketMap.insert(std::pair<struct ifaddrs *, int>(tmp, packet_socket));

//                unsigned char *ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(tmp->ifa_addr));
//                printf(": %02x:%02x:%02x:%02x:%02x:%02x\n\n",
//                       *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));

                //mymac = (struct sockaddr_ll *) tmp->ifa_addr;
//                printf("Our Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",mymac->sll_addr[0],mymac->sll_addr[1],mymac->sll_addr[2],mymac->sll_addr[3],mymac->sll_addr[4],mymac->sll_addr[5]);

                sockets.push_back(packet_socket);
                //packet_socket->sockaddr_ll;
                if (packet_socket < 0) {
                    perror("socket");

                }
                //Bind the socket to the address, so we only get packets
                //recieved on this specific interface. For packet sockets, the
                //address structure is a struct sockaddr_ll (see the man page
                //for "packet"), but of course bind takes a struct sockaddr.
                //Here, we can use the sockaddr we got from getifaddrs (which
                //we could convert to sockaddr_ll if we needed to)

                if (bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1) {
                    perror("bind");
                }





                //struct ether_header *etherH = (struct ether_header*)(buf);
                //struct ether_arp *arpH = (struct ether_arp*)(buf);


            }


        }
    }

    void printInterfaces() {
        std::cout << "Interfaces:\n";
        std::map<struct ifaddrs *, int>::iterator it;
        const int nums = socketMap.size();
        std::thread t[5];
        int i = 0;
        for (it = socketMap.begin(); it != socketMap.end(); it++) {

            std::cout << "Interface : " << it->first->ifa_name << " socket: "
                      << it->second << std::endl;
            struct sockaddr_ll *mymac = (struct sockaddr_ll *) it->first->ifa_addr;
            printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac->sll_addr[0], mymac->sll_addr[1], mymac->sll_addr[2],
                   mymac->sll_addr[3], mymac->sll_addr[4], mymac->sll_addr[5]);
            //struct sockaddr_in *myip = (struct sockaddr_in *) it->first->ifa_addr;
            if (!strncmp(&(it->first->ifa_name)[3], "eth", 3)) {
                std::cout << "found: " << it->first->ifa_name << std::endl;
                //if (i <= nums) {
                    t[i] = std::thread (&Router::listen, this, *it->first, it->second);
                    //t[i].join();
                    t[i].detach();
                    i++;
                //}
                //listen(*it->first, it->second);

            }
            std::cout << std::endl;
        }

    }

    int listen(struct ifaddrs interface, int socket) {

        int packet_socket = socket;

        std::cout << "listening on interface " << interface.ifa_name << std::endl;
        struct sockaddr_ll *mymac = (struct sockaddr_ll *) interface.ifa_addr;
        while (1) {

            char buf[1500];
            struct sockaddr_ll recvaddr;
            socklen_t recvaddrlen = sizeof(struct sockaddr_ll);
            int n = recvfrom(packet_socket, buf, 1500, 0, (struct sockaddr *) &recvaddr, &recvaddrlen);
            if (recvaddr.sll_pkttype == PACKET_OUTGOING)
                continue;

            //READ ETHER HEADER
            struct ether_header *etherH = (struct ether_header *) (buf);
            printf("type: %x\n", ntohs(etherH->ether_type));
            //Handle Arp
            if (ntohs(etherH->ether_type) == ETHERTYPE_ARP) {
                struct ether_arp *arpH = (struct ether_arp *) (buf + 14);
                char replyBuffer[42];
                struct ether_header *outEther = (struct ether_header *) (replyBuffer);
                struct ether_arp *arpResp = (struct ether_arp *) (replyBuffer + 14);
                memcpy(outEther->ether_dhost, etherH->ether_shost, 6);
                memcpy(outEther->ether_shost, mymac->sll_addr, 6);
                outEther->ether_type = 1544;
                arpResp->ea_hdr.ar_hrd = 0x100;
                arpResp->ea_hdr.ar_pro = 0x8;
                arpResp->ea_hdr.ar_hln = 0x6;
                arpResp->ea_hdr.ar_pln = 0x4;
                arpResp->ea_hdr.ar_op = htons(0x2);
                memcpy(arpResp->arp_tha, arpH->arp_sha, 6);
                memcpy(arpResp->arp_tpa, arpH->arp_spa, 4);
                memcpy(arpResp->arp_sha, outEther->ether_shost, 6);
                memcpy(arpResp->arp_spa, arpH->arp_tpa, 4);
                int sent = send(packet_socket, &replyBuffer, 42, 0);
                if (sent < 0) { perror("SEND"); }
            }
            //Handle IP
            if (ntohs(etherH->ether_type) == ETHERTYPE_IP) {
                printf("Got IPV4 packet!\n");
                struct ip *ipH = (struct ip *) (buf + 14);
                //HANDLE ME OR SOMEONE ELSE




                //HANDLE ICMP TO ME
                struct icmphdr *icmpH = (struct icmphdr *) (buf + 34);
                printf("IP HEADER: --------------------------------- \n");
                //printf("Target IP: %02d:%02d:%02d:%02d\n", ipH->ip_src[0],ipH->ip_src[1],ipH->ip_src[2],ipH->ip_src[3]);
                //printf("Target IP: %02d:%02d:%02d:%02d\n", ipH->ip_dst[0],ipH->ip_dst[1],ipH->ip_dst[2],ipH->ip_dst[3]);
                //char *sip = inet_ntoa(ipH->ip_src);
                //char *dip = inet_ntoa(ipH->ip_dst);
                //printf("%s\n",sip);
                //printf("%s\n",dip);
                //printf("Protocol: %d\n",(unsigned int)ipH->ip_p);
                printf("IP HexCheck: %x\n", ntohs(ipH->ip_sum));

                //printf("%d\n",(unsigned int)ipH->ip_hl);
                //printf("%d\n",(unsigned short)ipH->ip_len);
                int payload = (ipH->ip_len - sizeof(struct icmphdr));
                if ((unsigned int) ipH->ip_p == 1) {
                    printf("Got ICMP Packet\n");
                    //getting and building ICMP
                    char replyBuffer[90];
                    struct ether_header *outEther = (struct ether_header *) (replyBuffer);
                    struct ip *ipHR = (struct ip *) (replyBuffer + sizeof(struct ether_header));
                    struct icmphdr *icmpHR = (struct icmphdr *) (replyBuffer + 14 + sizeof(struct ip));
                    memcpy(outEther->ether_dhost, etherH->ether_shost, 6);
                    memcpy(outEther->ether_shost, mymac->sll_addr, 6);
                    outEther->ether_type = htons(2048);
                    printf("My Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", outEther->ether_shost[0],
                           outEther->ether_shost[1],
                           outEther->ether_shost[2], outEther->ether_shost[3], outEther->ether_shost[4],
                           outEther->ether_shost[5]);
                    printf("Dest Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", outEther->ether_dhost[0],
                           outEther->ether_dhost[1],
                           outEther->ether_dhost[2], outEther->ether_dhost[3], outEther->ether_dhost[4],
                           outEther->ether_dhost[5]);
                    printf("Protocol: %x\n", outEther->ether_type);

                    //IP building
                    ipHR->ip_src = ipH->ip_dst;
                    ipHR->ip_dst = ipH->ip_src;
                    ipHR->ip_hl = 5;
                    ipHR->ip_v = 4;
                    ipHR->ip_tos = 0;
                    ipHR->ip_len = htons(76); //sizeof(struct ip) + sizeof(struct icmphdr);
                    ipHR->ip_id = htons(56);
                    ipHR->ip_off = 0;
                    ipHR->ip_ttl = 64;
                    ipHR->ip_p = 1;
                    ipHR->ip_sum = 0;
                    ipHR->ip_sum = checksum((unsigned short *) (replyBuffer + 14), sizeof(struct ip));
                    printf("IP HexCheck: %x\n", htons(ipHR->ip_sum));
                    printf("IP HexCheck: %x\n", ntohs(ipHR->ip_sum));
                    printf("IP HexCheck: %x\n", ipHR->ip_sum);
                    //printf("Target IP: %02d:%02d:%02d:%02d\n", ipH->ip_src[0],ipH->ip_src[1],ipH->ip_src[2],ipH->ip_src[3]);
                    //printf("Target IP: %02d:%02d:%02d:%02d\n", ipH->ip_dst[0],ipH->ip_dst[1],ipH->ip_dst[2],ipH->ip_dst[3]);
                    char *sip = inet_ntoa(ipHR->ip_src);
                    printf("Source IP: %s\n", sip);
                    char *dip = inet_ntoa(ipHR->ip_dst);
                    printf("Target IP: %s\n", dip);
                    printf("TLength: %5d\n", htons(ipHR->ip_len));
                    printf("TOS: %4d\n", ipHR->ip_tos);
                    printf("TTL: %4d\n", ipHR->ip_ttl);
                    //set up icmp
                    printf("ICMP Type: %d\n", icmpH->type);
                    if (icmpH->type == 8) {
                        icmpHR->type = 0;
                        icmpHR->code = 0;
                        icmpHR->un.echo.sequence = icmpH->un.echo.sequence;
                        icmpHR->un.echo.id = icmpH->un.echo.id;
                        icmpHR->checksum = 0;
                        memcpy(replyBuffer + 42, buf + 50, 48);
                        icmpHR->checksum = checksum((unsigned short *) (replyBuffer + 34),
                                                    (sizeof(struct icmphdr) + 48));
                        //memcpy(replyBuffer+50,buf+50,48);
                        int sender = send(packet_socket, &replyBuffer, 90, 0);
                        if (sender < 0) { perror("Send ICMP"); }


                    }

                }

            }
        }


        //response(buf);


        return 0;
    }


    void buildTable(std::string filename) {
        FILE *fp = fopen(filename.c_str(), "r");
        char buff[1000];
        fread(buff, 1, 200, fp);
        char *token;
        token = strtok(buff, " \n");
        int i = 0;
        std::string str = ".";
        std::vector<std::string> current;

        while (1) {

            if (i % 3 == 0 && i != 0) {
                table.insert(std::pair<std::string, std::vector<std::string> >(str, current));
                current.clear();
                std::cout << "added list: " << str << std::endl;
                if (token == NULL)break;
            }

            if (i % 3 == 0) {
                str = token;
                std::cout << "Key: " << str << std::endl;
            } else {
                current.push_back(token);
                std::cout << "added: " << token << std::endl;
            }
            ++i;
            if (token == NULL) {
                break;

            }

            token = strtok(NULL, " \n");

        }


    }

};

int main() {

    Router test;
    test.printInterfaces();
    //test.buildTable("r1-table.txt");
    //test.buildTable("r1-table.txt");    
    printf("done");
    while(1){}

    return 0;
}
