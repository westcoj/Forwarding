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
    std::map<char *, struct sockaddr_in *> ipv4map;
    //std::map<char *, struct sockaddr_in *>::iterator ipv4IT;

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
            *((u_char *) &oddbyte) = *(u_char *) ptr;
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
            if (tmp->ifa_addr->sa_family == AF_INET) {
                printf("found IP address\n");
                printf("name: %s \n", tmp->ifa_name);
                printf("family: %u \n", tmp->ifa_addr->sa_family);
                struct sockaddr_in *ip = (struct sockaddr_in *) tmp->ifa_addr;
                ipv4map.insert(
                        std::pair<char *, struct sockaddr_in *>(tmp->ifa_name, (struct sockaddr_in *) tmp->ifa_addr));
                char *ipN = inet_ntoa(ip->sin_addr);
                printf("Address: <%s>\n", ipN);
            }


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
            printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac->sll_addr[0], mymac->sll_addr[1],
                   mymac->sll_addr[2],
                   mymac->sll_addr[3], mymac->sll_addr[4], mymac->sll_addr[5]);
            //struct sockaddr_in *myip = (struct sockaddr_in *) it->first->ifa_addr;
            if (!strncmp(&(it->first->ifa_name)[3], "eth", 3)) {
                std::cout << "found: " << it->first->ifa_name << std::endl;
                //if (i <= nums) {
                t[i] = std::thread(&Router::listen, this, *it->first, it->second);
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
        //GET PERSONAL MAC/IP
        //if (interface.ifa_addr.sa_family)
        struct sockaddr_in *myIP;


        std::cout << "listening on interface " << interface.ifa_name << std::endl;
        struct sockaddr_ll *mymac = (struct sockaddr_ll *) interface.ifa_addr;

        for (auto &x: ipv4map) {
            char *ipN = inet_ntoa(x.second->sin_addr);
            std::cout << x.first << " : " << ipN << '\n';
            int comp = strncmp(x.first, interface.ifa_name, 7);
            if (comp == 0) {
                printf("Got Match\n");
                std::cout << interface.ifa_name << "|" << x.first << '\n';
                myIP = x.second;
                //ipN = inet_ntoa(myIP->sin_addr);
                printf("Listening Address: <%s>\n", ipN);
                break;
            } else {
                //printf("Fuck\n");

            }

        }

        //if(ipN==NULL) return 0;

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

            //HANDLE ARP
            if (ntohs(etherH->ether_type) == ETHERTYPE_ARP) {

                //IF ARP REQUEST
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
                struct ip *ipH = (struct ip *) (buf + 14);
                //HANDLE ME OR SOMEONE ELSE

                printf("11111\n");
                //THIS PACKET FOR ME
                //char *rcvIP = inet_ntoa(ipH->ip_src);
                //char *ipVN = inet_ntoa(myIP->sin_addr);
                //std::cout << inet_ntoa(myIP->sin_addr) << "|" << rcvIP << '\n';
                if (myIP->sin_addr.s_addr==ipH->ip_dst.s_addr){
                    //HANDLE ICMP TO ME
                    struct icmphdr *icmpH = (struct icmphdr *) (buf + 34);

                    //printf("IP HEADER: --------------------------------- \n");

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
                        //printf("Target IP: %02d:%02d:%02d:%02d\n", ipH->ip_src[0],ipH->ip_src[1],ipH->ip_src[2],ipH->ip_src[3]);
                        //printf("Target IP: %02d:%02d:%02d:%02d\n", ipH->ip_dst[0],ipH->ip_dst[1],ipH->ip_dst[2],ipH->ip_dst[3]);
                        char *sip = inet_ntoa(ipHR->ip_src);
                        char *dip = inet_ntoa(ipHR->ip_dst);
                        //set up icmp
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

                    //THIS PACKET NOT FOR ME
                else {
                    printf("22222222\n");
                    //Make me an AAAAAAARP, also get proper path.
                    char arpReqBuffer[42];
                    struct ether_header *outEther = (struct ether_header *) (arpReqBuffer);
                    struct ether_arp *arpResp = (struct ether_arp *) (arpReqBuffer + 14);
                    outEther->ether_dhost[0] = 0xff;
                    outEther->ether_dhost[1] = 0xff;
                    outEther->ether_dhost[2] = 0xff;
                    outEther->ether_dhost[3] = 0xff;
                    outEther->ether_dhost[4] = 0xff;
                    outEther->ether_dhost[5] = 0xff;
                    memcpy(outEther->ether_shost, mymac->sll_addr, 6);
                    outEther->ether_type = 1544;
                    arpResp->ea_hdr.ar_hrd = 0x100;
                    arpResp->ea_hdr.ar_pro = 0x8;
                    arpResp->ea_hdr.ar_hln = 0x6;
                    arpResp->ea_hdr.ar_pln = 0x4;
                    arpResp->ea_hdr.ar_op = htons(0x1);
                    arpResp->arp_tha[0] = 0x00;
                    arpResp->arp_tha[1] = 0x00;
                    arpResp->arp_tha[2] = 0x00;
                    arpResp->arp_tha[3] = 0x00;
                    arpResp->arp_tha[4] = 0x00;
                    arpResp->arp_tha[5] = 0x00;
                    memcpy(arpResp->arp_spa, &ipH->ip_dst, 4);
                    memcpy(arpResp->arp_sha, outEther->ether_shost, 6);
                    memcpy(arpResp->arp_spa, &myIP->sin_addr, 4);
                    //TARGET IP FROM ROUTE TABLE
                    std::string ipStr(interface.ifa_name);
                    char *ipGet = inet_ntoa(ipH->ip_dst);
                    std::string ipStrGet(ipGet);
                    std::vector<std::string> targetIF;

                    printf("ARPRESP HEADER:__________________\n");

                    printf("Hardware: %x\n", ntohs(arpResp->arp_hrd));
                    printf("Protocol: %x\n", ntohs(arpResp->arp_pro));
                    printf("Hlen: %x\n", arpResp->arp_hln);
                    printf("Plen: %x\n", arpResp->arp_pln);
                    printf("Arp Op: %x\n", ntohs(arpResp->arp_op));
                    printf("Sender Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arpResp->arp_sha[0], arpResp->arp_sha[1],
                           arpResp->arp_sha[2], arpResp->arp_sha[3], arpResp->arp_sha[4], arpResp->arp_sha[5]);
                    printf("Sender Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arpResp->arp_tha[0], arpResp->arp_tha[1],
                           arpResp->arp_tha[2], arpResp->arp_tha[3], arpResp->arp_tha[4], arpResp->arp_tha[5]);
                    printf("Sender IP: %02d:%02d:%02d:%02d\n", arpResp->arp_spa[0], arpResp->arp_spa[1],
                           arpResp->arp_spa[2], arpResp->arp_spa[3]);
                    printf("Target IP: %02d:%02d:%02d:%02d\n", arpResp->arp_tpa[0], arpResp->arp_tpa[1],
                           arpResp->arp_tpa[2], arpResp->arp_tpa[3]);

                    for (auto &x:table) {
                        std::string bitsS = x.first.substr(x.first.find("/") + 1);
                        unsigned int bits8 = std::stoul(bitsS);
                        unsigned int bits = bits8/8;
                        printf("%d\n", bits);
                        if(bits8==24) bits = 6;
                        if(bits8==16) bits = 4;
                        std::string cutIpGet = ipStrGet.substr(0, bits);
                        std::string cutIpMap = x.first.substr(0, bits);
                        std::cout << cutIpGet << "|" << cutIpMap << '\n';
                        if (cutIpGet.compare(cutIpMap) == 0) {
                            printf("Next Hop Match\n");
                            targetIF = x.second;
                        }
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
                char *x = (char *)"-";
                if (token != x) {
                    current.push_back(token);
                    std::cout << "added: " << token << std::endl;
                }
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
    test.buildTable("r1-table.txt");
    //test.buildTable("r1-table.txt");
    printf("done");
    while (1) {}

    return 0;
}
