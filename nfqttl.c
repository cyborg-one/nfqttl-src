#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#define _GNU_SOURCE
#define  __USE_MISC 1


#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdint.h>

#include <pwd.h>
#include <fcntl.h>

#define VERSION "v2.7"

struct globalArgs_t {
    uint8_t ttl;                    /* Time to live */
    uint8_t ttllocal;
    uint8_t tos;
    uint16_t queue_num;              /* number queue */
    uint16_t daemon;
    uint16_t splittcp;
    uint32_t mark;
    uint32_t marki;
    uint32_t marko;
    uint32_t vpn;
    int nf_action;
} globalArgs;
static const char *optString = "dhm::n::s::t::?";

static const struct option longOpts[] = {
    { "ttl", optional_argument, NULL, 't' },
    { "mark", optional_argument, NULL, 'm' },
    { "queue-num", optional_argument, NULL, 'n' },
    { "split-tcp", optional_argument, NULL, 's' },
    { "daemon", no_argument, NULL, 'd' },
    { "processingvpn", no_argument, NULL, 0 },
    { "nf_accept", no_argument, NULL, 0 },
    { "help", no_argument, NULL, 'h' },
    { NULL, no_argument, NULL, 0 }
};


struct ip_addr {
    struct _ip_addr *next;
    sa_family_t sa_family;
    char        sa_data[16];
};
struct if_addr{
    struct if_addr *next;
    uint8_t vpn;
    uint8_t mac;
    char name[IFNAMSIZ+1];
    unsigned int index;
    struct ip_addr *ip_addr;
};

struct rtattr {
    unsigned short      rta_len;
    unsigned short      rta_type;
};
struct rtgenmsg {
    unsigned char       rtgen_family;
};
struct ifinfomsg {
    unsigned char       ifi_family;
    unsigned char       __ifi_pad;
    unsigned short      ifi_type;
    int         ifi_index;
    unsigned    ifi_flags;
    unsigned    ifi_change;
};

#define NI_MAXHOST      1025

#define RTM_NEWLINK     16
#define RTM_GETLINK     18
#define RTM_NEWADDR     20
#define RTM_GETADDR     22

#define IFLA_ADDRESS    1
#define IFLA_BROADCAST  2
#define IFLA_IFNAME     3
#define IFLA_STATS      7

struct ifaddrmsg {
    uint8_t             ifa_family;
    uint8_t             ifa_prefixlen;
    uint8_t             ifa_flags;
    uint8_t             ifa_scope;
    uint32_t    ifa_index;
};

#define IFA_ADDRESS     1
#define IFA_LOCAL       2
#define IFA_LABEL       3
#define IFA_BROADCAST   4
/* musl */

#define NETLINK_ALIGN(len)      (((len)+3) & ~3)
#define NLMSG_DATA(nlh)         ((void*)((char*)(nlh)+sizeof(struct nlmsghdr)))
#define NLMSG_DATALEN(nlh)      ((nlh)->nlmsg_len-sizeof(struct nlmsghdr))
#define NLMSG_DATAEND(nlh)      ((char*)(nlh)+(nlh)->nlmsg_len)
#define NLMSG_NEXT(nlh)         (struct nlmsghdr*)((char*)(nlh)+NETLINK_ALIGN((nlh)->nlmsg_len))
#define NLMSG_OK(nlh,end)       ((char*)(end)-(char*)(nlh) >= sizeof(struct nlmsghdr))
#define RTA_DATA(rta)           ((void*)((char*)(rta)+sizeof(struct rtattr)))
#define RTA_DATALEN(rta)        ((rta)->rta_len-sizeof(struct rtattr))
#define RTA_DATAEND(rta)        ((char*)(rta)+(rta)->rta_len)
#define RTA_NEXT(rta)           (struct rtattr*)((char*)(rta)+NETLINK_ALIGN((rta)->rta_len))
#define RTA_OK(nlh,end)         ((char*)(end)-(char*)(rta) >= sizeof(struct rtattr))
#define NLMSG_RTA(nlh,len)      ((void*)((char*)(nlh)+sizeof(struct nlmsghdr)+NETLINK_ALIGN(len)))
#define NLMSG_RTAOK(rta,nlh)    RTA_OK(rta,NLMSG_DATAEND(nlh))

void freeif_addr(struct if_addr *ifp)
{
    struct if_addr *f;
    struct if_addr *p;
    while (ifp) {
        while (ifp->ip_addr) {
            p = ifp->ip_addr->next;
            free(ifp->ip_addr);
            ifp->ip_addr = p;
        }
        f = ifp->next;
        free(ifp);
        ifp = f;
    }
}
static int netlink_msg_to_ifaddr(struct if_addr *ifaddr, struct nlmsghdr *h){

	struct ifaddrs_storage *ifs, *ifs0;
        struct ifinfomsg *ifi = NLMSG_DATA(h);
	struct ifaddrmsg *ifa = NLMSG_DATA(h);
        struct rtattr *rta;
	int stats_len = 0;

        struct ip_addr *ip_addr0 = NULL;

        if(ifaddr->index != (h->nlmsg_type == RTM_NEWLINK ? ifi->ifi_index : ifa->ifa_index))
		return 0;

        for (rta = NLMSG_RTA(h, h->nlmsg_type == RTM_NEWLINK ? sizeof(*ifi) : sizeof(*ifa)); NLMSG_RTAOK(rta, h); rta = RTA_NEXT(rta)) {
    	        if(rta->rta_type == IFA_ADDRESS) {

        	        if(ifaddr->ip_addr) {
                		for(ip_addr0 = ifaddr->ip_addr; ip_addr0->next != NULL; ip_addr0 = ip_addr0->next);
                		ip_addr0->next = calloc(1, sizeof(struct ip_addr));
                		ip_addr0 = ip_addr0->next;

            		} else {
                		ifaddr->ip_addr = calloc(1, sizeof(struct ip_addr));
                		ip_addr0 = ifaddr->ip_addr;
            		}

            		if (ip_addr0 == 0) {
                		return -1;
            		}
    			ip_addr0->sa_family = h->nlmsg_type == RTM_NEWLINK ? AF_PACKET : ifa->ifa_family;
			if(ip_addr0->sa_family == AF_PACKET)
				ifaddr->mac = 1;
            		memcpy(ip_addr0->sa_data, RTA_DATA(rta), RTA_DATALEN(rta));


        	}
        	if(rta->rta_type == IFA_LABEL) {
            	        memcpy(ifaddr->name, RTA_DATA(rta), RTA_DATALEN(rta));
		        if((ifaddr->name[0] == 'l' && ifaddr->name[1] == 'o') || (ifaddr->name[0] == 't' && ((ifaddr->name[1] == 'u' && ifaddr->name[2] == 'n') || (ifaddr->name[1] == 'a' || ifaddr->name[2] == 'p'))))
			        ifaddr->vpn = 1;
        	}
        }
	return 0;
}

static int __netlink_enumerate(int fd, unsigned int seq, int type, int af,
    int (*cb)(void *if_addr, struct nlmsghdr *h), struct if_addr *ifaddr)
{
    struct nlmsghdr *h;
    union {
        uint8_t buf[8192];
        struct {
            struct nlmsghdr nlh;
            struct rtgenmsg g;
        } req;
        struct nlmsghdr reply;
    } u;
    int r, ret;

    memset(&u.req, 0, sizeof(u.req));
    u.req.nlh.nlmsg_len = sizeof(u.req);
    u.req.nlh.nlmsg_type = type;
    u.req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    u.req.nlh.nlmsg_seq = seq;
    u.req.g.rtgen_family = af;
    r = send(fd, &u.req, sizeof(u.req), 0);
    if (r < 0) return r;
    while (1) {
        r = recv(fd, u.buf, sizeof(u.buf), MSG_DONTWAIT);
        if (r <= 0) return -1;
        for (h = &u.reply; NLMSG_OK(h, (void*)&u.buf[r]); h = NLMSG_NEXT(h)) {
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == NLMSG_ERROR) return -1;
            ret = cb(ifaddr, h);
            if (ret) return ret;
        }
    }
}


int getifaddrs(struct if_addr *ifaddr)
{
        int fd, r;
        fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) return -1;
	r = __netlink_enumerate(fd, 1, RTM_GETLINK, AF_UNSPEC, netlink_msg_to_ifaddr, ifaddr);
        close(fd);
	return 0;
}



int checkhost(uint8_t *data, int len) {
        for(int i = 0; len > i; i++) {
                if(data[i] == 'h' || data[i] == 'H') {

                        if((data[i+1] == 't' || data[i+1] == 'T') && (data[i+2] == 't' || data[i+2] == 'T') && (data[i+3] == 'p' || data[i+3] == 'P')) {
                                return 1;
                        }
                }
        }

        return 0;
}

int splittcp(uint8_t *data, int len, struct if_addr *ifaddr) {

	if(globalArgs.splittcp == 0)
		return 0;
	int sock = 0;
	uint8_t newdata[len];
	memcpy(newdata, data, len);
	struct iphdr *iphdr = (struct iphdr *)newdata;

	if(iphdr->protocol != IPPROTO_TCP)
		return 0;
	uint16_t iphdrl = iphdr->ihl*4;
	struct tcphdr *tcphdr = (struct tcphdr *)( newdata + iphdrl);

	if(tcphdr->syn)
		return 0;
	uint16_t dport = ntohs(tcphdr->dest);
	if(dport != 443 && dport != 80 && dport != 8000)
		return 0;

	uint16_t tcphdrl = tcphdr->doff*4;
	uint16_t allhdrl = iphdrl+tcphdrl;
	int len_payload = len-iphdrl-tcphdrl;

	if(globalArgs.splittcp > len_payload)
		return 0;

	if(checkhost(data + allhdrl, len_payload) == 0)
		return 0;

	iphdr->tot_len = htons(allhdrl+globalArgs.splittcp);
	iphdr->ttl = (globalArgs.ttl + ifaddr->mac);

	nfq_tcp_compute_checksum_ipv4(tcphdr, iphdr);
	struct sockaddr_in si;
	si.sin_family=AF_INET;
	si.sin_port = tcphdr ? tcphdr->dest : 0;
	si.sin_addr.s_addr = iphdr->daddr;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == -1)	{
		perror("sock");
	}
	if (setsockopt(sock, SOL_SOCKET, SO_MARK, &globalArgs.marko, sizeof(globalArgs.marko)) == -1) {
	        perror("setsockopt not success mark");
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifaddr->name, strlen(ifaddr->name)) == -1) {
    		perror("setsockopt not success mark");
	}


	if (sendto(sock, (char*)newdata, allhdrl+globalArgs.splittcp, 0, (struct sockaddr*)&si, sizeof(struct sockaddr)) == -1) {
		perror("sendto 1");
	}

	memcpy((char*)newdata+iphdrl+sizeof(struct tcphdr), (char*)data+globalArgs.splittcp+allhdrl, len_payload-globalArgs.splittcp);

	iphdr->tot_len = htons(len_payload-globalArgs.splittcp+iphdrl+sizeof(struct tcphdr));

	tcphdr->seq = htonl(ntohl(tcphdr->seq)+globalArgs.splittcp);
	tcphdr->doff = 5;
	nfq_tcp_compute_checksum_ipv4(tcphdr, iphdr);
	int len2 = len_payload-globalArgs.splittcp+iphdrl+sizeof(struct tcphdr);

	if(sendto(sock, (char*)newdata, len2, 0, (struct sockaddr*)&si, sizeof(struct sockaddr)) == -1)	{
		perror("sendto 2");
	}
	close(sock);

	return 1;
}

struct nfq_handle
{
        struct nfnl_handle *nfnlh;
        struct nfnl_subsys_handle *nfnlssh;
        struct nfq_q_handle *qh_list;
};
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t iout = nfq_get_outdev (nfa);
	uint32_t iin = nfq_get_indev (nfa);
	uint32_t mark = nfq_get_nfmark(nfa);
	uint8_t *newdata;
	int len = nfq_get_payload(nfa, &newdata);
	int ret = 0;
        if (ph) {
		struct if_addr *ifaddr = calloc(1, sizeof(struct if_addr));
		ifaddr->index = iout ? iout : iin;
		getifaddrs(ifaddr);
		id = ntohl(ph->packet_id);
		if(ntohs(ph->hw_protocol) == 0x0800 && (ifaddr->vpn == 0 || globalArgs.vpn == 1 )){
    			struct iphdr *iphdr = (struct iphdr *) newdata;
			if(iout > 0 && mark != globalArgs.mark && mark != globalArgs.marko) {
					if (splittcp(newdata, len, ifaddr)) {
						ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					} else if (iphdr->ttl != (globalArgs.ttl + ifaddr->mac)) {
						iphdr->ttl = (globalArgs.ttl + ifaddr->mac);
						nfq_ip_set_checksum(iphdr);
						ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.marko, len, newdata);
					} else ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.marko, 0, NULL);
			} else if(iin > 0 && mark != globalArgs.mark && mark != globalArgs.marki){
				if( ifaddr->mac == 0 && iphdr->ttl <= 1) {
					iphdr->ttl = globalArgs.ttl;
					nfq_ip_set_checksum(iphdr);
					ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.marki, len, newdata);
				} else ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.marki, 0, NULL);
			} else ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.mark, 0, NULL);
		}
		else if(ntohs(ph->hw_protocol) == 0x86dd && (ifaddr->vpn == 0 || globalArgs.vpn == 1)){
			struct ip6_hdr *iphdr = (struct ip6_hdr *) newdata;
			if(iout > 0 && mark != globalArgs.marko){
				struct if_addr *ifaddr = calloc(1, sizeof(struct if_addr));
				ifaddr->index = iout;
				getifaddrs(ifaddr);
				if(ifaddr->mac || iphdr->ip6_hlim != globalArgs.ttl) {
				        ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				} else ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.marko, 0, NULL);
			} else if(mark != globalArgs.marki) ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.marki, 0, NULL);
		} else  ret = nfq_set_verdict2(qh, id, globalArgs.nf_action, globalArgs.mark, 0, NULL);
		freeif_addr(ifaddr);
	}

	return ret;
}

void daemonize()
{


	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	/* stdin */
	dup(0);
	/* stdout */
	dup(0);
	/* stderror */
}


void display_usage( void )
{
	printf(	"Nfqttl version %s\n"
		"Commands:\n"
		"  -d         --daemon             demonize\n"
		"  -n1-65535  --queue-num=1-65535  queue number, default 1\n"
		"  -t1-255    --ttl=1-255          set time to live, default 64\n"
		"  -s1-65535  --split-tcp=1-65535  split tcp sequence, default disable\n"
		"  --processingvpn		   processing package on tun/tap interface\n"
		"  --nf_accept                     change action NF_REPEAT to NF_ACCEPT\n"
		"  -h         --help               print help\n",
		VERSION );
	exit(0);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[196608] __attribute__ ((aligned));

        globalArgs.ttl = 64;
        globalArgs.ttllocal = 65;
	globalArgs.tos = 255;
	globalArgs.splittcp = 0;
	globalArgs.mark =  0x10000001;
	globalArgs.marki = 0x10000002;
	globalArgs.marko = 0x10000003;
        globalArgs.queue_num = 0x1000;
	globalArgs.vpn = 0;
	globalArgs.nf_action = NF_REPEAT;
	int opt = 0;
	int option_index = 0;
	int opta;



	while(1) {
	opt = getopt_long( argc, argv, optString, longOpts, &option_index );
        if (opt == -1)
            break;
	    switch( opt ) {
			case 't':
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 255){
					globalArgs.ttl = opta;
					break;
				    } else{
				    printf("Wrong ttl value: %d\n", opta);
				    display_usage();
				    break;
				    }
			case 'n':
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					globalArgs.queue_num = opta;
					break;
				    } else{
				    printf("Wrong queue number value: %d\n", opta);
				    display_usage();
				    break;
				    }
			case 's':
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					globalArgs.splittcp = opta;
					break;
				    } else{
				    printf("Wrong split tcp pakage value: %d\n", opta);
				    display_usage();
				    break;
				    }
			case 'd':
				globalArgs.daemon = 1;
    				break;
			case 'h':	/* fall-through is intentional */
			case '?':
				display_usage();
				break;
			case 0:
        			if( strcmp( "processingvpn", longOpts[option_index].name ) == 0 ) {
printf("processingvpn\n");
                			globalArgs.vpn = 1;
            			}
        			if( strcmp( "nf_accept", longOpts[option_index].name ) == 0 ) {
printf("nf_accept\n");
                			globalArgs.nf_action = NF_ACCEPT;
            			}
            			break;
			default:
				display_usage();
				break;
		}

	}


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET6 (if any)\n");
        if (nfq_unbind_pf(h, AF_INET6) < 0) {
	    fprintf(stderr, "error during nfq_unbind_pf()\n");
	    exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET6\n");
        if (nfq_bind_pf(h, AF_INET6) < 0) {
	    fprintf(stderr, "error during nfq_bind_pf()\n");
	    exit(1);
        }

	printf("binding this socket to queue '0x%x'\nchange ttl to '%d'\nmark package '0x%x'\nSplit tcp package '%hu'\n",
		globalArgs.queue_num, globalArgs.ttl, globalArgs.marko, globalArgs.splittcp);
	qh = nfq_create_queue(h, globalArgs.queue_num, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	if(globalArgs.daemon == 1) {
		printf("daemonize\n");
		daemonize();
	}

	nfnl_rcvbufsiz(h->nfnlh, 196608);

	printf("Waiting for packets...\n");
	fd = nfq_fd(h);
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
//			printf("pkt received\n");
			int r = nfq_handle_packet(h, buf, rv);
			if (r) printf("nfq_handle_packet %i rv %i\n", r, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
