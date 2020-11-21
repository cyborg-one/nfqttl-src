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

#define VERSION "v2.5"



struct globalArgs_t {
    uint8_t ttl;                    /* Time to live */
    uint16_t queue_num;              /* number queue */
    uint16_t daemon;
    uint16_t splittcp;
    uint32_t mark;
} globalArgs;
static const char *optString = "dhm::n::s::t::?";

static const struct option longOpts[] = {
    { "ttl", optional_argument, NULL, 't' },
    { "mark", optional_argument, NULL, 'm' },
    { "queue-num", optional_argument, NULL, 'n' },
    { "split-tcp", optional_argument, NULL, 's' },
    { "daemon", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { NULL, no_argument, NULL, 0 }
};

uint16_t checklocal(struct iphdr *iphdr) {
    uint16_t i = 0;
    if ((0x0000ffff & iphdr->saddr) == 0x0000a8c0)
	i++;
    if ((0x000000ff & iphdr->saddr) == 0x0000000a)
	i++;
    if ((0x000000ff & iphdr->saddr) == 0x0000007f)
	i++;
    if ((0x0000ffff & iphdr->saddr) == 0x0000fea9)
	i++;
    if ((0x0000ffff & iphdr->saddr) == 0x000010ac)
	i++;

    if ((0x0000ffff & iphdr->daddr) == 0x0000a8c0)
	i = i + 2;
    if ((0x000000ff & iphdr->daddr) == 0x0000000a)
	i = i + 2;
    if ((0x000000ff & iphdr->daddr) == 0x0000007f)
	i = i + 2;
    if ((0x0000ffff & iphdr->daddr) == 0x0000fea9)
	i = i + 2;
    if ((0x0000ffff & iphdr->daddr) == 0x000010ac)
	i = i + 2;
    return i;
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

int splittcp(uint8_t *data, int len) {

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
	uint16_t tcphdrl = tcphdr->doff*4;
	uint16_t allhdrl = iphdrl+tcphdrl;
	int len_payload = len-iphdrl-tcphdrl;

	if(globalArgs.splittcp > len_payload)
		return 0;

	if(checkhost(data + allhdrl, len_payload) == 0)
		return 0;

	iphdr->tot_len = htons(allhdrl+globalArgs.splittcp);
	iphdr->ttl = globalArgs.ttl;
	nfq_tcp_compute_checksum_ipv4(tcphdr, iphdr);
	struct sockaddr_in si;
	si.sin_family=AF_INET;
	si.sin_port = tcphdr ? tcphdr->dest : 0;
	si.sin_addr.s_addr = iphdr->daddr;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == -1)	{
		perror("sock");
	}
	if (setsockopt(sock, SOL_SOCKET, SO_MARK, &globalArgs.mark, sizeof(globalArgs.mark)) == -1) {
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

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t iout = nfq_get_outdev (nfa);
	uint8_t *newdata;
	int len = nfq_get_payload(nfa, &newdata);
        if (ph) {
		id = ntohl(ph->packet_id);
		if(ntohs(ph->hw_protocol) == 0x0800 && nfq_get_nfmark(nfa) != globalArgs.mark){
    			struct iphdr *iphdr = (struct iphdr *) newdata;
			uint8_t inlocal = checklocal(iphdr);
			if(inlocal <= 1) {
				if(iout != 0) {
					if (splittcp(newdata, len)) {
						return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					} else {
						iphdr->ttl = globalArgs.ttl;
						nfq_ip_set_checksum(iphdr);
		    				return nfq_set_verdict2(qh, id, NF_ACCEPT, globalArgs.mark, len, newdata);
					}
				} else if(inlocal == 0 && iphdr->ttl <= 1){
					iphdr->ttl = globalArgs.ttl;
					nfq_ip_set_checksum(iphdr);
					return nfq_set_verdict2(qh, id, NF_ACCEPT, globalArgs.mark, len, newdata);
				}
			}
		}
		else if(ntohs(ph->hw_protocol) == 0x86dd){
		        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

//			struct ip6_hdr *ip6hdr  = (struct ip6_hdr *) newdata;
//			ip6hdr->ip6_hlim = globalArgs.ttl;
//		        return nfq_set_verdict2(qh, id, NF_ACCEPT, globalArgs.mark, len, newdata);
		}

         }
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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
		"  -m1-65535  --mark=1-65535       set mark processing package, default 0x10000000\n"
		"  -h         --help               print help\n",
		VERSION );
	exit(0);
}
//to do rewrite demonize
//in run script chech success enveropment value
int main(int argc, char **argv)
{

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

        globalArgs.ttl = 64;
	globalArgs.splittcp = 0;
	globalArgs.mark =  0x10000000;
        globalArgs.queue_num = 1;
	int opt = 0;
	int option_index = 0;
	int opta;



	while(1) {
//        int this_option_optind = optind ? optind : 1;
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
			case 'm':
				    opta = atoi(optarg);
				    if(opta > 0 && opta <= 65535){
					globalArgs.mark = opta;
					break;
				    } else{
				    printf("Wrong mark processing package: %d\n", opta);
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

			default:
				display_usage();
				break;
		}

//		opt = getopt_long( argc, argv, optString, longOpts, &option_index );
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

	printf("binding this socket to queue '%d'\nchange ttl to '%d'\nmark package %X\nSplit tcp package %hu\n",
		globalArgs.queue_num, globalArgs.ttl, globalArgs.mark, globalArgs.splittcp);
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

	printf("Waiting for packets...\n");
	fd = nfq_fd(h);
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
//			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
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
