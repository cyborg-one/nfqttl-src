#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
/* #include <libnetfilter_queue/src/internal.h> */
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <getopt.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>

struct globalArgs_t {
    uint16_t ttl;                    /* Tim to live */
    uint16_t numq;              /* number queue */
    uint16_t daemon;
} globalArgs;

static const char *optString = "t:n:dh?";

static const struct option longOpts[] = {
    { "ttl", optional_argument, NULL, 't' },
    { "num-queue", optional_argument, NULL, 'n' },
    { "daemon", no_argument, NULL, 'd' },
    { "help", no_argument, NULL, 'h' },
    { NULL, no_argument, NULL, 0 }
};
/* returns packet id */
static uint32_t set_ttl (struct nfq_data *tb,unsigned char *data,int len)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct pkt_buff *pktb;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		    if(ntohs(ph->hw_protocol) == 0x0800){
			struct iphdr *iphdr  = (struct iphdr *) data;
			pktb = pktb_alloc(AF_INET,data,len,4096);
			iphdr->ttl = globalArgs.ttl;
			nfq_ip_set_checksum(iphdr);
			pktb = (struct pkt_buff *)iphdr;

		    }
		    else if(ntohs(ph->hw_protocol) == 0x86dd){
			printf("test 0x86dd\n");
			struct ip6_hdr *ip6hdr  = (struct ip6_hdr *) data;
			pktb = pktb_alloc(AF_INET,data,len,4096);
			ip6hdr->ip6_hlim = globalArgs.ttl;
			pktb = (struct pkt_buff *)ip6hdr;
		    }
		}
		else{
		}
	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *cookie)
{
	unsigned char *data;
	int len = nfq_get_payload(nfa, &data);
	uint32_t id = set_ttl(nfa, data, len);
//	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, len, data);
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
	puts( "Usage:\n -d --daemon;\tdo not demonize\n -n --num-queue=1-65535;\tnum queue, default 201\n -t --ttl=1-255;\tset time to live, default 64\n -h --help;\tprint help\n" );

	exit( EXIT_FAILURE );
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	int opt = 0;
	int option_index = 0;
	globalArgs.ttl = 64;
	globalArgs.numq = 201;
	globalArgs.daemon = 1;
	int opta;

	opt = getopt_long( argc, argv, optString, longOpts, &option_index );

	while( opt != -1 ) {
	    switch( opt ) {
			case 't':
				opta = atoi(optarg);
				if(opta > 0 && opta <= 255){
				    globalArgs.ttl = opta;
    				    break;
				} else{
				    printf("Wrong ttl value: %d\n", opta);
				    display_usage();
				}

			case 'n':
				opta = atoi(optarg);
				if(opta > 0 && opta <= 65535){
				    globalArgs.numq = opta;
    				    break;
				} else{
				    printf("Wrong number queue value: %d\n", opta);
				    display_usage();
				}
			case 'd':
//				    printf("daemonize\n");
				    globalArgs.daemon = 0;
//				    daemonize();
    				    break;
				

			case 'h':	/* fall-through is intentional */
			case '?':
				display_usage();
				break;

			default:
				display_usage();
				break;
		}

		opt = getopt_long( argc, argv, optString, longOpts, &option_index );
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

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d', change ttl to '%d'\n", globalArgs.numq, globalArgs.ttl);
	qh = nfq_create_queue(h, globalArgs.numq, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	printf("Waiting for packets...\n");

	fd = nfq_fd(h);
	if(globalArgs.daemon == 1){
	    printf("demonize");
	    daemonize();
	}
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
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
