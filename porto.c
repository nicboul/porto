/* Copyright 2016 Nicolas J. Bouliane. All rights reserved
 * Use of this source code is governed by a Simplified BSD license.
 */

#include <sys/types.h>

#include <netinet/in.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <event2/event.h>
#include <dnet.h>
#include <pcap.h>

char			*ip_local = NULL;
char			*ip_target = NULL;
char			*interface = NULL;
int 			 link_hdr_len;
int			 max_port = 65535;
int			 seen_port = 0;
int			 total = 0;
int			*port_array;
ip_t			*ip_handle;
pcap_t			*p;
rand_t			*rnd;
struct addr		 src;
struct addr		 dst;
struct event		*read_ev;
struct event		*probe_ev;
struct event		*ev_int;
struct event_base	*base;
struct timeval		 tv;

static void
scan(const u_char *frame)
{
	struct ip_hdr	*ip_h;
	struct tcp_hdr	*tcp_h;
	const u_char	*packet;

	packet = frame + link_hdr_len;
	ip_h = (struct ip_hdr *)packet;
	if (ip_h->ip_v != 4)
		return;

	tcp_h = (struct tcp_hdr *)(packet + IP_HDR_LEN);
	seen_port = ntohs(tcp_h->th_sport);
	if (port_array[seen_port] == 0) {
		port_array[seen_port] = 1;
		fprintf(stdout, "%d \t open \n", seen_port);
	}
}

#define MAXWAIT 3
static void
on_read(int fd, short event, void *arg)
{
	struct pcap_pkthdr	 ph;
	const u_char		*frame;
	static time_t		 lastcall = 0;

	if ((frame = pcap_next(p, &ph)) != NULL)
		scan(frame);

	if (total >= max_port) {
		if (lastcall == 0)
			lastcall = time(NULL);
		else if (seen_port >= max_port ||
				time(NULL) - lastcall > MAXWAIT) {
			return;
		}
	}

	event_add(read_ev, &tv);
}

static void
on_probe(int fd, short event, void *arg)
{
	int	len;
	int	sprint = 0;
	struct {
		union {
			struct ip_hdr	ip;
		} pkt_hdr_ip;
		union {
			struct tcp_hdr	tcp;
		} pkt_hdr_tcp;
	} pkt;

	len = IP_HDR_LEN + TCP_HDR_LEN;

	while (sprint++ < 100 && total++ <= max_port) {
		ip_pack_hdr(&pkt.pkt_hdr_ip, IP_TOS_LOWDELAY, len,
				rand_uint16(rnd), 0, 64, IP_PROTO_TCP,
				src.addr_ip, dst.addr_ip);

		tcp_pack_hdr(&pkt.pkt_hdr_tcp, rand_uint16(rnd), total,
				rand_uint32(rnd), rand_uint32(rnd),
				TH_SYN, rand_uint16(rnd), 0);

		ip_checksum(&pkt, len);

		ip_send(ip_handle, &pkt, len);
	}

	if (total <= max_port)
		event_add(probe_ev, &tv);

	return;
}

static int
link_offset(pcap_t *p)
{
	int offset = -1;

	switch (pcap_datalink(p)) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
	case DLT_NULL:
		offset = 4;
		break;
	default:
		warnx("unsupported datalink type");
		break;
	}
	return (offset);
}

static void
usage()
{
	fprintf(stderr, "Options:\n"
		"  -i <interface>\n"
		"  -s <local ip>\n"
		"  -d <target ip>\n"
		"  -p [max port number] Default 65535\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	char	strbpf[2048];
	int	fd, opt;
	struct	bpf_program bpf;


	if (argc < 2)
		usage();

	while ((opt = getopt(argc, argv, "s:d:i:p:")) != -1) {
		switch (opt) {
		case 's':
			ip_local = strdup(optarg);
			break;
		case 'd':
			ip_target = strdup(optarg);
			break;
		case 'i':
			interface = strdup(optarg);
			break;
		case 'p':
			max_port = atoi(optarg);
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (ip_local == NULL ||
	    ip_target == NULL ||
	    interface == NULL) {
		usage();
	}

	if ((p = pcap_open_live(interface, 1500, 1, 500, errbuf)) == NULL)
		err(1, "pcap_open_live");

	snprintf(strbpf, sizeof(strbpf),
		"tcp[tcpflags] == tcp-syn|tcp-ack and src %s and dst %s",
		ip_target, ip_local);

	if (pcap_compile(p, &bpf, strbpf, 1, PCAP_NETMASK_UNKNOWN) == -1)
		err(1, "pcap_compile");

	if (pcap_setfilter(p, &bpf) == -1)
		err(1, "pcap_setfilter");

	ip_handle = ip_open();
	fd = pcap_fileno(p);
	rnd = rand_open();
	link_hdr_len = link_offset(p);
	tv.tv_sec = 0;
	tv.tv_usec = 500;
	addr_aton(ip_local, &src);
	addr_aton(ip_target, &dst);
	port_array = calloc(1, sizeof(int) * max_port);

	base = event_base_new();

	read_ev = event_new(base, fd, EV_READ, on_read, NULL);
	event_add(read_ev, &tv);

	probe_ev = event_new(base, fd, EV_WRITE, on_probe, NULL);
	event_add(probe_ev, &tv);

	printf("Scanning %s...\n", ip_target);
	event_base_dispatch(base);
	printf("-- completed --\n");

	pcap_close(p);
	ip_close(ip_handle);
	event_base_free(base);
	free(interface);
	free(ip_local);
	free(ip_target);
	free(port_array);

	return(0);
}
