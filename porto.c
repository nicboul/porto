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
#include <event2/listener.h>
#ifdef __FreeBSD__
#include <dnet.h>
#elif __linux__
#include <dumbnet.h>
#endif
#include <pcap.h>

struct scanner {
	char			*interface;
	char			*ip_local;
	char			*ip_target;
	char			*port_array;
	char			 strbpf[2048];
	int			 fd;
	int 			 link_hdr_len;
	int			 max_port;
	int			 seen_port;
	int			 total;
	ip_t			*ip_handle;
	pcap_t			*p;
	rand_t			*rnd;
	time_t			 lastcall;
	struct bpf_program	 bpf;
	struct addr		 src;
	struct addr		 dst;
	struct event		*read_ev;
	struct event		*probe_ev;
	struct event_base	*base;
	struct timeval		 tv;
};

#define MAXWAIT 3
#define MAXPORT 65535

static void
scan(struct scanner *s, const u_char *frame)
{
	struct ip_hdr	*ip_h;
	struct tcp_hdr	*tcp_h;
	const u_char	*packet;

	packet = frame + s->link_hdr_len;
	ip_h = (struct ip_hdr *)packet;
	if (ip_h->ip_v != 4)
		return;

	tcp_h = (struct tcp_hdr *)(packet + IP_HDR_LEN);
	s->seen_port = ntohs(tcp_h->th_sport);
	if (s->port_array[s->seen_port] == 0) {
		s->port_array[s->seen_port] = 1;
		fprintf(stdout, "%d \t open \n", s->seen_port);
	}
}

static void
on_read(int fd, short event, void *arg)
{
	const u_char		*frame;
	struct pcap_pkthdr	 ph;
	struct scanner		*s = arg;

	if ((frame = pcap_next(s->p, &ph)) != NULL)
		scan(s, frame);

	if (s->total >= s->max_port) {
		if (s->lastcall == 0)
			s->lastcall = time(NULL);
		else if (s->seen_port >= s->max_port ||
				time(NULL) - s->lastcall > MAXWAIT) {
			return;
		}
	}

	event_add(s->read_ev, &s->tv);
}

static void
on_probe(int fd, short event, void *arg)
{
	int		 len;
	int		 sprint = 0;
	struct scanner	*s = arg;

	struct {
		union {
			struct ip_hdr	ip;
		} pkt_hdr_ip;
		union {
			struct tcp_hdr	tcp;
		} pkt_hdr_tcp;
	} pkt;

	len = IP_HDR_LEN + TCP_HDR_LEN;

	while (sprint++ < 100 && s->total++ <= s->max_port) {
		ip_pack_hdr(&pkt.pkt_hdr_ip, IP_TOS_LOWDELAY, len,
				rand_uint16(s->rnd), 0, 64, IP_PROTO_TCP,
				s->src.addr_ip, s->dst.addr_ip);

		tcp_pack_hdr(&pkt.pkt_hdr_tcp, rand_uint16(s->rnd), s->total,
				rand_uint32(s->rnd), rand_uint32(s->rnd),
				TH_SYN, rand_uint16(s->rnd), 0);

		ip_checksum(&pkt, len);

		ip_send(s->ip_handle, &pkt, len);
	}

	if (s->total <= s->max_port)
		event_add(s->probe_ev, &s->tv);

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
scanner_init(struct scanner *s)
{
	char	errbuf[PCAP_ERRBUF_SIZE];

	if ((s->p = pcap_open_live(s->interface, 1500, 1, 500, errbuf)) == NULL)
		err(1, "pcap_open_live");

	snprintf(s->strbpf, sizeof(s->strbpf),
		"tcp[tcpflags] == tcp-syn|tcp-ack and src %s and dst %s",
		s->ip_target, s->ip_local);

	if (pcap_compile(s->p, &s->bpf, s->strbpf, 1, PCAP_NETMASK_UNKNOWN) == -1)
		err(1, "pcap_compile");

	if (pcap_setfilter(s->p, &s->bpf) == -1)
		err(1, "pcap_setfilter");

	s->ip_handle = ip_open();
	s->fd = pcap_fileno(s->p);
	s->rnd = rand_open();
	s->link_hdr_len = link_offset(s->p);
	s->tv.tv_sec = 0;
	s->tv.tv_usec = 500;
	if (s->max_port == 0)
		s->max_port = MAXPORT;
	addr_aton(s->ip_local, &s->src);
	addr_aton(s->ip_target, &s->dst);
	s->port_array = calloc(1, sizeof(char) * s->max_port);

	s->base = event_base_new();

	s->read_ev = event_new(s->base, s->fd, EV_READ, on_read, s);
	event_add(s->read_ev, &s->tv);

	s->probe_ev = event_new(s->base, s->fd, EV_WRITE, on_probe, s);
	event_add(s->probe_ev, &s->tv);
}

static void
scanner_free(struct scanner *s)
{
	event_free(s->read_ev);
	event_free(s->probe_ev);
	event_base_free(s->base);

	pcap_freecode(&s->bpf);
	pcap_close(s->p);

	ip_close(s->ip_handle);
	rand_close(s->rnd);

	free(s->interface);
	free(s->ip_local);
	free(s->ip_target);
	free(s->port_array);
}

static void
scan_test()
{
	struct evconnlistener   **listener_array;
	int		 	 i, port, error = 0;
	struct scanner	 	 s;
	struct sockaddr_in       sin;

	memset(&s, 0, sizeof(s));
	listener_array = calloc(1, sizeof(struct evconnlistener *) * MAXPORT);

	s.ip_local = strdup("127.0.0.1");
	s.ip_target = strdup("127.0.0.1");

#ifdef __FreeBSD__
	s.interface = strdup("lo0");
#elif __linux__
	s.interface = strdup("lo");
#endif

	scanner_init(&s);
	s.tv.tv_usec = 0;

	for (i = 1; i < 100; i++) {

		port = rand_uint16(s.rnd);

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(0);
		sin.sin_port = htons(port);

		listener_array[port] = evconnlistener_new_bind(s.base, NULL, NULL,
		LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
		(struct sockaddr*)&sin, sizeof(sin));
	}

	printf("Test Scanning...\n");
	event_base_dispatch(s.base);
	printf("-- completed --\n");

	for (i = 0; i < s.max_port; i++) {
		if (listener_array[i] != NULL) {
			evconnlistener_free(listener_array[i]);
			if (s.port_array[i] == 0)
				error++;
		}
	}

	scanner_free(&s);

	printf("%d error(s) found\n", error);
}

static void
usage()
{
	fprintf(stderr, "Options:\n"
		"  -i <interface>\n"
		"  -s <local ip>\n"
		"  -d <target ip>\n"
		"  -p [max port number] Default 65535\n"
		"  -t perform test scanner\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	int		test, opt;
	struct scanner	s;


	if (argc < 2)
		usage();

	memset(&s, 0, sizeof(s));

	while ((opt = getopt(argc, argv, "s:d:i:p:t")) != -1) {
		switch (opt) {
		case 's':
			s.ip_local = strdup(optarg);
			break;
		case 'd':
			s.ip_target = strdup(optarg);
			break;
		case 'i':
			s.interface = strdup(optarg);
			break;
		case 'p':
			s.max_port = atoi(optarg);
			break;
		case 't':
			test = 1;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test == 1) {
		scan_test();
		return 0;
	}

	if (s.ip_local == NULL ||
	    s.ip_target == NULL ||
	    s.interface == NULL) {
		usage();
	}

	scanner_init(&s);

	printf("Scanning %s...\n", s.ip_target);
	event_base_dispatch(s.base);
	printf("-- completed --\n");

	scanner_free(&s);

	return(0);
}
