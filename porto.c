#include <err.h>

#include <event2/event.h>
#include <pcap.h>

struct event_base	*base;
struct event		*ev_int;
pcap_t			*p;
struct timeval		 tv;

static void
on_read(int fd, short event, void *arg)
{
	printf("on read\n");	
}

static void
on_write(int fd, short event, void *arg)
{
	printf("on write\n");
}

int
main(int argc, char *argv[])
{

	char		 errbuf[PCAP_ERRBUF_SIZE];
	int		 fd;
	struct	event	*read_ev;
	struct	event	*write_ev;

	base = event_base_new();

	if ((p = pcap_open_live("wlan0", 1500, 1, 500, errbuf)) == NULL)
		err(1, "pcap_open_live");

	fd = pcap_fileno(p);

	read_ev = event_new(base, fd, EV_READ, on_read, NULL);
	event_add(read_ev, &tv);

	write_ev = event_new(base, fd, EV_WRITE, on_write, NULL);
	event_add(write_ev, &tv);

	event_base_dispatch(base);

	return(0);
}
