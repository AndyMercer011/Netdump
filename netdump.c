#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int Packet_num = 0;
int IP4 = 0;
int IP6 = 0;
int ARP = 0;
int DNS = 0;
int ICMP = 0;
int TCP = 0;
int UDP = 0;
int SMTP = 0;
int POP = 0;
int IMAP = 0;
int HTTP = 0;

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
		}
		printf("IP Count: %d \n", IP4);
		printf("ARP Count: %d \n", ARP);
		printf("TCP Count: %d \n", TCP);
		printf("DNS Count: %d \n", DNS);
		printf("ICMP Count: %d \n", ICMP);
		printf("SMTP Count: %d \n", SMTP);
		printf("POP count: %d \n", POP);
		printf("IMAP count: %d \n", IMAP);
		printf("HTTP Count: %d \n", HTTP);
	}
	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
insert your code in this routine

*/

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	const u_char *data = p+14;
	
        u_int length = h->len;
        u_int caplen = h->caplen;
	printf("================================\n");
	printf("Dest Address: %02X:%02X:%02X:%02X:%02X:%02X \n",p[0],p[1],p[2],
			p[3],p[4],p[5]);
	printf("Source Address: %02X:%02X:%02X:%02X:%02X:%02X \n",p[6],p[7],
			p[8],p[9],p[10],p[11]);

	uint16_t e_type = p[12]*256+p[13];
	switch(e_type){
		case 0X800:
			printf("Payload Type: IPv4 \n");
			IP4 ++;
			print_IP(data);
			break;
		case 0X806:
			printf("Payload Type: ARP \n");
			ARP ++;
			print_ARP(data);
			break;

		case 0X86DD:
			printf("Payload Type : IPv6 \n");
			IP6 ++;
			break;
	}
	

        default_print(p, caplen);
	Packet_num ++;
	//printf("\nPacket %d been analysised",Packet_num);
	printf("\n============================");
	printf("\n]\n");
}
void print_IP(const u_char *p){
	const u_char *data = p+20;
	printf("Version: %d \n",(p[0] >> 4));
	printf("Header Length: %d \n", (p[0]&0x0f));
	printf("Service Type = %02X \n", p[1]);
	printf("Payload length = %u \n",((p[2] << 8) +p[3]));
	printf("ID = %u \n",((p[4] << 8)+p[5]));
	uint8_t flag = p[6] >> 5;
	printf("Flag = %u %u %u \n",(flag >> 2), 
			((flag >> 1) & 0b10), flag & 1);
	printf("Offset = %u \n", (((p[6] << 8) & 0x1F)+p[7]));
	printf("TTL: %u \n",p[8]);
	uint8_t protocal = p[9];
	printf("Protocal: %u \n", protocal);
	printf("Checksum: %u \n", ((p[10] << 8)+p[11]));
	printf("Source IP: %d.%d.%d.%d \n", p[12],p[13],p[14],p[15]);
	printf("DEST IP: %d.%d.%d.%d \n", p[16],p[17],p[18],p[19]);
	
	switch(protocal){
		case 1:
			ICMP ++;
			printf("ICMP spoted \n");
			print_ICMP(data);
			break;
		case 6:
			TCP ++;
			printf("TCP spoted \n");
			print_TCP(data);
			break;
		case 17:
			DNS ++;
			printf("DNS Spoted \n");
			break;
	}
}

void print_ARP(const u_char *p){
	printf("Hardware Type: %u \n",((p[0] << 8) + p[1]));
	printf("Prototype Type: %u \n",((p[2]<<8) + p[3]));
	printf("Hardware Length: %u \n",p[4]);
	printf("Protocal length: %u \n",p[5]);
	if(((p[6] << 8) + p[7]) == 1){
		printf("Operation: Request \n");
	}
	else{
		printf("Operation: Reply \n");
	}
	printf("Sender hardware address: %02X:%02X:%02X:%02X:%02X:%02X \n",p[8]
			,p[9],p[10],p[11],p[12],p[13]);
	printf("Sender Protocal address: %d:%d:%d:%d \n",p[14],p[15],p[16]
			,p[17]);
	printf("Target Hardware address: %02X:%02X:%02X:%02X:%02X:%02X \n",
			p[18],p[19],p[20],p[21],p[22],p[23]);
	printf("Target Protocal address: %d:%d:%d:%d \n",p[24],p[25],p[26]
			,p[27]);


}

void print_ICMP(const u_char *p){
	printf("------------------------------------\n");
	printf("ICMP Header: \n");
	printf("Type: %d \n",p[0]);
	printf("Code: %d \n",p[1]);
	printf("Check Sum: %u \n", ((p[2] << 8) + p[3]));
	uint32_t Parameter = (p[4] << 24) +(p[5] << 16) + (p[6] << 8) + p[7];
	printf("Parameter: %u \n", Parameter);

}

void print_TCP(const u_char *p){
	uint16_t SP = (p[0] << 8) + p[1];
	uint16_t DP = (p[2] << 8) + p[3];
	printf("TCP Header: \n");
	printf("Source Port:%u \n", SP);
	printf("DEST Port: %u \n", DP);
	uint32_t SN = (p[4] << 24) + (p[5] << 16) + (p[6] << 8) + p[7];
	uint32_t AN = (p[8] << 24) + (p[9] << 16) + (p[10] << 8) + p[11];
	printf("Sequence Number: %u \n", SN);
	printf("Ack Number: %u \n", AN);

	uint16_t HRF = (p[12] << 8) + p[13];
	printf("Head Length: %u \n", ((HRF >> 12) *4));
	int i = (HRF >> 12) * 4;
	//printf("test: %d\n",i);
	const u_char *data = p + i;
	printf("Reserved: %u \n", ((HRF >> 6) & 0b111111));
	uint8_t flag = p[13] & 0x3f;
	printf("Flag:\n");
	printf("URG: %u \n", (flag >> 5));
	printf("ACK: %u \n", (flag >> 4) & 0b1);
	printf("PSH: %u \n", (flag >> 3) & 0b1);
	printf("RST: %u \n", (flag >> 2) & 0b1);
	printf("SYN: %u \n", (flag >> 1) & 0b1);
	printf("FIN: %u \n", flag & 0b1);
	printf("windows Sizes: %u \n", ((p[14] << 8) + p[15]));
	printf("Check sum: %u \n", ((p[16] << 8) + p[17]));
	printf("Urgent pointer: %u \n", ((p[18] << 8) + p[19]));
	
	
	if(DP == 25 || SP == 25 || DP == 465 || SP == 465 || 
			DP == 587 || SP == 587){
		SMTP ++;
		printf("SMTP Payload: \n");
		print_payload(data);
	}
	else if(DP == 143 || SP == 143 || DP == 993 || SP == 993){
		IMAP ++ ;
		printf("IMAP Payload: \n");
		print_payload(data);
	}
	else if(DP == 80 || SP == 80 || DP == 443 || SP == 443){
		HTTP ++;
		printf("HTTP Payload: \n");
		print_payload(data);
	}
	else if(DP == 110 || SP == 110 || DP == 995 || SP == 995){
		POP ++;
		printf("POP Payload: \n");
		print_payload(data);
	}
	else if(DP == 53 || SP == 53){
		DNS++;
		printf("DNS SPOTED \n");
	}
}
void print_payload(const u_char *p){
	char *end;
	while((end = strstr(p, "\r\n")) != NULL){
		*end = '\0';
		printf("%s\n",p);
		p = end +1;
	}
	
}
