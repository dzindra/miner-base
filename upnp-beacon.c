#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <signal.h>

int openSocket(const char * socketPath) {
	struct sockaddr_un addr;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s < 0) {
		printf("Error: Unable to open socket: %d\n", s);
		return -1;
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socketPath, sizeof(addr.sun_path));
	if(connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		printf("Error: Unable to connect to socket %s\n", socketPath);
		return -2;
	}

	return s;
}

/* Encode length by using 7bit per Byte :
 * Most significant bit of each byte specifies that the
 * following byte is part of the code */
#define DECODELENGTH(n, p) n = 0; \
                           do { n = (n << 7) | (*p & 0x7f); } \
                           while(*(p++)&0x80);

#define CODELENGTH(n, p) if(n>=268435456) *(p++) = (n >> 28) | 0x80; \
                         if(n>=2097152) *(p++) = (n >> 21) | 0x80; \
                         if(n>=16384) *(p++) = (n >> 14) | 0x80; \
                         if(n>=128) *(p++) = (n >> 7) | 0x80; \
                         *(p++) = n & 0x7f;

char * writeString(char * p, const char * string) {
	int stringLen = (int)strlen(string);
	CODELENGTH(stringLen, p);
	memcpy(p, string, stringLen);
        p += stringLen;
	return p;
}

void submitDevice(int socket, const char * dt, const char * usn, const char * server, const char * location) {
	char buffer[2048];
	char * p;

	buffer[0] = 4;
	p = buffer + 1;
	p = writeString(p, dt);
	p = writeString(p, usn);
	p = writeString(p, server);
	p = writeString(p, location);
	write(socket, buffer, p - buffer);
}

int sendNotify(in_addr_t sourceAddr, const char * uuid, const char * location, const char * server) {
	const char *theMessage[3] = {
		"NOTIFY * HTTP/1.1\r\n"
                "USN: %s::upnp:rootdevice\r\n"
                "LOCATION: %s\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "SERVER: %s\r\n"
                "NTS: ssdp:alive\r\n"
                "CACHE-CONTROL: max-age=120\r\n"
                "NT: upnp:rootdevice\r\n"
                "Content-Length: 0\r\n\r\n",

		"NOTIFY * HTTP/1.1\r\n"
                "USN: %1$s\r\n"
                "LOCATION: %2$s\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "SERVER: %3$s\r\n"
                "NTS: ssdp:alive\r\n"
                "CACHE-CONTROL: max-age=120\r\n"
                "NT: %1$s\r\n"
                "Content-Length: 0\r\n\r\n",

		"NOTIFY * HTTP/1.1\r\n"
                "USN: %s::urn:schemas-upnp-org:device:Basic:1\r\n"
                "LOCATION: %s\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "SERVER: %s\r\n"
                "NTS: ssdp:alive\r\n"
                "CACHE-CONTROL: max-age=120\r\n"
                "NT: urn:schemas-upnp-org:device:Basic:1\r\n"
                "Content-Length: 0\r\n\r\n"
	};

	int ss = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ss < 0) {
		printf("Error: Unable to create socket\n");
		return -1;
	}

	int ttl = 4;
	int ret = setsockopt(ss,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl));
	if (ret < 0) {
		printf("Error: setsockopt\n");
		close(ss); // don't leak sockets...
		return -2;
	}

	if (sourceAddr != INADDR_ANY) {
		ret = setsockopt(ss,IPPROTO_IP, IP_MULTICAST_IF, &sourceAddr, sizeof(sourceAddr));
		if (ret < 0) {
			printf("Error: setsockopt IF\n");
			close(ss);
			return -3;
		}
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(1900);
	sin.sin_addr.s_addr = inet_addr("239.255.255.250");

	char fmtMessage[2048];
	int message;
	for (message = 0; message < 3; message++) {
		snprintf(fmtMessage, sizeof(fmtMessage), theMessage[message], uuid, location, server);
		int n = sendto(ss, fmtMessage, strlen(fmtMessage), 0, (struct sockaddr *) &sin, sizeof(sin));
		if (n < 0) {
			printf("Warning: sending notify failed with %d\n",n);
		}
	}

	close(ss);
	return 0;
}

int sendSspd(const char * socketName, const char * uuid, const char * location, const char * server) {
	int s = openSocket(socketName);
        if (s < 0) {
		printf("Error: unable to open socket %s\n", socketName);
		return -1;
	}

	char buffer[2048];

	snprintf(buffer, sizeof(buffer), "%s::upnp:rootdevice", uuid);
	submitDevice(s, "upnp:rootdevice", buffer, server, location);

	submitDevice(s, uuid, uuid, server, location);

	snprintf(buffer, sizeof(buffer), "%s::urn:schemas-upnp-org:device:Basic:1", uuid);
	submitDevice(s, "urn:schemas-upnp-org:device:Basic:1", buffer, server, location);

        close(s);

	return 0;
}

/**
 * Get the IPv4 address from a string
 * representing the address or the interface name
 */
static in_addr_t GetIfAddrIPv4(const char * ifaddr) {
	in_addr_t addr;
	int s;
	struct ifreq ifr;
	int ifrlen;

	/* let's suppose ifaddr is a IPv4 address
	 * such as 192.168.1.1 */
	addr = inet_addr(ifaddr);
	if(addr != INADDR_NONE)	{
		return addr;
	}
	/* let's suppose the ifaddr was in fact an interface name
	 * such as eth0 */
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s < 0) {
		return INADDR_NONE;
	}
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifaddr, IFNAMSIZ);
	if(ioctl(s, SIOCGIFADDR, &ifr, &ifrlen) < 0) {
		close(s);
		return INADDR_NONE;
	}
	addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	close(s);
	return addr;
}

int main(int argc, char * * argv) {
	signal(SIGPIPE, SIG_IGN);

	char addrStr[INET_ADDRSTRLEN];
	in_addr_t addr = GetIfAddrIPv4("eth0");
	inet_ntop(AF_INET, &addr, addrStr, INET_ADDRSTRLEN);
	printf("Using address %s\n", addrStr);

	char * uuid = "uuid:ABBB6631-67A4-4BA1-8E6A-C073FAE13FC1";
	char location[2048];
	snprintf(location, sizeof(location), "http://%s/upnp.xml?uuid=%s", addrStr, uuid);

	sendSspd("/var/run/minissdpd.sock", uuid, location, "upnp-beacon/1.0");
	sendNotify(INADDR_ANY, uuid, location, "upnp-beacon/1.0");

	return 0;
}
