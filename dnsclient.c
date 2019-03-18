#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <strings.h>
#include <math.h>

#define A 1
#define NS 2
#define CNAME 5
#define MX 15
#define SOA 6
#define TXT 16

int commandlogfd, answerlogfd;
char commandstr[100];
char outputstr[200];

typedef struct {
	unsigned short id;
	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1;
	unsigned char rcode :4;
	unsigned char z :3;
	unsigned char ra :1;
// schimba (LITTLE/BIG ENDIAN) folosind htons/ntohs
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} dns_header_t;

typedef struct {
	char qname[256];
	unsigned short qtype;
	unsigned short qclass;
} dns_question_t;

typedef struct {
	unsigned char name[256];
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
	unsigned char rdata[256];
} dns_rr_t;

typedef struct {
	dns_header_t header;
	dns_question_t question;
} Query;

typedef struct {
	dns_header_t header;
	dns_question_t question;
	dns_rr_t record[256];
} Answer;

int toCharArray(Query* q, unsigned char* cq, char* argv[]) {
	//unsigned char cq[sizeof(Query) - 6];
	memset(cq, 0, sizeof(Query) - 6);

	//header
	memcpy(cq, &(q->header.id), 2);
	cq[2] |= q->header.rd;
	cq[2] |= q->header.tc * 2;
	cq[2] |= q->header.aa * 4;
	cq[2] |= q->header.opcode * 8;
	cq[2] |= q->header.qr * 128;
	cq[3] |= q->header.rcode;
	cq[3] |= q->header.z * 16;
	cq[3] |= q->header.ra * 128;
	memcpy(cq + 4, &(q->header.qdcount), 2);
	memcpy(cq + 6, &(q->header.ancount), 2);
	memcpy(cq + 8, &(q->header.nscount), 2);
	memcpy(cq + 10, &(q->header.arcount), 2);

	//question
	char str[256];
	char *token;
	char array[256];memset(array, 0, 256);
	char len[4];

	memset(str, 0, 256);
	memcpy(str, q->question.qname, strlen(q->question.qname));

	token = strtok(str, ".");

	while( token != NULL ) {
		memset(len, 0, 4);
		sprintf(len, "%c", (char)strlen(token));
		strcat(array, len);
		strcat(array, token);
		token = strtok(NULL, ".");
	}

	//long int arraylen = strlen(array);
	//memcpy(cq + 12, array, arraylen);
	//memcpy(cq + 12 + arraylen, q->type, strlen(q->type));
	//memcpy(cq + 12 + arraylen + strlen(q->type), q->class, strlen(q->class));
	strcat(cq + 12, array);
	strcat(cq + 12 + strlen(array), "\0");
	memcpy(cq + 13 + strlen(array), &(q->question.qtype), 2);
	memcpy(cq + 15 + strlen(array), &(q->question.qclass), 2);

	//writing to dns.log:
	memset(outputstr, 0, 200);
	strcpy(outputstr, ";; QUESTION SECTION:\n;");
	strcat(outputstr, argv[1]);
	strcat(outputstr, ".\t\t\t\tIN\t");
	strcat(outputstr, argv[2]);
	printf("%s\n", outputstr);
	write(answerlogfd, outputstr, strlen(outputstr));

	return 17 + strlen(array);
}

Answer* toAnswer(unsigned char ca[], Answer* answer, int questionLength, char* argv[]) {
	memcpy(answer, ca, questionLength);
	answer->header.qdcount = ntohs(answer->header.qdcount);
	answer->header.ancount = ntohs(answer->header.ancount);
	answer->header.nscount = ntohs(answer->header.nscount);
	answer->header.arcount = ntohs(answer->header.arcount);
	short offset = (short) ((short) ((ca[questionLength] * 256 + ca[questionLength + 1]) << 2) >> 2);
	int nameLength = questionLength - 18;

	memset(outputstr, 0, 200);
	strcpy(outputstr, "\n\n;; ANSWER SECTION:\n;");
	write(answerlogfd, outputstr, strlen(outputstr));

	for (int answerNo = 0; answerNo < answer->header.ancount; answerNo++) {
		memcpy(answer->record[answerNo].name, ca + offset, nameLength + 1); // necesita decodificare
		answer->record[answerNo].type = ca[questionLength + 2] * 256 + ca[questionLength + 3];
		answer->record[answerNo].class = ca[questionLength + 4] * 256 + ca[questionLength + 5];
		answer->record[answerNo].ttl = ca[questionLength + 6] * pow(256, 3) + ca[questionLength + 7] * pow(256, 2) + ca[questionLength + 8] * 256 + ca[questionLength + 9];
		answer->record[answerNo].rdlength = ca[questionLength + 10] * 256 + ca[questionLength + 11];
		strcpy(answer->record[answerNo].rdata, ca + questionLength + 12);

	printf("%4x\n", answer->record[answerNo].rdata[0]);
		
		memset(outputstr, 0, 200);
		strcpy(outputstr, argv[1]);
		strcat(outputstr, ".\t\t");
		strcat(outputstr, "5\t\tIN\t");
		strcat(outputstr, argv[2]);
		strcat(outputstr, "\t");
		write(answerlogfd, outputstr, strlen(outputstr));
		memset(outputstr, 0, 200);
		sprintf(outputstr, "%1d.%1d.%1d.%1d\n", answer->record[answerNo].rdata[0],
			answer->record[answerNo].rdata[1], answer->record[answerNo].rdata[2],
			answer->record[answerNo].rdata[3]);
		write(answerlogfd, outputstr, strlen(outputstr));
		printf("%s\n", outputstr);
	}

	return answer;
}

char whichtype(char type[]) {
	if (strcmp("A", type) == 0)
		return A;
	if (strcmp("NS", type) == 0)
		return NS;
	if (strcmp("CNAME", type) == 0)
		return CNAME;
	if (strcmp("MX", type) == 0)
		return MX;
	if (strcmp("SOA", type) == 0)
		return SOA;
	if (strcmp("TXT", type) == 0)
		return TXT;
	return 0;
}

void solver(char* argv[]) {
	commandlogfd = open("message.log", O_WRONLY | O_CREAT | O_TRUNC, -1);
	answerlogfd = open("dns.log", O_WRONLY | O_CREAT | O_TRUNC, -1);

	//writing to message.log:
	memset(commandstr, 0, 100);
	strcpy(commandstr, "./dnsclient ");
	strcat(commandstr, argv[1]);
	strcat(commandstr, " ");
	strcat(commandstr, argv[2]);
	write(commandlogfd, commandstr, strlen(commandstr));

	//writing output to dns.log:
	memset(outputstr, 0, 200);
	strcpy(outputstr, "Trying \"");
	strcat(outputstr, argv[1]);
	strcat(outputstr, "\"\n");
	write(answerlogfd, outputstr, strlen(outputstr));
	
	memset(outputstr, 0, 200);
	strcpy(outputstr, ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5663\n");
	strcat(outputstr, ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n\n");
	write(answerlogfd, outputstr, strlen(outputstr));

	//starting effective dns search:
	Query* packet = (Query*)malloc(sizeof(Query));
	packet->header.id = htons(0xaaaa);
	packet->header.qr = 0; // 1
	packet->header.opcode = 0; // 1
	packet->header.aa = 0; // 1
	packet->header.tc = 0; // 4
	packet->header.rd = 1; // 1
	packet->header.ra = 0; // 4
	packet->header.z = 0; // 3
	packet->header.rcode = 0; // 1
	packet->header.qdcount = htons(1);
	packet->header.ancount = htons(0);
	packet->header.nscount = htons(0);
	packet->header.arcount = htons(0);
	memcpy(packet->question.qname, argv[1], strlen(argv[1]));
	packet->question.qtype = htons(whichtype(argv[2]));
	packet->question.qclass = htons(1); // == IN
	
	unsigned char buffer[1024];
	memset(buffer, 0, 1024);
	int queryLen = toCharArray(packet, buffer, argv);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
	}
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(53);
	inet_aton("8.8.8.8", &(server.sin_addr)); // pub.pub.ro 141.85.128.1
	int length = sizeof(struct sockaddr_in);

	int n = sendto(sock, buffer, 30, 0, (struct sockaddr*) &server, length);
	if (n < 0) {
		perror("send error");
	}
	memset(buffer, 0, 1024);
	n = recvfrom(sock, buffer, 1024, 0, (struct sockaddr*) &server, &length);

	Answer* answer = (Answer*)malloc(sizeof(Answer));
	toAnswer(buffer, answer, queryLen, argv);

	for (int i = 0; i < queryLen; i++) {
		printf("%1x.", buffer[i]);
	}
}

int main(int argc, char* argv[]) {
	solver(argv);
}
