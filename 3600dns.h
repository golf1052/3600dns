/*
 * CS3600, Spring 2014
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__


// structure for the header
typedef struct dnsheader_s {
	// GCC lays out structures backwards in each
	// individual byte. the bytes themselves are in order

	// bytes 1-2
	unsigned short id;

	// byte 3
	unsigned short rd:1;
	unsigned short tc:1;
	unsigned short aa:1;
	unsigned short opcode:4;
	unsigned short qr:1;

	// byte 4
	unsigned short rcode:4;
	unsigned short z:3;
	unsigned short ra:1;
	
	// bytes 5-12
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} dnsheader;

// structure for the question
typedef struct dnsquestion_s{
	unsigned char* qname;
	unsigned short qtype;
	unsigned short qclass;
} dnsquestion;

// structure for the answer
typedef struct dnsanswer_s{
	unsigned char* name;
	unsigned short type;
	unsigned short qclass;
	unsigned int ttl;
	unsigned short rdlength;
	unsigned char* rdata;
} dnsanswer;

void packHeaderBuffer(unsigned char* buf, dnsheader header);
unsigned char* unpointerfy(unsigned char* response, int initLocation, int size);
unsigned char* unstringify(unsigned char* str);
unsigned char* pointerFollower(unsigned char* response, int initLocation, int originalLocation);

#endif

