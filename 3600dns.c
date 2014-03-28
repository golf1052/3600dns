/*
 * CS3600, Spring 2014
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

int main(int argc, char *argv[]) {
  /**
   * I've included some basic code for opening a socket in C, sending
   * a UDP packet, and then receiving a response (or timeout).  You'll 
   * need to fill in many of the details, but this should be enough to
   * get you started.
   */

  // process the arguments
  char* serverport = argv[1];

  // unfortunately I didn't do the extra credit
  // check to make sure we can actually process this
  if (serverport[0] != '@') {
    printf("ERROR\tMalformed request\n");
    return 0;
  }

  char* server;
  char* port;
  unsigned short portNumber = 0;

  // make sure we have more than 3 arguments
  // the program, the ip, and the name
  if (argc < 3) {
    printf("ERROR\tMalformed request\n");
    return 0;
  }
  char* name = argv[2];
  int weHaveAPort = 0;

  // find where the colon is in the address. there also could be
  // no port number so handle that as well
  int i = 0;
  while (serverport[i] != ':' && serverport[i] != '\0') {
    i++;
  }

  if (serverport[i] == ':') {
    weHaveAPort = 1;
    int colonLocation = i;
    server = (char*)calloc(i + 1, sizeof(char));
    serverport++;
    strncpy(server, serverport, i - 1);
    server[i - 1] = '\0';

    while (serverport[i] != '\0') {
      i++;
    }

    port = (char*)calloc(i - colonLocation, sizeof(char));
    serverport += colonLocation;
    strncpy(port, serverport, i - colonLocation);
    portNumber = atoi(port);
  }
  else {
    server = (char*)calloc(i, sizeof(char));
    serverport++;
    strcpy(server, serverport);
  }

  // construct the DNS request
  dnsheader header;
  header.id = htons(1337);
  header.qr = 0;
  header.opcode = 0;
  header.aa = 0;
  header.tc = 0;
  header.rd = 1;
  header.ra = 0;
  header.z = 0;
  header.rcode = htons(0);
  header.qdcount = htons(1);
  header.ancount = 0;
  header.nscount = 0;
  header.arcount = 0;

  //set up the header
  unsigned char headerbuf[12];
  memset(headerbuf, 0, 12);
  packHeaderBuffer(headerbuf, header);

  // O_O O_O O_O QUESTION CODE O_O O_O O_O
  //set up the request
  dnsquestion question;
  // find out how many sections (strings) there
  // are in the name
  unsigned short sections[12];
  i = 0;
  // set up the array
  for (i = 0; i < 12; i++) {
    sections[i] = -1;
  }
  i = 0;
  int sectionCounter = 0;
  int charCounter = 0;
  // while we aren't at the end of the string if
  // the counter is on a '.' then we have found
  // a division. when we hit the end of the string
  // '\0' we make another section for the last part
  // of the name string
  while (name[i] != '\0') {
    if (name[i] == '.') {
      sections[sectionCounter] = charCounter;
      charCounter = 0;
      sectionCounter++;
    }
    else {
      charCounter++;
    }

    if (name[i + 1] == '\0') {
      sections[sectionCounter] = charCounter;
      sectionCounter++;
    }

    i++;
  }

  // figure out how many bytes we need to store the question
  int qnamebufferlength = 0;
  for (i = 0; i < sectionCounter; i++) {
    qnamebufferlength += sections[i];
  }
  qnamebufferlength += sectionCounter;

  // create the buffer
  // +1 for the 0 buffer at the end of the string
  unsigned char qnamebuf[qnamebufferlength + 1];
  memset(qnamebuf, 0, qnamebufferlength + 1);

  // now pack the buffer
  // we need to keep track of how many bytes we have added
  // so far so we can place subsequent bytes in the correct place
  int bytesAdded = 0;
  for (i = 0; i < sectionCounter; i++) {
    // length parts are 1 byte
    memcpy(qnamebuf + bytesAdded, &sections[i], 1);
    bytesAdded++;
    // add the current string section to the buffer
    // a char is 1 byte so we just copy however many
    // chars are in the current string section
    // we also need to increase the pointer to the name by
    // how ever big the last section was so that we
    // add the right chars
    if (i == 0) {
      memcpy(qnamebuf + bytesAdded, name, sections[i]);
    }
    else {
      memcpy(qnamebuf + bytesAdded, (name + sections[i - 1]), sections[i]);
    }
    bytesAdded += sections[i];

    // then actually increase the name pointer so that we can keep going
    // we dont really need the parts of the name we have gone through
    // already
    if (i == 0) {
      name++;
    }
    else {
      name += sections[i - 1] + 1;
    }
  }
  question.qname = (unsigned char*)calloc(qnamebufferlength + 1, sizeof(char));
  memset(question.qname, 0, qnamebufferlength + 1);
  memcpy(question.qname, qnamebuf, qnamebufferlength + 1);
  question.qtype = htons(1);
  question.qclass = htons(1);
  unsigned char questionbuf[qnamebufferlength + 5];
  memset(questionbuf, 0, qnamebufferlength + 5);
  memcpy(questionbuf, question.qname, qnamebufferlength);
  memcpy(questionbuf + qnamebufferlength + 1, &question.qtype, sizeof(short));
  memcpy(questionbuf + qnamebufferlength + 1 + sizeof(short), &question.qclass, sizeof(short));


  //dump_packet(questionbuf, qnamebufferlength + 5);

  unsigned char request[12 + qnamebufferlength + 5];
  memset(request, 0, 12 + qnamebufferlength + 5);
  memcpy(request, headerbuf, 12);
  memcpy(request + 12, questionbuf, qnamebufferlength + 5);
  dump_packet(request, 12 + qnamebufferlength + 5);

  unsigned char response[65536];
  memset(response, 0, 65536);

  // send the DNS request (and call dump_packet with your request)
  
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;

  if (portNumber == 0) {
    portNumber = 53;
  }

  out.sin_port = htons(portNumber);
  out.sin_addr.s_addr = inet_addr(server);

  if (sendto(sock, request, 12 + qnamebufferlength + 5, 0, (struct sockaddr *)&out, sizeof(out)) < 0) {
    printf("ERROR\tPacket failed to send\n");
    return 0;
  }

  // wait for the DNS reply (timeout: 5 seconds)
  struct sockaddr_in in;
  socklen_t in_len;

  // construct the socket set
  fd_set socks;
  FD_ZERO(&socks);
  FD_SET(sock, &socks);

  // construct the timeout
  struct timeval t;
  t.tv_sec = 5;
  t.tv_usec = 0;

  int size = 0;

  // wait to receive, or for a timeout
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    // store the size of the response
    size = recvfrom(sock, response, sizeof(response), 0, (struct sockaddr *)&in, &in_len);
    if (size < 0) {
      printf("ERROR\tFailed to receive packet\n");
      return 0;
    }
  } else {
    printf("NORESPONSE\n");
    return 0;
  }

  dnsheader r_header;
  // copy the header from the response into
  // the header
  memcpy(&r_header, response, 12);
  r_header.id = ntohs(r_header.id);
  r_header.qdcount = ntohs(r_header.qdcount);
  r_header.nscount = ntohs(r_header.nscount);
  r_header.ancount = ntohs(r_header.ancount);
  r_header.arcount = ntohs(r_header.arcount);

  // Error Checks
  if (r_header.rcode == 1) {printf("ERROR\tFormat Error\n"); return 0; }
  if (r_header.rcode == 2) {printf("ERROR\tServer Failure\n"); return 0; }  
  if (r_header.rcode == 3) {printf("NOTFOUND\n"); return 0; }
  if (r_header.rcode == 4) {printf("ERROR\tNot Implemented\n"); return 0; }
  if (r_header.rcode == 5) {printf("ERROR\tRefused\n"); return 0; }

  // we have to uncompress the answer section
  unsigned char* fixedResponse = (unsigned char*)calloc(size * 5, sizeof(unsigned char));
  memset(fixedResponse, 0, size * 5);
  memcpy(fixedResponse, unpointerfy(response, 17 + qnamebufferlength, size), size * 5);

  // pointer location so we know how far into the response we are
  int fixedResponsePointer = 0;
  // print out an answer for how many answers we have
  for (i = 0; i < r_header.ancount; i++) {
    dnsanswer r_answer;
    int j = 0;
    // loop through the name section until we reach the end of the string
    while (fixedResponse[fixedResponsePointer] != '\0') {
      j++;
      fixedResponsePointer++;
    }
    j++;
    fixedResponsePointer++;
    unsigned char r_namebuf[j];
    memset(r_namebuf, 0, j);
    memcpy(r_namebuf, fixedResponse + fixedResponsePointer - j, j);
    r_answer.name = r_namebuf;
    r_answer.type = (unsigned short)(*(fixedResponse + fixedResponsePointer) + *(fixedResponse + fixedResponsePointer + 1));
    fixedResponsePointer += 2;
    r_answer.qclass = (unsigned short)(*(fixedResponse + fixedResponsePointer) + *(fixedResponse + fixedResponsePointer + 1));
    fixedResponsePointer += 2;
    r_answer.ttl = (unsigned int)(*(fixedResponse + fixedResponsePointer) + 
      *(fixedResponse + fixedResponsePointer + 1) +
      *(fixedResponse + fixedResponsePointer + 2) +
      *(fixedResponse + fixedResponsePointer + 3));

    // get the size of the rdata section depending on if it is
    // a IP or a CNAME
    unsigned char r_rdatabuf[1024];
    if (r_answer.type == 1) {
      // if it is an IP then proceed as normal
      fixedResponsePointer += 4;
      r_answer.rdlength = (unsigned short)(*(fixedResponse + fixedResponsePointer) + *(fixedResponse + fixedResponsePointer + 1));
      fixedResponsePointer += 2;
      //unsigned char r_rdatabuf[r_answer.rdlength];
      memset(r_rdatabuf, 0, r_answer.rdlength);
      memcpy(r_rdatabuf, fixedResponse + fixedResponsePointer, r_answer.rdlength);
      fixedResponsePointer += r_answer.rdlength;
    }
    else if (r_answer.type == 5) {
      // if it is a CNAME we need to read the entire string
      // the rdlength isnt fully correct
      fixedResponsePointer += 6;
      j = 0;
      while (fixedResponse[fixedResponsePointer] != '\0') {
        j++;
        fixedResponsePointer++;
      }
      j++;
      fixedResponsePointer++;
      r_answer.rdlength = j;
      //unsigned char r_rdatabuf[j];
      memset(r_rdatabuf, 0, j);
      memcpy(r_rdatabuf, fixedResponse + fixedResponsePointer - j, j);
    }

    // print out the answers
    if (r_answer.type == 1) {
      unsigned int ip[4];
      ip[0] = (unsigned int)(r_rdatabuf[0]);
      ip[1] = (unsigned int)(r_rdatabuf[1]);
      ip[2] = (unsigned int)(r_rdatabuf[2]);
      ip[3] = (unsigned int)(r_rdatabuf[3]);

      if (r_header.aa == 1) {
        printf("IP\t%d.%d.%d.%d\tauth\n", ip[0], ip[1], ip[2], ip[3]);
      }
      else {
        printf("IP\t%d.%d.%d.%d\tnonauth\n", ip[0], ip[1], ip[2], ip[3]);
      }
    }
    else if (r_answer.type == 5) {
      if (r_header.aa == 1) {
        printf("CNAME\t%s\tauth\n", unstringify(r_rdatabuf));
      }
      else {
        printf("CNAME\t%s\tnonauth\n", unstringify(r_rdatabuf));
      }
    }
  }

  return 0;
}

void packHeaderBuffer(unsigned char* buf, dnsheader header) {
  memcpy(buf, &header.id, sizeof(header));
}

// turns a response with pointers into a response without pointers
unsigned char* unpointerfy(unsigned char* response, int initLocation, int size) {
  // our current pointer location
  int currentLocation = initLocation;
  // make a buffer big enough to store the new response
  unsigned char* fixedResponse = (unsigned char*)calloc(size * 5, sizeof(char));
  // this keeps track of how many bytes we have added to the response
  // so far
  int bytesAdded = 0;
  memset(fixedResponse, 0, size * 5);
  // while we still have a response to go through
  while (currentLocation < size) {
    if (*(response + currentLocation) == 0xc0) {
      // if we hit a pointer follow it
      unsigned char* tmpnamebuf = (unsigned char*)calloc(100, sizeof(unsigned char));
      memset(tmpnamebuf, 0, 100);
      tmpnamebuf = pointerFollower(response, *(response + currentLocation + 1), currentLocation);
      currentLocation += 2;
      int i = 0;
      // then figure out how big the name is
      while (tmpnamebuf[i] != '\0') {
        i++;
      }
      // then copy it into our response
      memcpy(fixedResponse + bytesAdded, tmpnamebuf, i);
      bytesAdded += i + 1;
    }
    else {
      // if we arent at a pointer copy the byte we are currently are at and keep going
      memcpy(fixedResponse + bytesAdded, response + currentLocation, 1);
      currentLocation++;
      bytesAdded++;
    }
  }

  return fixedResponse;
}

// follows a pointer, can also follow recursive pointers
unsigned char* pointerFollower(unsigned char* response, int initLocation, int originalLocation) {
  int currentLocation = initLocation;
  int i = 0;
  unsigned char* rest = (unsigned char*)calloc(100, sizeof(unsigned char));
  memset(rest, 0, 100);
  while(response[currentLocation] != 0x0) {
    if (response[currentLocation] >= 0xc0 && currentLocation != originalLocation) {
      // if we hit a pointer AND we arent back where we came from then follow the pointer
      // checking to see if we are back where we came from prevents looping forever
      // when following a pointer.
      // probably the most annoying bug to find ever...
      rest = pointerFollower(response, *(response + currentLocation + 1), originalLocation);
      currentLocation += 2;
    }
    else if (currentLocation == originalLocation) {
      // if we are back at where we came from break out of the while loop
      break;
    }
    else {
      // if we arent at a pointer just keep going till we find the end of the string
      i++;
      currentLocation++;
    }
  }

  // find the length of the name
  int j = 0;
  while (rest[j] != '\0') {
    j++;
  }

  // and now return it
  unsigned char* tmpstr = (unsigned char*)calloc(i + j, sizeof(unsigned char));
  memset(tmpstr, 0, i + j);
  memcpy(tmpstr, response + initLocation, i);
  memcpy(tmpstr + i, rest, j);
  return tmpstr;
}

// turns a dns name into a regular name
// 3www6google3com --> www.google.com
unsigned char* unstringify(unsigned char* str) {
  int i = 0;
  unsigned char* newstr = (unsigned char*)calloc(1024, sizeof(unsigned char));
  memset(newstr, 0, 1024);
  int charsInserted = 0;
  while (str[i] != 0x0) {
    int j = str[i];
    i++;
    for (int k = 0; k < j; k++) {
      newstr[charsInserted] = str[i];
      i++;
      charsInserted++;
    }

    if (str[i] != 0x0) {
      newstr[charsInserted] = '.';
      charsInserted++;
    }
  }

  return newstr;
}
