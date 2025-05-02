#include "dns.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void parse_dns_query_name(char *domain, char *qname) {
  char *buf_ptr = qname, *buf_domain_ptr = domain;
#ifdef DEBUG
  // printf("[Debug] qname: %s, domain: %s\n", qname, domain);
#endif
  while (*buf_ptr) {
    int len = *buf_ptr++;
    for (int i = 0; i < len; i++) {
      *buf_domain_ptr++ = *buf_ptr++;
    }
    *buf_domain_ptr++ = '.';
  }
  *--buf_domain_ptr = '\0';
}

void parse_dns_flags(struct DnsFlags *flags, uint16_t uflags) {
  flags->QR = (uflags >> 15) & 0x1;
  flags->OPcode = (uflags >> 11) & 0xf;
  flags->AA = (uflags >> 10) & 0x1;
  flags->TC = (uflags >> 9) & 0x1;
  flags->RD = (uflags >> 8) & 0x1;
  flags->RA = (uflags >> 7) & 0x1;
  flags->Z = (uflags >> 4) & 0x7;
  flags->RCODE = (uflags)&0xf;
}

void parse_dns_header(struct HeaderDnsDatagram *header, uint8_t *buffer) {
  int offset = 0;
  memcpy(&header->id, buffer + offset, sizeof(uint16_t));
  header->id = ntohs(header->id);
  uint16_t flags;
  offset += 2;
  memcpy(&flags, buffer + offset, sizeof(uint16_t));
  flags = ntohs(flags);
  parse_dns_flags(&header->flags, flags);
  offset += 2;
  memcpy(&header->QDCOUNT, buffer + offset, sizeof(uint16_t));
  header->QDCOUNT = ntohs(header->QDCOUNT);
  offset += 2;
  memcpy(&header->ANCOUNT, buffer + offset, sizeof(uint16_t));
  header->ANCOUNT = ntohs(header->ANCOUNT);
  offset += 2;
  memcpy(&header->NSCOUNT, buffer + offset, sizeof(uint16_t));
  header->NSCOUNT = ntohs(header->NSCOUNT);
  offset += 2;
  memcpy(&header->ARCOUNT, buffer + offset, sizeof(uint16_t));
  header->ARCOUNT = ntohs(header->ARCOUNT);
  offset += 2;
}

void parse_dns_response(struct ResponseDnsDatagram *response, uint8_t *buffer) {
  if (response == NULL || buffer == NULL) return;

  int offset = 0;
  parse_dns_header(&response->header, buffer);
  offset += 12;

  if (buffer[offset] == '\0') return;

  parse_dns_query_name(response->query.name, (char *)(buffer + offset));
  offset += strlen((char *)(buffer + offset)) + 1;

  if (offset + 4 > DNS_BUFFER_SIZE) return;

  memcpy(&response->query.type, buffer + offset, sizeof(uint16_t));
  response->query.type = ntohs(response->query.type);
  offset += 2;

  memcpy(&response->query.class, buffer + offset, sizeof(uint16_t));
  response->query.class = ntohs(response->query.class);
  offset += 2;

  if (response->answer == NULL) {
    response->answer = array_init(sizeof(struct AnswerDnsDatagram));
    if (response->answer == NULL) return;
  }

  struct AnswerDnsDatagram answer;

  while (offset < DNS_BUFFER_SIZE && *(buffer + offset)) {
    if (offset + 12 > DNS_BUFFER_SIZE) break;

    memcpy(&answer.name, buffer + offset, sizeof(uint16_t));
    offset += 2;

    memcpy(&answer.type, buffer + offset, sizeof(uint16_t));
    answer.type = ntohs(answer.type);
    offset += 2;

    memcpy(&answer.class, buffer + offset, sizeof(uint16_t));
    answer.class = ntohs(answer.class);
    offset += 2;

    memcpy(&answer.ttl, buffer + offset, sizeof(uint32_t));
    answer.ttl = ntohl(answer.ttl);
    offset += 4;

    uint16_t data_len;
    memcpy(&data_len, buffer + offset, sizeof(uint16_t));
    data_len = ntohs(data_len);
    answer.data_len = data_len;
    offset += 2;

    if (data_len > DNS_BUFFER_SIZE || offset + data_len > DNS_BUFFER_SIZE) {
      break;
    }

    if (answer.type == 1 && data_len == 4) {
      memcpy(&answer.address, buffer + offset, sizeof(uint32_t));
    } else {
      answer.address = 0;
    }

    offset += data_len;

    if (answer.type == 1) {
      array_append(response->answer, &answer);
    }
  }
}

void init_flags(struct DnsFlags *flags) {
  flags->QR = QR_QUERY;
  flags->OPcode = 0x0;
  flags->AA = 0;
  flags->TC = 0;
  flags->RD = 1;
  flags->RA = 0;
  flags->Z = 0;
  flags->RCODE = 0x0;
}

void init_header(struct HeaderDnsDatagram *header) {
  header->id = generate_random_id();
  init_flags(&header->flags);
  header->QDCOUNT = 0x0001;
  header->ANCOUNT = 0x0000;
  header->NSCOUNT = 0x0000;
  header->ARCOUNT = 0x0000;
}

void init_query(struct QueryDnsDatagram *query) {
  query->type = 0x0001;
  query->class = 0x0001;
}

void init_request(struct RequestDnsDatagram *request) {
  init_header(&request->header);
  init_query(&request->query);
}

void init_answer(struct AnswerDnsDatagram *answer) {
  answer->name = 0xC00C;
  answer->type = 0x0001;
  answer->class = 0x0001;
  answer->ttl = DEFAULT_TTL;
  answer->data_len = 4;
}

static void put_flags(struct DnsFlags *flags, uint8_t *buffer) {
  int offset = 0;
  buffer[offset++] |= (flags->QR << 7) | (flags->OPcode << 3) | (flags->AA << 2) | (flags->TC << 1) | (flags->RD);
  buffer[offset++] |= (flags->RA << 7) | (flags->Z << 4) | (flags->RCODE);
}

int put_header(struct HeaderDnsDatagram *header, uint8_t *buffer) {
  if (header == NULL || buffer == NULL) return 0;

  int offset = 0;
  w_bytes16(buffer + offset, header->id);
  offset += 2;

  buffer[offset] = 0;
  buffer[offset + 1] = 0;

  put_flags(&header->flags, buffer + offset);
  offset += 2;

  w_bytes16(buffer + offset, header->QDCOUNT);
  offset += 2;

  w_bytes16(buffer + offset, header->ANCOUNT);
  offset += 2;

  w_bytes16(buffer + offset, header->NSCOUNT);
  offset += 2;

  w_bytes16(buffer + offset, header->ARCOUNT);
  offset += 2;

  return offset;
}

int put_request(struct RequestDnsDatagram *request, uint8_t *buffer) {
  if (request == NULL || buffer == NULL) return 0;

  int offset = 0;
  offset += put_header(&request->header, buffer + offset);

  int cnt = 0;
  for (int i = 0; request->query.name[i] != '\0'; i++) {
    if (request->query.name[i] == '.') {
      buffer[offset] = (uint8_t)cnt;
      offset += cnt + 1;
      cnt = 0;
    } else {
      buffer[offset + cnt + 1] = (uint8_t)request->query.name[i];
      ++cnt;
    }
  }
  buffer[offset] = (uint8_t)cnt;
  offset += cnt + 1;
  buffer[offset++] = 0x00;

  w_bytes16(buffer + offset, request->query.type);
  offset += 2;

  w_bytes16(buffer + offset, request->query.class);
  offset += 2;

  return offset;
}

void put_answers(array_t *answers, uint8_t *buffer) {
  if (answers == NULL || buffer == NULL) return;

  int offset = 0;
  for (int i = 0; i < answers->length; i++) {
    struct AnswerDnsDatagram *ans = &array_index(answers, i, struct AnswerDnsDatagram);
    if (ans == NULL) continue;

    w_bytes16(buffer + offset, ans->name);
    offset += 2;

    w_bytes16(buffer + offset, ans->type);
    offset += 2;

    w_bytes16(buffer + offset, ans->class);
    offset += 2;

    w_bytes32(buffer + offset, ans->ttl);
    offset += 4;

    w_bytes16(buffer + offset, ans->data_len);
    offset += 2;

    memcpy(buffer + offset, &ans->address, sizeof(uint32_t));
    offset += 4;
  }
}

void print_flags(struct DnsFlags *flags) {
  printf(
      "QR: %d\n"
      "OPcode: %d\n"
      "AA: %d\n"
      "TC: %d\n"
      "RD: %d\n"
      "RA: %d\n"
      "Z: %d\n"
      "RCODE: %d\n",
      flags->QR, flags->OPcode, flags->AA, flags->TC, flags->RD, flags->RA, flags->Z, flags->RCODE);
}

void print_header(struct HeaderDnsDatagram *header) {
  printf("ID: %x\n", header->id);
  print_flags(&header->flags);
  printf(
      "QDCOUNT: %d\n"
      "ANCOUNT: %d\n"
      "NSCOUNT: %d\n"
      "ARCOUNT: %d\n",
      header->QDCOUNT, header->ANCOUNT, header->NSCOUNT, header->ARCOUNT);
}

uint16_t generate_random_id() {
  static __thread unsigned int seed = 0;
  if (seed == 0) {
    seed = (unsigned int)time(NULL) ^ (unsigned int)pthread_self();
  }
  return (uint16_t)rand_r(&seed);
}

void w_bytes32(uint8_t *b, uint32_t v) {
  if (b == NULL) return;
  b[0] = (v >> 24) & 0xff;
  b[1] = (v >> 16) & 0xff;
  b[2] = (v >> 8) & 0xff;
  b[3] = (v)&0xff;
}

void w_bytes16(uint8_t *b, uint16_t v) {
  if (b == NULL) return;
  b[0] = (v >> 8) & 0xff;
  b[1] = (v)&0xff;
}