#include "dns.h"

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void construct_dns_name(const char *domain, uint8_t *buf) {
  const char *p = domain;
  while (*p) {
    const char *base = p;
    uint8_t len = 0;
    while (*p && *p != '.') {
      ++len;
      ++p;
    }

    *buf++ = len;
    memcpy(buf, base, len);
    buf += len;
    if (*p == '.') {
      ++p;
    }
  }
  *buf = 0;
}

void parse_dns_name(char *domain, char *name) {
  char *buf_ptr = name, *buf_domain_ptr = domain;
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

void parse_dns_flags(struct DnsMessageHeaderFlags *flags, uint16_t uflags) {
  flags->QR = (uflags >> 15) & 0x1;
  flags->OPcode = (uflags >> 11) & 0xf;
  flags->AA = (uflags >> 10) & 0x1;
  flags->TC = (uflags >> 9) & 0x1;
  flags->RD = (uflags >> 8) & 0x1;
  flags->RA = (uflags >> 7) & 0x1;
  flags->Z = (uflags >> 4) & 0x7;
  flags->RCODE = (uflags)&0xf;
}

void parse_dns_header(struct DnsMessageHeader *header, const uint8_t *buffer) {
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

void parse_dns_request(DnsRequest *request, const uint8_t *buffer) {
  assert(request && buffer);

  int offset = 0;
  parse_dns_header(&request->header, buffer);
  offset += MSG_HEADER_SIZE;

  request->query.name = (char *)malloc(NAME_MAX_SIZE);
  assert(request->query.name);
  parse_dns_name(request->query.name, (char *)(buffer + offset));
  offset += strlen((char *)(buffer + offset)) + 1;

  memcpy(&request->query.type, buffer + offset, sizeof(uint16_t));
  request->query.type = ntohs(request->query.type);
  offset += 2;

  memcpy(&request->query.class, buffer + offset, sizeof(uint16_t));
  request->query.class = ntohs(request->query.class);
  offset += 2;
}

void parse_dns_response(struct DnsResponse *response, const uint8_t *buffer) {
  assert(response && buffer);

  int offset = 0;

  parse_dns_header(&response->header, buffer);
  offset += MSG_HEADER_SIZE;

  response->query.name = malloc(NAME_MAX_SIZE);
  assert(response->query.name);
  parse_dns_name(response->query.name, (char *)(buffer + offset));

  memcpy(&response->query.type, buffer + offset, 2);
  response->query.type = ntohs(response->query.type);
  offset += 2;

  memcpy(&response->query.class, buffer + offset, 2);
  response->query.class = ntohs(response->query.class);
  offset += 2;

  response->answer = array_init(sizeof(DnsMessageAnswer));

  DnsMessageAnswer *answer = RR_init();
  uint16_t first2 = 0;
  while (offset < UDP_DATAGRAM_MAX && buffer[offset] != 0x00) {
    first2 = *(uint16_t *)(buffer + offset);
    if /* 是指针 */ (!((first2 & DOMAIN_PTR_MASK) ^ DOMAIN_PTR_MASK)) {
      parse_dns_name((char *)answer->name, (char *)buffer + first2);
      offset += 2;
    } else {
      parse_dns_name((char *)answer->name, (char *)buffer + offset);
      offset += strlen((char *)answer->name) + 1;
    }

    memcpy(&answer->type, buffer + offset, sizeof(uint16_t));
    answer->type = ntohs(answer->type);
    offset += 2;

    memcpy(&answer->class, buffer + offset, sizeof(uint16_t));
    answer->class = ntohs(answer->class);
    offset += 2;

    memcpy(&answer->ttl, buffer + offset, sizeof(uint32_t));
    answer->ttl = ntohl(answer->ttl);
    offset += 4;

    uint16_t data_len;
    memcpy(&data_len, buffer + offset, sizeof(uint16_t));
    data_len = ntohs(data_len);
    answer->rdlength = data_len;
    offset += 2;

    switch (data_len) {
      case 4: {
        memcpy(&answer->rdata.a_record.ipv4_address, buffer + offset, data_len);
        break;
      }
      case 16: {
        memcpy(&answer->rdata.aaaa_record.ipv6_address, buffer + offset, data_len);
        break;
      }
    }
    offset += data_len;
    array_append(response->answer, &answer);
  }
}

void init_flags(DnsMessageHeaderFlags *flags, uint8_t QR, uint8_t OPcode, uint8_t AA, uint8_t TC, uint8_t RD, uint8_t RA, uint8_t Z,
                uint8_t RCODE) {
  flags->QR = QR;
  flags->OPcode = OPcode;
  flags->AA = AA;
  flags->TC = TC;
  flags->RD = RD;
  flags->RA = RA;
  flags->Z = Z;
  flags->RCODE = RCODE;
}

void init_header(DnsMessageHeader *header, uint16_t id, DnsMessageHeaderFlags flags, uint16_t QDCOUNT, uint16_t ANCOUNT, uint16_t NSCOUNT,
                 uint16_t ARCOUNT) {
  header->id = id;
  header->flags = flags;
  header->QDCOUNT = QDCOUNT;
  header->ANCOUNT = ANCOUNT;
  header->NSCOUNT = NSCOUNT;
  header->ARCOUNT = ARCOUNT;
}

void init_answer(DnsMessageAnswer *answer) {
  answer->type = 0x0001;
  answer->class = 0x0001;
  answer->ttl = DEFAULT_TTL;
  answer->rdlength = 4;
}

DnsResourceRecord *RR_init() {
  DnsResourceRecord *newRR = (DnsResourceRecord *)malloc(sizeof(DnsResourceRecord));
  assert(newRR);
  newRR->name = (uint8_t *)malloc(NAME_MAX_SIZE);
  assert(newRR->name);
  return newRR;
}

DnsResourceRecord *RR_dup(DnsResourceRecord *RR) {
  DnsResourceRecord *newRR = (DnsResourceRecord *)malloc(sizeof(DnsResourceRecord));
  assert(newRR);
  memcpy(newRR, RR, sizeof(DnsResourceRecord));
  int name_len = strlen((char *)RR->name) + 1;
  newRR->name = (uint8_t *)malloc(sizeof(uint8_t) * name_len);
  assert(newRR->name);
  memcpy(newRR->name, RR->name, name_len);
  return newRR;
}

void RR_delete(DnsResourceRecord *RR) {
  free(RR->name);
  free(RR);
}

static void put_flags(struct DnsMessageHeaderFlags *flags, uint8_t *buffer) {
  int offset = 0;
  buffer[offset++] |= (flags->QR << 7) | (flags->OPcode << 3) | (flags->AA << 2) | (flags->TC << 1) | (flags->RD);
  buffer[offset++] |= (flags->RA << 7) | (flags->Z << 4) | (flags->RCODE);
}

void put_header(struct DnsMessageHeader *header, uint8_t *buffer) {
  assert(header != NULL && buffer != NULL);

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
}

int put_request(struct DnsRequest *request, uint8_t *buffer) {
  if (request == NULL || buffer == NULL) return 0;

  int offset = 0;
  put_header(&request->header, buffer + offset);
  offset += MSG_HEADER_SIZE;

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

int put_answer(DnsMessageAnswer *answer, uint8_t *buffer) {
  assert(answer != NULL && buffer != NULL);
  int offset = 0;
  int name_len = 0;
  uint16_t first2 = *(uint16_t *)answer->name;
  if /* 是指针 */ (!((first2 & DOMAIN_PTR_MASK) ^ DOMAIN_PTR_MASK)) {
    name_len = 2;
    w_bytes16(buffer + offset, first2);
  } /* 是域名普通表示 */ else {
    /* name 也以 0x00 结尾，故用 strlen 计算长度 */
    name_len = strlen((char *)answer->name) + 1;
    memcpy(buffer + offset, answer->name, name_len);
  }

  offset += name_len;

  w_bytes16(buffer + offset, answer->type);
  offset += 2;

  w_bytes16(buffer + offset, answer->class);
  offset += 2;

  w_bytes32(buffer + offset, answer->ttl);
  offset += 4;

  w_bytes16(buffer + offset, answer->rdlength);
  offset += 2;

  switch (answer->rdlength) {
    case 4: {
      memcpy(buffer + offset, &answer->rdata.a_record.ipv4_address, 4);
      break;
    }
    case 16: {
      memcpy(buffer + offset, &answer->rdata.aaaa_record.ipv6_address, 16);
      break;
    }
  }
  memcpy(buffer + offset, &answer->rdata, answer->rdlength);
  offset += answer->rdlength;

  return offset;
}

void put_answers(array_t *answers, uint8_t *buffer) {
  assert(answers != NULL && buffer != NULL);

  int offset = 0;
  for (int i = 0; i < answers->length; i++) {
    DnsMessageAnswer *ans = &array_index(answers, i, DnsMessageAnswer);
    offset += put_answer(ans, buffer + offset);
  }
}

void print_flags(struct DnsMessageHeaderFlags *flags) {
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

void print_header(struct DnsMessageHeader *header) {
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