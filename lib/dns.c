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

int encode_dns_name(uint8_t *buffer, const char *domain) {
  int offset = 0;
  const char *label = domain;
  const char *dot = strchr(label, '.');

  while (dot) {
    int len = dot - label;
    buffer[offset++] = len;
    memcpy(buffer + offset, label, len);
    offset += len;

    label = dot + 1;
    dot = strchr(label, '.');
  }

  // 最后一个标签
  int len = strlen(label);
  if (len > 0) {
    buffer[offset++] = len;
    memcpy(buffer + offset, label, len);
    offset += len;
  }

  buffer[offset++] = 0;  // 终止符
  return offset;
}

int parse_dns_name(char **domain, const uint8_t *buf, int offset) {
  int jumped = 0;
  int consumed = 0;

  const uint8_t *ptr = buf + offset;
  char *dst = *domain;
  int dst_len = 0;

  while (1) {
    uint8_t len = *ptr;

    // 指针跳转判断（压缩模式，11 开头）
    if ((len & 0xC0) == 0xC0) {
      uint16_t pointer = ((ptr[0] & 0x3F) << 8) | ptr[1];
      if (!jumped) consumed += 2;
      ptr = buf + pointer;
      jumped = 1;
      continue;
    }

    if (len == 0) {
      if (!jumped) consumed += 1;
      break;
    }

    ptr++;
    if (!jumped) consumed += (len + 1);

    for (int i = 0; i < len; i++) {
      dst[dst_len++] = *ptr++;
    }
    dst[dst_len++] = '.';
  }

  if (dst_len > 0)
    dst[dst_len - 1] = '\0';  // 替换最后一个点
  else
    dst[0] = '\0';

  return consumed;
}

// int parse_dns_name(char **domain, const uint8_t *buf, int offset) {
//   int len = 0;
//   uint8_t *buf_ptr = (uint8_t *)buf, *name_ptr = (uint8_t *)buf + offset, *buf_domain_ptr = (uint8_t *)(*domain);
//   uint16_t first2 = *(uint16_t *)name_ptr;
//   if /* 是指针 */ (!((first2 & DOMAIN_PTR_MASK) ^ DOMAIN_PTR_MASK)) {
//     len = 2;
//     buf_ptr += first2 & 0x3fff;
//   } else {
//     len = strlen((char *)name_ptr) + 1;
//     buf_ptr += offset;
//   }

//   while (*buf_ptr) {
//     int len = *buf_ptr++;
//     for (int i = 0; i < len; i++) {
//       *buf_domain_ptr++ = *buf_ptr++;
//     }
//     *buf_domain_ptr++ = '.';
//   }
//   *--buf_domain_ptr = '\0';

//   return len;
// }

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
  offset += parse_dns_name(&request->query.name, buffer, offset);

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
  offset += parse_dns_name(&response->query.name, buffer, offset);

  memcpy(&response->query.type, buffer + offset, sizeof(uint16_t));
  response->query.type = ntohs(response->query.type);
  offset += 2;

  memcpy(&response->query.class, buffer + offset, sizeof(uint16_t));
  response->query.class = ntohs(response->query.class);
  offset += 2;

  response->answer = array_init(sizeof(DnsMessageAnswer));

  int total = response->header.ANCOUNT + response->header.ARCOUNT + response->header.NSCOUNT;
  for (int i = 0; i < total && offset < UDP_DATAGRAM_MAX; ++i) {
    DnsMessageAnswer *answer = RR_init();
    offset += parse_dns_name((char **)&answer->name, buffer, offset);

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

    if (answer->type == DNS_TYPE_A) {
      memcpy(&answer->rdata.a_record.ipv4_address, buffer + offset, data_len);
    } else if (answer->type == DNS_TYPE_AAAA) {
      memcpy(&answer->rdata.aaaa_record.ipv6_address, buffer + offset, data_len);
    } else if (answer->type == DNS_TYPE_CNAME) {
      answer->rdata.cname_record.cname = malloc(NAME_MAX_SIZE);
      assert(answer->rdata.cname_record.cname);
      parse_dns_name(&answer->rdata.cname_record.cname, buffer, offset);
    }

    offset += data_len;
    array_append(response->answer, answer);
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
  if (RR->type == DNS_TYPE_CNAME) {
    newRR->rdata.cname_record.cname = strdup(RR->rdata.cname_record.cname);
  }
  return newRR;
}

void RR_delete(DnsResourceRecord *RR) {
  free(RR->name);
  if (RR->type == DNS_TYPE_CNAME && RR->rdata.cname_record.cname) {
    free(RR->rdata.cname_record.cname);
  }
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

  // 写入 NAME 字段
  uint16_t first2 = *(uint16_t *)answer->name;
  if ((first2 & 0xC000) == 0xC000) {
    // 是压缩指针
    w_bytes16(buffer + offset, first2);
    offset += 2;
  } else {
    // 普通域名
    int name_len = encode_dns_name(buffer + offset, (char *)answer->name);
    offset += name_len;
  }

  // 写入 TYPE, CLASS, TTL
  w_bytes16(buffer + offset, answer->type);
  offset += 2;

  w_bytes16(buffer + offset, answer->class);
  offset += 2;

  w_bytes32(buffer + offset, answer->ttl);
  offset += 4;

  // 写入 RDLENGTH 占位（稍后会覆盖）
  int rdlength_pos = offset;
  offset += 2;

  int data_start = offset;

  switch (answer->type) {
    case DNS_TYPE_A:
      memcpy(buffer + offset, &answer->rdata.a_record.ipv4_address, 4);
      offset += 4;
      break;

    case DNS_TYPE_AAAA:
      memcpy(buffer + offset, &answer->rdata.aaaa_record.ipv6_address, 16);
      offset += 16;
      break;

    case DNS_TYPE_CNAME: {
      // 写入 cname 域名
      int cname_len = encode_dns_name(buffer + offset, answer->rdata.cname_record.cname);
      offset += cname_len;
      break;
    }

    default:
      // 不支持的类型
      return -1;
  }

  // 写入实际 RDLENGTH
  uint16_t rdlength = offset - data_start;
  w_bytes16(buffer + rdlength_pos, rdlength);

  return offset;
}

// int put_answer(DnsMessageAnswer *answer, uint8_t *buffer) {
//   assert(answer != NULL && buffer != NULL);
//   int offset = 0;
//   int name_len = 0;
//   uint16_t first2 = *(uint16_t *)answer->name;
//   if /* 是指针 */ (!((first2 & DOMAIN_PTR_MASK) ^ DOMAIN_PTR_MASK)) {
//     name_len = 2;
//     w_bytes16(buffer + offset, first2);
//   } /* 是域名普通表示 */ else {
//     /* name 也以 0x00 结尾，故用 strlen 计算长度 */
//     name_len = strlen((char *)answer->name) + 1;
//     memcpy(buffer + offset, answer->name, name_len);
//   }

//   offset += name_len;

//   w_bytes16(buffer + offset, answer->type);
//   offset += 2;

//   w_bytes16(buffer + offset, answer->class);
//   offset += 2;

//   w_bytes32(buffer + offset, answer->ttl);
//   offset += 4;

//   w_bytes16(buffer + offset, answer->rdlength);
//   offset += 2;

//   switch (answer->rdlength) {
//     case 4: {
//       memcpy(buffer + offset, &answer->rdata.a_record.ipv4_address, 4);
//       break;
//     }
//     case 16: {
//       memcpy(buffer + offset, &answer->rdata.aaaa_record.ipv6_address, 16);
//       break;
//     }
//   }
//   memcpy(buffer + offset, &answer->rdata, answer->rdlength);
//   offset += answer->rdlength;

//   return offset;
// }

void put_answers(array_t *answers, uint8_t *buffer) {
  assert(answers != NULL && buffer != NULL);

  int offset = 0;
  for (int i = 0; i < answers->length; i++) {
    DnsMessageAnswer *ans = &array_index(answers, i, DnsMessageAnswer);
    offset += put_answer(ans, buffer + offset);
  }
}

void print_flags(DnsMessageHeaderFlags *flags) {
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

void print_header(DnsMessageHeader *header) {
  printf("ID: %x\n", header->id);
  print_flags(&header->flags);
  printf(
      "QDCOUNT: %d\n"
      "ANCOUNT: %d\n"
      "NSCOUNT: %d\n"
      "ARCOUNT: %d\n",
      header->QDCOUNT, header->ANCOUNT, header->NSCOUNT, header->ARCOUNT);
}

void print_question(DnsMessageQuestion *question) {
  printf("qname: %s\n", question->name);
  printf("qtype: %d\n", question->type);
  printf("qclass: %d\n", question->class);
}

// void print_answer(DnsMessageAnswer *answer) {
//   printf("name: %s\n", answer->name);
//   printf("type: %d\n", answer->type);
//   printf("class: %d\n", answer->class);
//   printf("ttl: %u\n", answer->ttl);
//   printf("rdlength: %d\n", answer->rdlength);
//   switch (answer->type) {
//     case DNS_TYPE_A: {
//       break;
//     }
//     case DNS_TYPE_AAAA: {
//       break;
//     }
//     case DNS_TYPE_CNAME: {
//       break;
//     }
//   }
// }

void print_answer(DnsMessageAnswer *answer) {
  char ip_str[INET6_ADDRSTRLEN];

  printf("name: %s\n", answer->name);
  printf("type: %d\n", answer->type);
  printf("class: %d\n", answer->class);
  printf("ttl: %u\n", answer->ttl);
  printf("rdlength: %d\n", answer->rdlength);

  switch (answer->type) {
    case DNS_TYPE_A: {
      if (inet_ntop(AF_INET, &(answer->rdata.a_record.ipv4_address), ip_str, INET_ADDRSTRLEN) != NULL) {
        printf("IPv4 Address: %s\n", ip_str);
      } else {
        printf("Failed to convert IPv4 address.\n");
      }
      break;
    }
    case DNS_TYPE_AAAA: {
      if (inet_ntop(AF_INET6, &(answer->rdata.aaaa_record.ipv6_address), ip_str, INET6_ADDRSTRLEN) != NULL) {
        printf("IPv6 Address: %s\n", ip_str);
      } else {
        printf("Failed to convert IPv6 address.\n");
      }
      break;
    }
    case DNS_TYPE_CNAME: {
      printf("CNAME: %s\n", answer->rdata.cname_record.cname);
      break;
    }
    default: {
      printf("Unsupported record type.\n");
      break;
    }
  }
}

void print_response(DnsResponse *response) {
  print_header(&response->header);
  print_question(&response->query);
  for (int i = 0; i < response->answer->length; ++i) {
    DnsMessageAnswer *ans = &array_index(response->answer, i, DnsMessageAnswer);
    print_answer(ans);
  }
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