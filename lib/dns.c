#include "dns.h"

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

int construct_dns_name_with_compression(const char *domain, uint8_t *buf,
                                        int buf_base_offset,  // buffer 的起始偏移（用于计算绝对位置）
                                        DnsNameOffsetEntry *entries,
                                        int *entry_count  // 输入输出参数
) {
  const char *p = domain;
  int written = 0;

  while (*p) {
    // 检查是否有后缀可复用
    for (int i = 0; i < *entry_count; i++) {
      if (strcasecmp(p, entries[i].name) == 0) {
        // 使用指针压缩
        uint16_t pointer = 0xC000 | entries[i].offset;
        buf[written++] = (pointer >> 8) & 0xFF;
        buf[written++] = pointer & 0xFF;
        return written;
      }
    }

    // 记录当前后缀位置（相对整个 buffer 起始的偏移）
    if (*entry_count < MAX_ENTRY_COUNT) {
      entries[*entry_count].name = p;
      entries[*entry_count].offset = buf_base_offset + written;
      (*entry_count)++;
    }

    const char *label_start = p;
    uint8_t len = 0;
    while (*p && *p != '.') {
      len++;
      p++;
    }

    buf[written++] = len;
    memcpy(buf + written, label_start, len);
    written += len;

    if (*p == '.') p++;
  }

  buf[written++] = 0;  // end with zero
  return written;
}

int parse_dns_name(char *domain, const uint8_t *buf, int name_offset) {
  int state = 0;
  int offset = 0;
  uint8_t cur_offset = 0;
  uint8_t *buf_ptr = (uint8_t *)buf + name_offset;
  bool first_ptr = true;
  while (state != -1) {
    switch (state) {
      case 0: {
        if ((*buf_ptr & 0xC0) == 0xC0) {
          state = 2;
          cur_offset = ((*buf_ptr & 0x3F) << 8) | *(buf_ptr + 1);
          buf_ptr += 2;
          if (first_ptr == true) {
            first_ptr = false;
            offset += 2;
          }
        } else {
          state = 1;
          cur_offset = *buf_ptr;
          if (cur_offset == 0) {
            if (first_ptr == true) {
              ++offset;
            }
            state = -1;
            break;
          }
          ++buf_ptr;
          if (first_ptr == true) ++offset;
        }
        break;
      }
      case 1: {
        for (int i = 0; i < cur_offset; ++i) {
          *domain = *buf_ptr++;
          ++domain;
          if (first_ptr == true) ++offset;
        }
        *domain++ = '.';
        state = 0;
        break;
      }
      case 2: {
        buf_ptr = (uint8_t *)buf + cur_offset;
        state = 0;
        break;
      }
    }
  }
  *(domain - 1) = '\0';
  return offset;
}

void parse_dns_flags(DnsMessageHeaderFlags *flags, uint16_t uflags) {
  flags->QR = (uflags >> 15) & 0x1;
  flags->OPcode = (uflags >> 11) & 0xf;
  flags->AA = (uflags >> 10) & 0x1;
  flags->TC = (uflags >> 9) & 0x1;
  flags->RD = (uflags >> 8) & 0x1;
  flags->RA = (uflags >> 7) & 0x1;
  flags->Z = (uflags >> 4) & 0x7;
  flags->RCODE = (uflags)&0xf;
}

void parse_dns_header(DnsMessageHeader *header, const uint8_t *buffer) {
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
  offset += parse_dns_name(request->query.name, buffer, offset);

  memcpy(&request->query.type, buffer + offset, sizeof(uint16_t));
  request->query.type = ntohs(request->query.type);
  offset += 2;

  memcpy(&request->query.class, buffer + offset, sizeof(uint16_t));
  request->query.class = ntohs(request->query.class);
  offset += 2;
}

void parse_dns_response(DnsResponse *response, const uint8_t *buffer) {
  assert(response && buffer);

  int offset = 0;

  parse_dns_header(&response->header, buffer);
  offset += MSG_HEADER_SIZE;

  response->query.name = (char *)malloc(NAME_MAX_SIZE);
  assert(response->query.name);
  offset += parse_dns_name(response->query.name, buffer, offset);

  memcpy(&response->query.type, buffer + offset, sizeof(uint16_t));
  response->query.type = ntohs(response->query.type);
  offset += 2;

  memcpy(&response->query.class, buffer + offset, sizeof(uint16_t));
  response->query.class = ntohs(response->query.class);
  offset += 2;

  response->answer = array_init(sizeof(DnsMessageAnswer));

  int total = response->header.ANCOUNT + response->header.NSCOUNT;
  for (int i = 0; i < total; ++i) {
    DnsMessageAnswer *answer = RR_init();
    offset += parse_dns_name(answer->name, buffer, offset);

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
      answer->rdata.cname_record.cname = (char *)malloc(NAME_MAX_SIZE);
      assert(answer->rdata.cname_record.cname);
      parse_dns_name(answer->rdata.cname_record.cname, buffer, offset);
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
  newRR->name = (char *)malloc(NAME_MAX_SIZE);
  assert(newRR->name);
  return newRR;
}

DnsResourceRecord *RR_dup(DnsResourceRecord *RR) {
  DnsResourceRecord *newRR = (DnsResourceRecord *)malloc(sizeof(DnsResourceRecord));
  assert(newRR);
  memcpy(newRR, RR, sizeof(DnsResourceRecord));
  int name_len = strlen((char *)RR->name) + 1;
  newRR->name = (char *)malloc(sizeof(char) * name_len);
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
}

static void put_flags(DnsMessageHeaderFlags *flags, uint8_t *buffer) {
  int offset = 0;
  buffer[offset++] |= (flags->QR << 7) | (flags->OPcode << 3) | (flags->AA << 2) | (flags->TC << 1) | (flags->RD);
  buffer[offset++] |= (flags->RA << 7) | (flags->Z << 4) | (flags->RCODE);
}

/* header 的 offset 默认是 0，所以就不加 offset 参数了 */
void put_header(DnsMessageHeader *header, uint8_t *buffer) {
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

int put_request(DnsRequest *request, uint8_t *buffer) {
  if (request == NULL || buffer == NULL) return 0;

  int offset = 0;
  put_header(&request->header, buffer + offset);
  offset += MSG_HEADER_SIZE;

  /* qname 是最早出现的域名，没必要做域名压缩 */
  offset += construct_dns_name(request->query.name, buffer + offset);

  w_bytes16(buffer + offset, request->query.type);
  offset += 2;

  w_bytes16(buffer + offset, request->query.class);
  offset += 2;

  return offset;
}

int new_put_answer(DnsMessageAnswer *answer, uint8_t *buffer, int answer_offset, DnsNameOffsetEntry *compression_table,
                   int *compression_count) {
  assert(answer != NULL && buffer != NULL);

  int offset = 0;
  uint8_t *answer_buf = buffer + answer_offset;

  char qname[NAME_MAX_SIZE] = {0};
  parse_dns_name(qname, buffer, MSG_HEADER_SIZE);

  if (strcasecmp(answer->name, qname) == 0) {
    answer_buf[offset++] = 0xC0;
    answer_buf[offset++] = 0x0C;
  } else {
    int name_len = construct_dns_name_with_compression(answer->name, answer_buf + offset, answer_offset + offset, compression_table,
                                                       compression_count);
    offset += name_len;
  }

  w_bytes16(answer_buf + offset, answer->type);
  offset += 2;

  w_bytes16(answer_buf + offset, answer->class);
  offset += 2;

  w_bytes32(answer_buf + offset, answer->ttl);
  offset += 4;

  int rdlength_pos = offset;
  offset += 2;  // 占位，稍后填写

  int tmp_offset = 0;

  switch (answer->type) {
    case DNS_TYPE_A:
      memcpy(answer_buf + offset, &answer->rdata.a_record.ipv4_address, 4);
      tmp_offset = 4;
      break;
    case DNS_TYPE_AAAA:
      memcpy(answer_buf + offset, &answer->rdata.aaaa_record.ipv6_address, 16);
      tmp_offset = 16;
      break;
    case DNS_TYPE_CNAME:
      tmp_offset = construct_dns_name_with_compression(answer->rdata.cname_record.cname, answer_buf + offset, answer_offset + offset,
                                                       compression_table, compression_count);
      break;
  }

  w_bytes16(answer_buf + rdlength_pos, tmp_offset);
  offset += tmp_offset;

  return offset;
}

void print_flags(DnsMessageHeaderFlags *flags) {
  printf(
      "QR: %d, "
      "OPcode: %d, "
      "AA: %d, "
      "TC: %d, "
      "RD: %d, "
      "RA: %d, "
      "Z: %d, "
      "RCODE: %d\n",
      flags->QR, flags->OPcode, flags->AA, flags->TC, flags->RD, flags->RA, flags->Z, flags->RCODE);
}

void print_header(DnsMessageHeader *header) {
  printf("ID: %04x, ", header->id);
  print_flags(&header->flags);
  printf(
      "QDCOUNT: %d, "
      "ANCOUNT: %d, "
      "NSCOUNT: %d, "
      "ARCOUNT: %d\n",
      header->QDCOUNT, header->ANCOUNT, header->NSCOUNT, header->ARCOUNT);
}

void print_question(DnsMessageQuestion *question) {
  printf("qname: %s\n", question->name);
  printf("qtype: %d\n", question->type);
  printf("qclass: %d\n", question->class);
}

void print_answer(DnsMessageAnswer *answer) {
  char ip_str[INET6_ADDRSTRLEN];

  // TODO
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

static char lower_case(char c) {
  if (c >= 'A' && c <= 'Z') {
    c += 32;
  }
  return c;
}

bool case_insentive_strcmp(const char *a, const char *b) {
  char *a_ptr = (char *)a, *b_ptr = (char *)b;
  while (*a_ptr && *b_ptr) {
    if (lower_case(*a_ptr) == lower_case(*b_ptr)) {
      ++a_ptr;
      ++b_ptr;
    } else {
      return false;
    }
  }
  return true;
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