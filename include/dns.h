#ifndef HEADER_DNS_H
#define HEADER_DNS_H

#include <stdint.h>

#include "array.h"

#define BUFFER_SIZE 1024
#define EX_DNS_ADDR "8.8.8.8"
#define LOCAL_ADDR "127.0.0.1"
#define BLACK_IP "0.0.0.0"
#define DEFAULT_TTL 360
#define FLAGS_BAN 5

enum QR_TYPE { QR_QUERY, QR_RESPONSE };

enum PORT { DNS_PORT = 53, RELAY_PORT = 4090 };

#pragma region StructDefinitions
struct DnsFlags {
  uint8_t QR;     /* 0 */
  uint8_t OPcode; /* 1-4 */
  uint8_t AA;     /* 5 */
  uint8_t TC;     /* 6 */
  uint8_t RD;     /* 7 */
  uint8_t RA;     /* 8 */
  uint8_t Z;      /* 9-11 */
  uint8_t RCODE;  /* 12-15 */
};

struct HeaderDnsDatagram {
  uint16_t id;
  struct DnsFlags flags;
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
};

struct QueryDnsDatagram {
  uint16_t type;
  uint16_t class;
  char name[128];
};

struct AnswerDnsDatagram {
  uint16_t name;
  uint16_t type;
  uint16_t class;
  uint16_t data_len;
  uint32_t ttl;
  uint32_t address;
};

struct RequestDnsDatagram {
  struct HeaderDnsDatagram header;
  struct QueryDnsDatagram query;
};

/* 中继服务器提供的查找比较局限，仅仅处理Type=1的情况，将域名解析为IPv4地址 */
struct ResponseDnsDatagram {
  struct HeaderDnsDatagram header;
  struct QueryDnsDatagram query;
  array_t *answer;  // struct AnswerDnsDatagram
};
#pragma endregion

#pragma region FunctionDefinitions

/**
 * @brief 解析 DNS Message->Question->QNAME
 *
 * @param domain 用于存储解析的 QNAME 内容
 * @param qname Message->Question->QNAME buffer
 *
 */
void parse_dns_query_name(char *domain, char *qname);

/**
 * @brief 解析 DNS Message->Header->uflags
 *
 * @param flags 用于存储解析的 uflags
 * @param uflags Message->Header->uflags buffer
 *
 */
void parse_dns_flags(struct DnsFlags *flags, uint16_t uflags);

/**
 * @brief 解析 DNS Message->Header
 *
 * @param header 用于存储解析的 Header 内容
 * @param buffer Message->Header buffer
 *
 */
void parse_dns_header(struct HeaderDnsDatagram *header, uint8_t *buffer);

/**
 * @brief 解析 DNS 响应报文
 *
 * @param response 用于存储解析的报文内容
 * @param buffer Message buffer
 *
 */
void parse_dns_response(struct ResponseDnsDatagram *response, uint8_t *buffer);

/* init */
void init_flags(struct DnsFlags *flags);
void init_header(struct HeaderDnsDatagram *header);
void init_query(struct QueryDnsDatagram *query);
void init_request(struct RequestDnsDatagram *request);
void init_answer(struct AnswerDnsDatagram *answer);

/* put */
// void put_flags(struct DnsFlags *flags, uint8_t *buffer);
int put_header(struct HeaderDnsDatagram *header, uint8_t *buffer);
int put_request(struct RequestDnsDatagram *request, uint8_t *buffer);
void put_answers(array_t *answers, uint8_t *buffer);

/* log */
void print_flags(struct DnsFlags *flags);
void print_header(struct HeaderDnsDatagram *header);

/* Utils */
uint16_t generate_random_id();
void w_bytes32(uint8_t *b, uint32_t v);
void w_bytes16(uint8_t *b, uint16_t v);

#pragma endregion

#endif /* HEADER_DNS_H */