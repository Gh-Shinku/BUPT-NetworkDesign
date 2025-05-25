#ifndef HEADER_DNS_H
#define HEADER_DNS_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#include "array.h"

#define BUFFER_SIZE 1024
#define UDP_DATAGRAM_MAX 1024
#define NAME_MAX_SIZE 512
#define MSG_HEADER_SIZE 12
#define EX_DNS_ADDR "114.114.114.114"
#define LOOP_BACK_ADDR "127.0.0.1"
#define BLACK_IP "0.0.0.0"
#define DEFAULT_TTL 300
#define FLAGS_BAN 5
#define DOMAIN_PTR_MASK 0xC000
#define MAX_RETRY 3
#define DOMAIN_PTR 2
#define MAX_ENTRY_COUNT 32

enum QR_TYPE { QR_QUERY, QR_RESPONSE };

enum PORT { DNS_PORT = 53, RELAY_PORT = 4090 };

enum { DNS_TYPE_A = 1, DNS_TYPE_AAAA = 28, DNS_TYPE_CNAME = 5, DNS_TYPE_OPT = 41 };

typedef struct {
  uint32_t ipv4_address;
} A_RData;

typedef struct {
  struct in6_addr ipv6_address;
} AAAA_RData;

typedef struct {
  char *cname;
} CNAME_RData;

typedef union {
  A_RData a_record;
  AAAA_RData aaaa_record;
  CNAME_RData cname_record;
} RData;

typedef struct {
  const char *name;  // 域名字符串（后缀）
  int offset;        // 在 buffer 中的偏移
} DnsNameOffsetEntry;

/* name 需要进行内存分配，故提供了 RR_init */
typedef struct DnsResourceRecord {
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
  RData rdata;
} DnsResourceRecord;

/* 无任何需要内存分配的成员 */
typedef struct DnsMessageHeaderFlags {
  uint8_t QR;     /* 0 */
  uint8_t OPcode; /* 1-4 */
  uint8_t AA;     /* 5 */
  uint8_t TC;     /* 6 */
  uint8_t RD;     /* 7 */
  uint8_t RA;     /* 8 */
  uint8_t Z;      /* 9-11 */
  uint8_t RCODE;  /* 12-15 */
} DnsMessageHeaderFlags;

/* 无任何需要内存分配的成员 */
typedef struct DnsMessageHeader {
  uint16_t id;
  struct DnsMessageHeaderFlags flags;
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
} DnsMessageHeader;

/* name 需要进行内存分配，但 question 不会被直接使用，因此由使用该类型的结构体负责其初始化 */
typedef struct DnsMessageQuestion {
  uint16_t type;
  uint16_t class;
  char *name;
} DnsMessageQuestion;

typedef struct DnsResourceRecord DnsMessageAnswer;

typedef struct DnsRequest {
  struct DnsMessageHeader header;
  struct DnsMessageQuestion query;
} DnsRequest;

typedef struct DnsResponse {
  struct DnsMessageHeader header;
  struct DnsMessageQuestion query;
  array_t *answer; /* array of struct DnsMessageAnswer */
} DnsResponse;

/**
 * @brief 从域名字符串构造 DNS 规定的域名存储格式
 *
 * @param domain
 * @param buf
 *
 */
int construct_dns_name(const char *domain, uint8_t *buf);

/**
 * @brief 解析 DNS 域名格式，包括对指针的处理
 *
 * @param domain domain 要求调用方进行预先分配，传入需要存储 domain 的地址，解析后，*domain 就指向字符串形式域名
 * @param buf 完整的 response buffer
 * @param offset 该偏移量是指当前待解析域名相对于 buf 的偏移量
 *
 * @return int 该 domain 在 buf 中占的长度
 */
int parse_dns_name(char *domain, const uint8_t *buf, int offset);

/**
 * @brief 解析 DNS Message->Header->uflags
 *
 * @param flags 用于存储解析的 uflags
 * @param uflags Message->Header->uflags buffer
 *
 */
void parse_dns_flags(DnsMessageHeaderFlags *flags, uint16_t uflags);

/**
 * @brief 解析 DNS Message->Header
 *
 * @param header 用于存储解析的 Header 内容
 * @param buffer Message->Header buffer
 *
 */
void parse_dns_header(DnsMessageHeader *header, const uint8_t *buffer);

/**
 * @brief 解析 DNS 请求报文
 *
 * @param request
 * @param buffer
 *
 */
void parse_dns_request(DnsRequest *request, const uint8_t *buffer);

/**
 * @brief 解析 DNS 响应报文
 *
 * @param response 用于存储解析的报文内容
 * @param buffer Message buffer
 *
 */
void parse_dns_response(DnsResponse *response, const uint8_t *buffer);

/* init */
void init_flags(DnsMessageHeaderFlags *flags, uint8_t QR, uint8_t OPcode, uint8_t AA, uint8_t TC, uint8_t RD, uint8_t RA, uint8_t Z,
                uint8_t RCODE);
void init_header(DnsMessageHeader *header, uint16_t id, DnsMessageHeaderFlags flags, uint16_t QDCOUNT, uint16_t ANCOUNT, uint16_t NSCOUNT,
                 uint16_t ARCOUNT);
void init_answer(DnsMessageAnswer *answer);

/**
 * @brief 初始化 RR，进行内存分配
 *
 * @return DnsResourceRecord*
 */
DnsResourceRecord *RR_init();

/**
 * @brief 复制 RR，进行内存分配
 *
 * @param RR
 *
 * @return DnsResourceRecord*
 */
DnsResourceRecord *RR_dup(DnsResourceRecord *RR);

/**
 * @brief 回收 RR 的内存
 *
 * @param RR
 *
 */
void RR_delete(DnsResourceRecord *RR);

/* put */
void put_header(DnsMessageHeader *header, uint8_t *buffer);
int put_request(DnsRequest *request, uint8_t *buffer);

/**
 * @brief 将 answer 装载到 buffer 中
 *
 * @param answer
 * @param buffer 完整的 buffer
 * @param offset answer 应当开始填充的初始位置偏移量
 *
 * @return int
 */
int put_answer(DnsMessageAnswer *answer, uint8_t *buffer, int answer_offset, DnsNameOffsetEntry *compression_table, int *compression_count);

/* log */
void print_flags(DnsMessageHeaderFlags *flags);
void print_header(DnsMessageHeader *header);
void print_question(DnsMessageQuestion *question);
void print_answer(DnsMessageAnswer *answer);
void print_response(DnsResponse *response);

/* Utils */
uint16_t generate_random_id();

/**
 * @brief 大小写不敏感字符串比较
 *
 * @param a
 * @param b
 *
 * @return bool
 */
bool case_insentive_strcmp(const char *a, const char *b);

/**
 * @brief 按大端法将 32bit 的值写入 b 缓冲区中
 *
 * @param b
 * @param v
 *
 */
void w_bytes32(uint8_t *b, uint32_t v);

/**
 * @brief 按大端法将 16bit 的值写入 b 缓冲区中
 *
 * @param b
 * @param v
 *
 */
void w_bytes16(uint8_t *b, uint16_t v);

#endif /* HEADER_DNS_H */