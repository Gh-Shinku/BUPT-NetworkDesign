#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cache.h"
#include "dns.h"
#include "hashtable.h"
#include "thpool.h"

#define THREAD_NUM 32

// TODO: 域名大小写不敏感

/* 0 = no debug, 1 = basic, 2 = verbose */
static int debug_level = 0;
static char dns_server_ip[64] = EX_DNS_ADDR;
static char config_file[256];

static hash_table_t *local_dns_table;
static lru_cache_t *dns_cache;
static int relay_sock; /* socket: 监听 DNS 请求 */
static struct sockaddr_in relay_addr;
static pthread_mutex_t mutex_ldt;        /* mutex of local_dns_table */
static pthread_mutex_t mutex_dc;         /* mutex of dns_cache */
static pthread_mutex_t mutex_relay_sock; /* mutex of relay_sock */
static threadpool thpool;

static void read_record();
static void *serve(void *args);
static void init_resource_limits();
static int init_data_structures();
static int init_socket();
static void handle_requests();
static void cleanup_resources();
void print_usage(const char *prog_name);
static void parse_args(int argc, char *argv[]);

struct TaskArgs {
  uint8_t *buffer;
  struct sockaddr_in sockaddr;
  ssize_t recv_len;
};

int main(int argc, char *argv[]) {
  parse_args(argc, argv);

  // init_resource_limits();

  if (init_data_structures() != 0) {
    return 1;
  }

  if (init_socket() != 0) {
    cleanup_resources();
    return 1;
  }

  if (debug_level > 0) {
    printf("[DEBUG] Using DNS server: %s\n", dns_server_ip);
    printf("[DEBUG] Using dnsrelay file: %s\n", config_file);
  }

  if (debug_level >= 1) {
    printf("Debug level: %d\n", debug_level);
  }

  handle_requests();
  cleanup_resources();
  return 0;
}

static void init_resource_limits() {
  struct rlimit rl;
  rl.rlim_cur = 128;
  rl.rlim_max = 256;
  if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
    perror("Failed to increase file descriptor limit");
  }
}

static int init_data_structures() {
  local_dns_table = ht_init(NULL, ht_str_comp, 1024, STRING);
  dns_cache = lru_cache_init();

  if (pthread_mutex_init(&mutex_ldt, NULL) < 0) {
    perror("Failed to initialize local DNS table mutex");
    return 1;
  }

  if (pthread_mutex_init(&mutex_dc, NULL) < 0) {
    perror("Failed to initialize DNS cache mutex");
    pthread_mutex_destroy(&mutex_ldt);
    return 1;
  }

  if (pthread_mutex_init(&mutex_relay_sock, NULL) < 0) {
    perror("Failed to initialize relay socket mutex");
    pthread_mutex_destroy(&mutex_ldt);
    pthread_mutex_destroy(&mutex_dc);
    return 1;
  }

  read_record();

  thpool = thpool_init(THREAD_NUM);

  return 0;
}

static int init_socket() {
  relay_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (relay_sock < 0) {
    perror("Failed to create relay socket");
    return 1;
  }

  relay_addr.sin_family = AF_INET;
  relay_addr.sin_addr.s_addr = INADDR_ANY;
  relay_addr.sin_port = htons(RELAY_PORT);

  if (bind(relay_sock, (const struct sockaddr *)&relay_addr, sizeof(relay_addr)) < 0) {
    perror("[Error] relay_sock bind failed");
    close(relay_sock);
    return 1;
  }

  return 0;
}

static void handle_requests() {
  uint8_t buffer[UDP_DATAGRAM_MAX];
  struct TaskArgs *args;
  struct sockaddr_in client_addr;
  socklen_t client_addr_len;

  while (1) {
    memset(buffer, 0, UDP_DATAGRAM_MAX * sizeof(uint8_t));
    client_addr_len = sizeof(client_addr);

    ssize_t recv_len = recvfrom(relay_sock, buffer, UDP_DATAGRAM_MAX, 0, (struct sockaddr *)&client_addr, &client_addr_len);

    if (recv_len < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      perror("[Error] recvfrom relay_sock failed");
      continue;
    }

    args = (struct TaskArgs *)malloc(sizeof(struct TaskArgs));
    args->buffer = (uint8_t *)malloc(UDP_DATAGRAM_MAX);
    memcpy(args->buffer, buffer, UDP_DATAGRAM_MAX);
    args->sockaddr = client_addr;
    args->recv_len = recv_len;

    thpool_add_job(thpool, serve, args);
  }
}

static void cleanup_record(ht_node_t *node) {
  local_record_t *record = (local_record_t *)node->value;
  free(record->domain);
  free(record->ip);
  free(record);
  free(node->key);
}

static void cleanup_resources() {
  close(relay_sock);

  pthread_mutex_destroy(&mutex_ldt);
  pthread_mutex_destroy(&mutex_dc);
  pthread_mutex_destroy(&mutex_relay_sock);

  thpool_wait(thpool);
  thpool_destroy(thpool);

  ht_free_custom(local_dns_table, cleanup_record);
  cache_free(dns_cache);
}

static void read_record() {
  FILE *table_relay = fopen(config_file, "r");
  if (table_relay == NULL) {
    perror("Failed to open DNS relay configuration file");
    fprintf(stderr, "Tried to open: %s\n", config_file);
    return;
  }

  char buf_ip[NAME_MAX_SIZE], buf_domain[NAME_MAX_SIZE];
  while (fscanf(table_relay, "%s", buf_ip) != EOF) {
    fscanf(table_relay, "%s", buf_domain);
    /* 不论该 key 是否重复，都进行插入 */
    local_record_t *record = local_record_init(buf_domain, buf_ip);
    ht_insert(local_dns_table, buf_domain, record);
  }
  fclose(table_relay);

  if (debug_level >= 1) {
    printf("Loaded DNS records from %s\n", config_file);
  }
}

static void *serve(void *args) {
  /* 解析 task 参数，包括 buffer 和客户端地址信息 */
  struct TaskArgs *taskargs = (struct TaskArgs *)args;
  uint8_t *buffer = taskargs->buffer;
  struct sockaddr_in *client_addr = &taskargs->sockaddr;
  ssize_t relay_recv_len = taskargs->recv_len, pass_recv_len = 0, send_len = 0, back_len = 0;

  /* 创建转发 socket: relay server -> externel dns server */
  int pass_sock;
  pass_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (pass_sock < 0) {
    perror("pass_sock creation failed");
    goto cleanup;
  }

  struct timeval pass_tv;
  pass_tv.tv_sec = 1;
  pass_tv.tv_usec = 0;
  if (setsockopt(pass_sock, SOL_SOCKET, SO_RCVTIMEO, &pass_tv, sizeof(pass_tv)) < 0) {
    perror("[Error] setting socket timeout for pass_sock failed");
    goto cleanup;
  }

  struct sockaddr_in pass_addr;
  pass_addr.sin_family = AF_INET;
  pass_addr.sin_port = htons(DNS_PORT);
  inet_pton(AF_INET, EX_DNS_ADDR, &pass_addr.sin_addr);

  DnsMessageHeaderFlags flags;
  DnsMessageHeader header;

  DnsRequest request;
  parse_dns_request(&request, buffer);

  DnsResponse response;

  if (debug_level > 0) {
    printf("[Debug] parse_dns_query_name successfully: %s\n", request.query.name);
    printf("[Debug] Query type: %d, class: %d\n", request.query.type, request.query.class);
  }

  /* ====================== 到此为止，前半部分在解析请求，后半部分就处理请求 ============================ */

  /* 先从 local_dns_table 中查找 */
  pthread_mutex_lock(&mutex_ldt);
  ht_node_t *ht_node = ht_lookup(local_dns_table, request.query.name);
  pthread_mutex_unlock(&mutex_ldt);

  if (ht_node != NULL) {
    local_record_t *record = (local_record_t *)ht_node->value;
    assert(record != NULL);
    /* 给定 header，header 不能先设置，还要判断 IP 是否被封禁 */
    parse_dns_header(&header, buffer);

    char *ip = record->ip;
    if (debug_level > 0) {
      printf("[Debug] ip: %s\n", ip);
    }

    /* 判断 IP 是否被封禁 */
    if (!strcmp(ip, BLACK_IP)) {
      init_flags(&flags, QR_RESPONSE, header.flags.OPcode, 0, 0, header.flags.TC, 1, 0, 5);
      init_header(&header, header.id, flags, header.QDCOUNT, 0, 0, 0);

      put_header(&header, buffer);
      /* 因为被封禁，所以根本不提供 answer 部分 */
      back_len = relay_recv_len;
    } else {
      init_flags(&flags, QR_RESPONSE, header.flags.OPcode, 0, 0, header.flags.TC, 1, 0, 0);
      init_header(&header, header.id, flags, header.QDCOUNT, 1, 0, 0);

      put_header(&header, buffer);
      DnsMessageAnswer *answer = RR_init();
      answer->type = 1;
      answer->class = 1;
      answer->ttl = DEFAULT_TTL;
      answer->rdlength = 4;
      inet_pton(AF_INET, ip, &answer->rdata.a_record.ipv4_address);
      *(uint16_t *)answer->name = MSG_HEADER_SIZE | DOMAIN_PTR_MASK; /* 0xc00c */
      /* 在 local_dns_table 中的记录不需要 Authority & Additional */
      /* put answer */
      if (debug_level > 0) {
        printf("[DEBUG] recv_len: %ld\n", relay_recv_len);
      }
      back_len = relay_recv_len + put_answer(answer, buffer + relay_recv_len);
      RR_delete(answer);
    }
  } else /* 再从 dns_cache 中查找 */ {
    /* TODO: 从缓存中构造的操作并不正确 */
    pthread_mutex_lock(&mutex_dc);
    cache_node_t *cache_node = cache_lookup(dns_cache, request.query.name);
    pthread_mutex_unlock(&mutex_dc);
    if (cache_node != NULL) {
      array_t *RRs = cache_node->RRs;
      /* 还需要判断是否超出 UDP 报文大小，这个放在最后发送的位置进行判断 */
      init_flags(&flags, QR_RESPONSE, request.header.flags.OPcode, 0, 0, request.header.flags.TC, 1, 0, 5);
      init_header(&header, request.header.id, flags, request.header.QDCOUNT, RRs->length, 0, 0);
      put_header(&header, buffer);
      int offset = 0;
      for (int i = 0; i < RRs->length; i++) {
        /* 这里的 RR 是 parse_dns_response 时插入的，理论上已经过正确的设置 */
        DnsMessageAnswer *ans = &array_index(RRs, i, DnsMessageAnswer);
        print_answer(ans);
        offset += put_answer(ans, buffer + relay_recv_len + offset);
      }
      back_len = relay_recv_len + offset;
    } else /* 向外部 DNS 服务器发送请求 */ {
      /* TODO: 这里有个所谓的 ID 转换，之后再说 */
      /* 由于 UDP 请求可能会失败，设置重传机制 */
      int cnt = 0;
      bool success = false;
      if (back_len > UDP_DATAGRAM_MAX) {
        printf("[DEBUG] back_len:%ld = recv_len:%ld + offset:%ld\n", back_len, relay_recv_len, back_len - relay_recv_len);
      }
      while (cnt < MAX_RETRY && !success) {
        ++cnt;
        send_len = sendto(pass_sock, buffer, relay_recv_len, 0, (struct sockaddr *)&pass_addr, sizeof(pass_addr));
        if (send_len < 0) {
          printf("[DEBUG] send buffer hex dump (len = %ld):\n", relay_recv_len);
          for (int i = 0; i < relay_recv_len; ++i) {
            printf("%02x ", (unsigned char)buffer[i]);
            if (i % 16 == 15) printf("\n");
          }
          perror("[ERROR] sendto pass_sock failed");
          usleep(100000);
        } else {
          pass_recv_len = recvfrom(pass_sock, buffer, UDP_DATAGRAM_MAX, 0, NULL, NULL);
          if (pass_recv_len < 0) {
            printf("[DEBUG] recv buffer hex dump (len = %ld):\n", pass_recv_len);
            for (int i = 0; i < pass_recv_len; ++i) {
              printf("%02x ", (unsigned char)buffer[i]);
              if (i % 16 == 15) printf("\n");
            }
            perror("[ERROR] recvfrom pass_sock failed");
            usleep(100000);
          } else {
            success = true;
          }
        }
      }

      if (!success) /* 没能成功从外部 DNS 服务器获取响应 */ {
        /* 构造失败响应 */
        init_flags(&flags, QR_RESPONSE, request.header.flags.OPcode, 0, 0, request.header.flags.RD, 1, 0, 2);
        init_header(&header, request.header.id, flags, request.header.QDCOUNT, 0, 0, 0);
        put_header(&header, buffer);
        if (debug_level > 0) {
          perror("[DEBUG] failed to relay request");
        }
      } else /* 成功获取响应 */ {
        /* tmp: 打印响应内容进行查看 */

        /* 解析响应 */
        parse_dns_response(&response, buffer);
        if (debug_level > 0) {
          print_response(&response);
        }

        /* 进行缓存 */
        cache_node_t *cache_node = cache_node_init(response.query.name, response.answer);
        pthread_mutex_lock(&mutex_dc);
        cache_insert(dns_cache, cache_node);
        pthread_mutex_unlock(&mutex_dc);
        /* 构造响应 */
        /* 如果不做 id 转换，直接将响应的 buffer 回传即可 */
        back_len = pass_recv_len;
        free(response.query.name);
      }
    }
  }
  /* 回传响应 */
  /* 先不考虑超出 512 字节的情况 */
  pthread_mutex_lock(&mutex_relay_sock);
  send_len = sendto(relay_sock, buffer, back_len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
  pthread_mutex_unlock(&mutex_relay_sock);
  if (send_len < 0) {
    perror("[ERROR] sendto relay_sock failed!");
  }

  if (debug_level > 0) {
    printf("[Debug] send to relay_sock successfully\n");
  }

  free(request.query.name);
cleanup:
  if (pass_sock > 0) {
    close(pass_sock);
  }

  free(taskargs->buffer);
  free(taskargs);
  return NULL;
}

void print_usage(const char *prog_name) {
  printf("Usage: %s [-d | -dd] [dns-server-ipaddr] [config-filename]\n", prog_name);
  printf("Options:\n");
  printf("  -d         Enable debug mode (level 1)\n");
  printf("  -dd        Enable debug mode (level 2)\n");
  printf("  -h, --help Show this help message and exit\n");
  printf("\n");
  printf("Defaults:\n");
  printf("  DNS Server IP: %s\n", EX_DNS_ADDR);
  printf("  Config File  : ../data/dnsrelay.txt\n");
}

/**
 * Parse command-line arguments according to the syntax:
 * dnsrelay [-d | -dd] [dns-server-ipaddr] [filename]
 */
static void parse_args(int argc, char *argv[]) {
  int current_arg = 1;

  debug_level = 0;
  strncpy(dns_server_ip, EX_DNS_ADDR, sizeof(dns_server_ip) - 1);
  strncpy(config_file, "../data/dnsrelay.txt", sizeof(config_file) - 1);

  if (current_arg < argc) {
    if (strcmp(argv[current_arg], "-h") == 0 || strcmp(argv[current_arg], "--help") == 0) {
      print_usage(argv[0]);
      exit(0);
    } else if (strcmp(argv[current_arg], "-d") == 0) {
      debug_level = 1;
      current_arg++;
    } else if (strcmp(argv[current_arg], "-dd") == 0) {
      debug_level = 2;
      current_arg++;
    }
  }

  if (current_arg < argc) {
    struct in_addr addr;
    if (inet_pton(AF_INET, argv[current_arg], &addr) == 1) {
      strncpy(dns_server_ip, argv[current_arg], sizeof(dns_server_ip) - 1);
      current_arg++;
    }
  }

  if (current_arg < argc) {
    strncpy(config_file, argv[current_arg], sizeof(config_file) - 1);
    current_arg++;
  }

  if (current_arg < argc) {
    fprintf(stderr, "Error: too many arguments.\n");
    print_usage(argv[0]);
    exit(1);
  }
}