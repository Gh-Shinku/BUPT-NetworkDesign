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
#include <time.h>
#include <unistd.h>

#include "cache.h"
#include "dns.h"
#include "hashtable.h"
#include "log.h"
#include "thpool.h"

#define THREAD_NUM 32

static int debug_level; /* 0 = no debug, 1 = basic, 2 = verbose */
static uint64_t request_num;
static char dns_server_ip[64] = EX_DNS_ADDR;
static char config_file[256];
static char prog_name[256];

static hash_table_t *local_dns_table;
static lru_cache_t *dns_cache;
static int relay_sock; /* socket: 监听 DNS 请求 */
static struct sockaddr_in relay_addr;
static pthread_mutex_t mutex_ldt;         /* mutex of local_dns_table */
static pthread_mutex_t mutex_dc;          /* mutex of dns_cache */
static pthread_mutex_t mutex_relay_sock;  /* mutex of relay_sock */
static pthread_mutex_t mutex_request_num; /* mutex of request_num */
static threadpool thpool;

static int init_data_structures();
static int init_socket();
static void read_record();
static void *serve(void *args);
static void handle_requests();
static void record_clear(ht_node_t *node);
static void clear_resources();
static void print_usage();
static void parse_args(int argc, char *argv[]);
static void print_basic_info();
static void print_current_time();
static void print_ipv4(struct sockaddr_in *addr);

struct TaskArgs {
  uint8_t *buffer;
  struct sockaddr_in sockaddr;
  ssize_t recv_len;
};

int main(int argc, char *argv[]) {
  parse_args(argc, argv);
  print_basic_info();

  if (init_data_structures() != 0) {
    return 1;
  }

  if (init_socket() != 0) {
    clear_resources();
    return 1;
  }

  handle_requests();
  clear_resources();
  return 0;
}

static int init_data_structures() {
  local_dns_table = ht_init(NULL, ht_str_comp, record_clear, 1024, STRING);
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

static void read_record() {
  FILE *table_relay = fopen(config_file, "r");
  if (table_relay == NULL) {
    perror("Failed to open DNS relay configuration file");
    fprintf(stderr, "Tried to open: %s\n", config_file);
    return;
  }

  int record_num = 0;
  char buf_ip[NAME_MAX_SIZE], buf_domain[NAME_MAX_SIZE];
  while (fscanf(table_relay, "%s", buf_ip) != EOF) {
    fscanf(table_relay, "%s", buf_domain);
    if (debug_level == 2) {
      printf("%d %s %s\n", record_num++, buf_domain, buf_ip);
    }
    /* 不论该 key 是否重复，都进行插入 */
    local_record_t *record = local_record_init(buf_domain, buf_ip);
    /* key 和 value 的内存管理由 record 维护 */
    ht_insert(local_dns_table, record->domain, record);
  }
  fclose(table_relay);
}

static void handle_requests() {
  uint8_t buffer[BUFFER_SIZE];
  struct TaskArgs *args;
  struct sockaddr_in client_addr;
  socklen_t client_addr_len;

  while (1) {
    memset(buffer, 0, BUFFER_SIZE * sizeof(uint8_t));
    client_addr_len = sizeof(client_addr);

    ssize_t recv_len = recvfrom(relay_sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len);

    if (recv_len < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      perror("[Error] recvfrom relay_sock failed");
      continue;
    }

    args = (struct TaskArgs *)malloc(sizeof(struct TaskArgs));
    args->buffer = (uint8_t *)malloc(BUFFER_SIZE);
    memcpy(args->buffer, buffer, BUFFER_SIZE);
    args->sockaddr = client_addr;
    args->recv_len = recv_len;

    thpool_add_job(thpool, serve, args);
  }
}

static void record_clear(ht_node_t *node) {
  local_record_t *record = (local_record_t *)node->value;
  if (record == NULL) return;
  free(record->domain);
  free(record->ip);
  free(record);
}

static void clear_resources() {
  close(relay_sock);

  pthread_mutex_destroy(&mutex_ldt);
  pthread_mutex_destroy(&mutex_dc);
  pthread_mutex_destroy(&mutex_relay_sock);

  thpool_wait(thpool);
  thpool_destroy(thpool);

  ht_free(local_dns_table);
  cache_free(dns_cache);
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
  DnsResponse response;

  parse_dns_request(&request, buffer);

  if (debug_level >= 2) {
    printf("RECV from ");
    print_ipv4(client_addr);
    printf(":%d (%lu bytes)  ", client_addr->sin_port, relay_recv_len);
    for (int i = 0; i < relay_recv_len; ++i) {
      if (i < relay_recv_len - 1) {
        printf("%02x ", buffer[i]);
      } else {
        printf("%02x\n", buffer[i]);
      }
    }
    print_header(&request.header);
  }

  if (debug_level >= 1) {
    pthread_mutex_lock(&mutex_request_num);
    printf("%lu:  ", request_num++);
    pthread_mutex_unlock(&mutex_request_num);
    print_current_time();
    printf("  Client ");
    print_ipv4(client_addr);
    printf("    %s, TYPE %d, CLASS %d\n", request.query.name, request.query.type, request.query.class);
  }

  /* 先判断请求类型 */
  bool canCache = true;
  /* 非缓存类型直接进行中继转发 */
  if (request.query.type != DNS_TYPE_A && request.query.type != DNS_TYPE_AAAA && request.query.type != DNS_TYPE_CNAME) {
    canCache = false;
    goto RELAY_REQUEST;
  } else /* 是缓存类型再根据缓存判断 */ {
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

      /* 判断 IP 是否被封禁 */
      if (!strcmp(ip, BLACK_IP)) {
        init_flags(&flags, QR_RESPONSE, header.flags.OPcode, 0, 0, header.flags.TC, 1, 0, 5);
        init_header(&header, header.id, flags, header.QDCOUNT, 0, 0, 0);

        put_header(&header, buffer);
        /* 因为被封禁，所以根本不提供 answer 部分 */
        back_len = relay_recv_len;
      } else {
        init_flags(&flags, QR_RESPONSE, header.flags.OPcode, 1, 0, header.flags.TC, 1, 0, 0);
        init_header(&header, header.id, flags, header.QDCOUNT, 1, 0, 0);

        put_header(&header, buffer);
        int compression_count = 0;
        DnsNameOffsetEntry compression_table[MAX_ENTRY_COUNT];
        DnsMessageAnswer *answer = RR_init();
        answer->type = 1;
        answer->class = 1;
        answer->ttl = DEFAULT_TTL;
        answer->rdlength = 4;
        inet_pton(AF_INET, ip, &answer->rdata.a_record.ipv4_address);
        strcpy(answer->name, record->domain);
        /* 在 local_dns_table 中的记录不需要 Authority & Additional */
        /* put answer */
        if (debug_level > 0) {
          printf("[DEBUG] recv_len: %ld\n", relay_recv_len);
        }
        back_len = relay_recv_len + put_answer(answer, buffer, relay_recv_len, compression_table, &compression_count);
        RR_delete(answer);
      }
    } else /* 再从 dns_cache 中查找 */ {
      pthread_mutex_lock(&mutex_dc);
      cache_node_t *cache_node = cache_lookup(dns_cache, request.query.name);
      pthread_mutex_unlock(&mutex_dc);
      if (cache_node != NULL) {
        array_t *RRs = cache_node->RRs;
        /* 还需要判断是否超出 UDP 报文大小，这个放在最后发送的位置进行判断 */
        init_flags(&flags, QR_RESPONSE, request.header.flags.OPcode, 1, 0, request.header.flags.TC, 1, 0, 0);
        init_header(&header, request.header.id, flags, request.header.QDCOUNT, RRs->length, 0, 0);
        put_header(&header, buffer);
        int offset = 0;
        int compression_count = 0;
        DnsNameOffsetEntry compression_table[MAX_ENTRY_COUNT];
        for (int i = 0; i < RRs->length; i++) {
          DnsMessageAnswer *ans = &array_index(RRs, i, DnsMessageAnswer);
          offset += put_answer(ans, buffer, relay_recv_len + offset, compression_table, &compression_count);
        }
        back_len = relay_recv_len + offset;
      } else /* 向外部 DNS 服务器发送请求 */ {
      /* 由于 UDP 请求可能会失败，设置重传机制 */
      RELAY_REQUEST : {
        int cnt = 0;
        bool success = false;
        /* id 转换 */
        uint16_t ex_id = generate_random_id();
        memcpy(&header, &request.header, sizeof(header));
        header.id = ex_id;
        put_header(&header, buffer);
        while (cnt < MAX_RETRY && !success) {
          ++cnt;
          send_len = sendto(pass_sock, buffer, relay_recv_len, 0, (struct sockaddr *)&pass_addr, sizeof(pass_addr));
          if (debug_level >= 2) {
            printf("SEND to %s (%lu bytes) [ID %04x->%04x]\n", dns_server_ip, relay_recv_len, request.header.id, ex_id);
          }
          if (send_len < 0) {
            perror("[ERROR] sendto pass_sock failed");
            usleep(100000);
          } else {
            pass_recv_len = recvfrom(pass_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
            if (pass_recv_len < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // perror("[INFO] No data available at the moment");
              } else {
                perror("[ERROR] recvfrom pass_sock failed");
              }
              usleep(100000);
            } else {
              success = true;
              if (debug_level >= 2) {
                printf("RECV from %s (%lu bytes) ", dns_server_ip, pass_recv_len);
                for (int i = 0; i < pass_recv_len; ++i) {
                  if (i < pass_recv_len - 1) {
                    printf("%02x ", buffer[i]);
                  } else {
                    printf("%02x\n", buffer[i]);
                  }
                }
              }
              /* id 回转 */
              parse_dns_header(&header, buffer);
              header.id = request.header.id;
              header.flags.AA = 1;
              put_header(&header, buffer);
            }
          }
        }

        if (!success) /* 没能成功从外部 DNS 服务器获取响应 */ {
          /* 构造失败响应 */
          init_flags(&flags, QR_RESPONSE, request.header.flags.OPcode, 0, 0, request.header.flags.RD, 1, 0, 2);
          init_header(&header, request.header.id, flags, request.header.QDCOUNT, 0, 0, 0);
          put_header(&header, buffer);
        } else /* 成功获取响应 */ {
          /* 解析响应 */
          parse_dns_response(&response, buffer);
          if (response.header.ANCOUNT == 0) {
            canCache = false;
          } else {
            canCache = false;
            for (int i = 0; i < response.answer->length; ++i) {
              DnsMessageAnswer *ans = &array_index(response.answer, i, DnsMessageAnswer);
              if (ans->type == DNS_TYPE_A || ans->type == DNS_TYPE_AAAA) {
                canCache = true;
                break;
              }
            }
          }

          /* 进行缓存 */
          if (canCache) {
            /* 如果 cache 过，response.answer 的生命周期由 cache_node 进行管理 */
            cache_node_t *cache_node = cache_node_init(response.query.name, response.answer);
            pthread_mutex_lock(&mutex_dc);
            cache_insert(dns_cache, cache_node);
            pthread_mutex_unlock(&mutex_dc);
          } else {
            for (int i = 0; i < response.answer->length; ++i) {
              RR_delete(&array_index(response.answer, i, DnsMessageAnswer));
            }
            array_free(response.answer);
          }
          /* 构造响应 */
          back_len = pass_recv_len;
          free(response.query.name);
        }
      }
      }
    }
  }
  /* 回传响应 */
  pthread_mutex_lock(&mutex_relay_sock);
  send_len = sendto(relay_sock, buffer, back_len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
  pthread_mutex_unlock(&mutex_relay_sock);
  if (send_len < 0) {
    perror("[ERROR] sendto relay_sock failed!");
  }

  free(request.query.name);
cleanup : {
  if (pass_sock > 0) {
    close(pass_sock);
  }

  free(taskargs->buffer);
  free(taskargs);
}
  return NULL;
}

static void print_usage() {
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
      strncpy(prog_name, argv[0], 256);
      print_usage();
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
    print_usage();
    exit(1);
  }
}

static void print_basic_info() {
  printf("DNSRELAY, Version 1.0, Build: May 20 2025 16:28\n");
  print_usage();
  printf("\nName server %s\n", dns_server_ip);
  printf("Debug level %d\n", debug_level);
}

void print_current_time() {
  time_t rawtime;
  struct tm *timeinfo;
  char buffer[20];

  time(&rawtime);

  timeinfo = localtime(&rawtime);

  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

  printf("%s", buffer);
}

void print_ipv4(struct sockaddr_in *addr) {
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
  printf("%s", ip_str);
}