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

/* 0 = no debug, 1 = basic, 2 = verbose */
static int debug_level = 0;
static char dns_server_ip[64] = EX_DNS_ADDR;
static char config_file[256];

static hash_table_t *local_dns_table;
static cache_table_t *dns_cache;
static int relay_sock;
static struct sockaddr_in relay_addr;
static pthread_mutex_t mutex_ldt;
static pthread_mutex_t mutex_dc;
static pthread_mutex_t mutex_relay_sock;
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

  init_resource_limits();

  if (init_data_structures() != 0) {
    return 1;
  }

  if (init_socket() != 0) {
    cleanup_resources();
    return 1;
  }

  printf("DNS Relay Server started.\n");
  printf("Using DNS server: %s\n", dns_server_ip);
  printf("Using configuration file: %s\n", config_file);

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
  dns_cache = cache_init();

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

static void cleanup_resources() {
  close(relay_sock);

  pthread_mutex_destroy(&mutex_ldt);
  pthread_mutex_destroy(&mutex_dc);
  pthread_mutex_destroy(&mutex_relay_sock);

  thpool_wait(thpool);
  thpool_destroy(thpool);

  ht_free(local_dns_table);
  cache_free(dns_cache);
}

static void read_record() {
  FILE *table_relay = fopen(config_file, "r");
  if (table_relay == NULL) {
    perror("Failed to open DNS relay configuration file");
    fprintf(stderr, "Tried to open: %s\n", config_file);
    return;
  }

  char buf_ip[128], buf_domain[128];
  while (fscanf(table_relay, "%s", buf_ip) != EOF) {
    fscanf(table_relay, "%s", buf_domain);
    char *domain = strdup(buf_domain);
    char *ip = strdup(buf_ip);
    ht_node_t *ht_node = ht_lookup(local_dns_table, domain);
    if (ht_node == NULL) {
      array_t *ip_arr = array_init(sizeof(char *));
      array_append(ip_arr, &ip);
      cache_node_t *cachenode = cache_node_init(domain, ip_arr);
      ht_insert(local_dns_table, domain, cachenode);
    } else {
      cache_node_t *cachenode = (cache_node_t *)ht_node->value;
      array_append(cachenode->ip_table, &ip);
    }
  }
  fclose(table_relay);

  if (debug_level >= 1) {
    printf("Loaded DNS records from %s\n", config_file);
  }
}

static void *serve(void *args) {
  struct TaskArgs *taskargs = (struct TaskArgs *)args;
  uint8_t *buffer = taskargs->buffer;
  struct sockaddr_in *client_addr = &taskargs->sockaddr;

  int pass_sock;
  struct sockaddr_in pass_addr;
  struct ResponseDnsDatagram response = {0};
  response.answer = array_init(sizeof(struct AnswerDnsDatagram));
  bool response_initialized = true;

  pass_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (pass_sock < 0) {
    perror("pass_sock creation failed");
    response_initialized = false;
    goto cleanup;
  }

  /* Set timeout for external DNS server communications */
  struct timeval pass_tv;
  pass_tv.tv_sec = 1;
  pass_tv.tv_usec = 0;
  if (setsockopt(pass_sock, SOL_SOCKET, SO_RCVTIMEO, &pass_tv, sizeof(pass_tv)) < 0) {
    perror("Error setting socket timeout for pass_sock");
    goto cleanup;
  }

  pass_addr.sin_family = AF_INET;
  pass_addr.sin_port = htons(DNS_PORT);
  inet_pton(AF_INET, EX_DNS_ADDR, &pass_addr.sin_addr);

  ssize_t recv_len = taskargs->recv_len, send_len, back_len;
  struct HeaderDnsDatagram header;
  struct AnswerDnsDatagram answer;
  init_header(&header);
  header.id = ntohs(((uint16_t *)buffer)[0]);
  init_answer(&answer);

  // Parse the original DNS query
  parse_dns_header(&header, buffer);

  struct RequestDnsDatagram request;
  parse_dns_query_name(request.query.name, (char *)(buffer + 12));
  // Extract query type and class from the original request
  request.query.type = ntohs(*(uint16_t *)(buffer + 12 + strlen((char *)(buffer + 12)) + 1));
  request.query.class = ntohs(*(uint16_t *)(buffer + 12 + strlen((char *)(buffer + 12)) + 3));

  if (debug_level > 0) {
    printf("[Debug] parse_dns_query_name successfully: %s\n", request.query.name);
    printf("[Debug] Query type: %d, class: %d\n", request.query.type, request.query.class);
  }

  pthread_mutex_lock(&mutex_ldt);
  ht_node_t *ht_node = ht_lookup(local_dns_table, request.query.name);
  pthread_mutex_unlock(&mutex_ldt);
  array_t *ipArr = NULL;
  if (ht_node != NULL) {
    ipArr = ((cache_node_t *)ht_node->value)->ip_table;
  } else {
    pthread_mutex_lock(&mutex_dc);
    cache_node_t *cache_node = cache_lookup(dns_cache, request.query.name);
    pthread_mutex_unlock(&mutex_dc);
    if (cache_node != NULL) {
      ipArr = cache_node->ip_table;
    }
  }

  if (ipArr != NULL) {
    if (debug_level > 0) printf("[Debug] ipArr != NULL\n");
    // This is a locally stored domain - construct a proper DNS response

    header.flags.QR = QR_RESPONSE;
    header.flags.AA = 1;
    header.flags.RD = 1;
    header.flags.RA = 1;
    header.ANCOUNT = 0;

    uint8_t response_buffer[BUFFER_SIZE];
    memset(response_buffer, 0, BUFFER_SIZE);

    memcpy(response_buffer, buffer, recv_len);

    uint16_t answer_offset = recv_len;
    bool blacklisted = false;

    for (int i = 0; i < ipArr->length && !blacklisted; i++) {
      char *ip = array_index(ipArr, i, char *);
      if (debug_level > 0) {
        printf("[Debug] ip: %s\n", ip);
      }

      if (!strcmp(ip, BLACK_IP)) {
        // Domain is blacklisted, return "域名不存在" (domain does not exist) error
        header.flags.QR = QR_RESPONSE;
        header.flags.RCODE = 3;  // Name Error (NXDOMAIN) - indicates the domain does not exist
        header.ANCOUNT = 0;      // No answers for blacklisted domains
        blacklisted = true;

        // Update header in response buffer
        put_header(&header, response_buffer);

        // Set response length to include only the query portion
        back_len = recv_len;
        break;
      }

      // For each IP, create an answer record
      header.ANCOUNT++;

      // Add name pointer (compression - points back to the query name)
      // 0xC0 is the compression flag, 0x0C is the offset to the query name
      response_buffer[answer_offset++] = 0xC0;
      response_buffer[answer_offset++] = 0x0C;

      // Add type (A record = 1)
      response_buffer[answer_offset++] = 0x00;
      response_buffer[answer_offset++] = 0x01;

      // Add class (IN = 1)
      response_buffer[answer_offset++] = 0x00;
      response_buffer[answer_offset++] = 0x01;

      // Add TTL (use 300 seconds = 5 minutes)
      uint32_t ttl = htonl(300);
      memcpy(response_buffer + answer_offset, &ttl, 4);
      answer_offset += 4;

      // Add data length (4 bytes for IPv4)
      uint16_t data_len = htons(4);
      memcpy(response_buffer + answer_offset, &data_len, 2);
      answer_offset += 2;

      // Add IP address
      struct in_addr addr;
      inet_pton(AF_INET, ip, &addr);
      memcpy(response_buffer + answer_offset, &addr.s_addr, 4);
      answer_offset += 4;
    }

    // If the domain isn't blacklisted, update the header in the response buffer
    // and set the response length
    if (!blacklisted) {
      put_header(&header, response_buffer);
      back_len = answer_offset;
    }

    // Use the response buffer instead of the original buffer
    uint8_t *temp_buffer = taskargs->buffer;
    taskargs->buffer = malloc(BUFFER_SIZE);
    memcpy(taskargs->buffer, response_buffer, BUFFER_SIZE);
    free(temp_buffer);
    buffer = taskargs->buffer;
  } else {
    // ... existing code for handling non-local domains ...
    // This is the external DNS server lookup path - no changes needed
    int max_retries = 3;
    int retry_count = 0;
    bool success = false;

    while (retry_count < max_retries && !success) {
      // Check if the packet size is too large for UDP (typically 512 bytes is the safe size for DNS)
      if (recv_len > 512) {
        // Set truncation flag to indicate packet is too large
        header.flags.QR = QR_RESPONSE;
        header.flags.TC = 1;  // Set truncation flag
        put_header(&header, buffer);
        back_len = 12;  // Just send the header
        success = true;
        break;
      }

      send_len = sendto(pass_sock, buffer, recv_len, 0, (struct sockaddr *)&pass_addr, sizeof(pass_addr));
      if (send_len < 0) {
        if (errno == EMSGSIZE) {
          // Message too large for UDP, set truncation flag
          header.flags.QR = QR_RESPONSE;
          header.flags.TC = 1;  // Set truncation flag
          put_header(&header, buffer);
          back_len = 12;  // Just send the header
          success = true;
          break;
        }
        perror("sendto pass_sock failed");
        retry_count++;
        usleep(10000);
        continue;
      }
      if (debug_level > 0) {
        printf("[Debug] send to pass_sock successfully\n");
      }
      recv_len = recvfrom(pass_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
      if (recv_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          if (debug_level > 0) {
            printf("[Debug] External DNS timeout - retry %d of %d\n", retry_count + 1, max_retries);
          }
          retry_count++;
          usleep(10000);
          continue;
        } else {
          perror("recvfrom pass_sock failed");
          break;
        }
      }
      success = true;
    }

    if (!success) {
      header.flags.QR = QR_RESPONSE;
      header.flags.RCODE = 2;
      put_header(&header, buffer);
      back_len = 12;
    } else {
      parse_dns_response(&response, buffer);
      array_t *answers = array_init(sizeof(char *));
      char ipstr[128];

      uint32_t min_ttl = DEFAULT_TTL;
      for (int i = 0; i < response.answer->length; ++i) {
        struct AnswerDnsDatagram *ans = &array_index(response.answer, i, struct AnswerDnsDatagram);
        if (ans->ttl < min_ttl) {
          min_ttl = ans->ttl;
        }
      }

      if (min_ttl < 10) min_ttl = 10;

      for (int i = 0; i < response.answer->length; ++i) {
        struct AnswerDnsDatagram *ans = &array_index(response.answer, i, struct AnswerDnsDatagram);
        inet_ntop(AF_INET, (char *)&ans->address, ipstr, INET_ADDRSTRLEN);
        char *val = strdup(ipstr);
        array_append(answers, &val);
      }
      cache_node_t *cachenode = cache_node_init_with_ttl(strdup(response.query.name), answers, min_ttl);
      pthread_mutex_lock(&mutex_dc);
      cache_insert(dns_cache, cachenode);
      pthread_mutex_unlock(&mutex_dc);

      if (debug_level > 0) {
        printf("[Debug] receive buffer from pass_sock successfully\n");
      }
      back_len = recv_len;
    }
  }

// The maximum safe size for a UDP DNS packet
#define MAX_DNS_UDP_SIZE 512

  pthread_mutex_lock(&mutex_relay_sock);
  // Check if the response is too large for standard UDP
  if (back_len > MAX_DNS_UDP_SIZE) {
    // Set truncation flag to indicate client should retry with TCP
    struct HeaderDnsDatagram truncated_header;
    memcpy(&truncated_header, buffer, sizeof(struct HeaderDnsDatagram));
    truncated_header.flags.QR = QR_RESPONSE;
    truncated_header.flags.TC = 1;  // Set truncation flag

    // Create truncated response with just the header and query
    uint8_t truncated_buffer[MAX_DNS_UDP_SIZE];
    memset(truncated_buffer, 0, MAX_DNS_UDP_SIZE);
    memcpy(truncated_buffer, buffer, recv_len < MAX_DNS_UDP_SIZE ? recv_len : MAX_DNS_UDP_SIZE);
    put_header(&truncated_header, truncated_buffer);

    // Send truncated response (just header + query)
    send_len = sendto(relay_sock, truncated_buffer, 12 + strlen((char *)(buffer + 12)) + 5, 0, (struct sockaddr *)client_addr,
                      sizeof(*client_addr));
  } else {
    // Normal sized response - send as is
    send_len = sendto(relay_sock, buffer, back_len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
  }
  pthread_mutex_unlock(&mutex_relay_sock);

  if (send_len < 0) {
    if (errno == EMSGSIZE) {
      // If we still get message too large error despite our checks,
      // send a minimal response with truncation flag
      struct HeaderDnsDatagram minimal_header;
      memset(&minimal_header, 0, sizeof(minimal_header));
      minimal_header.id = header.id;
      minimal_header.flags.QR = QR_RESPONSE;
      minimal_header.flags.TC = 1;  // Set truncation flag
      minimal_header.QDCOUNT = 1;   // Keep the original query count

      uint8_t minimal_buffer[12];  // Just the header
      memset(minimal_buffer, 0, sizeof(minimal_buffer));
      put_header(&minimal_header, minimal_buffer);

      pthread_mutex_lock(&mutex_relay_sock);
      sendto(relay_sock, minimal_buffer, sizeof(minimal_buffer), 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
      pthread_mutex_unlock(&mutex_relay_sock);
      if (debug_level > 0) {
        printf("[Debug] Sent minimal truncated response due to message size limitations\n");
      }
    } else {
      perror("sendto relay_sock failed");
    }
    goto cleanup;
  }

  if (debug_level > 0) {
    printf("[Debug] send to relay_sock successfully\n");
  }

cleanup:
  if (pass_sock > 0) {
    close(pass_sock);
  }

  if (response_initialized) {
    array_free(response.answer);
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