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

static hash_table_t *local_dns_table;
static cache_table_t *dns_cache;
static int relay_sock;
static struct sockaddr_in relay_addr;
static pthread_mutex_t mutex_ldt;
static pthread_mutex_t mutex_dc;
static pthread_mutex_t mutex_relay_sock;

static void read_record();
static void *serve(void *args);

struct TaskArgs {
  uint8_t *buffer;
  struct sockaddr_in sockaddr;
  ssize_t recv_len;
};

int main() {
  // Increase file descriptor limits
  struct rlimit rl;
  rl.rlim_cur = 4096;  // Soft limit
  rl.rlim_max = 8192;  // Hard limit
  if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
    perror("Failed to increase file descriptor limit");
  }

  local_dns_table = ht_init(NULL, ht_str_comp, 1024, STRING);
  dns_cache = cache_init();
  if (pthread_mutex_init(&mutex_ldt, NULL) < 0) {
    return 1;
  }
  if (pthread_mutex_init(&mutex_dc, NULL) < 0) {
    return 1;
  }
  if (pthread_mutex_init(&mutex_relay_sock, NULL) < 0) {
    return 1;
  }
  read_record();

  threadpool thpool = thpool_init(THREAD_NUM);

  relay_sock = socket(AF_INET, SOCK_DGRAM, 0);
  relay_addr.sin_family = AF_INET;
  relay_addr.sin_addr.s_addr = INADDR_ANY;
  relay_addr.sin_port = htons(RELAY_PORT);

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(relay_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("Error setting socket timeout");
  }

  int rcvbufsize = 8 * 1024 * 1024;  // 8MB receive buffer
  int sndbufsize = 8 * 1024 * 1024;  // 8MB send buffer
  if (setsockopt(relay_sock, SOL_SOCKET, SO_RCVBUF, &rcvbufsize, sizeof(rcvbufsize)) < 0) {
    perror("Error setting receive buffer size");
  }
  if (setsockopt(relay_sock, SOL_SOCKET, SO_SNDBUF, &sndbufsize, sizeof(sndbufsize)) < 0) {
    perror("Error setting send buffer size");
  }

  if (bind(relay_sock, (const struct sockaddr *)&relay_addr, sizeof(relay_addr)) < 0) {
    perror("relay_sock bind failed");
    return -1;
  }

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
      perror("recvfrom relay_sock failed");
      continue;
    }
    args = (struct TaskArgs *)malloc(sizeof(struct TaskArgs));
    args->buffer = (uint8_t *)malloc(BUFFER_SIZE);
    memcpy(args->buffer, buffer, BUFFER_SIZE);
    args->sockaddr = client_addr;
    args->recv_len = recv_len;

    thpool_add_job(thpool, serve, args);
  }
  close(relay_sock);
  pthread_mutex_destroy(&mutex_ldt);
  pthread_mutex_destroy(&mutex_dc);
  pthread_mutex_destroy(&mutex_relay_sock);
  thpool_wait(thpool);
  thpool_destroy(thpool);
  ht_free(local_dns_table);
  cache_free(dns_cache);
  return 0;
}

static void read_record() {
  FILE *table_relay = fopen("../data/dnsrelay.txt", "r");
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
#ifdef DEBUG
  printf("load dnsrelay.txt into memory successfully\n");
#endif
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

  // Error handling flag
  bool need_cleanup = false;

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
    need_cleanup = true;
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

  struct RequestDnsDatagram request;
  parse_dns_query_name(request.query.name, (char *)(buffer + 12));
#ifdef DEBUG
  printf("[Debug] parse_dns_query_name successfully: %s\n", request.query.name);
#endif
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
#ifdef DEBUG
    printf("[Debug] ipArr != NULL\n");
#endif
    header.flags.QR = QR_RESPONSE;

    for (int i = 0; i < ipArr->length; i++) {
      ++header.ANCOUNT;
      char *ip = array_index(ipArr, i, char *);
#ifdef DEBUG
      printf("[Debug] ip: %s\n", ip);
#endif
      if (!strcmp(ip, BLACK_IP)) {
        header.flags.RCODE = FLAGS_BAN;
        inet_pton(AF_INET, BLACK_IP, &answer.address);
        break;
      } else {
        inet_pton(AF_INET, ip, &answer.address);
        array_append(response.answer, &answer);
      }
    }
#ifdef DEBUG
    printf("[Debug] before put_header\n");
#endif
    put_header(&header, buffer);
    put_answers(response.answer, buffer + recv_len);
#ifdef DEBUG
    printf("[Debug] put_answer successfully\n");
#endif
    back_len = recv_len + sizeof(struct AnswerDnsDatagram) * header.ANCOUNT;
  } else {
#ifdef DEBUG
    printf("[Debug] ipArr = NULL\n");
#endif
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
#ifdef DEBUG
      printf("[Debug] send to pass_sock successfully\n");
#endif
      recv_len = recvfrom(pass_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
      if (recv_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
#ifdef DEBUG
          printf("[Debug] External DNS timeout - retry %d of %d\n", retry_count + 1, max_retries);
#endif
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

#ifdef DEBUG
      printf("[Debug] receive buffer from pass_sock successfully\n");
#endif
      back_len = recv_len;
    }
  }

#ifdef DEBUG
  printf("[Debug] before send info back to relay_sock\n");
#endif

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
#ifdef DEBUG
      printf("[Debug] Sent minimal truncated response due to message size limitations\n");
#endif
    } else {
      perror("sendto relay_sock failed");
    }
    need_cleanup = true;
    goto cleanup;
  }

#ifdef DEBUG
  printf("[Debug] send to relay_sock successfully\n");
#endif

cleanup:
  // Always close the socket if it was created, regardless of the need_cleanup flag
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