#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cache.h"
#include "dns.h"
#include "hashtable.h"
#include "thpool.h"

#define THREAD_NUM 1

static hash_table_t *local_dns_table;
static cache_table_t *dns_cache;
static int relay_sock;
static struct sockaddr_in relay_addr;

static void read_record();
static void serve(void *args);

struct TaskArgs {
  uint8_t *buffer;
  struct sockaddr_in sockaddr;
  ssize_t recv_len;
};

int main() {
  local_dns_table = ht_init(NULL, ht_str_comp, 1024, STRING);
  dns_cache = cache_init();
  read_record();

  threadpool thpool = thpool_init(THREAD_NUM);

  relay_sock = socket(AF_INET, SOCK_DGRAM, 0);
  relay_addr.sin_family = AF_INET;
  relay_addr.sin_addr.s_addr = INADDR_ANY;
  relay_addr.sin_port = htons(RELAY_PORT);
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
      perror("recvfrom relay_sock failed");
      continue;
    }
    args = (struct TaskArgs *)malloc(sizeof(struct TaskArgs));
    args->buffer = (uint8_t *)malloc(BUFFER_SIZE);
    memcpy(args->buffer, buffer, BUFFER_SIZE);
    args->sockaddr = client_addr;
    args->recv_len = recv_len;

    thpool_add_work(thpool, serve, args);
  }
  close(relay_sock);
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

static void serve(void *args) {
  struct TaskArgs *taskargs = (struct TaskArgs *)args;
  uint8_t *buffer = taskargs->buffer;
  struct sockaddr_in *client_addr = &taskargs->sockaddr;

  int pass_sock;
  struct sockaddr_in pass_addr;

  pass_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (pass_sock < 0) {
    perror("pass_sock creation failed");
    return;
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
  struct ResponseDnsDatagram response;
  response.answer = array_init(sizeof(struct AnswerDnsDatagram));

  char *buf_ptr = (char *)(buffer + 12);
  parse_dns_query_name(request.query.name, buf_ptr);
#ifdef DEBUG
  printf("[Debug] parse_dns_query_name successfully: %s\n", request.query.name);
#endif
  ht_node_t *ht_node = ht_lookup(local_dns_table, request.query.name);
  array_t *ipArr = NULL;
  if (ht_node != NULL) {
    ipArr = ((cache_node_t *)ht_node->value)->ip_table;
  } else {
    cache_node_t *cache_node = cache_lookup(dns_cache, request.query.name);
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
    send_len = sendto(pass_sock, buffer, recv_len, 0, (struct sockaddr *)&pass_addr, sizeof(pass_addr));
    if (send_len < 0) {
      perror("sendto pass_sock failed");
      return;
    }
#ifdef DEBUG
    printf("[Debug] send to pass_sock successfully\n");
#endif
    recv_len = recvfrom(pass_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
      perror("recvfrom pass_sock failed");
      return;
    }
    parse_dns_response(&response, buffer);
    array_t *answers = array_init(sizeof(char *));
    char ipstr[128];
    for (int i = 0; i < response.answer->length; ++i) {
      struct AnswerDnsDatagram *ans = &array_index(response.answer, i, struct AnswerDnsDatagram);
      inet_ntop(AF_INET, (char *)&ans->address, ipstr, INET_ADDRSTRLEN);
      char *val = strdup(ipstr);
      array_append(answers, &val);
    }
    cache_node_t *cachenode = cache_node_init(strdup(response.query.name), answers);
    cache_insert(dns_cache, cachenode);

#ifdef DEBUG
    printf("[Debug] receive buffer from pass_sock successfully\n");
#endif
    back_len = recv_len;
  }

#ifdef DEBUG
  printf("[Debug] before send info back to relay_sock\n");
#endif
  send_len = sendto(relay_sock, buffer, back_len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
  if (send_len < 0) {
    perror("sendto relay_sock failed");
    return;
  }
#ifdef DEBUG
  printf("[Debug] send to relay_sock successfully\n");
#endif

  free(taskargs->buffer);
  free(taskargs);
  array_free(response.answer);
  close(pass_sock);
}