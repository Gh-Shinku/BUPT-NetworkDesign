#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns.h"
#include "thpool.h"

#define THREAD_NUM 32
// #define DEBUG_MODE

static GHashTable *table_dns;
static int relay_sock;
static struct sockaddr_in relay_addr;

static void print_key_value(gpointer key, gpointer value, gpointer data);
static void destroy_key_value(gpointer key, gpointer value, gpointer data);
static void read_record();
static void serve(void *args);

struct TaskArgs
{
  uint8_t *buffer;
  struct sockaddr_in sockaddr;
  ssize_t recv_len;
};

int main()
{
  table_dns = g_hash_table_new(g_str_hash, g_str_equal);
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
    memset(buffer, 0, BUFFER_SIZE);
    client_addr_len = sizeof(client_addr);
    ssize_t recv_len = recvfrom(relay_sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr,
                                &client_addr_len);
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
  g_hash_table_foreach(table_dns, destroy_key_value, NULL);
  g_hash_table_destroy(table_dns);
  return 0;
}

static void print_key_value(gpointer key, gpointer value, gpointer data)
{
  gchar *key_str = (gchar *)key;
  printf("Key: %s, Value: %s\n", key_str, (char *)value);
}

static void destroy_key_value(gpointer key, gpointer value, gpointer data)
{
  g_free(key);
  g_array_free(value, TRUE);
}

static void read_record()
{
  FILE *table_relay = fopen("../data/dnsrelay.txt", "r");
  char buf_ip[128], buf_domain[128];
  while (fscanf(table_relay, "%s", buf_ip) != EOF) {
    if (fscanf(table_relay, "%s", buf_domain) == EOF) {
      fprintf(stderr, "Error occured when reading dnsrelay.txt");
      fclose(table_relay);
      return;
    }
    gchar *key = g_strdup(buf_domain);
    gchar *value = g_strdup(buf_ip);
    GArray *valueArr = g_hash_table_lookup(table_dns, key);
    if (valueArr == NULL) {
      valueArr = g_array_new(FALSE, FALSE, sizeof(char *));
      g_array_append_val(valueArr, value);
      g_hash_table_insert(table_dns, (gpointer)key, (gpointer)valueArr);
    } else {
      g_array_append_val(valueArr, value);
    }
  }
  fclose(table_relay);
#ifdef DEBUG_MODE
  printf("load dnsrelay.txt into memory successfully\n");
#endif
}

static void serve(void *args)
{
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
  response.answer = g_array_new(FALSE, FALSE, sizeof(struct AnswerDnsDatagram));

  char *buf_ptr = (char *)(buffer + 12);
  parse_dns_query_name(buf_ptr, request.query.name);
#ifdef DEBUG_MODE
  printf("parse_dns_query_name successfully: %s\n", request.query.name);
#endif
  GArray *ipArr = g_hash_table_lookup(table_dns, request.query.name);

  if (ipArr != NULL) {
    header.flags.QR = QR_RESPONSE;

    for (int i = 0; i < ipArr->len; i++) {
      header.ANCOUNT++;
      char *ip = g_array_index(ipArr, char *, i);
      if (!strcmp(ip, BLACK_IP)) {
        header.flags.RCODE = FLAGS_BAN;
        inet_pton(AF_INET, BLACK_IP, &answer.address);
        break;
      } else {
        inet_pton(AF_INET, ip, &answer.address);
        g_array_append_val(response.answer, answer);
      }
    }

    // printHeader(&header);
    put_header(&header, buffer);
    put_answers(response.answer, buffer + recv_len);
#ifdef DEBUG_MODE
    printf("put_answer successfully\n");
#endif
    back_len = recv_len + sizeof(struct AnswerDnsDatagram) * header.ANCOUNT;
  } else {
    send_len =
        sendto(pass_sock, buffer, recv_len, 0, (struct sockaddr *)&pass_addr, sizeof(pass_addr));
    if (send_len < 0) {
      perror("sendto pass_sock failed");
      return;
    }
#ifdef DEBUG_MODE
    printf("send to pass_sock successfully\n");
#endif
    recv_len = recvfrom(pass_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
      perror("recvfrom pass_sock failed");
      return;
    }
    // cache into table_dns
    parse_dns_response(&response, buffer);
    GArray *answers = g_array_new(FALSE, FALSE, sizeof(char *));
    char ipstr[128];
    for (int i = 0; i < response.answer->len; i++) {
      struct AnswerDnsDatagram *ans = &g_array_index(response.answer, struct AnswerDnsDatagram, i);
      inet_ntop(AF_INET, (char *)&ans->address, ipstr, INET_ADDRSTRLEN);
      char *val = g_strdup(ipstr);
      g_array_append_val(answers, val);
    }
    g_hash_table_insert(table_dns, g_strdup(response.query.name), answers);

#ifdef DEBUG_MODE
    printf("receive buffer from pass_sock successfully\n");
#endif
    back_len = recv_len;
  }

#ifdef DEBUG_MODE
  printf("before send info back to relay_sock\n");
#endif
  send_len =
      sendto(relay_sock, buffer, back_len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
  if (send_len < 0) {
    perror("sendto relay_sock failed");
    return;
  }
#ifdef DEBUG_MODE
  printf("send to relay_sock successfully\n");
#endif

  free(taskargs->buffer);
  free(taskargs);
  g_array_free(response.answer, TRUE);
  close(pass_sock);
}