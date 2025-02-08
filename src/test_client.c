#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "dns.h"

int main()
{
  int send_sock;
  unsigned int send_addr_len;
  struct sockaddr_in send_addr;
  uint8_t buffer[BUFFER_SIZE] = {0};

  printf("Input domain to search the corresponding IP\n");
  send_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (send_sock < 0) {
    perror("send_sock creation failed");
    return -1;
  }

  send_addr.sin_family = AF_INET;
  send_addr.sin_port = htons(RELAY_PORT);
  inet_pton(AF_INET, LOCAL_ADDR, &send_addr.sin_addr);

  struct RequestDnsDatagram request;
  struct ResponseDnsDatagram response;
  init_request(&request);

  int req_len, send_len, recv_len;
  char domain[128] = {0}, ipstr[INET_ADDRSTRLEN];
  while (1) {
    printf("> ");
    scanf("%s", domain);
    strcpy(request.query.name, domain);

    req_len = put_request(&request, buffer);
    send_len =
        sendto(send_sock, buffer, req_len, 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
    if (send_len < 0) {
      perror("send_sock send failed");
      continue;
    }
    printf("send to send_sock successfully\n");

    recv_len = recvfrom(send_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
      perror("send_sock receive failed");
      continue;
    }
    printf("receive from send_sock successfully\n");

    // 解析response，输出相关信息
    parse_dns_response(&response, buffer);
    printf("parse_dns_response successfully\n");
    // printHeader(&response.header);
    if (response.header.flags.RCODE == FLAGS_BAN) {
      printf("域名不存在\n");
    } else {
      for (int i = 0; i < response.answer->len; i++) {
        struct AnswerDnsDatagram ans = g_array_index(response.answer, struct AnswerDnsDatagram, i);
        printf(
            "Name: %s\n"
            "Address: %s\n",
            response.query.name, inet_ntop(AF_INET, (char *)&ans.address, ipstr, INET_ADDRSTRLEN));
      }
    }

    g_array_free(response.answer, TRUE);
    memset(buffer, 0, BUFFER_SIZE);
  }
  return 0;
}
