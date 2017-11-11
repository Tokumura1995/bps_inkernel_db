#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PUT 0
#define GET 1
#define DEL 2
#define STR 3

int main(int argc, char ** argv)
{
  int sd;
  struct sockaddr_in addr;

  struct pkt_data {
    int type;
    int key;
    int value;
  };

  struct pkt_data pkt;
  struct pkt_data recv_pkt;

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  char ser_addr[32];
  printf("IP addr::");
  scanf("%s", ser_addr);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(22222);
  addr.sin_addr.s_addr = inet_addr(ser_addr);

  while (1) {
    char  p_type[8];

    printf(">>>");
    scanf("%s", p_type);

    if (strcmp(p_type, "put") == 0 || strcmp(p_type, "PUT") == 0) {
      pkt.type = PUT;
      printf("key>>");
      scanf("%d", &pkt.key);
      printf("value>>");
      scanf("%d", &pkt.value);
    } else if (strcmp(p_type, "get") == 0 || strcmp(p_type, "GET") == 0) {
      pkt.type = GET;
      printf("key>>");
      scanf("%d", &pkt.key);
      pkt.value = 0;
    } else if (strcmp(p_type, "del") == 0 || strcmp(p_type, "DEL") == 0) {
      pkt.type = DEL;
      printf("key>>");
      scanf("%d", &pkt.key);
      pkt.value = 0;
    } else if (strcmp(p_type, "exit") == 0) {
      break;
    } else if (strcmp(p_type, "start") == 0) {
      pkt.type = STR;
      printf("start\n");
      pkt.value = 0;
    }  else {
      printf("no such key\n");
      continue;
    }
    
    if (sendto(sd, &pkt, sizeof(struct pkt_data), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
      perror("send");
      return -1;
    }

    if (pkt.type == GET) {
      if (recvfrom(sd, &recv_pkt, sizeof(struct pkt_data), 0, NULL, NULL) < 0) {
	perror("recv");
	return -1;
      }

      printf("value = %d\n", recv_pkt.value);
    }
    
    if (strcmp("exit", p_type) == 0) {
      break;
    }
  }

  close(sd);

  return 0;
}
