#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "libbpf.h"


int main(int argc, char ** argv)
{
  int sd;
  struct sockaddr_in addr;
  
  struct pkt_data {
    int type;
    int key;
    int value;
  };
  
  socklen_t sin_size;
  struct sockaddr_in from_addr;
  struct pkt_data pkt;

  int db_map_fd;
  int map_fd2, prog_fd;
  int key;
  int value;
  FILE * fp;
  int ret;

  if ((db_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), 256)) < 0) {
    perror("bpf_create_map");
    return -1;
  }

  if ((map_fd2 = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(pkt.key), 4)) < 0) {
    perror("bpf_create_map");
    return -1;
  }
   
  struct bpf_insn prog[] = {
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
    BPF_LD_ABS(BPF_B, 8),

    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 1, 14),

    BPF_LD_ABS(BPF_B, 12),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_2),
    BPF_LD_MAP_FD(BPF_REG_1, db_map_fd),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_send),
    
    /*
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    BPF_LD_ABS(BPF_B, 12),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
z    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
    BPF_LD_MAP_FD(BPF_REG_1, map_fd2),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),

    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
    BPF_LD_MAP_FD(BPF_REG_1, map_fd),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
    */
    
    BPF_EXIT_INSN(),
  };
    

  if ((prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog), "GPL", 4)) < 0) {
    printf("bpf_prog_load() err=%d\n%s", errno, bpf_log_buf);
    return -1;	
  } 
  
  if ((fp = fopen("./db_data", "r")) == NULL) {
    perror("fopen");
    return -1;
  }

  while((ret = fscanf(fp, "%d%d", &key, &value)) != EOF) {
    if (bpf_update_elem(db_map_fd, &key, &value, 0) < 0) {
      perror("bpf_update_elem");
      return -1;
    }
  }

  fclose(fp);
    
  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(22222);
  addr.sin_addr.s_addr = INADDR_ANY;
  sin_size = sizeof(from_addr);
  memset(&pkt, 0, sizeof(pkt));
  
  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return -1;
  }
  

  int flag = 0;
  /*while (flag != 3) {
    if(recvfrom(sd, &pkt, sizeof(struct pkt_data), 0, (struct sockaddr *)&from_addr, &sin_size) < 0) {
      perror("recvfrom");
      return -1;
    }
    printf("recv\n");
    flag = pkt.type;
    if (sendto(sd, &pkt, sizeof(struct pkt_data), 0, (struct sockaddr *)&from_addr, sin_size) < 0 ) {
      perror("send");
      return -1;
    }
    
  }
  printf("start!\n");
  */
  if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
    perror("setsockeopt");
    return -1;
  }
  printf("success\n");

  while(1)
    {
      sleep(3);
    }

  close(sd);
  close(db_map_fd);
  close(map_fd2);
  return 0;
}
