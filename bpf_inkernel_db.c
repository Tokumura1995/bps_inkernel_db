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

#define MAP_SIZE 512

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

  int db_map_fd;
  int prog_fd;
  int key;
  int value;
  char c;
  FILE * fp;
  int ret;
 
  if ((db_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), MAP_SIZE)) < 0) {
    perror("bpf_create_map");
    return -1;
  }

  
  struct bpf_insn prog[] = {
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
    BPF_LD_ABS(BPF_B, 8),
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

    /*PUT*/
    BPF_JMP_IMM(BPF_JNE, BPF_REG_9, 0, 14),
    BPF_LD_ABS(BPF_W, 12),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_2),
    BPF_LD_ABS(BPF_W, 16),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_MOV64_IMM(BPF_REG_4, 0),
    BPF_LD_MAP_FD(BPF_REG_1, db_map_fd),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),

    /*GET*/
    BPF_JMP_IMM(BPF_JNE, BPF_REG_9, 1, 15),
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    BPF_LD_ABS(BPF_W, 12),
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

    /*DEL*/
    BPF_JMP_IMM(BPF_JNE, BPF_REG_9, 2, 8),
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    BPF_LD_ABS(BPF_W, 12),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_LD_MAP_FD(BPF_REG_1, db_map_fd),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_delete_elem),      
    
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
  fseek(fp, 0, 0);
  while((ret = fscanf(fp, "%d%c %d", &key, &c, &value)) != EOF && key < MAP_SIZE) {
    //printf("key = %d, value = %d\n",key, value);
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
  memset(&pkt, 0, sizeof(pkt));
  
  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return -1;
  }
  
 
  if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
    perror("setsockeopt");
    return -1;
  }
  printf("success\n");
  
  char  comm[8];
  while(1)
    {
      printf(">>");
      scanf("%s", comm);

      if (strcmp(comm, "disp") == 0 || strcmp(comm, "DISP") == 0) {
	int key1 = 1;
	int value1 = 0;
	while(key1 < MAP_SIZE) {
	  if(bpf_lookup_elem(db_map_fd, &key1, &value1) < 0) {
	    printf("bpf_lookup_elem() err=%d\n", errno);
	    return -1;	
	  }
	  
	  printf("key[%d]::value = %d\n", key1, value1);
	  key1++;
	}
      } else if(strcmp(comm, "exit") == 0) {
	break;
      } else {
	printf("no sush a key\n");
	continue;
      }
    }
    
  close(sd);
  close(db_map_fd);
  return 0;
}
