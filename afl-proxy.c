/*
   american fuzzy lop++ - afl-proxy skeleton example
   ---------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0


   HOW-TO
   ======

   You only need to change the while() loop of the main() to send the
   data of buf[] with length len to the target and write the coverage
   information to __afl_area_ptr[__afl_map_size]


*/

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include <arpa/inet.h>
#include <assert.h>
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include "json-c/json.h"
#include <netdb.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "types.h"
#include <unistd.h>

u8 *__afl_area_ptr;

#ifdef __ANDROID__
u32 __afl_map_size = MAP_SIZE;
#else
__thread u32 __afl_map_size = MAP_SIZE;
#endif

#define BUFF_LEN 1024
#define BITMAP_RCV_PORT 5001

// Variables used by tcp socket that recieves bitmap
struct sockaddr_in sockaddr_bitmap;
int                listenfd_bitmap = 0, connfd_bitmap = 0;
unsigned char      rcvBuffer_bitmap[BUFF_LEN];
unsigned char      bitmap[MAP_SIZE];

// initialized tcp socket to listen and later recieve bitmap from qemu
void init_bitmap_socket() {
  int n = 0;

  listenfd_bitmap = socket(AF_INET, SOCK_STREAM, 0);
  memset(&sockaddr_bitmap, '0', sizeof(sockaddr_bitmap));
  memset(rcvBuffer_bitmap, '0', sizeof(rcvBuffer_bitmap));
  memset(bitmap, '0', sizeof(bitmap));

  sockaddr_bitmap.sin_family = AF_INET;
  sockaddr_bitmap.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr_bitmap.sin_port = htons(BITMAP_RCV_PORT);

  bind(listenfd_bitmap, (struct sockaddr *)&sockaddr_bitmap,
       sizeof(sockaddr_bitmap));

  listen(listenfd_bitmap, 10);
}

// accept connection on port and read whole bitmap
void accept_bitmap() {
  int n = 0;
  printf("Waiting to accept connection for bitmap!\n");
  connfd_bitmap = accept(listenfd_bitmap, (struct sockaddr *)NULL, NULL);

  int cnt = 0;

  while (1) {
    if ((n = read(connfd_bitmap, rcvBuffer_bitmap, sizeof(rcvBuffer_bitmap))) >
        0) {
      for (int j = 0; j < n; j++) {
        bitmap[cnt * BUFF_LEN + j] = rcvBuffer_bitmap[j];
      }
      cnt++;
      if (cnt == MAP_SIZE / BUFF_LEN) break;
    } else {
      printf("Waiting for bitmap!\n");
    }
  }
  printf("Received bitmap, closing connection!\n");
  close(connfd_bitmap);
}

// variables that will be used to send qmp commands over tcp socket
int                qmp_socket_fd = 0;
char               recvBuff_qmp[1024];
struct sockaddr_in sockaddr_qmp;
char               save_bb_enter_json_string[1024];
char               start_bb_enter_json_string[1024];

// send qmp capabilities and prepare json strings
void init_qmp_communication() {
  int n = 0;
  memset(recvBuff_qmp, '0', sizeof(recvBuff_qmp));
  memset(&sockaddr_qmp, '0', sizeof(sockaddr_qmp));

  if ((qmp_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Error : Could not create socket \n");
  }

  sockaddr_qmp.sin_family = AF_INET;
  sockaddr_qmp.sin_port = htons(4444);

  if (inet_pton(AF_INET, "127.0.0.1", &sockaddr_qmp.sin_addr) <= 0) {
    printf("\n inet_pton error occured\n");
  }

  if (connect(qmp_socket_fd, (struct sockaddr *)&sockaddr_qmp,
              sizeof(sockaddr_qmp)) < 0) {
    printf("\n Error : Connect Failed \n");
  }

  // Send HMP command qmp_capabilities
  // this command needs to be sent just once
  json_object *jobj = json_object_new_object();
  char         qmp_cap[] = "qmp_capabilities";
  char         tmp_buff[1024];
  json_object_object_add(jobj, "execute", json_object_new_string(qmp_cap));
  if (strcpy(tmp_buff, json_object_to_json_string(jobj)) == NULL) {
    printf("Strcpy error");
  }
  if (write(qmp_socket_fd, tmp_buff, strlen(tmp_buff)) == -1) {
    printf("Error while writing json.");
  }

  if ((n = read(qmp_socket_fd, recvBuff_qmp, sizeof(recvBuff_qmp) - 1)) > 0) {
    printf("Response after sending QMP_CAPABILITES: \n");
    recvBuff_qmp[n] = 0;
    if (fputs(recvBuff_qmp, stdout) == EOF) {
      printf("\n Error : Fputs error\n");
    }
  }

  // Prepare QMP command save_bb_enter
  json_object *jobj2 = json_object_new_object();
  char         qmp_save_bb_enter[] = "save-bb-enter";
  printf("Json command add object!\n");
  json_object_object_add(jobj2, "execute",
                         json_object_new_string(qmp_save_bb_enter));

  if (strcpy(save_bb_enter_json_string, json_object_to_json_string(jobj2)) ==
      NULL) {
    printf("Strcpy error");
  }

  // Prepare QMP command start_bb_enter
  json_object *jobj1 = json_object_new_object();
  char         qmp_start_bb_enter[] = "start-bb-enter";
  json_object_object_add(jobj1, "execute",
                         json_object_new_string(qmp_start_bb_enter));
  if (strcpy(start_bb_enter_json_string, json_object_to_json_string(jobj1)) ==
      NULL) {
    printf("Strcpy error");
  }
}

// We send command to start recoding bitmap to QEMU
int start_qmp_command() {
  int n = 0;

  if (n < 0) { printf("\n Read error \n"); }

  if (write(qmp_socket_fd, start_bb_enter_json_string,
            strlen(start_bb_enter_json_string)) == -1) {
    printf("Error while writing json.");
  }

  if ((n = read(qmp_socket_fd, recvBuff_qmp, sizeof(recvBuff_qmp) - 1)) > 0) {
    printf("Response after sending START-BB-ENTER: ");
    recvBuff_qmp[n] = 0;
    if (fputs(recvBuff_qmp, stdout) == EOF) {
      printf("\n Error : Fputs error\n");
    }
  }
  return 0;
}

// We send command to save bitmap, send it and clear stuff to QEMU
void save_hmp_command() {
  int n = 0;

  if (write(qmp_socket_fd, save_bb_enter_json_string,
            strlen(save_bb_enter_json_string)) == -1) {
    printf("Error while writing json.");
  }

  if ((n = read(qmp_socket_fd, recvBuff_qmp, sizeof(recvBuff_qmp) - 1)) > 0) {
    printf("Response after sending SAVE-BB-ENTER: ");
    recvBuff_qmp[n] = 0;
    if (fputs(recvBuff_qmp, stdout) == EOF) {
      printf("\n Error : Fputs error\n");
    }
  }
}

// Variables needed for bind shell which will be used to send commands to guest
int                sockfd_bind_shell = 0;
struct sockaddr_in serv_addr_bind_shell;

int init_bind_shell_connection() {
  if ((sockfd_bind_shell = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Error : Could not create socket \n");
    return 1;
  }

  memset(&serv_addr_bind_shell, '0', sizeof(serv_addr_bind_shell));

  serv_addr_bind_shell.sin_family = AF_INET;
  serv_addr_bind_shell.sin_port = htons(1080);

  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr_bind_shell.sin_addr) <= 0) {
    printf("\n inet_pton error occured\n");
    return 1;
  }

  if (connect(sockfd_bind_shell, (struct sockaddr *)&serv_addr_bind_shell,
              sizeof(serv_addr_bind_shell)) < 0) {
    printf("\n Error : Connect Failed (Bind shell connection) \n");
    return 1;
  }

  return 0;
}

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {
  u32 status;
//  if (!error || error > 0xffff) {
//    printf("Prvi return errrora");
//    return;
//  }
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) {
    printf("Drugi return errora");
    return;
  }
}

/* SHM setup. */

static void __afl_map_shm(void) {
  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  /* NOTE TODO BUG FIXME: if you want to supply a variable sized map then
     uncomment the following: */

  /*
  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    u32 val = atoi(ptr);
    if (val > 0) __afl_map_size = val;

  }

  */

  if (__afl_map_size > MAP_SIZE) {
    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {
      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {
        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);
      }

    } else {
      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
    }
  }

  if (id_str) {
#ifdef USEMMAP
    const char *   shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {
      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);
    }

    /* map the shared memory segment to the address space of the process */
    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shm_base == MAP_FAILED) {
      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);
    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, 0, 0);

#endif

    if (__afl_area_ptr == (void *)-1) {
      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);
    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;
  }
}

/* Fork server logic. */

static void __afl_start_forkserver(void) {
  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;
}

static u32 __afl_next_testcase(u8 *buf, u32 max_len) {
  s32 status, res = 0xffffff;

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &status, 4) != 4) return 0;

  /* we have a testcase - read it */
  status = read(0, buf, max_len);

  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &res, 4) != 4) return 0;

  return status;
}

static void __afl_end_testcase(int status) {
//  int status = 0xffffff;
//
//  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);
//
  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);
}

enum afl_child_ret {

  // Persistent
  AFL_CHILD_NEXT,
  // Crash discovered but still alive in persistent mode
  AFL_CHILD_FOUND_CRASH,
  // Read again, one afl_tsl struct.
  AFL_CHILD_TSL_REQUEST,
  // Child no longer there. Read status code.
  AFL_CHILD_EXITED,

};

/* you just need to modify the while() loop in this main() */

int main(int argc, char *argv[]) {
  /* This is were the testcase data is written into */
  u8  buf[1024];  // this is the maximum size for a test case! set it!
  s32 len;
  int cnt = 0;
  init_qmp_communication();

  init_bitmap_socket();

  /* here you specify the map size you need that you are reporting to
     afl-fuzz.  Any value is fine as long as it can be divided by 32. */
  __afl_map_size = MAP_SIZE;  // default is 65536

  /* then we initialize the shared memory map and start the forkserver */
  __afl_map_shm();
  __afl_start_forkserver();

  //  char *command = "\"| ./test1";
  //  char *echoRead = "echo \"";
  //  char *end_command = " ; echo \"\\n$?\" ; echo done1234\n";
  //  char *endCommand = "done1234";
  char sendBuffer[BUFF_LEN];
  printf("Start testcases");
  init_bind_shell_connection();
  int     status;
  char    rcvBuff[BUFF_LEN];
  clock_t begin;
  enum afl_child_ret msg = AFL_CHILD_FOUND_CRASH;
  while ((len = __afl_next_testcase(buf, sizeof(buf))) > 0) {
    if (len > 1 && buf[0] != 0) {
      buf[len] = '\0';
      printf("Start testcase: %d\n", cnt++);

      /* here you have to create the magic that feeds the buf/len to the
         target and write the coverage to __afl_area_ptr */

      // ... the magic ...

      // first we send command to QEMU to start recording
      start_qmp_command();
      printf("Start qmp\n");
      //    memset(sendBuffer, 0, BUFF_LEN);
      //    //      strcat(sendBuffer, echoRead);
      //    //      buf[strcspn(buf, "\n")] = 0;
      //    strcat(sendBuffer, buf);
      //    //      strcat(sendBuffer, command);
      //
      //    //      strcat(sendBuffer, end_command);
      // buf[0] = 0xff;
      printf("===========================\n");
      printf("Len: %d: [%d, %d, %d, %d, %d...]\n", len, buf[0], buf[1], buf[2],
             buf[3], buf[4]);
      printf("%s", buf);
      printf("===========================\n");

      //    // send command to bind shell
      size_t write_result = write(sockfd_bind_shell, buf, strlen(buf));
      printf("Sent command\n");
      int n;
      memset(rcvBuff, 0, BUFF_LEN);
      begin = clock();
      while (1) {
        if ((n = read(sockfd_bind_shell, rcvBuff, sizeof(rcvBuff))) > 0) {
          break;
        }
        if (((double)(clock() - begin) / CLOCKS_PER_SEC) > 0.5) {
          printf("Timeout, send again!");
          begin = clock();
          size_t write_result = write(sockfd_bind_shell, buf, strlen(buf));
        }
      }
      ////    close(sockfd_bind_shell);
      status = atoi(rcvBuff);
      ////    status = 0;
      printf("Status is: %d\n", status);

      save_hmp_command();

      accept_bitmap();

      strncpy(__afl_area_ptr, bitmap, MAP_SIZE);
//      if (status != 0) {
//        return 127;
//        send_forkserver_error(2);
//      }
//        printf("Sending status to fork!\n");
//        status = 0x00010000;
//        if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);
//      }
      //    for (int i = 0; i < MAP_SIZE; i++) {
      //      __afl_area_ptr[i] = bitmap[i];
      //    }

      memset(bitmap, '0', sizeof(bitmap));
      memset(buf, '0', sizeof(buf));
    }
    /* report the test case is done and wait for the next */
    if (status != 0) {
      __afl_end_testcase(137);
    } else {
      __afl_end_testcase(0);
    }
  }

  return 0;
}
