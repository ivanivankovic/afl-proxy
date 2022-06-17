#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#define PORT 1081

int main(void) {
  int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

  listen(listen_sock, 10);
  int  conn_sock;
  char rcvBuff[1024];
  while (1) {
    memset(rcvBuff, 0, 1024);
    conn_sock = accept(listen_sock, NULL, NULL);
    int n;
    if ((n = read(conn_sock, rcvBuff, sizeof(rcvBuff))) > 0) {
      int statval;
      if (fork() == 0) {
        execl("./test1", "./test1", rcvBuff);
      } else {
        wait(&statval);
        if (WIFEXITED(statval))
            write(conn_sock, "1", strlen("1"));
        else
            write(conn_sock, "0", strlen("0"));
      }
    }

    close(conn_sock);
  }
}