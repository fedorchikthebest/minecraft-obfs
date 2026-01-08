#include "callbacks.h"
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <ev.h>
#include <stddef.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <netdb.h>

#define CONTINUE_BIT 0x80
#define SEGMENT_BITS 0x7F
#define READER_BUFFER_SIZE 2048
#define AUTH_BUFFER_SIZE 512
#define VERIFY_BEGIN 12
#define PROXY_BUFFER_SIZE 4096
#define CIPHER EVP_aes_256_cfb()

static ev_io serv;
static size_t size;

static unsigned char key[32];
static unsigned char iv[16];

typedef struct {
  EVP_CIPHER_CTX *ctx;
  ev_io *vports[256];
} proxy_client;

typedef struct {
  int size;
  char type;
  unsigned char data[PROXY_BUFFER_SIZE - 4 - 1];  
}  client_request_base;

int get_packet_id(unsigned char *buf) {
  int id = 0, position = 0, pos = 0;
  char byte;
  
  while (buf[pos] & CONTINUE_BIT) {
    if (pos >= 4)
      return -1;
	pos++;
  }
  pos++;
  for (;;) {
    byte = buf[pos++];
    id |= (byte & SEGMENT_BITS) << position;
    if ((byte & CONTINUE_BIT) == 0)
      break;

    position += 7;

    if (position >= 32)
      return -1;    
  }
  return id;
}

static void minecraft_readdr(EV_P_ ev_io *w, int revents){
  static char buf[READER_BUFFER_SIZE];
  ev_io *reciver = w->data;
  static size_t size;
  size = recv(w->fd, buf, READER_BUFFER_SIZE, 0);
  if (size <= 0) {
    close(reciver->fd);
	ev_io_stop(loop, reciver);
	free(reciver);
    ev_io_stop(loop, w);
    free(w);
    return;    
  }
  send(reciver->fd, buf, size, 0);
}

static void socks_proxy(EV_P_ ev_io *w, int revents) {
  static client_request_base req;
  proxy_client *client = w->data;

  size = recv(w->fd, &req, PROXY_BUFFER_SIZE, 0);

  if (size <= 0) {
    EVP_CIPHER_CTX_cleanup(client->ctx);
    for (int i = 0; i < 256; i++) {
      ev_io_stop(loop, client->vports[i]);
	  free(client->vports[i]);
    }
    ev_io_stop(loop, w);
    free(client);
	free(w);
  }    
  
  if (req.size > size || req.size <= 0 || req.size > PROXY_BUFFER_SIZE) {
    return;
  }

  switch (req.type) {
  case 0:
	  
  }    
}  

static void minecraft_proxy_client(EV_P_ ev_io *w, int revents) {
  EVP_CIPHER_CTX *ctx;  
  unsigned char buf[AUTH_BUFFER_SIZE] = {0}, verify_key[16];
  int pos;
  ev_io *reciver = w->data;
  proxy_client *pc;
  
  size = recv(w->fd, buf, AUTH_BUFFER_SIZE, 0);
  if (size <= 0) {
    close(reciver->fd);
	ev_io_stop(loop, reciver);
	free(reciver);
    ev_io_stop(loop, w);
	free(w);
    return;
  }
  send(reciver->fd, buf, size, 0);
  if (get_packet_id(buf) == 1) {
    printf("ENCRYPTION! %ld\n", size);
	ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, CIPHER, key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
    ev_io_stop(loop, w);

    if (EVP_DecryptUpdate(ctx, verify_key, &pos, &buf[VERIFY_BEGIN], 16) &&
        memcmp("fuck-RKNfuck-RKN", verify_key, 16) == 0) {
      ev_io_stop(loop, reciver);
      close(reciver->fd);
	  free(reciver);
      pc = calloc(1, sizeof(proxy_client));
	  pc->ctx = ctx;
      w->data = pc;
      ev_io_init(w, socks_proxy, w->fd, EV_READ);
    } else {
      ev_io_init(w,  minecraft_readdr, w->fd, EV_READ);
	  EVP_CIPHER_CTX_cleanup(ctx);
	}          
    ev_io_start(loop, w);
  }  
}

static void on_accept(EV_P_ ev_io *w, int revents) {
  struct sockaddr_in client_address;
  struct sockaddr_in addr;
  int client_fd, minecraft_fd;

  minecraft_fd = socket(AF_INET, SOCK_STREAM, 0);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(25565);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (connect(minecraft_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("FATAL: cant connect to minecraft server\n");
	exit(1);
  }    
  
  socklen_t client_len = sizeof(client_address);
  client_fd = accept(w->fd, (struct sockaddr *)&client_address, &client_len);
  
  ev_io *minecraft_watcher_client = malloc(sizeof(ev_io));
  ev_io *minecraft_watcher_server = malloc(sizeof(ev_io));

  minecraft_watcher_client->data = minecraft_watcher_server;
  minecraft_watcher_server->data = minecraft_watcher_client;

  ev_io_init(minecraft_watcher_client, minecraft_proxy_client, client_fd,
             EV_READ);
  ev_io_init(minecraft_watcher_server, minecraft_readdr, minecraft_fd,
             EV_READ);
  
  ev_io_start(loop, minecraft_watcher_client);
  ev_io_start(loop, minecraft_watcher_server);
}  

int run_server(unsigned short int port) {
  int server_fd;
  struct sockaddr_in address;
  FILE *fp = fopen("key", "rb");
  if (fp == NULL) {
    perror("FATAL: cant load key file\n");
	exit(1);
  }
  fread(key, 1, 32, fp);
  fread(iv, 1, 16, fp);
  fclose(fp);
  
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("FATAL: cant bind\n");
	exit(1);
  }    
  listen(server_fd, 5);
  
  struct ev_loop *loop = EV_DEFAULT;
  ev_io_init(&serv, on_accept, server_fd, EV_READ);
  ev_io_start(loop, &serv);
  ev_run(loop, 0);
  return 0;
}  
