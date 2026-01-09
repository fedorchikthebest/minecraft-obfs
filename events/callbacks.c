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
#include <arpa/inet.h>

#define CONTINUE_BIT 0x80
#define SEGMENT_BITS 0x7F
#define READER_BUFFER_SIZE 2048
#define AUTH_BUFFER_SIZE 512
#define VERIFY_BEGIN 12
#define CIPHER EVP_aes_256_cfb()

static ev_io serv;
static size_t size;
unsigned int proxy_addr_size, minecraft_addr_size;
static struct sockaddr *proxy_addr, *minecraft_addr;
static struct sockaddr_in proxy_addr4, minecraft_addr4;
static struct sockaddr_in6 proxy_addr6, minecraft_addr6;

static unsigned char key[32];
static unsigned char iv[16];

typedef struct {
  EVP_CIPHER_CTX *ctx;
  ev_io *vports[256];
} proxy_client;


void fill_minecraft_addr(int af, char *addr, unsigned short int port) {
  if (af == AF_INET && inet_pton(af, addr, &minecraft_addr4.sin_addr) > 0) {
    minecraft_addr4.sin_family = AF_INET;
    minecraft_addr4.sin_port = htons(port);
	minecraft_addr_size = sizeof(struct sockaddr_in);
    minecraft_addr = (struct sockaddr*) &minecraft_addr4;
    return;
  }
  if (af == AF_INET6 && inet_pton(af, addr, &minecraft_addr6.sin6_addr) > 0) {
    minecraft_addr6.sin6_family = AF_INET6;
    minecraft_addr6.sin6_port = htons(port);
	minecraft_addr_size = sizeof(struct sockaddr_in6);
    minecraft_addr = (struct sockaddr*) &minecraft_addr6;
    return;
  }
  perror("FATAL: invalid minecraft addr\n");
  exit(1);
}

void fill_proxy_addr(int af, char *addr, unsigned short int port) {
  if (af == AF_INET && inet_pton(af, addr, &proxy_addr4.sin_addr) > 0) {
    proxy_addr4.sin_family = AF_INET;
    proxy_addr4.sin_port = htons(port);
    proxy_addr_size = sizeof(struct sockaddr_in);
    proxy_addr = (struct sockaddr*) &proxy_addr4;
    return;
  }
  if (af == AF_INET6 && inet_pton(af, addr, &proxy_addr6.sin6_addr) > 0) {
    proxy_addr6.sin6_family = AF_INET6;
    proxy_addr6.sin6_port = htons(port);
	proxy_addr_size = sizeof(struct sockaddr_in6);
    proxy_addr = (struct sockaddr*) &proxy_addr6;
    return;
  }
  perror("FATAL: invalid proxy addr\n");
  exit(1);
}

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

static void full_readdr(EV_P_ ev_io *w, int revents){
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

static void minecraft_proxy_client(EV_P_ ev_io *w, int revents) {
  EVP_CIPHER_CTX *ctx;
  unsigned char buf[AUTH_BUFFER_SIZE] = {0}, verify_key[16];
  struct sockaddr_in addr;
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
        memcmp("fuck-RKN", verify_key, 8) == 0) {
      ev_io_stop(loop, reciver);
      close(reciver->fd);
      reciver->fd = socket(proxy_addr->sa_family, SOCK_STREAM, 0);
	  printf("CONNECTED CLIENT!\n");
      if (connect(reciver->fd, proxy_addr, proxy_addr_size) < 0) {
        perror("FATAL: cant connect to proxy server\n");
        exit(1);
      }      
      ev_io_init(w, full_readdr, w->fd, EV_READ);
    } else {
      ev_io_init(w,  full_readdr, w->fd, EV_READ);
    }
    ev_io_start(loop, w);
    EVP_CIPHER_CTX_cleanup(ctx);    
  }  
}

static void on_accept(EV_P_ ev_io *w, int revents) {
  struct sockaddr_in client_address;
  int client_fd, minecraft_fd;
  socklen_t client_len = sizeof(client_address);
  client_fd = accept(w->fd, (struct sockaddr *)&client_address, &client_len);

  minecraft_fd = socket(minecraft_addr->sa_family, SOCK_STREAM, 0);
  if (minecraft_fd <= 0) {
    perror("FATAL: cant create minecraft socket\n");
	exit(1);
  }    

  if (connect(minecraft_fd, minecraft_addr, minecraft_addr_size) < 0) {
    perror("FATAL: cant connect to minecraft server\n");
	exit(1);
  }    
  
  ev_io *minecraft_watcher_client = malloc(sizeof(ev_io));
  ev_io *minecraft_watcher_server = malloc(sizeof(ev_io));

  minecraft_watcher_client->data = minecraft_watcher_server;
  minecraft_watcher_server->data = minecraft_watcher_client;

  ev_io_init(minecraft_watcher_client, minecraft_proxy_client, client_fd,
             EV_READ);
  ev_io_init(minecraft_watcher_server, full_readdr, minecraft_fd,
             EV_READ);
  
  ev_io_start(loop, minecraft_watcher_client);
  ev_io_start(loop, minecraft_watcher_server);
}  

int run_server(unsigned short int port) {
  int server_fd;
  struct sockaddr_in address;

  fill_minecraft_addr(AF_INET, "127.0.0.1", 25565);
  fill_proxy_addr(AF_INET, "127.0.0.1", 12345);
  
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
