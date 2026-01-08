#include "events/callbacks.h"
#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main() {
	run_server(25566);
}  
