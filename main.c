#include "events/callbacks.h"
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
  char *slash = strrchr(argv[0], '/');
  if (slash != NULL)
    *slash = 0;
  chdir(argv[0]);  
  run_server(25565);  
}  
