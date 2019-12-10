#include "router_hal.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
using namespace std;
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
char buffer[1024];

int main(int argc, char *argv[]) {
  uint32_t addr, len, if_index, nexthop;
  char tmp;
  while (fgets(buffer, sizeof(buffer), stdin)) {
    // cout << "I" << endl;
    if (buffer[0] == 'I') {
      sscanf(buffer, "%c,%x,%d,%d,%x", &tmp, &addr, &len, &if_index, &nexthop);
      RoutingTableEntry entry = {
          .addr = addr, .len = len, .if_index = if_index, .nexthop = nexthop};
      update(true, entry);
      // cout << "I" << endl;
    } else if (buffer[0] == 'D') {
      sscanf(buffer, "%c,%x,%d", &tmp, &addr, &len);
      RoutingTableEntry entry = {
        .addr = addr,
        .len = len,
        .if_index = 0,
        .nexthop = 0
      };
      update(false, entry);
    } else if (buffer[0] == 'Q') {
      sscanf(buffer, "%c,%x", &tmp, &addr);
      // cout << "D" << endl;
      if (query(addr, &nexthop, &if_index)) {
        printf("0x%08x %d\n", nexthop, if_index);
      } else {
        printf("Not Found\n");
      }
      
    }
  }
  return 0;
}