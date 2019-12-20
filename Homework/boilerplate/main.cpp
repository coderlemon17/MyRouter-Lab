#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <iomanip>
using namespace std;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void setIPChecksum(uint8_t *packet);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer, uint32_t out_if_addr);
extern void assembleRipPacket(RipPacket* ripPacket);
extern void pringRouteTable();

const int BUFFER_SIZE = 2048;

//收到的IP包(response/request)的缓冲区
uint8_t packet[BUFFER_SIZE]{0};


uint8_t output[BUFFER_SIZE]{0};
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序


// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};
// 10.1.1.2
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0201010a, 0x0301010a, 0x0401010a,
//                                      0x0501010a};

// macaddr_t macs[N_IFACE_ON_BOARD];


int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);

  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = 1
    };
    update(true, entry);
  }

  // Add mac address
  for(uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    macaddr_t mac;
    HAL_GetInterfaceMacAddress(i, mac);
    fprintf(stderr, "%d: %02X:%02X:%02X:%02X:%02X:%02X\n", i, mac[0], mac[1],
            mac[2], mac[3], mac[4], mac[5]);
    // macs[i] = mac;
  }


  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09


      for(int i = 0; i < N_IFACE_ON_BOARD; i++){
        memset(packet, 0, BUFFER_SIZE);

        RipPacket rip;
        //assemble
        //TODO
        assembleRipPacket(&rip);

        // IP
        packet[0] = 0x45;
        //DSF
        packet[1] = 0xc0;
        //Total Length
        //ID
        packet[4] = 0x00;
        packet[5] = 0x00;
        //Flag
        packet[6] = 0x00;
        packet[7] = 0x00;
        //TTL
        packet[8] = 0x01;
        //Protocal
        packet[9] = 0x11;
        //checksum
        //TODO:wait until IP head is finish
        packet[10] = 0x00;
        packet[11] = 0x00;

        //source ip
        packet[12] = addrs[i] & 0x000000ff;
        packet[13] = (addrs[i] & 0x0000ff00) >> 8;
        packet[14] = (addrs[i] & 0x00ff0000) >> 16;
        packet[15] = (addrs[i] & 0xff000000) >> 24;

        //des ip
        packet[16] = 0xe0;
        packet[17] = 0x00;
        packet[18] = 0x00;
        packet[19] = 0x09;

        // ...
        // UDP
        // port = 520
        packet[20] = 0x02;
        packet[21] = 0x08;
        packet[22] = 0x02;
        packet[23] = 0x08;
        packet[26] = 0x00;
        packet[27] = 0x00;
        // ...
        // RIP
        //split horizon
        size_t length = (size_t) assemble(&rip, &packet[20+8], addrs[i]);
        
        //Total length in IP
        uint16_t len = 20 + 8 + length;
        packet[2] = len >> 8;
        packet[3] = len & 0x00ff;
        len -= 20;
        packet[24] = len >> 8;
        packet[25] = len & 0x00ff;
        //checksum
        setIPChecksum(packet);
        // setUDPChecksum(&packet[20]);

        macaddr_t des_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};

        HAL_SendIPPacket(i, packet, length+20+8, des_mac);
      }
      printf("30s Timer\n");
      pringRouteTable();
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;

    memset(packet, 0, BUFFER_SIZE);
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);


    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      printf("Time Out\n");
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    uint32_t s = 0, d = 0;
    for(uint8_t i = 0; i < 0x04; i++){
      s <<= 8;
      d <<= 8;
      s += *(packet + i + 12);
      d += *(packet + i + 16);
    }

    src_addr = htonl(s);
    dst_addr = htonl(d);

    // 2. check whether dst is me
    bool dst_is_me = false;

    in_addr_t broad_addr = 0x090000e0;

    // TODO: Handle rip multicast address(224.0.0.9)?
    if(memcmp(&dst_addr, &broad_addr, sizeof(in_addr_t)) == 0){
      dst_is_me = true;
    }else{
      for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
          dst_is_me = true;
          break;
        }
      }
    }

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          // TODO: fill resp
          RipPacket resp;
          assembleRipPacket(&resp);

          // assemble
          memset(output, 0, BUFFER_SIZE);
          // IP
          output[0] = 0x45;
          //DSF
          output[1] = 0xc0;
          //Total Length
          //ID
          output[4] = 0x00;
          output[5] = 0x00;
          //Flag
          output[6] = 0x00;
          output[7] = 0x00;
          //TTL
          output[8] = 0x40;
          //Protocal
          output[9] = 0x11;
          //checksum
          //TODO:wait until IP head is finish
          output[10] = 0x00;
          output[11] = 0x00;

          //source ip
          output[12] = addrs[if_index] & 0x000000ff;
          output[13] = (addrs[if_index] & 0x0000ff00) >> 8;
          output[14] = (addrs[if_index] & 0x00ff0000) >> 16;
          output[15] = (addrs[if_index] & 0xff000000) >> 24;

          //des ip
          output[16] = src_addr & 0x000000ff;
          output[17] = (src_addr & 0x0000ff00) >> 8;
          output[18] = (src_addr & 0x00ff0000) >> 16;
          output[19] = (src_addr & 0xff000000) >> 24;

          // ...
          // UDP
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;
          output[26] = 0x00;
          output[27] = 0x00;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8], addrs[if_index]);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          
          //Total length in IP
          uint16_t len = 20 + 8 + rip_len;
          output[2] = len >> 8;
          output[3] = len & 0x00ff;
          len -= 20;
          output[24] = len >> 8;
          output[25] = len & 0x00ff;
          //checksum
          setIPChecksum(output);

          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          for(int i = 0; i < rip.numEntries; i++){
            // cout << "mask: " << hex << setw(8) << setfill('0') << ntohl(rip.entries[i].mask) << endl;
            uint32_t len = 0;
            for(uint32_t j = 0x0; j <= 0x20; j++){
              if((ntohl(rip.entries[i].mask) >> j) % 0x2 != 0x0){
                len = 0x20 - j;
                break;
              }
            }
            // cout << "len: " << dec << setw(2) << len << endl;

            if(rip.entries[i].nexthop == 0){
              rip.entries[i].nexthop = src_addr;
            }


            bool dr = false;
            for(int j = 0; j < N_IFACE_ON_BOARD; j++){
              if((ntohl(rip.entries[i].addr) & 0xffffff00) == (ntohl(addrs[j]) & 0xffffff00)){
                dr = true;
                break;
              }
            }

            if(!dr){
              RoutingTableEntry entry = {
              .addr = rip.entries[i].addr, .len = len, .if_index = if_index, .nexthop = rip.entries[i].nexthop, .metric = ntohl(rip.entries[i].metric) + 1};

              update(true, entry);
            }
          }
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memset(output, 0, BUFFER_SIZE);
          memcpy(output, packet, res);
          // update ttl and checksum
          if(forward(output, res)){
            // TODO: you might want to check ttl=0 case
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }else{
            printf("TTL Count To Zero\n");
          }
          
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
