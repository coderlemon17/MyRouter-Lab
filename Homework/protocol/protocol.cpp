#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>

using namespace std;
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  RipPacket rp;

  //Total length
  uint16_t totoalLength = *(packet + 2) << 8;
  totoalLength += *(packet + 3);

  // cout << 1;
  if(totoalLength > len){
    return false;
  }

  int ipLen = (*packet & 0x0f) * 4;

  // cout << "ipLen" << ipLen << endl;

  const uint8_t* UDPStart = (packet + ipLen);

  uint16_t lenUdpAndRe = *(UDPStart + 4) << 8;
  lenUdpAndRe += *(UDPStart + 5);

  uint8_t reNum = (lenUdpAndRe - 8 - 4) / 20;

  // cout << "reNum" << (uint16_t) reNum << endl;

  const uint8_t* RipHeadStart = UDPStart + 8;
  
  //command
  uint8_t command = *(RipHeadStart);
  if(command != 0x01 && command != 0x02){
    return false;
  }
  

  //version
  uint8_t version = *(RipHeadStart + 1);
  if(version != 0x02){
    return false;
  }
  // cout << "here";


  //zero
  uint16_t zero = *(RipHeadStart + 2) << 8;
  zero += *(RipHeadStart + 3);
  if(zero != 0x0000){
    return false;
  }

  // cout << "here";
  const uint8_t* ReStart = RipHeadStart + 4;
  const uint8_t* thisRe;

  rp.numEntries = reNum;
  rp.command = command;

  for(uint8_t i = 0; i < reNum; i++){
    thisRe = ReStart + i*20;

    RipEntry re;

    uint16_t family = *(thisRe) << 8;
    family += *(thisRe + 1);

    uint16_t tag = *(thisRe + 2) << 8;
    tag += *(thisRe + 3);

    uint32_t ip = 0, sm = 0, nh = 0, me = 0;
    for(int p = 0; p < 4; p++){
      ip <<= 8;
      sm <<= 8;
      nh <<= 8;
      me <<= 8;

      ip += *(thisRe + 4 + p);
      sm += *(thisRe + 4 + 4 + p);
      nh += *(thisRe + 4 + 8 + p);
      me += *(thisRe + 4 + 12 + p);
    }

    // cout << hex << "command" << (uint16_t)command << " " << "family" << (uint16_t) family << endl;
    // cout << "ip "<< hex << setw(8) << setfill('0')  << ip << endl;
    // cout << "sm "<< hex << setw(8) << setfill('0')  << sm << endl;
    // cout << "nh "<< hex << setw(8) << setfill('0')  << nh << endl;
    // cout << "me "<< hex << setw(8) << setfill('0')  << me << endl;
    if(!((command == 0x01 && family == 0x0000) || (command == 0x02 && family == 0x0002))){
      return false;
    }
    // cout << "here";
    if(tag != 0x0000){
      return false;
    }
    // cout << "here";
    if(me == 0x00000000 || me > 0x00000010){
      return false;
    }

    // cout << "here";
    // cout << ((~sm)+1 & (~sm)) << endl;
    if(((~sm)+1 & (~sm)) != 0x00000000){
      return false;
    }
    // cout << "here";

    re.addr = htonl(ip); // 大端口序
    re.mask = htonl(sm);
    re.nexthop = htonl(nh);
    re.metric = htonl(me);
    
    rp.entries[i] = re;
  }

  *output = rp;
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @param out_if_addr the address of the interface where RIP packet will be sent from (horizon split) // big endian
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer, uint32_t out_if_addr) {
  // TODO:
  *buffer = rip->command;
  *(buffer + 1) = 0x02;
  *(buffer + 2) = 0x00;
  *(buffer + 3) = 0x00;
  uint8_t* rpstart = buffer+4;

  //out_if_addr = 0xffffffff means assemble all route

  uint8_t j = 0x00;

  for(uint8_t i = 0; i < rip->numEntries; i++){
    // cout << "Out_if: " << hex << setw(8) << ntohl(out_if_addr) << endl;
    // cout << hex << setw(8) << (ntohl(rip->entries[i].nexthop)) << endl;
    // cout << hex << setw(8) << (ntohl(out_if_addr) & 0xffffff00) << endl;
    // cout << ((ntohl(rip->entries[i].nexthop) & ntohl(rip->entries[i].mask)) != (ntohl(out_if_addr) & 0xffffff00)) << endl;
    uint32_t nHop;
    bool directLine = false;
    if(rip->entries[i].nexthop == 0){
      nHop = ntohl(rip->entries[i].addr);
      directLine = true;
    }else{
      nHop = ntohl(rip->entries[i].nexthop);
    }
    // cout << hex << setw(8) << (ntohl(nHop)) << endl;
    if((nHop & 0xffffff00) != (ntohl(out_if_addr) & 0xffffff00)){
      //j: actual number of rip entry in IP packet
      uint8_t* thisRe = rpstart + j*20;
      *(thisRe) = (rip->command == 0x01) ? 0x00 : 0x00;
      *(thisRe + 1) = (rip->command == 0x01) ? 0x00 : 0x02;
      *(thisRe + 2) = 0x00;
      *(thisRe + 3) = 0x00;

      uint32_t metric = ntohl(rip->entries[i].metric);

      if(directLine){
        // no need for changing next hop, change next hop when receive
        // nHop = ntohl(out_if_addr);
        nHop = 0x00000000;
      }
      
      for(uint8_t t = 0; t < 4; t++){
        *(thisRe + 4 + t) = ntohl(rip->entries[i].addr) >> ((3 - t)*8);
        *(thisRe + 4 + t + 4) = ntohl(rip->entries[i].mask) >> ((3 - t)*8);
        *(thisRe + 4 + t + 8) =  nHop >> ((3 - t)*8);
        *(thisRe + 4 + t + 12) = (metric >> ((3 - t)*8));
      }

      j++;
    }
  }
  return 4 + 20*j;
}
