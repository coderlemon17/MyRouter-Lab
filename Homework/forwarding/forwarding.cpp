#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include<iomanip>

using namespace std;


/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {

  uint16_t testNum = 0;
  for(int i = 10; i < 12; i++){
    testNum <<= 8;
    testNum += *(packet+i);
    *(packet+i) = 0;
  }

  // cout << "test_num: " << hex << setw(4) << setfill('0') << testNum << endl;
  
  
  int size = ((*packet) & 0x0F) * 2;
  uint32_t allAns = 0;


  for(int i = 0; i < size; i++){
    uint16_t ans_16 = 0;
    for(int j = 0; j < 2; j++){
      ans_16 <<= 8;
      // cout << "packet: " << hex << (uint16_t)*(packet+i) << endl;
      ans_16 += *(packet+i*2+j);
      
    }
    // cout << 2*i << " :ans_16 " << hex << setw(4) <<setfill('0') << ans_16 << endl;
    allAns += ans_16;
  }

  while(true){
    uint16_t hi = allAns >> 16;
    //force type transfer
    uint16_t low = allAns;

    // cout << "hi: " << hex << setw(4) << setfill('0') << hi << endl;
    // cout << "low: " << hex << setw(4) << setfill('0') << low << endl;

    if(hi == 0)break;

    allAns = hi+low;
  }

  uint16_t re_ans = 0x0000FFFF & ~allAns;
  // cout << "re_ans: " << hex << setw(4) << setfill('0') << re_ans << endl;
  // cout << "re_ans: " << hex << setw(4) << setfill('0') << ~allAns << endl;

  *(packet + 10) = re_ans >> 8;
  *(packet + 11) = re_ans;

  return (re_ans == testNum) ? true : false;  
}


/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if(validateIPChecksum(packet, len)){
    //实际上TTL只有8位，这里因为网上给的是16位的数据改变后checksum会怎么变，所以取了16

    uint8_t TTL = *(packet+8);
    uint8_t newTTL = TTL - 1;

    // cout << "newTTL: " << hex << setw(2) << setfill('0') << (uint16_t)newTTL << endl;

    *(packet+8) = newTTL;

    //~C' = ~(C + (-m) + m') = ~C + (m - m') = ~C + m + ~m';

    uint16_t checkSum = 0;

    for(int i = 10; i < 12; i++){
      checkSum <<= 8;
      checkSum += *(packet+i);
    }


    // cout << "checkSum: " << hex << setw(4) << setfill('0') << checkSum << endl;


    // uint16_t new_checkSum = ~(~checkSum + ~TTL + newTTL);

    uint16_t new_checkSum = checkSum + 0x0100;
    if(new_checkSum == 0xffff){
      new_checkSum = 0x0000;
    }

    *(packet+10) = new_checkSum >> 8;
    *(packet+11) = new_checkSum;

    return true;
  }else{
    return false;
  }
}
