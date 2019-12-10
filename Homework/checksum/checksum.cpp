#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include<iomanip>

using namespace std;


//test link

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
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
  *(packet + 10) = re_ans;

  return (re_ans == testNum) ? true : false;  
}


