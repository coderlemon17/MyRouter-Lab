#include "router.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>
#include <list>

using namespace std;

list<MyRT> myTable;



const uint32_t MAX_HOP = 0x00000010;

void print32(string str, uint32_t t){
  cout << str;
  cout << " " << hex << setw(8) << setfill('0') << t << endl;
} 


/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {

  // if(insert){
  //   cout << "INSERT ";
  // }else{
  //   cout << "DELETE ";
  // }


  // cout << hex << setw(8) << setfill('0') << ntohl(entry.addr);
  // cout << "/" << dec << entry.len << " next hop: ";
  // cout << hex << setw(8) << setfill('0') << ntohl(entry.nexthop);
  // cout << " via " << entry.if_index;
  // cout << " metric: " << entry.metric << endl;

  
  for(auto it = myTable.begin(); it != myTable.end();){
    if((*it).len == entry.len && (*it).addr == entry.addr && (*it).nexthop == entry.nexthop){
      myTable.erase(it++);
    }else{
      it++;
    }
  }

  if(insert && entry.metric < MAX_HOP){
    myTable.push_front(new MyRT(&entry));
  }


  // cout << "FINISH UPDATE\n";
}

//uint32_t mask[33]{0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff, 0x0fffffff, 0x07ffffff, 0x03ffffff, 0x01ffffff, 0x00ffffff, 0x007fffff, 0x003fffff, 0x001fffff, 0x000fffff, 0x0007ffff, 0x0003ffff, 0x0001ffff, 0x0000ffff, 0x00007fff, 0x00003fff, 0x00001fff, 0x00000fff, 0x000007ff, 0x000003ff, 0x000001ff, 0x000000ff, 0x0000007f, 0x0000003f, 0x0000001f, 0x0000000f, 0x00000007, 0x00000003, 0x00000001};
// uint32_t mask2[32]{0xfffffffe, 0xfffffffd, 0xfffffffb, 0xfffffff7, 0xffffffef, 0xffffffdf, 0xffffffbf, 0xffffff7f, 0xfffffeff, 0xfffffdff, 0xfffffbff, 0xfffff7ff, 0xffffefff, 0xffffdfff, 0xffffbfff, 0xffff7fff, 0xfffeffff, 0xfffdffff, 0xfffbffff, 0xfff7ffff, 0xffefffff, 0xffdfffff, 0xffbfffff, 0xff7fffff, 0xfeffffff, 0xfdffffff, 0xfbffffff, 0xf7ffffff, 0xefffffff, 0xdfffffff, 0xbfffffff, 0x7fffffff};



/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  
  *nexthop = 0;
  *if_index = 0;
  bool find = false;
  
  uint32_t sAddr = ntohl(addr);


  uint32_t max_match_length = 0x00000000;
  uint32_t min_match_metric = 0xffffffff;
  auto max_match_entry = myTable.begin();

  for(auto it = myTable.begin(); it != myTable.end(); it++){
    uint32_t tmpt = (*it).len == 32 ? 0xffffffff : ((1 << (*it).len) - 1);

    if( ((~(ntohl((*it).addr) ^ sAddr)) >> (32-(*it).len)) == tmpt){
      find = true;
      // cout << "i: " << i << endl;
      // cout << (*it).len << endl;
      // cout << ((*it).len > max_match_length) << endl;
      

      cout << "MATCH: " << hex << ntohl((*it).addr) << endl;


      if((*it).len > max_match_length){
        max_match_length = (*it).len;
        max_match_entry = it;
        // cout << "?\n";
        // cout << "max" << max_match_entry << endl;
      }else if((*it).len == max_match_length && max_match_length != 0x00000000){
        if((*it).metric < min_match_metric){
          min_match_metric = (*it).metric;
          max_match_entry = it;
        }
      }
      // cout << "r" << endl;
    } 
  }
  if(find){
    //直连在main中处理了
    *nexthop = (*max_match_entry).nexthop;
    *if_index = (*max_match_entry).if_index;
  }
  return find;
}


void pringRouteTable(){
  cout << "MY ROUTE TABLE\n";

  for(auto it = myTable.begin(); it != myTable.end(); it++){
    cout << hex << setw(8) << setfill('0') << ntohl((*it).addr);
    cout << "/" << dec << setw(2) << (*it).len << " next hop: ";
    cout << hex << setw(8) << setfill('0') << ntohl((*it).nexthop);
    cout << " via " << (*it).if_index;
    cout << " metric: " << (*it).metric << endl;
  }
}

