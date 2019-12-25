#include <stdint.h>

// 路由表的一项
typedef struct {
    uint32_t addr; // 地址
    uint32_t len; // 前缀长度
    uint32_t if_index; // 出端口编号
    uint32_t nexthop; // 下一条的地址，0 表示直连
    uint32_t metric;
    // 为了实现 RIP 协议，需要在这里添加额外的字段
} RoutingTableEntry;

class MyRT{
  public:
    MyRT(RoutingTableEntry* entry){
      this->addr = entry->addr;
      this->len = entry->len;
      this->if_index = entry->if_index;
      this->nexthop = entry->nexthop;
      this->metric = entry->metric;
      // print32("addr", this->nexthop);
      // print32("len", this->len);
      // print32("metric", entry->metric);
    }

    MyRT(MyRT* entry){
      this->addr = entry->addr;
      this->len = entry->len;
      this->if_index = entry->if_index;
      this->nexthop = entry->nexthop;
      this->metric = entry->metric;
      // print32("addr", this->nexthop);
      // print32("len", this->len);
    }

    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
    uint32_t metric; //小端序
};