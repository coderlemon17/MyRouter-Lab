#include <iostream>
#include<iomanip>
using namespace std;

int main(){
    uint32_t num = 0xFFFFFFFF;

    for(int i = 0; i < 32; i++){
        cout << "0x";
        cout << hex << setw(8) << setfill('0') << (num - (1 << i)) << ", ";
    }
    return 0;
}