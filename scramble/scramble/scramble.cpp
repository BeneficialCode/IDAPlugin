// scramble.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

uint64_t scramble(uint64_t x, uint64_t y) {
    return ((((x + ((~x) & y)) | ((x + y) - (2 * (x & y)))) + ((~(x + ((~x) & y))) | ((x + y) - (2 * (x & y))))) - (~(x + ((~x) & y))));
}

int main(int argc,char* argv[]) {
    int a, b;
    printf("Please input a and b:");
    scanf_s("%d %d", &a, &b);
    printf("a:%d,b:%d\n", a, b);
    printf("Result %" PRIu64 "\n", scramble(a, b));
    return 0;
}

