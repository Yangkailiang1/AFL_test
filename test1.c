#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/*
  AFL 变异策略测试程序
  初始种子："AAAA"（0x41 0x41 0x41 0x41）

  目标：通过特定的变异策略触发程序崩溃
*/

int main(int argc, char** argv) {
    char buf[100];
    memset(buf, 0, sizeof(buf));
    
    // 从标准输入读取数据
    read(0, buf, 50);

    // 1. Bitflip（位翻转）策略
    // 'A' (0x41) -> 'C' (0x43)
    // 0100 0001 -> 0100 0011（翻转第 2 位）
    // 对应 AFL 策略：bitflip 1/1
    if (buf[0] == 'C') {
        abort(); // 崩溃点 1
    }

    // 2. Arithmetic（算术变异）策略
    // 'A' (0x41) -> 'K' (0x4B)
    // 差值：+10
    // 对应 AFL 策略：arith 8/8
    if (buf[1] == 'K') {
        abort(); // 崩溃点 2
    }

    // 3. Interest（特殊整数）策略
    // 将字节替换为“有趣的值”，如 -128 (0x80) 或 0 (0x00)
    // 对应 AFL 策略：interest 8/8
    if (buf[2] == '\0') {
        // 仅当其他字节保持不变时，确保是该策略触发
        if (buf[0] == 'A' && buf[1] == 'A')
            abort(); // 崩溃点 3
    }

    // 4. Dictionary / Extras（字典）策略
    // 将输入替换为字符串 "ABCD"
    // 对应 AFL 策略：user extras（覆盖）
    if (memcmp(buf, "ABCD", 4) == 0) {
        abort(); // 崩溃点 4
    }

    return 0;
}
