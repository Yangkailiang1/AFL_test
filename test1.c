#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/*
  Strategies Test for AFL
  Seed: "AAAA" (0x41 0x41 0x41 0x41)
  
  Goal: Trigger crashes using specific mutation strategies.
*/

int main(int argc, char** argv) {
    char buf[100];
    memset(buf, 0, sizeof(buf));
    
    // Read from stdin
    read(0, buf, 50);

    // 1. Bitflip Strategy
    // 'A' (0x41) -> 'C' (0x43)
    // 0100 0001 -> 0100 0011 (Flip 2nd bit)
    // Strategy: bitflip 1/1
    if (buf[0] == 'C') {
        abort(); // Crash 1
    }

    // 2. Arithmetic Strategy
    // 'A' (0x41) -> 'K' (0x4B)
    // Difference: +10
    // Strategy: arith 8/8
    if (buf[1] == 'K') {
        abort(); // Crash 2
    }

    // 3. Interest (Known Integers) Strategy
    // Replace byte with interesting value, e.g., -128 (0x80) or 0 (0x00)
    // Strategy: interest 8/8
    if (buf[2] == '\0') {
        // Only if others are unchanged to ensure it's this strategy
        if (buf[0] == 'A' && buf[1] == 'A')
            abort(); // Crash 3
    }

    // 4. Dictionary / Extras Strategy
    // Replace with "ABCD"
    // Strategy: user extras (over)
    if (memcmp(buf, "ABCD", 4) == 0) {
        abort(); // Crash 4
    }

    return 0;
}
