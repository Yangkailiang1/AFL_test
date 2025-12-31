#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

/*
  Comprehensive Strategies Test for AFL
  
  Targeting specific mutation strategies described in AFL documentation.
  Seed 1: 64 bytes of 0x00
  Seed 2: 64 bytes of 0xFF (for splicing)
*/

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

int main(int argc, char** argv) {
    u8 buf[128];
    memset(buf, 0, sizeof(buf));
    
    // Read up to 100 bytes
    int len = read(0, buf, 100);
    if (len < 64) return 0; // Require at least 64 bytes

    // =========================================================
    // 1. Walking Bit Flips
    // =========================================================
    
    // Strategy: bitflip 1/1
    // Flip bit 0 of byte 0: 0x00 -> 0x01
    // Note: This could also be triggered by arith +1, but AFL tries bitflips first.
    if (buf[0] == 0x01) {
        // Double check it's not arith (others are 0)
        if (buf[1] == 0) abort(); 
    }

    // Strategy: bitflip 2/1 (Two bits in a row)
    // Flip bits 0-1 of byte 1: 0x00 -> 0x03 (0000 0011)
    // Bitflip 1/1 would produce 0x01 or 0x02, but not 0x03 in one go.
    if (buf[1] == 0x03) {
        if (buf[0] == 0) abort();
    }

    // Strategy: bitflip 4/1 (Four bits in a row)
    // Flip bits 0-3 of byte 2: 0x00 -> 0x0F (0000 1111)
    if (buf[2] == 0x0F) {
        if (buf[0] == 0) abort();
    }

    // =========================================================
    // 2. Walking Byte Flips
    // =========================================================

    // Strategy: bitflip 8/8 (Flip all bits in a byte)
    // Byte 3: 0x00 -> 0xFF
    if (buf[3] == 0xFF) {
        if (buf[0] == 0) abort();
    }

    // Strategy: bitflip 16/8 (Flip 2 bytes)
    // Bytes 4-5: 0x0000 -> 0xFFFF
    // Use u16 cast
    if (*(u16*)(buf + 4) == 0xFFFF) {
        if (buf[0] == 0) abort();
    }

    // Strategy: bitflip 32/8 (Flip 4 bytes)
    // Bytes 6-9: 0x00000000 -> 0xFFFFFFFF
    if (*(u32*)(buf + 6) == 0xFFFFFFFF) {
        if (buf[0] == 0) abort();
    }

    // =========================================================
    // 3. Simple Arithmetics
    // =========================================================

    // Strategy: arith 8/8
    // Byte 10: 0x00 -> 0x0A (+10)
    // Avoid small values like 1, 2 which bitflip might catch
    if (buf[10] == 10) {
        // Ensure it's not a bitflip. 10 is 0000 1010.
        // From 00, flipping bits would be 0x08 (bit 3) or 0x02 (bit 1).
        // 0x0A requires 2 bits flipped (unlikely in 1/1) or +10.
        if (buf[0] == 0) abort();
    }

    // Strategy: arith 16/8
    // Bytes 12-13: 0x0000 -> 0x0100 (256)
    // This requires a carry operation, affecting MSB.
    // 0x00FF + 1 = 0x0100.
    // But our seed is 0x0000. 
    // AFL tries adding to 16-bit values.
    // If it adds 256 to 0, result is 256 (0x0100).
    // This change touches MSB (00 -> 01), so it's a valid 16-bit arith op.
    // Byte 12 is LSB or MSB depending on endianness, but AFL tries both.
    // Let's check for 0x0100 (Little Endian: 00 01) or (Big Endian: 01 00).
    // Since x86 is LE, let's target LE 0x0100 (Byte 12=0x00, Byte 13=0x01).
    // Wait, seed is 00 00.
    // If AFL treats it as LE: 0x0000. Adds 256 -> 0x0100. Memory: 00 01.
    // If AFL treats it as BE: 0x0000. Adds 1 -> 0x0001. Memory: 00 01.
    // So 00 01 in memory is likely found by BE arith +1 OR LE arith +256.
    // Let's target 0x0100 (value 256).
    // Condition: buf[13] == 0x01 && buf[12] == 0x00.
    if (buf[12] == 0x00 && buf[13] == 0x01) {
        if (buf[0] == 0) abort();
    }

    // Strategy: arith 32/8
    // Bytes 16-19. 0x00000000.
    // Target: 0x00010000 (65536).
    // Memory (LE): 00 00 01 00.
    if (buf[16] == 0x00 && buf[17] == 0x00 && buf[18] == 0x01 && buf[19] == 0x00) {
        if (buf[0] == 0) abort();
    }

    // =========================================================
    // 4. Known Integers (Interest)
    // =========================================================

    // Strategy: interest 8/8
    // Byte 20. Interesting values: -128 (0x80), 127 (0x7F), 0, etc.
    // Seed is 0. Let's look for -128 (0x80).
    // 0x80 is 1000 0000 (1 bit flipped from 0).
    // Wait, bitflip 1/1 will find 0x80!
    // We need an interesting value that isn't a single bit flip from 0.
    // 0x7F (0111 1111) is 7 bits flipped.
    // 100 (0x64). Not standard interesting?
    // Interesting values: -128, -1, 0, 1, 16, 32, 64, 100, 127.
    // Let's try 127 (0x7F).
    if (buf[20] == 0x7F) {
        if (buf[0] == 0) abort();
    }

    // Strategy: interest 16/8
    // Bytes 22-23.
    // Interesting 16-bit: 32768 (0x8000), 65535 (0xFFFF).
    // 0xFFFF is covered by bitflip 16/8.
    // Let's use 32768 (0x8000).
    // Memory (LE): 00 80.
    // 0x8000 is 1000...0000 (1 bit set). 
    // From 0000, 0x8000 is 1 bit flip (bit 15).
    // Bitflip 1/1 will find this!
    // We need something else.
    // MAX_INT-1?
    // Let's pick a value that is interesting but not simple bitflip.
    // How about -32768? (same as 0x8000).
    // How about 1000? 0x03E8.
    // AFL interest list includes powers of 2 and off-by-ones.
    // Let's try -2 (0xFFFE).
    // From 0000 -> FFFE (15 bits flipped).
    // Interest 16/8 inserts it directly.
    if (*(u16*)(buf + 22) == 0xFFFE) {
        if (buf[0] == 0) abort();
    }

    // Strategy: interest 32/8
    // Bytes 26-29.
    // Target: 0xDEADBEEF (Common magic, but maybe not in standard AFL list).
    // AFL list: -2147483648 (MIN_INT), MAX_INT, etc.
    // Let's try MAX_INT (0x7FFFFFFF).
    // From 00000000 -> 7FFFFFFF (31 bits flipped).
    if (*(u32*)(buf + 26) == 0x7FFFFFFF) {
        if (buf[0] == 0) abort();
    }

    // =========================================================
    // 5. Stacked Tweaks (Havoc) & Splicing
    // =========================================================

    // Havoc: complex conditions or multiple bytes changed randomly.
    // Let's check for a specific string "HVC".
    // Probability of "HVC" (3 bytes) appearing from 000000 is low, but Havoc does overwrites.
    if (buf[30] == 'H' && buf[31] == 'V' && buf[32] == 'C') {
        if (buf[0] == 0) abort();
    }

    // Splicing
    // We have Seed 1 (All 0x00) and Seed 2 (All 0xFF).
    // Splicing joins them.
    // Let's look for a boundary.
    // e.g. buf[40] is 0x00 (from Seed 1) AND buf[41] is 0xFF (from Seed 2).
    // And to ensure it's not just a random byte set, let's require a block.
    // buf[40..43] == 0x00, buf[44..47] == 0xFF.
    if (*(u32*)(buf + 40) == 0x00000000 && *(u32*)(buf + 44) == 0xFFFFFFFF) {
        // This implies a splice point around 44.
        abort();
    }

    // =========================================================
    // 6. Dictionary (User Extras)
    // =========================================================

    // Strategy: user extras (over/insert)
    // Search for "ABCD" provided in dictionary.
    // Location: Byte 50.
    if (buf[50] == 'A' && buf[51] == 'B' && buf[52] == 'C' && buf[53] == 'D') {
        if (buf[0] == 0) abort();
    }

    return 0;
}
