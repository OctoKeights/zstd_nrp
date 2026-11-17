/* The C half of the comparison of the Zstandard compressor with zstd
   (https://github.com/facebook/zstd). examples/dump.rs prints the same from the Rust port,
   and compare/compare.sh compares the two.

     dump zstd_compress <seed> <count>         made-up data of thirteen kinds, from nothing to
                                               five megabytes, compressed by ZSTD_compress
                                               into ZSTD_compressBound bytes at the levels
                                               the port takes: 1 to 3, 0 (the default), 4
                                               for the sizes it is ported for, and negative
                                               ones down to the lowest. A running hash of
                                               each size, level and frame
     dump zstd_compress_small <seed> <count>   the same with no more than 300,000 bytes in
                                               each, for a test that is quick to run
     dump zstd_compress_more <seed> <count>    the same data at the levels from 4 to 22 (and
                                               now and then a higher one, which is 22)
     dump zstd_compress_more_small <seed> <count>   the same with no more than 40,000 bytes

     dump zstd_compress_long <seed> <count>    made-up data of 64 to 80 megabytes, pieces of
                                               the other kinds and copies of what came
                                               before, from near and far and a little
                                               changed, at level 22: for the long-distance
                                               matching that level takes for that much

   (With a fifth argument, a level whose strategy for the size is past that number is taken
   as level 3: for a port that is not finished.) */
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The two programs make the same data from the same seed: a 64-bit linear congruential
   generator, the high half of its state. */
static uint64_t g_state;
static uint32_t Next(void)
{
    g_state = g_state * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(g_state >> 32);
}

/* FNV-1a, 64 bits. */
static uint64_t g_hash = 14695981039346656037ull;
static void Add(const void *data, size_t size)
{
    const unsigned char *bytes = (const unsigned char *)data;
    size_t i;
    for (i = 0; i < size; ++i)
    {
        g_hash ^= bytes[i];
        g_hash *= 1099511628211ull;
    }
}
static void AddNumber(uint32_t value)
{
    unsigned char bytes[4];
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
    Add(bytes, 4);
}

static const char *const kWords[16] = { "the", "texture", "block", "of", "and", "compress", "a", "level", "mip", "to", "pixels", "in", "format", "is", "cube", "data" };

/* Made-up bytes of one of thirteen kinds. */
static void FillData(uint8_t *buf, size_t len, uint32_t kind)
{
    size_t at = 0, i;
    switch (kind)
    {
        case 0: /* noise */
            for (i = 0; i < len; ++i)
                buf[i] = (uint8_t)(Next() >> 13);
            break;
        case 1: /* four letters */
            for (i = 0; i < len; ++i)
                buf[i] = (uint8_t)('a' + Next() % 4);
            break;
        case 2: /* words */
            while (at < len)
            {
                const char *word = kWords[Next() % 16];
                for (i = 0; word[i] && at < len; ++i)
                    buf[at++] = (uint8_t)word[i];
                if (at < len)
                    buf[at++] = ' ';
            }
            break;
        case 3: /* runs */
            while (at < len)
            {
                uint8_t byte = (uint8_t)Next();
                uint32_t run = 1 + Next() % 300;
                for (i = 0; i < run && at < len; ++i)
                    buf[at++] = byte;
            }
            break;
        case 4: /* copies of what came before */
            while (at < len)
            {
                uint32_t pick = at < 64 ? 0 : Next() % 4;
                if (pick == 0)
                    buf[at++] = (uint8_t)(Next() >> 9);
                else
                {
                    size_t reach = at < 40000 ? at : 40000;
                    size_t dist = 1 + Next() % reach;
                    uint32_t n = 3 + Next() % 260;
                    for (i = 0; i < n && at < len; ++i, ++at)
                        buf[at] = buf[at - dist];
                }
            }
            break;
        case 5: /* nothing */
            memset(buf, 0, len);
            break;
        case 6: /* a slope */
            for (i = 0; i < len; ++i)
                buf[i] = (uint8_t)(i / 7 + i % 13);
            break;
        case 7: /* stretches of noise, of one value and of counting */
            while (at < len)
            {
                uint32_t stretch = 1 + Next() % 2000;
                uint32_t what = Next() % 3;
                uint32_t value = Next();
                for (i = 0; i < stretch && at < len; ++i, ++at)
                    buf[at] = (uint8_t)(what == 0 ? Next() >> 11 : what == 1 ? value : value + i);
            }
            break;
        case 8: /* parts of the kinds above, one after the other */
            while (at < len)
            {
                size_t n = 1 + Next() % 200000;
                uint32_t part = Next() % 8;
                if (n > len - at)
                    n = len - at;
                FillData(buf + at, n, part);
                at += n;
            }
            break;
        case 9: /* the same few bytes over and over, changed in a few places */
        {
            size_t period = 1 + Next() % 5000;
            uint32_t changes, c;
            for (i = 0; i < period && i < len; ++i)
                buf[i] = (uint8_t)(Next() >> 11);
            for (i = period; i < len; ++i)
                buf[i] = buf[i - period];
            changes = Next() % 6;
            for (c = 0; c < changes && len != 0; ++c)
            {
                size_t where = Next() % len;
                buf[where] ^= (uint8_t)(1 + Next() % 255);
            }
            break;
        }
        case 11: /* a few low values */
        {
            uint32_t m = 2 + Next() % 14;
            for (i = 0; i < len; ++i)
                buf[i] = (uint8_t)(Next() % m);
            break;
        }
        case 12: /* words of four bytes of noise, in any order */
        {
            size_t words = 1000 + Next() % 3000;
            for (i = 0; i < words * 4 && i < len; ++i)
                buf[i] = (uint8_t)(Next() >> 12);
            at = words * 4;
            while (at < len)
            {
                size_t word = Next() % words * 4;
                for (i = 0; i < 4 && at < len; ++i, ++at)
                    buf[at] = buf[word + i];
            }
            break;
        }
        default: /* sixty-four letters, with a rare copy of what came before */
            while (at < len)
            {
                uint32_t pick = at > 1000 ? Next() % 30000 : 1;
                if (pick == 0)
                {
                    size_t reach = at < 100000 ? at : 100000;
                    size_t dist = 1 + Next() % reach;
                    uint32_t n = 8 + Next() % 300;
                    for (i = 0; i < n && at < len; ++i, ++at)
                        buf[at] = buf[at - dist];
                }
                else
                    buf[at++] = (uint8_t)(48 + (Next() >> 10) % 64);
            }
            break;
    }
}

#define MAX_DATA 5000000
#define MAX_LONG (64 * 1024 * 1024 + 16000000)

/* Data of many pieces: of the kinds above, and copies of what came before from as far as
   70 megabytes back, with a few bytes changed. */
static void FillLong(uint8_t *buf, size_t len)
{
    size_t at = 0, i;
    while (at < len)
    {
        size_t piece = 1 + Next() % 4000000;
        if (piece > len - at)
            piece = len - at;
        if (at > 1000000 && Next() % 2 == 0)
        {
            size_t dist = 1 + Next() % (at < 70000000 ? at : 70000000);
            uint32_t changes = Next() % 16;
            for (i = 0; i < piece; ++i)
                buf[at + i] = buf[at + i - dist];
            while (changes-- > 0)
            {
                size_t place = at + Next() % piece;
                buf[place] = (uint8_t)Next();
            }
        }
        else
            FillData(buf + at, piece, Next() % 13);
        at += piece;
    }
}

static const int kLevels[20] = { 1, 1, 2, 2, 3, 3, 3, 0, 4, 4, -1, -1, -2, -3, -5, -7, -20, -100, -1000, -200000 };

int main(int argc, char **argv)
{
    uint32_t count, i;
    uint8_t *data, *back, *frame;
    size_t frame_room, max_data;
    uint64_t in_total = 0, frame_total = 0;
    int small, more, highest, longer;
    if (argc < 4 || (strcmp(argv[1], "zstd_compress") != 0 && strcmp(argv[1], "zstd_compress_small") != 0 && strcmp(argv[1], "zstd_compress_more") != 0 && strcmp(argv[1], "zstd_compress_more_small") != 0 && strcmp(argv[1], "zstd_compress_long") != 0))
    {
        fprintf(stderr, "usage: dump zstd_compress|zstd_compress_small|zstd_compress_more|zstd_compress_more_small|zstd_compress_long <seed> <count>\n");
        return 2;
    }
    longer = strcmp(argv[1], "zstd_compress_long") == 0;
    max_data = longer ? MAX_LONG : MAX_DATA;
    data = (uint8_t *)malloc(max_data + 1);
    back = (uint8_t *)malloc(max_data + 1);
    frame_room = ZSTD_compressBound(max_data);
    small = strcmp(argv[1], "zstd_compress_small") == 0;
    more = strncmp(argv[1], "zstd_compress_more", 18) == 0;
    highest = argc > 4 ? atoi(argv[4]) : 9;
    if (strcmp(argv[1], "zstd_compress_more_small") == 0)
        small = 2;
    g_state = strtoull(argv[2], NULL, 10);
    count = (uint32_t)strtoul(argv[3], NULL, 10);
    frame = (uint8_t *)malloc(frame_room);
    for (i = 0; i < count && longer; ++i)
    {
        size_t len = 64 * 1024 * 1024 + Next() % 16000000, frame_size, size;
        int level = 22;
        FillLong(data, len);
        frame_size = ZSTD_compress(frame, ZSTD_compressBound(len), data, len, level);
        if (ZSTD_isError(frame_size))
        {
            fprintf(stderr, "%s: %s\n", argv[1], ZSTD_getErrorName(frame_size));
            return 1;
        }
        size = ZSTD_decompress(back, max_data + 1, frame, frame_size);
        if (size != len || memcmp(back, data, len) != 0)
        {
            fprintf(stderr, "%s: frame %u does not give its data back\n", argv[1], i);
            return 1;
        }
        AddNumber((uint32_t)len);
        AddNumber((uint32_t)level);
        AddNumber((uint32_t)frame_size);
        Add(frame, frame_size);
        in_total += len;
        frame_total += frame_size;
        printf("%s %u %016llx\n", argv[1], i + 1, (unsigned long long)g_hash);
    }
    for (i = 0; i < count && !longer; ++i)
    {
        uint32_t kind = Next() % 13;
        uint32_t r = Next() % 16;
        uint32_t max = r == 0 ? 16 : r < 5 ? 300 : r < 9 ? 5000 : r < 12 ? 40000 : r < 14 ? 300000 : r == 14 ? 1500000 : MAX_DATA;
        size_t len, frame_size, size;
        int level;
        if (small == 1 && max > 300000)
            max = 300000;
        if (small == 2 && max > 40000)
            max = 40000;
        len = Next() % (max + 1);
        if (more)
        {
            level = 4 + (int)(Next() % 19);
            if (Next() % 20 == 0)
                level = 23 + (int)(Next() % 5);
            if ((int)ZSTD_getCParams(level, len ? len : 1, 0).strategy > highest)
                level = 3;
        }
        else
        {
            level = kLevels[Next() % 20];
            /* Level 4 takes a strategy that is ported for these sizes only. */
            if (level == 4 && !(len > 256 * 1024 || (len > 16 * 1024 && len <= 128 * 1024)))
                level = 3;
        }
        /* A block of nothing but matches of four bytes has so many sequences that their
           number is written the long way: it takes level 3 and a source of exactly this size. */
        if (kind == 12 && Next() % 2 == 0)
        {
            len = 262144;
            level = 3;
        }
        FillData(data, len, kind);
        frame_size = ZSTD_compress(frame, ZSTD_compressBound(len), data, len, level);
        if (ZSTD_isError(frame_size))
        {
            fprintf(stderr, "%s: %s\n", argv[1], ZSTD_getErrorName(frame_size));
            return 1;
        }
        size = ZSTD_decompress(back, max_data + 1, frame, frame_size);
        if (size != len || memcmp(back, data, len) != 0)
        {
            fprintf(stderr, "%s: frame %u does not give its data back\n", argv[1], i);
            return 1;
        }
        AddNumber((uint32_t)len);
        AddNumber((uint32_t)level);
        AddNumber((uint32_t)frame_size);
        Add(frame, frame_size);
        if (getenv("SHOW_EACH"))
            fprintf(stderr, "frame %u: %zu bytes at level %d, %zu bytes, %016llx\n", i, len, level, frame_size, (unsigned long long)g_hash);
        in_total += len;
        frame_total += frame_size;
        if ((i + 1) % 10 == 0 || i + 1 == count)
            printf("%s %u %016llx\n", argv[1], i + 1, (unsigned long long)g_hash);
    }
    printf("%s bytes: %llu; bytes of frames: %llu\n", argv[1], (unsigned long long)in_total, (unsigned long long)frame_total);
    free(data);
    free(back);
    free(frame);
    return 0;
}
