/* The C half of the comparison of the Zstandard compressor's entropy coders with zstd
   (https://github.com/facebook/zstd), one function at a time: what a whole frame seldom or
   never asks of them (outputs with too little room, counts that are hard to normalize, a
   table carried over from before) is asked here. examples/dump.rs prints the same from the
   Rust port, and compare/compare.sh compares the two.

     dump zstd_entropy <seed> <count>   one of three, <count> times:
                                        - made-up counts through FSE_normalizeCount, the
                                          result through FSE_writeNCount into room that may
                                          be too little, then symbols through
                                          FSE_buildCTable_wksp and FSE_compress_usingCTable
                                        - made-up bytes through HUF_compress1X_repeat or
                                          HUF_compress4X_repeat, with or without the table
                                          of the call before
                                        - made-up bytes through ZSTD_compressLiterals
                                        A running hash of every answer and output */
#define FSE_STATIC_LINKING_ONLY
#define HUF_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

#include "common/error_private.h"
#include "common/fse.h"
#include "common/huf.h"
#include "compress/zstd_compress_internal.h"
#include "compress/zstd_compress_literals.h"

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

/* An answer as a number: a size, or an error's code with the top bit set. */
static uint32_t Code(size_t answer)
{
    return ERR_isError(answer) ? 0x80000000u + (uint32_t)ERR_getErrorCode(answer) : (uint32_t)answer;
}

static uint32_t g_errors, g_outputs;

static void TryFse(void)
{
    static unsigned count[256];
    static short norm[256];
    static uint8_t header[512], pool[4096], symbols[600], out[1024];
    static FSE_CTable ct[FSE_CTABLE_SIZE_U32(12, 255)];
    /* (More than the size the library names: for 256 symbols and a table of 4096 that size
       is two bytes less than FSE_buildCTable_wksp uses, and it writes a byte past it.) */
    static U32 wksp[FSE_BUILD_CTABLE_WORKSPACE_SIZE_U32(255, 12) + 8];
    uint32_t max, shape, big, s, table_log, low, room, n, i, p = 0;
    size_t total = 0, answer;

    if (Next() % 4 == 0)
        max = 1 + Next() % 255;
    else
        max = 1 + Next() % 52;
    shape = Next() % 8;
    big = 1 + Next() % 5000;
    for (s = 0; s <= max; ++s)
    {
        uint32_t c;
        switch (shape)
        {
            case 0: c = 1 + Next() % 3; break;
            case 1: c = s < 64 ? big >> (s / 2) : 0; break;
            case 2:
                c = Next() % 5;
                c = c == 0 ? 1 + Next() % 40 : 0;
                break;
            case 3: c = s == 0 ? big * 20 : Next() % 3; break;
            case 4: c = big % 4 + 1; break;
            case 5: c = Next() % 1000; break;
            case 6: c = s < 3 ? big * 30 : s < 6 ? big * 3 : 1 + Next() % 2; break;
            default: c = Next() % 16 < 11; break;
        }
        count[s] = c;
    }
    if (count[max] == 0)
        count[max] = 1;
    for (s = 0; s <= max; ++s)
        total += count[s];
    if (total < 2)
    {
        count[0] += 2;
        total += 2;
    }
    if (Next() % 4 == 0)
        table_log = Next() % 14;
    else
        table_log = FSE_optimalTableLog(5 + Next() % 8, total, max);
    low = Next() & 1;

    answer = FSE_normalizeCount(norm, table_log, count, total, max, low);
    AddNumber(Code(answer));
    if (ERR_isError(answer) || answer == 0)
    {
        ++g_errors;
        return;
    }
    table_log = (uint32_t)answer;
    for (s = 0; s <= max; ++s)
        AddNumber((uint32_t)(int32_t)norm[s]);

    room = 512;
    if (Next() % 3 == 0)
        room = 2 + Next() % 22;
    answer = FSE_writeNCount(header, room, norm, max, table_log);
    AddNumber(Code(answer));
    if (ERR_isError(answer))
    {
        ++g_errors;
        return;
    }
    Add(header, answer);

    if (ERR_isError(FSE_buildCTable_wksp(ct, norm, max, table_log, wksp, sizeof(wksp))))
    {
        fprintf(stderr, "zstd_entropy: no table\n");
        exit(1);
    }
    for (s = 0; s <= max; ++s)
    {
        int k, times = norm[s] < 0 ? -norm[s] : norm[s];
        for (k = 0; k < times; ++k)
            pool[p++] = (uint8_t)s;
    }
    n = Next() % 600;
    for (i = 0; i < n; ++i)
        symbols[i] = pool[Next() % p];
    room = n + (n >> 7) + 12 + Next() % 64;
    if (Next() % 3 == 0)
        room = Next() % (n + 16);
    answer = FSE_compress_usingCTable(out, room, symbols, n, ct);
    AddNumber(Code(answer));
    Add(out, answer);
    ++g_outputs;
}

static uint8_t g_lit[140000], g_out[150000];
static size_t g_lit_len;

/* Made-up literals of one of six kinds. */
static void MakeLiterals(uint8_t *buf, size_t len)
{
    uint32_t shape = Next() % 6, m, value;
    size_t i;
    switch (shape)
    {
        case 0: /* one value */
            value = Next();
            memset(buf, (int)(value & 0xFF), len);
            break;
        case 1: /* a few low values */
            m = 2 + Next() % 15;
            for (i = 0; i < len; ++i)
                buf[i] = (uint8_t)(Next() % m);
            break;
        case 2: /* values with few bits set more often */
            for (i = 0; i < len; ++i)
            {
                value = Next();
                buf[i] = (uint8_t)(value & (value >> 8) & (value >> 16));
            }
            break;
        case 3: /* noise */
            for (i = 0; i < len; ++i)
                buf[i] = (uint8_t)(Next() >> 13);
            break;
        case 4: /* letters and spaces */
            for (i = 0; i < len; ++i)
            {
                value = Next();
                buf[i] = (uint8_t)(value % 7 == 0 ? ' ' : 'a' + (value >> 8) % 26);
            }
            break;
        default: /* a few low values, then noise */
            m = 2 + Next() % 15;
            for (i = 0; i < len; ++i)
            {
                value = Next();
                buf[i] = (uint8_t)(i < len / 2 ? value % m : value >> 13);
            }
            break;
    }
}

static HUF_CElt g_huf_table[HUF_CTABLE_SIZE_ST(255)];
static U64 g_huf_wksp[HUF_WORKSPACE_SIZE_U64];
static int g_fresh;

static void TryHuf(void)
{
    int again = 0, four, prefer, suspect;
    HUF_repeat repeat;
    size_t room, answer;
    if (g_fresh)
        again = Next() % 4 == 0;
    if (again)
        repeat = Next() % 2 ? HUF_repeat_valid : HUF_repeat_check;
    else
    {
        uint32_t r = Next() % 8;
        uint32_t pick = Next();
        g_lit_len = r == 0 ? pick % 70 : r < 3 ? 40 + pick % 300 : r < 5 ? pick % 3000 : r == 5 ? 900 + pick % 300 : r == 6 ? 16000 + pick % 1000 : pick % 131200;
        MakeLiterals(g_lit, g_lit_len);
        repeat = Next() % 3 == 0 ? HUF_repeat_check : HUF_repeat_none;
    }
    four = (int)(Next() & 1);
    prefer = (int)(Next() & 1);
    suspect = (int)(Next() & 1);
    room = g_lit_len + (g_lit_len >> 8) + 200;
    if (Next() % 3 == 0)
        room = Next() % (g_lit_len + 32);
    answer = (four ? HUF_compress4X_repeat : HUF_compress1X_repeat)(g_out, room, g_lit, g_lit_len, 255, 11, g_huf_wksp, sizeof(g_huf_wksp), g_huf_table, &repeat, (prefer ? HUF_flags_preferRepeat : 0) | (suspect ? HUF_flags_suspectUncompressible : 0));
    AddNumber(Code(answer));
    AddNumber((uint32_t)repeat);
    if (ERR_isError(answer))
        ++g_errors;
    else
    {
        Add(g_out, answer);
        ++g_outputs;
    }
    /* A new table was made and used: it has a code for every byte of these literals. */
    g_fresh = !ERR_isError(answer) && answer > 1 && repeat == HUF_repeat_none;
}

static ZSTD_hufCTables_t g_prev, g_next;

static void TryLiterals(void)
{
    uint32_t r = Next() % 6;
    uint32_t pick = Next();
    size_t len = r == 0 ? pick % 70 : r == 1 ? 60 + pick % 10 : r == 2 ? pick % 2000 : r == 3 ? 1000 + pick % 50 : r == 4 ? 16370 + pick % 30 : pick % 70000;
    int strategy, disable, suspect;
    size_t room, answer;
    /* The literals of the Huffman rounds are gone: no going over them again. */
    g_lit_len = len;
    g_fresh = 0;
    MakeLiterals(g_lit, len);
    strategy = 1 + (int)(Next() % 2);
    disable = Next() % 8 == 0;
    suspect = (int)(Next() & 1);
    room = len + 300;
    if (Next() % 3 == 0)
        room = Next() % (len + 16);
    answer = ZSTD_compressLiterals(g_out, room, g_lit, len, g_huf_wksp, sizeof(g_huf_wksp), &g_prev, &g_next, (ZSTD_strategy)strategy, disable, suspect, 0);
    AddNumber(Code(answer));
    AddNumber((uint32_t)g_next.repeatMode);
    if (ERR_isError(answer))
        ++g_errors;
    else
    {
        Add(g_out, answer);
        ++g_outputs;
        /* As a block that is kept does: the tables of this one are the next one's. */
        if (Next() % 2)
        {
            ZSTD_hufCTables_t keep = g_prev;
            g_prev = g_next;
            g_next = keep;
        }
    }
}

int main(int argc, char **argv)
{
    uint32_t count, i;
    if (argc < 4 || strcmp(argv[1], "zstd_entropy") != 0)
    {
        fprintf(stderr, "usage: dump zstd_entropy <seed> <count>\n");
        return 2;
    }
    g_state = strtoull(argv[2], NULL, 10);
    count = (uint32_t)strtoul(argv[3], NULL, 10);
    for (i = 0; i < count; ++i)
    {
        uint32_t what = Next() % 20;
        if (what < 12)
            TryFse();
        else if (what < 17)
            TryHuf();
        else
            TryLiterals();
        if ((i + 1) % 1000 == 0 || i + 1 == count)
            printf("%s %u %016llx\n", argv[1], i + 1, (unsigned long long)g_hash);
    }
    printf("%s outputs: %u, refused: %u\n", argv[1], g_outputs, g_errors);
    return 0;
}
