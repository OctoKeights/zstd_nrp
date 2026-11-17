/* The C half of the comparison with zstd (https://github.com/facebook/zstd). examples/dump.rs
   prints the same from the Rust port, and compare/compare.sh compares the two.

     dump zstd_decode <seed> <count> <file>         made-up data of eight kinds compressed by
                                                    the zstd library into frames of every
                                                    kind: every level from the fastest to 22,
                                                    with and without checksums, sizes in the
                                                    header, small windows, long-distance
                                                    matching, blocks of a size aimed for,
                                                    flushes, and dictionaries of plain content
                                                    and trained ones; a third of the frames
                                                    then damaged. Each is written to the file,
                                                    for the Rust side to read, and decoded by
                                                    the reference decoder (compare/
                                                    dump_zstd_edu.c): a running hash of what
                                                    comes out, or of the message it stops with
     dump zstd_decode_small <seed> <count> <file>   the same with little data in each, for a
                                                    file small enough to keep (tests/data) */
#define ZSTD_STATIC_LINKING_ONLY
#include "zdict.h"
#include "zstd.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int64_t EduDecompress(uint8_t *dst, size_t dst_len, const uint8_t *src, size_t src_len, const uint8_t *dict, size_t dict_len, const char **message);
int64_t EduSize(const uint8_t *src, size_t src_len, const char **message);

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

/* Made-up bytes of one of eight kinds. */
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
                if (at < 64 || Next() % 4 == 0)
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
        default: /* stretches of noise, of one value and of counting */
            while (at < len)
            {
                uint32_t stretch = 1 + Next() % 2000, what = Next() % 3, value = Next();
                for (i = 0; i < stretch && at < len; ++i, ++at)
                    buf[at] = (uint8_t)(what == 0 ? Next() >> 11 : what == 1 ? value : value + i);
            }
            break;
    }
}

static void WriteNumber(FILE *file, uint32_t value)
{
    unsigned char bytes[4];
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
    fwrite(bytes, 1, 4, file);
}

#define MAX_DATA 700000

int main(int argc, char **argv)
{
    uint32_t count, i, k, decoded = 0, refused = 0;
    uint8_t *data = (uint8_t *)malloc(MAX_DATA), *room = (uint8_t *)malloc(MAX_DATA + 1024), *frame, *dict = (uint8_t *)malloc(70000), *samples = (uint8_t *)malloc(400000);
    const size_t frame_room = ZSTD_compressBound(MAX_DATA) + 4096;
    uint64_t in_total = 0, frame_total = 0;
    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    FILE *file;
    int small;
    if (argc < 5 || (strcmp(argv[1], "zstd_decode") != 0 && strcmp(argv[1], "zstd_decode_small") != 0))
    {
        fprintf(stderr, "usage: dump zstd_decode|zstd_decode_small <seed> <count> <file>\n");
        return 2;
    }
    small = strcmp(argv[1], "zstd_decode_small") == 0;
    g_state = strtoull(argv[2], NULL, 10);
    count = (uint32_t)strtoul(argv[3], NULL, 10);
    file = fopen(argv[4], "wb");
    if (!file)
    {
        fprintf(stderr, "cannot write %s\n", argv[4]);
        return 2;
    }
    frame = (uint8_t *)malloc(frame_room);
    for (i = 0; i < count; ++i)
    {
        const uint32_t kind = Next() % 8;
        size_t len, frame_size, dict_size = 0, dst_len;
        int level;
        const char *message = "";
        int64_t size;
        uint32_t what_dict;
        int sound = 1;

        /* How much data: little, or up to several blocks' worth. */
        switch (Next() % 8)
        {
            case 0: len = Next() % 16; break;
            case 1: len = Next() % 300; break;
            case 2:
            case 3: len = Next() % (small ? 1500 : 5000); break;
            case 4:
            case 5: len = Next() % (small ? 2500 : 40000); break;
            case 6: len = small ? Next() % 4000 : 60000 + Next() % 20000; break;
            default:
                /* (Several blocks: in the small file only of data that packs to little.) */
                if (small)
                    len = (kind == 3 || kind == 5 || kind == 6) && Next() % 4 == 0 ? 130000 + Next() % 200000 : Next() % 3000;
                else
                    len = Next() % 4 == 0 ? 300000 + Next() % 400000 : Next() % 200000;
                break;
        }
        FillData(data, len, kind);

        /* A dictionary: none, plain content, or one trained from samples of the same kind. */
        what_dict = Next() % 6;
        if (what_dict == 0)
        {
            dict_size = 8 + Next() % (small ? 400 : 20000);
            FillData(dict, dict_size, kind);
        }
        else if (what_dict == 1)
        {
            size_t sizes[64], total = 0;
            for (k = 0; k < 64; ++k)
            {
                sizes[k] = 200 + Next() % 4000;
                total += sizes[k];
            }
            FillData(samples, total, kind);
            dict_size = ZDICT_trainFromBuffer(dict, small ? 600 : 8000 + Next() % 50000, samples, sizes, 64);
            if (ZDICT_isError(dict_size))
                dict_size = 0;
        }

        /* The frame. */
        level = Next() % 4 == 0 ? -1 - (int)(Next() % 7) : 1 + (int)(Next() % 22);
        ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, Next() % 3 == 0);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, Next() % 4 != 0);
        if (Next() % 4 == 0)
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, 10 + (int)(Next() % 8));
        if (Next() % 6 == 0)
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_enableLongDistanceMatching, 1);
        if (Next() % 8 == 0)
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_targetCBlockSize, 100 + (int)(Next() % 2000));
        if (Next() % 16 == 0)
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_dictIDFlag, 0);
        if (dict_size)
            ZSTD_CCtx_loadDictionary(cctx, dict, dict_size);
        if (Next() % 5 == 0)
        {
            /* In pieces, with the blocks ended between them. */
            ZSTD_inBuffer in = { data, 0, 0 };
            ZSTD_outBuffer out = { frame, frame_room, 0 };
            size_t left = 1;
            while (in.size < len)
            {
                in.size += 1 + Next() % (len / 3 + 1);
                if (in.size > len)
                    in.size = len;
                ZSTD_compressStream2(cctx, &out, &in, ZSTD_e_flush);
            }
            while (left)
                left = ZSTD_compressStream2(cctx, &out, &in, ZSTD_e_end);
            frame_size = out.pos;
        }
        else
            frame_size = ZSTD_compress2(cctx, frame, frame_room, data, len);
        if (ZSTD_isError(frame_size))
        {
            fprintf(stderr, "zstd: %s\n", ZSTD_getErrorName(frame_size));
            return 2;
        }

        /* Now and then decoded with the wrong dictionary, or with none. */
        if (dict_size && Next() % 10 == 0)
        {
            sound = 0;
            if (Next() % 2)
                dict_size = 0;
            else
                FillData(dict, dict_size, 0);
        }
        /* A third of them damaged: bits turned over, the end cut off, or a byte made up. */
        if (Next() % 3 == 0)
        {
            const uint32_t how = Next() % 4;
            sound = 0;
            if (how == 0)
            {
                for (k = 1 + Next() % 3; k > 0; --k)
                {
                    const uint32_t bit = Next() % (uint32_t)(frame_size * 8);
                    frame[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
                }
            }
            else if (how == 1)
                frame_size = Next() % frame_size;
            else if (how == 2)
                frame[Next() % (uint32_t)frame_size] = (uint8_t)Next();
            else
            {
                const uint32_t bit = Next() % (uint32_t)((frame_size < 24 ? frame_size : 24) * 8);
                frame[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
            }
        }
        /* Room for what it was, or now and then a byte less, or more. */
        switch (Next() % 16)
        {
            case 0: dst_len = len ? len - 1 : 0; break;
            case 1: dst_len = len + 1 + Next() % 1000; break;
            default: dst_len = len; break;
        }

        WriteNumber(file, (uint32_t)dst_len);
        WriteNumber(file, (uint32_t)dict_size);
        fwrite(dict, 1, dict_size, file);
        WriteNumber(file, (uint32_t)frame_size);
        fwrite(frame, 1, frame_size, file);
        in_total += len;
        frame_total += frame_size;

        size = EduSize(frame, frame_size, &message);
        AddNumber((uint32_t)size);
        AddNumber((uint32_t)((uint64_t)size >> 32));
        if (size == -1)
            Add(message, strlen(message) + 1);
        memset(room, 0, dst_len);
        size = EduDecompress(room, dst_len, frame, frame_size, dict_size ? dict : NULL, dict_size, &message);
        AddNumber((uint32_t)size);
        if (size >= 0)
        {
            Add(room, (size_t)size);
            ++decoded;
        }
        else
        {
            Add(message, strlen(message) + 1);
            ++refused;
#ifdef SHOW_REASONS
            fprintf(stderr, "%s\n", message);
#endif
        }
        /* A sound frame with room enough has to come back as the data it was made from. */
        if (sound && dst_len >= len && (size != (int64_t)len || memcmp(room, data, len) != 0))
        {
            fprintf(stderr, "%s: frame %u is sound and the reference decoder does not give its data back (%s)\n", argv[1], i, size < 0 ? message : "other bytes");
            return 3;
        }

        if ((i + 1) % 200 == 0 || i + 1 == count)
            printf("%s %u %016llx\n", argv[1], i + 1, (unsigned long long)g_hash);
    }
    (void)in_total;
    printf("%s bytes of frames: %llu; decoded: %u, refused: %u\n", argv[1], (unsigned long long)frame_total, decoded, refused);
    fclose(file);
    return 0;
}
