/* The reference decoder of zstd (doc/educational_decoder/zstd_decompress.c), built so that it
   can be called on damaged frames: where it stops the program with a message, this gives the
   message back. Its names are changed so that it can stand beside the zstd library, which
   compare/dump_zstd.c uses to make the frames. */
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static jmp_buf g_jump;
static const char *g_message;

/* What the decoder's ERROR macro calls: fprintf(stderr, "Error: %s\n", s), then exit(1). */
static int EduMessage(FILE *file, const char *format, const char *message)
{
    (void)file;
    (void)format;
    g_message = message;
    return 0;
}
static void EduStop(int code) __attribute__((noreturn));
static void EduStop(int code)
{
    (void)code;
    longjmp(g_jump, 1);
}

#define fprintf(...) EduMessage(__VA_ARGS__)
#define exit(code) EduStop(code)
#define ZSTD_decompress edu_ZSTD_decompress
#define ZSTD_decompress_with_dict edu_ZSTD_decompress_with_dict
#define ZSTD_get_decompressed_size edu_ZSTD_get_decompressed_size
#define create_dictionary edu_create_dictionary
#define parse_dictionary edu_parse_dictionary
#define free_dictionary edu_free_dictionary
#include "zstd_decompress.c"
#undef fprintf
#undef exit

/* Decodes a frame into `dst` (which is to hold zeros), with a dictionary when `dict` is not
   null. Gives the number of bytes, or -1 with the decoder's message. */
int64_t EduDecompress(uint8_t *dst, size_t dst_len, const uint8_t *src, size_t src_len, const uint8_t *dict, size_t dict_len, const char **message)
{
    dictionary_t *volatile parsed = NULL;
    size_t size;
    if (setjmp(g_jump))
    {
        *message = g_message;
        return -1;
    }
    parsed = edu_create_dictionary();
    if (dict)
        edu_parse_dictionary(parsed, dict, dict_len);
    size = edu_ZSTD_decompress_with_dict(dst, dst_len, src, src_len, parsed);
    edu_free_dictionary(parsed);
    return (int64_t)size;
}

/* The size a frame's header gives: -1 with the decoder's message, -2 when the header gives
   none. */
int64_t EduSize(const uint8_t *src, size_t src_len, const char **message)
{
    size_t size;
    if (setjmp(g_jump))
    {
        *message = g_message;
        return -1;
    }
    size = edu_ZSTD_get_decompressed_size(src, src_len);
    return size == (size_t)-1 ? -2 : (int64_t)size;
}
