// Fuzz the L2 frame layer: frame_push() receives one decoded (post-Viterbi, descrambled) logical
// channel frame, one bit per byte, exactly as decode.c delivers it. From there frame.c parses the PCI,
// RS-corrected PDU headers, header expansion fields, HDLC/FCS16-framed PSD (-> output_aas_push) and
// fixed CCC data, and assembles HDC audio packets for output.c/FAAD2.
//
// Input: byte 0 selects the frame type (and thus the frame length, logical channel and FM/AM mode);
// the remaining bytes are unpacked MSB-first into bits and fed as consecutive frames of that type
// (the last frame zero-padded). One fresh receiver per input.
#include <stdlib.h>
#include "private.h"
#include "fuzz_common.h"

static const struct {
    size_t len;
    logical_channel_t lc;
    int mode;
} kinds[] = {
    { P1_FRAME_LEN_FM, P1_LOGICAL_CHANNEL, NRSC5_MODE_FM },
    { P3_FRAME_LEN_MP3_MP11, P3_LOGICAL_CHANNEL, NRSC5_MODE_FM },
    { P3_FRAME_LEN_MP2, P3_LOGICAL_CHANNEL, NRSC5_MODE_FM },
    { P3_FRAME_LEN_MP3_MP11, P4_LOGICAL_CHANNEL, NRSC5_MODE_FM },
    { P1_FRAME_LEN_AM, P1_LOGICAL_CHANNEL, NRSC5_MODE_AM },
    { P3_FRAME_LEN_MA1, P3_LOGICAL_CHANNEL, NRSC5_MODE_AM },
    { P3_FRAME_LEN_MA3, P3_LOGICAL_CHANNEL, NRSC5_MODE_AM },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return -1;
    const unsigned k = data[0] % (sizeof(kinds) / sizeof(kinds[0]));
    data++;
    size--;

    nrsc5_t *st;
    if (nrsc5_open_pipe(&st) != 0)
        return 0;
    nrsc5_set_callback(st, fuzz_callback, NULL);
    nrsc5_set_mode(st, kinds[k].mode);

    const size_t flen = kinds[k].len;
    uint8_t *bits = malloc(flen);
    size_t bitpos = 0, total = size * 8;
    while (bitpos < total)
    {
        for (size_t i = 0; i < flen; i++, bitpos++)
            bits[i] = bitpos < total ? (data[bitpos >> 3] >> (7 - (bitpos & 7))) & 1 : 0;
        frame_push(&st->input.frame, bits, flen, kinds[k].lc);
    }
    free(bits);
    nrsc5_close(st);
    return 0;
}
