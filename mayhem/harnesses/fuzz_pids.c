// Fuzz the PIDS / SIS (Station Information Service) decoder: pids_frame_push() receives one 80-bit
// PIDS frame (one bit per byte, after Viterbi) and, once its CRC12 checks, decodes station ID, names,
// slogan, message, location, service descriptors, parameters and emergency alerts (sis_decode).
//
// Input: consecutive 10-byte groups, each unpacked MSB-first into 80 bits and pushed as one frame to
// ONE fresh receiver (names/messages/alerts are reassembled across frames). The CRC12 is a
// transmission integrity check computed by the transmitter, not part of the SIS format the decoder
// interprets, and the fuzzer cannot reach any SIS parsing without it, so when the first input byte
// has its low bit set the harness writes the correct CRC12 (the same polynomial as pids.c) into each
// frame's last 12 bits; with it clear the frames are pushed unmodified (the CRC-reject path).
#include "private.h"
#include "fuzz_common.h"

// Transmit-side CRC12 over the 68 payload bits, mirroring pids.c:crc12(). `bits` is in the decoder's
// post-reorder order (pids[] in pids_frame_push).
static uint16_t tx_crc12(const uint8_t *bits)
{
    uint16_t poly = 0xD010, reg = 0;
    for (int i = 67; i >= 0; i--)
    {
        int lowbit = reg & 1;
        reg >>= 1;
        reg ^= ((uint16_t)bits[i] << 15);
        if (lowbit) reg ^= poly;
    }
    for (int i = 0; i < 16; i++)
    {
        int lowbit = reg & 1;
        reg >>= 1;
        if (lowbit) reg ^= poly;
    }
    return (reg ^ 0x955) & 0xfff;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 + PIDS_FRAME_LEN / 8)
        return -1;
    const int fix_crc = data[0] & 1;
    data++;
    size--;

    nrsc5_t *st;
    if (nrsc5_open_pipe(&st) != 0)
        return 0;
    nrsc5_set_callback(st, fuzz_callback, NULL);

    for (size_t off = 0; off + PIDS_FRAME_LEN / 8 <= size; off += PIDS_FRAME_LEN / 8)
    {
        uint8_t pids[PIDS_FRAME_LEN], bits[PIDS_FRAME_LEN];
        for (int i = 0; i < PIDS_FRAME_LEN; i++)
            pids[i] = (data[off + (i >> 3)] >> (7 - (i & 7))) & 1;
        if (fix_crc)
        {
            uint16_t crc = tx_crc12(pids);
            for (int i = 0; i < 12; i++)
                pids[68 + i] = (crc >> (11 - i)) & 1;
        }
        // pids_frame_push reverses the bit order within each byte; apply the inverse.
        for (int i = 0; i < PIDS_FRAME_LEN; i++)
            bits[((i >> 3) << 3) + 7 - (i & 7)] = pids[i];
        pids_frame_push(&st->input.decode.pids, bits);
    }

    nrsc5_close(st);
    return 0;
}
