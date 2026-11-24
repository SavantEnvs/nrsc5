// Fuzz the public sample-input API, the path `nrsc5 -r <iq file>` and rtl_tcp/RTL-SDR samples take:
// nrsc5_pipe_samples_cu8 / nrsc5_pipe_samples_cs16 -> input.c (resampling, AGC, decimation) ->
// acquire.c (FFT, symbol/CFO acquisition) -> sync.c -> decode.c -> frame.c.
//
// Input: byte 0 bit 0 selects FM/AM mode, bit 1 selects cu8 vs cs16 samples; the rest is IQ data.
#include <stdlib.h>
#include <nrsc5.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    const uint8_t ctl = data[0];
    data++;
    size--;

    nrsc5_t *st;
    if (nrsc5_open_pipe(&st) != 0)
        return 0;
    nrsc5_set_callback(st, fuzz_callback, NULL);
    nrsc5_set_mode(st, (ctl & 1) ? NRSC5_MODE_AM : NRSC5_MODE_FM);

    if (ctl & 2)
    {
        size_t n = size / sizeof(int16_t);
        int16_t *s = malloc(n * sizeof(int16_t) + 1);
        memcpy(s, data, n * sizeof(int16_t));
        nrsc5_pipe_samples_cs16(st, s, (unsigned int)n);
        free(s);
    }
    else
    {
        nrsc5_pipe_samples_cu8(st, data, (unsigned int)size);
    }

    nrsc5_close(st);
    return 0;
}
