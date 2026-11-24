// Fuzz the AAS (Advanced Application Services) PDU layer: output_aas_push() is what frame.c hands
// every HDLC frame that passed its FCS16 check (protocol byte and FCS already stripped). It dispatches
// by port to ID3/PSD tags (output_id3 -> unicode.c), the Station Information Guide (parse_sig) and
// LOT/stream/packet ports (process_port -> here_images.c). A fuzzer cannot synthesise an FCS-valid
// frame through Viterbi+RS from raw IQ, so this is the layer boundary where radio bytes are parsed.
//
// Input: a sequence of records, each `len_lo len_hi payload[len]` (payload = port(2) seq(2) data;
// any length, including < 4, is delivered; payloads are capped at MAX_AAS_LEN-3 like parse_hdlc).
// All records go to ONE fresh receiver, so a SIG record can declare the port a later LOT record uses;
// state never outlives the input (nrsc5_open_pipe/nrsc5_close per input).
#include <stdlib.h>
#include <string.h>
#include "private.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nrsc5_t *st;
    if (nrsc5_open_pipe(&st) != 0)
        return 0;
    nrsc5_set_callback(st, fuzz_callback, NULL);

    static uint8_t buf[MAX_AAS_LEN];
    size_t off = 0;
    while (off + 2 <= size)
    {
        size_t len = data[off] | (data[off + 1] << 8);
        off += 2;
        if (len > size - off)
            len = size - off;
        // Model aas_push() in frame.c: the PDU sits at offset 1 of a MAX_AAS_LEN HDLC buffer (after
        // the 0x21 protocol byte) and len = frame length - 3, so it ranges 0..MAX_AAS_LEN-3. aas_push
        // does not check len >= 4, so short records are passed through as the library receives them.
        size_t plen = len > MAX_AAS_LEN - 3 ? MAX_AAS_LEN - 3 : len;
        memset(buf, 0, sizeof(buf));
        memcpy(buf + 1, data + off, plen);
        output_aas_push(&st->output, buf + 1, (unsigned int)plen);
        off += len;
    }

    nrsc5_close(st);
    return 0;
}
