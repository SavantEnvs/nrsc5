// Shared helpers for the nrsc5 fuzz harnesses.
#pragma once
#include <stdint.h>
#include <string.h>
#include <nrsc5.h>

static volatile size_t fuzz_sink;

static void fuzz_touch_str(const char *s)
{
    if (s)
        fuzz_sink += strlen(s);
}

static void fuzz_touch_buf(const uint8_t *p, size_t n)
{
    size_t acc = 0;
    if (!p)
        return;
    for (size_t i = 0; i < n; i++)
        acc += p[i];
    fuzz_sink += acc;
}

// Read every string/buffer the library hands to the application, so ASan checks what a real
// client (the nrsc5 CLI) would read.
static void fuzz_callback(const nrsc5_event_t *evt, void *opaque)
{
    (void)opaque;
    switch (evt->event)
    {
    case NRSC5_EVENT_ID3:
        fuzz_touch_str(evt->id3.title);
        fuzz_touch_str(evt->id3.artist);
        fuzz_touch_str(evt->id3.album);
        fuzz_touch_str(evt->id3.genre);
        fuzz_touch_str(evt->id3.ufid.owner);
        fuzz_touch_str(evt->id3.ufid.id);
        for (nrsc5_id3_comment_t *c = evt->id3.comments; c; c = c->next)
        {
            fuzz_touch_str(c->lang);
            fuzz_touch_str(c->short_content_desc);
            fuzz_touch_str(c->full_text);
        }
        fuzz_touch_str(evt->id3.commercial.price);
        fuzz_touch_str(evt->id3.commercial.contact_url);
        fuzz_touch_str(evt->id3.commercial.seller);
        fuzz_touch_str(evt->id3.commercial.description);
        break;
    case NRSC5_EVENT_SIG:
        for (nrsc5_sig_service_t *s = evt->sig.services; s; s = s->next)
        {
            fuzz_touch_str(s->name);
            for (nrsc5_sig_component_t *c = s->components; c; c = c->next)
                fuzz_sink += c->type;
        }
        break;
    case NRSC5_EVENT_LOT:
    case NRSC5_EVENT_LOT_HEADER:
        fuzz_touch_str(evt->lot.name);
        if (evt->event == NRSC5_EVENT_LOT)
            fuzz_touch_buf(evt->lot.data, evt->lot.size);
        break;
    case NRSC5_EVENT_LOT_FRAGMENT:
        fuzz_touch_buf(evt->lot_fragment.data, evt->lot_fragment.size);
        break;
    case NRSC5_EVENT_STREAM:
        fuzz_touch_buf(evt->stream.data, evt->stream.size);
        break;
    case NRSC5_EVENT_PACKET:
        fuzz_touch_buf(evt->packet.data, evt->packet.size);
        break;
    case NRSC5_EVENT_HERE_IMAGE:
        fuzz_touch_str(evt->here_image.name);
        fuzz_touch_buf(evt->here_image.data, evt->here_image.size);
        break;
    case NRSC5_EVENT_SIS:
        fuzz_touch_str(evt->sis.country_code);
        fuzz_touch_str(evt->sis.name);
        fuzz_touch_str(evt->sis.slogan);
        fuzz_touch_str(evt->sis.message);
        fuzz_touch_str(evt->sis.alert);
        break;
    case NRSC5_EVENT_STATION_ID:
        fuzz_touch_str(evt->station_id.country_code);
        break;
    case NRSC5_EVENT_STATION_NAME:
        fuzz_touch_str(evt->station_name.name);
        break;
    case NRSC5_EVENT_STATION_SLOGAN:
        fuzz_touch_str(evt->station_slogan.slogan);
        break;
    case NRSC5_EVENT_STATION_MESSAGE:
        fuzz_touch_str(evt->station_message.message);
        break;
    case NRSC5_EVENT_EMERGENCY_ALERT:
        fuzz_touch_str(evt->emergency_alert.message);
        fuzz_touch_buf(evt->emergency_alert.control_data, evt->emergency_alert.control_data_length);
        break;
    case NRSC5_EVENT_HDC:
        fuzz_touch_buf(evt->hdc.data, evt->hdc.count);
        break;
    case NRSC5_EVENT_AUDIO:
        fuzz_touch_buf((const uint8_t *)evt->audio.data, evt->audio.count * sizeof(int16_t));
        break;
    case NRSC5_EVENT_EXCITER_INFO:
        fuzz_touch_str(evt->exciter_info.manufacturer_id);
        break;
    case NRSC5_EVENT_IMPORTER_INFO:
        fuzz_touch_str(evt->importer_info.manufacturer_id);
        break;
    default:
        break;
    }
}
