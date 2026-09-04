#define _GNU_SOURCE

#include "wf_ov2_protocol.h"

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static const uint8_t wf_magic[8] = {'W', 'F', '5', '0', 'D', '2', '2', 'A'};
static const uint8_t wf_packet_domain[] = "worldforge-ollama-v2-d22a-packet-v1";

struct wf_sha256_state {
    uint32_t words[8];
    uint64_t length;
    uint8_t block[64];
    size_t used;
};

static const uint32_t wf_sha256_k[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf), UINT32_C(0xe9b5dba5),
    UINT32_C(0x3956c25b), UINT32_C(0x59f111f1), UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5),
    UINT32_C(0xd807aa98), UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7), UINT32_C(0xc19bf174),
    UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786), UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc),
    UINT32_C(0x2de92c6f), UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8), UINT32_C(0xbf597fc7),
    UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147), UINT32_C(0x06ca6351), UINT32_C(0x14292967),
    UINT32_C(0x27b70a85), UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e), UINT32_C(0x92722c85),
    UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b), UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3),
    UINT32_C(0xd192e819), UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c), UINT32_C(0x34b0bcb5),
    UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a), UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3),
    UINT32_C(0x748f82ee), UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7), UINT32_C(0xc67178f2),
};

static uint32_t wf_rotr(uint32_t value, unsigned int shift) {
    return (value >> shift) | (value << (32u - shift));
}

static uint16_t wf_load_u16(const uint8_t *value) {
    return (uint16_t)(((uint16_t)value[0] << 8u) | (uint16_t)value[1]);
}

static uint32_t wf_load_u32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24u) | ((uint32_t)value[1] << 16u) |
           ((uint32_t)value[2] << 8u) | (uint32_t)value[3];
}

static uint64_t wf_load_u64(const uint8_t *value) {
    uint64_t result = 0;
    size_t index;
    for (index = 0; index < 8u; ++index) {
        result = (result << 8u) | (uint64_t)value[index];
    }
    return result;
}

static void wf_store_u16(uint8_t *target, uint16_t value) {
    target[0] = (uint8_t)(value >> 8u);
    target[1] = (uint8_t)value;
}

static void wf_store_u32(uint8_t *target, uint32_t value) {
    target[0] = (uint8_t)(value >> 24u);
    target[1] = (uint8_t)(value >> 16u);
    target[2] = (uint8_t)(value >> 8u);
    target[3] = (uint8_t)value;
}

static void wf_store_u64(uint8_t *target, uint64_t value) {
    size_t index;
    for (index = 0; index < 8u; ++index) {
        target[7u - index] = (uint8_t)value;
        value >>= 8u;
    }
}

static int wf_bytes_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < length; ++index) {
        difference = (uint8_t)(difference | (uint8_t)(left[index] ^ right[index]));
    }
    return difference == 0u;
}

static void wf_bytes_copy(uint8_t *target, const uint8_t *source, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        target[index] = source[index];
    }
}

static void wf_bytes_zero(uint8_t *target, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        target[index] = 0u;
    }
}

static void wf_sha256_transform(struct wf_sha256_state *state, const uint8_t block[64]) {
    uint32_t schedule[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    size_t index;
    for (index = 0; index < 16u; ++index) {
        schedule[index] = wf_load_u32(block + (index * 4u));
    }
    for (index = 16u; index < 64u; ++index) {
        uint32_t s0 = wf_rotr(schedule[index - 15u], 7u) ^
                      wf_rotr(schedule[index - 15u], 18u) ^
                      (schedule[index - 15u] >> 3u);
        uint32_t s1 = wf_rotr(schedule[index - 2u], 17u) ^
                      wf_rotr(schedule[index - 2u], 19u) ^
                      (schedule[index - 2u] >> 10u);
        schedule[index] = schedule[index - 16u] + s0 + schedule[index - 7u] + s1;
    }
    a = state->words[0]; b = state->words[1]; c = state->words[2]; d = state->words[3];
    e = state->words[4]; f = state->words[5]; g = state->words[6]; h = state->words[7];
    for (index = 0; index < 64u; ++index) {
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t sigma0 = wf_rotr(a, 2u) ^ wf_rotr(a, 13u) ^ wf_rotr(a, 22u);
        uint32_t sigma1 = wf_rotr(e, 6u) ^ wf_rotr(e, 11u) ^ wf_rotr(e, 25u);
        uint32_t temporary1 = h + sigma1 + choice + wf_sha256_k[index] + schedule[index];
        uint32_t temporary2 = sigma0 + majority;
        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    state->words[0] += a; state->words[1] += b; state->words[2] += c; state->words[3] += d;
    state->words[4] += e; state->words[5] += f; state->words[6] += g; state->words[7] += h;
}

static void wf_sha256_init(struct wf_sha256_state *state) {
    static const uint32_t initial[8] = {
        UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85), UINT32_C(0x3c6ef372), UINT32_C(0xa54ff53a),
        UINT32_C(0x510e527f), UINT32_C(0x9b05688c), UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19),
    };
    size_t index;
    for (index = 0; index < 8u; ++index) {
        state->words[index] = initial[index];
    }
    state->length = 0u;
    state->used = 0u;
    wf_bytes_zero(state->block, sizeof(state->block));
}

static void wf_sha256_update(struct wf_sha256_state *state, const uint8_t *input, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        state->block[state->used++] = input[index];
        if (state->used == sizeof(state->block)) {
            wf_sha256_transform(state, state->block);
            state->used = 0u;
        }
    }
    state->length += (uint64_t)length;
}

static void wf_sha256_finish(struct wf_sha256_state *state, uint8_t output[32]) {
    uint64_t bit_length = state->length * UINT64_C(8);
    size_t index;
    state->block[state->used++] = UINT8_C(0x80);
    if (state->used > 56u) {
        while (state->used < 64u) {
            state->block[state->used++] = 0u;
        }
        wf_sha256_transform(state, state->block);
        state->used = 0u;
    }
    while (state->used < 56u) {
        state->block[state->used++] = 0u;
    }
    wf_store_u64(state->block + 56u, bit_length);
    wf_sha256_transform(state, state->block);
    for (index = 0; index < 8u; ++index) {
        wf_store_u32(output + (index * 4u), state->words[index]);
    }
    wf_bytes_zero((uint8_t *)state, sizeof(*state));
}

enum wf_ov2_error wf_ov2_sha256(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[WF_OV2_SHA256_SIZE]
) {
    struct wf_sha256_state state;
    if ((input == NULL && input_length != 0u) || output == NULL) {
        return WF_OV2_ERR_ARGUMENT;
    }
    wf_sha256_init(&state);
    wf_sha256_update(&state, input, input_length);
    wf_sha256_finish(&state, output);
    return WF_OV2_OK;
}

enum wf_ov2_error wf_ov2_body_hash(
    const uint8_t *body,
    size_t body_length,
    uint8_t output[WF_OV2_SHA256_SIZE]
) {
    if (body_length > WF_OV2_MAX_BODY_SIZE) {
        return WF_OV2_ERR_ARGUMENT;
    }
    return wf_ov2_sha256(body, body_length, output);
}

enum wf_ov2_error wf_ov2_packet_hash(
    const struct wf_ov2_record *record,
    uint8_t output[WF_OV2_SHA256_SIZE]
) {
    struct wf_sha256_state state;
    static const uint8_t separator = 0u;
    if (record == NULL || output == NULL || record->length < WF_OV2_HEADER_SIZE ||
        record->length > WF_OV2_MAX_RECORD_SIZE) {
        return WF_OV2_ERR_ARGUMENT;
    }
    wf_sha256_init(&state);
    wf_sha256_update(&state, wf_packet_domain, sizeof(wf_packet_domain) - 1u);
    wf_sha256_update(&state, &separator, 1u);
    wf_sha256_update(&state, record->bytes, record->length);
    wf_sha256_finish(&state, output);
    return WF_OV2_OK;
}

uint64_t wf_ov2_boottime_ns(enum wf_ov2_error *error) {
    struct timespec value;
    if (error == NULL) {
        return 0u;
    }
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0) {
        *error = WF_OV2_ERR_IO;
        return 0u;
    }
    *error = WF_OV2_OK;
    return ((uint64_t)value.tv_sec * UINT64_C(1000000000)) + (uint64_t)value.tv_nsec;
}

static enum wf_ov2_error wf_check_deadline(uint64_t deadline_ns) {
    enum wf_ov2_error error;
    uint64_t now = wf_ov2_boottime_ns(&error);
    if (error != WF_OV2_OK) {
        return error;
    }
    if (deadline_ns <= now || deadline_ns - now > WF_OV2_MAX_DEADLINE_WINDOW_NS) {
        return WF_OV2_ERR_DEADLINE;
    }
    return WF_OV2_OK;
}

static enum wf_ov2_error wf_common_header(
    const struct wf_ov2_record *record,
    uint16_t message_type,
    uint32_t body_length
) {
    uint8_t computed[32];
    size_t index;
    if (record == NULL || record->length != WF_OV2_HEADER_SIZE + (size_t)body_length) {
        return WF_OV2_ERR_HEADER;
    }
    if (!wf_bytes_equal(record->bytes, wf_magic, sizeof(wf_magic)) ||
        wf_load_u16(record->bytes + 8u) != 1u ||
        wf_load_u16(record->bytes + 10u) != WF_OV2_HEADER_SIZE ||
        wf_load_u16(record->bytes + 12u) != message_type ||
        wf_load_u16(record->bytes + 14u) != 0u ||
        wf_load_u32(record->bytes + 24u) != body_length ||
        wf_load_u16(record->bytes + 28u) != 0u ||
        wf_load_u16(record->bytes + 30u) != 0u) {
        return WF_OV2_ERR_HEADER;
    }
    for (index = 0; index < 16u && record->bytes[32u + index] == 0u; ++index) {
    }
    if (index == 16u) {
        return WF_OV2_ERR_NONCE;
    }
    if (wf_ov2_body_hash(record->bytes + WF_OV2_HEADER_SIZE, body_length, computed) != WF_OV2_OK ||
        !wf_bytes_equal(computed, record->bytes + 88u, sizeof(computed))) {
        return WF_OV2_ERR_HASH;
    }
    return wf_check_deadline(wf_load_u64(record->bytes + 48u));
}

static void wf_header(
    struct wf_ov2_record *output,
    uint16_t type,
    uint64_t sequence,
    uint32_t body_length,
    const uint8_t nonce[16],
    uint64_t deadline_ns,
    const uint8_t prior_hash[32]
) {
    wf_bytes_zero(output->bytes, sizeof(output->bytes));
    wf_bytes_copy(output->bytes, wf_magic, sizeof(wf_magic));
    wf_store_u16(output->bytes + 8u, 1u);
    wf_store_u16(output->bytes + 10u, WF_OV2_HEADER_SIZE);
    wf_store_u16(output->bytes + 12u, type);
    wf_store_u64(output->bytes + 16u, sequence);
    wf_store_u32(output->bytes + 24u, body_length);
    wf_bytes_copy(output->bytes + 32u, nonce, 16u);
    wf_store_u64(output->bytes + 48u, deadline_ns);
    wf_bytes_copy(output->bytes + 56u, prior_hash, 32u);
    output->length = WF_OV2_HEADER_SIZE + (size_t)body_length;
}

enum wf_ov2_error wf_ov2_encode_negotiate(
    const uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t deadline_ns,
    struct wf_ov2_record *output
) {
    static const uint8_t zero_hash[32] = {0};
    uint8_t *body;
    enum wf_ov2_error error;
    size_t index;
    if (nonce == NULL || output == NULL) {
        return WF_OV2_ERR_ARGUMENT;
    }
    for (index = 0; index < 16u && nonce[index] == 0u; ++index) {
    }
    if (index == 16u) {
        return WF_OV2_ERR_NONCE;
    }
    error = wf_check_deadline(deadline_ns);
    if (error != WF_OV2_OK) {
        return error;
    }
    wf_header(output, WF_OV2_MSG_NEGOTIATE, 0u, WF_OV2_NEGOTIATE_BODY_SIZE,
              nonce, deadline_ns, zero_hash);
    body = output->bytes + WF_OV2_HEADER_SIZE;
    wf_store_u16(body, 1u); wf_store_u16(body + 2u, 1u);
    wf_store_u32(body + 4u, WF_OV2_MAX_BODY_SIZE);
    wf_store_u32(body + 8u, WF_OV2_MAX_RECORD_SIZE);
    wf_store_u16(body + 12u, 0u); wf_store_u16(body + 14u, 0u);
    wf_store_u16(body + 16u, WF_OV2_MSG_NEGOTIATE);
    wf_store_u16(body + 18u, WF_OV2_MSG_UNAVAILABLE_TERMINAL);
    wf_store_u16(body + 20u, 2u); wf_store_u16(body + 22u, 0u);
    return wf_ov2_body_hash(body, WF_OV2_NEGOTIATE_BODY_SIZE, output->bytes + 88u);
}

enum wf_ov2_error wf_ov2_decode_negotiate(
    const struct wf_ov2_record *record,
    uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t *deadline_ns
) {
    static const uint8_t zero_hash[32] = {0};
    const uint8_t *body;
    enum wf_ov2_error error = wf_common_header(record, WF_OV2_MSG_NEGOTIATE,
                                                WF_OV2_NEGOTIATE_BODY_SIZE);
    if (error != WF_OV2_OK || nonce == NULL || deadline_ns == NULL) {
        return error == WF_OV2_OK ? WF_OV2_ERR_ARGUMENT : error;
    }
    if (wf_load_u64(record->bytes + 16u) != 0u ||
        !wf_bytes_equal(record->bytes + 56u, zero_hash, sizeof(zero_hash))) {
        return WF_OV2_ERR_SEQUENCE;
    }
    body = record->bytes + WF_OV2_HEADER_SIZE;
    if (wf_load_u16(body) != 1u || wf_load_u16(body + 2u) != 1u ||
        wf_load_u32(body + 4u) != WF_OV2_MAX_BODY_SIZE ||
        wf_load_u32(body + 8u) != WF_OV2_MAX_RECORD_SIZE ||
        wf_load_u16(body + 12u) != 0u || wf_load_u16(body + 14u) != 0u ||
        wf_load_u16(body + 16u) != WF_OV2_MSG_NEGOTIATE ||
        wf_load_u16(body + 18u) != WF_OV2_MSG_UNAVAILABLE_TERMINAL ||
        wf_load_u16(body + 20u) != 2u || wf_load_u16(body + 22u) != 0u) {
        return WF_OV2_ERR_BODY;
    }
    wf_bytes_copy(nonce, record->bytes + 32u, 16u);
    *deadline_ns = wf_load_u64(record->bytes + 48u);
    return WF_OV2_OK;
}

enum wf_ov2_error wf_ov2_encode_unavailable(
    const uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t deadline_ns,
    const uint8_t request_hash[WF_OV2_SHA256_SIZE],
    struct wf_ov2_record *output
) {
    uint8_t *body;
    enum wf_ov2_error error;
    if (nonce == NULL || request_hash == NULL || output == NULL) {
        return WF_OV2_ERR_ARGUMENT;
    }
    error = wf_check_deadline(deadline_ns);
    if (error != WF_OV2_OK) {
        return error;
    }
    wf_header(output, WF_OV2_MSG_UNAVAILABLE_TERMINAL, 1u,
              WF_OV2_UNAVAILABLE_BODY_SIZE, nonce, deadline_ns, request_hash);
    body = output->bytes + WF_OV2_HEADER_SIZE;
    wf_store_u16(body, 1u);
    wf_store_u16(body + 2u, WF_OV2_TERMINAL_CLASS_UNAVAILABLE);
    wf_store_u32(body + 4u, WF_OV2_REASON_EFFECT_EXECUTION_UNAVAILABLE);
    wf_store_u64(body + 8u, 0u);
    wf_bytes_copy(body + 16u, request_hash, 32u);
    return wf_ov2_body_hash(body, WF_OV2_UNAVAILABLE_BODY_SIZE, output->bytes + 88u);
}

enum wf_ov2_error wf_ov2_decode_unavailable(
    const struct wf_ov2_record *record,
    const uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t deadline_ns,
    const uint8_t request_hash[WF_OV2_SHA256_SIZE]
) {
    const uint8_t *body;
    enum wf_ov2_error error = wf_common_header(record, WF_OV2_MSG_UNAVAILABLE_TERMINAL,
                                                WF_OV2_UNAVAILABLE_BODY_SIZE);
    if (error != WF_OV2_OK || nonce == NULL || request_hash == NULL) {
        return error == WF_OV2_OK ? WF_OV2_ERR_ARGUMENT : error;
    }
    if (wf_load_u64(record->bytes + 16u) != 1u ||
        wf_load_u64(record->bytes + 48u) != deadline_ns ||
        !wf_bytes_equal(record->bytes + 32u, nonce, 16u) ||
        !wf_bytes_equal(record->bytes + 56u, request_hash, 32u)) {
        return WF_OV2_ERR_SEQUENCE;
    }
    body = record->bytes + WF_OV2_HEADER_SIZE;
    if (wf_load_u16(body) != 1u ||
        wf_load_u16(body + 2u) != WF_OV2_TERMINAL_CLASS_UNAVAILABLE ||
        wf_load_u32(body + 4u) != WF_OV2_REASON_EFFECT_EXECUTION_UNAVAILABLE ||
        wf_load_u64(body + 8u) != 0u ||
        !wf_bytes_equal(body + 16u, request_hash, 32u)) {
        return WF_OV2_ERR_BODY;
    }
    return WF_OV2_OK;
}

enum wf_ov2_error wf_ov2_random_nonce(uint8_t nonce[WF_OV2_NONCE_SIZE]) {
    size_t offset = 0u;
    unsigned int attempts;
    if (nonce == NULL) {
        return WF_OV2_ERR_ARGUMENT;
    }
    while (offset < WF_OV2_NONCE_SIZE) {
        ssize_t count = getrandom(nonce + offset, WF_OV2_NONCE_SIZE - offset, 0u);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            wf_bytes_zero(nonce, WF_OV2_NONCE_SIZE);
            return WF_OV2_ERR_IO;
        }
        offset += (size_t)count;
    }
    for (attempts = 0u; attempts < WF_OV2_NONCE_SIZE && nonce[attempts] == 0u; ++attempts) {
    }
    return attempts == WF_OV2_NONCE_SIZE ? WF_OV2_ERR_NONCE : WF_OV2_OK;
}

enum wf_ov2_error wf_ov2_validate_seqpacket_fd(
    int descriptor,
    struct wf_ov2_peer_observation *observation
) {
    int value;
    socklen_t length;
    struct ucred peer;
    if (descriptor < 0 || observation == NULL) {
        return WF_OV2_ERR_ARGUMENT;
    }
    value = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &value, sizeof(value)) != 0) {
        return WF_OV2_ERR_SOCKET;
    }
    length = (socklen_t)sizeof(value);
    if (getsockopt(descriptor, SOL_SOCKET, SO_DOMAIN, &value, &length) != 0 ||
        length != (socklen_t)sizeof(value) || value != AF_UNIX) {
        return WF_OV2_ERR_SOCKET;
    }
    length = (socklen_t)sizeof(value);
    if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &value, &length) != 0 ||
        length != (socklen_t)sizeof(value) || value != SOCK_SEQPACKET) {
        return WF_OV2_ERR_SOCKET;
    }
    length = (socklen_t)sizeof(value);
    if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &value, &length) != 0 ||
        length != (socklen_t)sizeof(value) || value != 0) {
        return WF_OV2_ERR_SOCKET;
    }
    length = (socklen_t)sizeof(value);
    if (getsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &value, &length) != 0 ||
        length != (socklen_t)sizeof(value) || value != 1) {
        return WF_OV2_ERR_SOCKET;
    }
    length = (socklen_t)sizeof(peer);
    if (getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0 ||
        length != (socklen_t)sizeof(peer) || peer.pid <= 0) {
        return WF_OV2_ERR_SOCKET;
    }
    observation->socket_pid = (int64_t)peer.pid;
    observation->socket_uid = (uint32_t)peer.uid;
    observation->socket_gid = (uint32_t)peer.gid;
    observation->message_pid = 0;
    observation->message_uid = 0u;
    observation->message_gid = 0u;
    return WF_OV2_OK;
}

static enum wf_ov2_error wf_wait(
    int descriptor,
    short events,
    uint64_t deadline_ns,
    short *observed_revents
) {
    struct itimerspec timer_value;
    struct pollfd descriptors[2];
    int timer_descriptor;
    int result;
    enum wf_ov2_error error = wf_check_deadline(deadline_ns);
    if (observed_revents != NULL) {
        *observed_revents = 0;
    }
    if (error != WF_OV2_OK) {
        return error;
    }
    timer_descriptor = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timer_descriptor < 0) {
        return WF_OV2_ERR_IO;
    }
    timer_value.it_interval.tv_sec = 0;
    timer_value.it_interval.tv_nsec = 0;
    timer_value.it_value.tv_sec = (time_t)(deadline_ns / UINT64_C(1000000000));
    timer_value.it_value.tv_nsec = (long)(deadline_ns % UINT64_C(1000000000));
    if (timerfd_settime(timer_descriptor, TFD_TIMER_ABSTIME, &timer_value, NULL) != 0) {
        (void)close(timer_descriptor);
        return WF_OV2_ERR_IO;
    }
    descriptors[0].fd = descriptor;
    descriptors[0].events = events;
    descriptors[0].revents = 0;
    descriptors[1].fd = timer_descriptor;
    descriptors[1].events = POLLIN;
    descriptors[1].revents = 0;
    do {
        result = ppoll(descriptors, 2u, NULL, NULL);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        error = WF_OV2_ERR_IO;
    } else if ((descriptors[1].revents & POLLIN) != 0) {
        error = WF_OV2_ERR_DEADLINE;
    } else if ((descriptors[0].revents & (events | POLLHUP)) == 0 ||
               (descriptors[0].revents & (POLLERR | POLLNVAL)) != 0) {
        error = WF_OV2_ERR_IO;
    } else {
        error = wf_check_deadline(deadline_ns);
    }
    if (observed_revents != NULL) {
        *observed_revents = descriptors[0].revents;
    }
    (void)close(timer_descriptor);
    return error;
}

enum wf_ov2_error wf_ov2_send_record(
    int descriptor,
    const struct wf_ov2_record *record,
    uint64_t deadline_ns
) {
    struct iovec vector;
    struct msghdr message;
    ssize_t count;
    enum wf_ov2_error error;
    if (descriptor < 0 || record == NULL || record->length < WF_OV2_HEADER_SIZE ||
        record->length > WF_OV2_MAX_RECORD_SIZE) {
        return WF_OV2_ERR_ARGUMENT;
    }
    error = wf_wait(descriptor, POLLOUT, deadline_ns, NULL);
    if (error != WF_OV2_OK) {
        return error;
    }
    vector.iov_base = (void *)record->bytes;
    vector.iov_len = record->length;
    message.msg_name = NULL; message.msg_namelen = 0;
    message.msg_iov = &vector; message.msg_iovlen = 1u;
    message.msg_control = NULL; message.msg_controllen = 0u;
    message.msg_flags = 0;
    do {
        count = sendmsg(descriptor, &message, MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    return count == (ssize_t)record->length ? WF_OV2_OK : WF_OV2_ERR_IO;
}

static int wf_close_rights(struct cmsghdr *control) {
    size_t bytes;
    size_t count;
    size_t index;
    int *descriptors;
    if (control->cmsg_len < CMSG_LEN(0u)) {
        return -1;
    }
    bytes = control->cmsg_len - CMSG_LEN(0u);
    count = bytes / sizeof(int);
    descriptors = (int *)(void *)CMSG_DATA(control);
    for (index = 0; index < count; ++index) {
        if (descriptors[index] >= 0) {
            (void)close(descriptors[index]);
        }
    }
    return bytes % sizeof(int) == 0u ? 0 : -1;
}

enum wf_ov2_error wf_ov2_recv_record(
    int descriptor,
    uint64_t deadline_ns,
    struct wf_ov2_record *record,
    struct wf_ov2_peer_observation *observation
) {
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) * 2u + CMSG_SPACE(sizeof(int) * 8u)];
    } control_storage;
    struct iovec vector;
    struct msghdr message;
    struct cmsghdr *control;
    unsigned int credential_count = 0u;
    int bad_ancillary = 0;
    ssize_t count;
    enum wf_ov2_error error;
    if (descriptor < 0 || record == NULL || observation == NULL) {
        return WF_OV2_ERR_ARGUMENT;
    }
    error = wf_wait(descriptor, POLLIN, deadline_ns, NULL);
    if (error != WF_OV2_OK) {
        return error;
    }
    wf_bytes_zero(record->bytes, sizeof(record->bytes));
    wf_bytes_zero(control_storage.bytes, sizeof(control_storage.bytes));
    vector.iov_base = record->bytes;
    vector.iov_len = sizeof(record->bytes);
    message.msg_name = NULL; message.msg_namelen = 0;
    message.msg_iov = &vector; message.msg_iovlen = 1u;
    message.msg_control = control_storage.bytes;
    message.msg_controllen = sizeof(control_storage.bytes);
    message.msg_flags = 0;
    do {
        count = recvmsg(descriptor, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        return WF_OV2_ERR_IO;
    }
    for (control = CMSG_FIRSTHDR(&message); control != NULL;
         control = CMSG_NXTHDR(&message, control)) {
        if (control->cmsg_level != SOL_SOCKET) {
            bad_ancillary = 1;
        } else if (control->cmsg_type == SCM_RIGHTS) {
            if (wf_close_rights(control) != 0) {
                bad_ancillary = 1;
            }
            bad_ancillary = 1;
        } else if (control->cmsg_type == SCM_CREDENTIALS) {
            struct ucred *credential;
            ++credential_count;
            if (control->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                bad_ancillary = 1;
                continue;
            }
            credential = (struct ucred *)(void *)CMSG_DATA(control);
            if (credential->pid <= 0) {
                bad_ancillary = 1;
                continue;
            }
            observation->message_pid = (int64_t)credential->pid;
            observation->message_uid = (uint32_t)credential->uid;
            observation->message_gid = (uint32_t)credential->gid;
        } else {
            bad_ancillary = 1;
        }
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        return WF_OV2_ERR_TRUNCATED;
    }
    if (bad_ancillary != 0 || credential_count != 1u) {
        return WF_OV2_ERR_ANCILLARY;
    }
    if (count == 0) {
        return WF_OV2_ERR_IO;
    }
    if ((size_t)count < WF_OV2_HEADER_SIZE || (size_t)count > WF_OV2_MAX_RECORD_SIZE) {
        return WF_OV2_ERR_HEADER;
    }
    record->length = (size_t)count;
    return wf_check_deadline(deadline_ns);
}

enum wf_ov2_error wf_ov2_require_eof(int descriptor, uint64_t deadline_ns) {
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 8u)];
    } control_storage;
    uint8_t byte = 0u;
    struct iovec vector;
    struct msghdr message;
    struct cmsghdr *control;
    ssize_t count;
    unsigned int credential_count = 0u;
    unsigned int control_count = 0u;
    int bad_ancillary = 0;
    short observed_revents = 0;
    enum wf_ov2_error error = wf_wait(
        descriptor,
        (short)(POLLIN | POLLRDHUP),
        deadline_ns,
        &observed_revents
    );
    if (error != WF_OV2_OK) {
        return error;
    }
    wf_bytes_zero(control_storage.bytes, sizeof(control_storage.bytes));
    vector.iov_base = &byte; vector.iov_len = 1u;
    message.msg_name = NULL; message.msg_namelen = 0;
    message.msg_iov = &vector; message.msg_iovlen = 1u;
    message.msg_control = control_storage.bytes;
    message.msg_controllen = sizeof(control_storage.bytes);
    message.msg_flags = 0;
    do {
        count = recvmsg(descriptor, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    for (control = CMSG_FIRSTHDR(&message); control != NULL;
         control = CMSG_NXTHDR(&message, control)) {
        control_count += 1u;
        if (control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_RIGHTS) {
            (void)wf_close_rights(control);
            bad_ancillary = 1;
        } else if (control->cmsg_level == SOL_SOCKET &&
                   control->cmsg_type == SCM_CREDENTIALS &&
                   control->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
            credential_count += 1u;
        } else {
            bad_ancillary = 1;
        }
    }
    if (count < 0) {
        return WF_OV2_ERR_IO;
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        return WF_OV2_ERR_TRUNCATED;
    }
    if (bad_ancillary != 0 ||
        (message.msg_controllen != 0u && control_count == 0u) ||
        credential_count > 1u) {
        return WF_OV2_ERR_ANCILLARY;
    }
    if (count != 0 || credential_count != 0u ||
        (message.msg_flags & MSG_EOR) != 0) {
        return WF_OV2_ERR_STATE;
    }
    if ((observed_revents & (POLLHUP | POLLRDHUP)) == 0) {
        return WF_OV2_ERR_STATE;
    }
    return WF_OV2_OK;
}

int wf_ov2_error_to_exit(enum wf_ov2_error error) {
    switch (error) {
        case WF_OV2_OK: return 0;
        case WF_OV2_ERR_ARGUMENT: return 64;
        case WF_OV2_ERR_HEADER:
        case WF_OV2_ERR_TYPE:
        case WF_OV2_ERR_BODY: return 65;
        case WF_OV2_ERR_SEQUENCE:
        case WF_OV2_ERR_STATE: return 66;
        case WF_OV2_ERR_SOCKET:
        case WF_OV2_ERR_ANCILLARY: return 67;
        case WF_OV2_ERR_IO:
        case WF_OV2_ERR_TRUNCATED: return 68;
        case WF_OV2_ERR_NONCE:
        case WF_OV2_ERR_DEADLINE: return 69;
        case WF_OV2_ERR_HASH: return 70;
        default: return 64;
    }
}
