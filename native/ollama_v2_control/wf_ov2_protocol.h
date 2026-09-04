#ifndef WF_OV2_PROTOCOL_H
#define WF_OV2_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define WF_OV2_HEADER_SIZE 120u
#define WF_OV2_OFFSET_MAGIC 0u
#define WF_OV2_OFFSET_MAJOR 8u
#define WF_OV2_OFFSET_HEADER_SIZE 10u
#define WF_OV2_OFFSET_TYPE 12u
#define WF_OV2_OFFSET_FLAGS 14u
#define WF_OV2_OFFSET_SEQUENCE 16u
#define WF_OV2_OFFSET_BODY_SIZE 24u
#define WF_OV2_OFFSET_FD_COUNT 28u
#define WF_OV2_OFFSET_RESERVED 30u
#define WF_OV2_OFFSET_NONCE 32u
#define WF_OV2_OFFSET_DEADLINE_NS 48u
#define WF_OV2_OFFSET_PRIOR_PACKET_SHA256 56u
#define WF_OV2_OFFSET_BODY_SHA256 88u
#define WF_OV2_NEGOTIATE_BODY_SIZE 24u
#define WF_OV2_UNAVAILABLE_BODY_SIZE 48u
#define WF_OV2_MAX_BODY_SIZE 48u
#define WF_OV2_MAX_RECORD_SIZE 168u
#define WF_OV2_NONCE_SIZE 16u
#define WF_OV2_SHA256_SIZE 32u
#define WF_OV2_NEGOTIATION_WINDOW_NS UINT64_C(2000000000)
#define WF_OV2_MAX_DEADLINE_WINDOW_NS UINT64_C(5000000000)

enum wf_ov2_message_type {
    WF_OV2_MSG_NEGOTIATE = 1,
    WF_OV2_MSG_UNAVAILABLE_TERMINAL = 2,
};

enum wf_ov2_terminal_class {
    WF_OV2_TERMINAL_CLASS_UNAVAILABLE = 1,
};

enum wf_ov2_unavailable_reason {
    WF_OV2_REASON_EFFECT_EXECUTION_UNAVAILABLE = 1,
};

enum wf_ov2_error {
    WF_OV2_OK = 0,
    WF_OV2_ERR_ARGUMENT = 1,
    WF_OV2_ERR_SOCKET = 2,
    WF_OV2_ERR_IO = 3,
    WF_OV2_ERR_TRUNCATED = 4,
    WF_OV2_ERR_HEADER = 5,
    WF_OV2_ERR_TYPE = 6,
    WF_OV2_ERR_SEQUENCE = 7,
    WF_OV2_ERR_NONCE = 8,
    WF_OV2_ERR_DEADLINE = 9,
    WF_OV2_ERR_HASH = 10,
    WF_OV2_ERR_BODY = 11,
    WF_OV2_ERR_ANCILLARY = 12,
    WF_OV2_ERR_STATE = 13,
};

struct wf_ov2_record {
    uint8_t bytes[WF_OV2_MAX_RECORD_SIZE];
    size_t length;
};

struct wf_ov2_peer_observation {
    int64_t message_pid;
    uint32_t message_uid;
    uint32_t message_gid;
    int64_t socket_pid;
    uint32_t socket_uid;
    uint32_t socket_gid;
};

enum wf_ov2_error wf_ov2_sha256(
    const uint8_t *input,
    size_t input_length,
    uint8_t output[WF_OV2_SHA256_SIZE]
);
enum wf_ov2_error wf_ov2_body_hash(
    const uint8_t *body,
    size_t body_length,
    uint8_t output[WF_OV2_SHA256_SIZE]
);
enum wf_ov2_error wf_ov2_packet_hash(
    const struct wf_ov2_record *record,
    uint8_t output[WF_OV2_SHA256_SIZE]
);
enum wf_ov2_error wf_ov2_encode_negotiate(
    const uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t deadline_ns,
    struct wf_ov2_record *output
);
enum wf_ov2_error wf_ov2_decode_negotiate(
    const struct wf_ov2_record *record,
    uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t *deadline_ns
);
enum wf_ov2_error wf_ov2_encode_unavailable(
    const uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t deadline_ns,
    const uint8_t request_hash[WF_OV2_SHA256_SIZE],
    struct wf_ov2_record *output
);
enum wf_ov2_error wf_ov2_decode_unavailable(
    const struct wf_ov2_record *record,
    const uint8_t nonce[WF_OV2_NONCE_SIZE],
    uint64_t deadline_ns,
    const uint8_t request_hash[WF_OV2_SHA256_SIZE]
);
enum wf_ov2_error wf_ov2_validate_seqpacket_fd(
    int descriptor,
    struct wf_ov2_peer_observation *observation
);
enum wf_ov2_error wf_ov2_send_record(
    int descriptor,
    const struct wf_ov2_record *record,
    uint64_t deadline_ns
);
enum wf_ov2_error wf_ov2_recv_record(
    int descriptor,
    uint64_t deadline_ns,
    struct wf_ov2_record *record,
    struct wf_ov2_peer_observation *observation
);
enum wf_ov2_error wf_ov2_require_eof(int descriptor, uint64_t deadline_ns);
uint64_t wf_ov2_boottime_ns(enum wf_ov2_error *error);
enum wf_ov2_error wf_ov2_random_nonce(uint8_t nonce[WF_OV2_NONCE_SIZE]);
int wf_ov2_error_to_exit(enum wf_ov2_error error);

#endif
