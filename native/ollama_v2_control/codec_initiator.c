#include "wf_ov2_protocol.h"

#include <stdint.h>
#include <sys/socket.h>

int main(void) {
    struct wf_ov2_peer_observation observation;
    struct wf_ov2_record request;
    struct wf_ov2_record response;
    uint8_t nonce[WF_OV2_NONCE_SIZE];
    uint8_t request_hash[WF_OV2_SHA256_SIZE];
    uint64_t now;
    uint64_t deadline;
    enum wf_ov2_error error;

    error = wf_ov2_validate_seqpacket_fd(0, &observation);
    if (error != WF_OV2_OK) {
        return wf_ov2_error_to_exit(error);
    }
    error = wf_ov2_random_nonce(nonce);
    if (error != WF_OV2_OK) {
        return wf_ov2_error_to_exit(error);
    }
    now = wf_ov2_boottime_ns(&error);
    if (error != WF_OV2_OK || UINT64_MAX - now < WF_OV2_NEGOTIATION_WINDOW_NS) {
        return wf_ov2_error_to_exit(error == WF_OV2_OK ? WF_OV2_ERR_DEADLINE : error);
    }
    deadline = now + WF_OV2_NEGOTIATION_WINDOW_NS;
    error = wf_ov2_encode_negotiate(nonce, deadline, &request);
    if (error == WF_OV2_OK) {
        error = wf_ov2_packet_hash(&request, request_hash);
    }
    if (error == WF_OV2_OK) {
        error = wf_ov2_send_record(0, &request, deadline);
    }
    if (error == WF_OV2_OK && shutdown(0, SHUT_WR) != 0) {
        error = WF_OV2_ERR_IO;
    }
    if (error == WF_OV2_OK) {
        error = wf_ov2_recv_record(0, deadline, &response, &observation);
    }
    if (error == WF_OV2_OK) {
        error = wf_ov2_decode_unavailable(&response, nonce, deadline, request_hash);
    }
    if (error == WF_OV2_OK) {
        error = wf_ov2_require_eof(0, deadline);
    }
    return wf_ov2_error_to_exit(error);
}
