#ifndef CODEXMAX_PROTECTED_RECEIVER_V1_H
#define CODEXMAX_PROTECTED_RECEIVER_V1_H
#include <stdint.h>

#define CMPR_PROTOCOL_VERSION 1u
#define CMPR_FIXED_GENERATION_ROOT "generation"
#define CMPR_FIXED_ENTRYPOINT "provider-runner"

struct cmpr_vnode { uint64_t device, inode; uint32_t mode, uid, gid; uint64_t size, mtime_ns; };
struct cmpr_process { int32_t pid; uint32_t euid, egid; uint64_t process_start; };
struct cmpr_collected_facts {
    uint32_t protocol_version;
    struct cmpr_vnode ancestor_before, ancestor_after, root_before, root_after;
    struct cmpr_vnode entrypoint_before, entrypoint_after;
    struct cmpr_process process_before, process_after;
    uint8_t code_identity_before[32], code_identity_after[32];
};

enum cmpr_result {
    CMPR_LOCAL_NONAUTHORITATIVE_READY = 0,
    CMPR_PENDING_LIVE_PRIMITIVE = 1,
    CMPR_INVALID_DESCRIPTOR = 2,
    CMPR_ZERO_FACT = 3,
    CMPR_VNODE_DRIFT = 4,
    CMPR_SAME_UID = 5,
    CMPR_OWNER_OR_MODE_INVALID = 6,
    CMPR_SYMLINK_REJECTED = 7,
    CMPR_PROCESS_DRIFT = 8,
    CMPR_CODE_IDENTITY_DRIFT = 9
};

/* Collects facts itself from an already protected root descriptor. */
int cmpr_collect_descriptor_facts(int ancestor_fd, uint32_t expected_root_uid,
                                  uint32_t distinct_service_uid,
                                  struct cmpr_collected_facts *out);
#endif
