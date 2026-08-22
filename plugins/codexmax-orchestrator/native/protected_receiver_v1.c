#include "protected_receiver_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(CMPR_TESTING)
#include <stdlib.h>
static const char *test_hook(void) { return getenv("CMPR_TEST_HOOK"); }
static int hook_is(const char *value) {
    const char *hook = test_hook();
    return hook != NULL && strcmp(hook, value) == 0;
}
static uid_t test_mismatched_uid(uint32_t expected) {
    return (uid_t)(expected == UINT32_MAX ? expected - 1U : expected + 1U);
}
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static void copy_stat(struct cmpr_vnode *out, const struct stat *value) {
    out->device = (uint64_t)value->st_dev; out->inode = (uint64_t)value->st_ino;
    out->mode = (uint32_t)value->st_mode; out->uid = (uint32_t)value->st_uid;
    out->gid = (uint32_t)value->st_gid; out->size = (uint64_t)value->st_size;
#if defined(__APPLE__)
    out->mtime_ns = (uint64_t)value->st_mtimespec.tv_sec * 1000000000ULL + (uint64_t)value->st_mtimespec.tv_nsec;
#else
    out->mtime_ns = (uint64_t)value->st_mtim.tv_sec * 1000000000ULL + (uint64_t)value->st_mtim.tv_nsec;
#endif
}

static int nonzero_vnode(const struct cmpr_vnode *value) {
    return value->device != 0 && value->inode != 0 && value->mode != 0;
}

static int protected_node(const struct cmpr_vnode *value, uint32_t owner, uint32_t type) {
    return nonzero_vnode(value) && value->uid == owner &&
           (value->mode & S_IFMT) == type && (value->mode & 0022) == 0;
}

static int validate_collected_facts(const struct cmpr_collected_facts *facts,
                                    uint32_t expected_root_uid,
                                    uint32_t distinct_service_uid) {
    static const uint8_t zero_code_identity[32] = {0};
    if (facts == NULL || facts->protocol_version != CMPR_PROTOCOL_VERSION) return CMPR_INVALID_DESCRIPTOR;
    if (!nonzero_vnode(&facts->ancestor_before) || !nonzero_vnode(&facts->ancestor_after) ||
        !nonzero_vnode(&facts->root_before) || !nonzero_vnode(&facts->root_after) ||
        !nonzero_vnode(&facts->entrypoint_before) || !nonzero_vnode(&facts->entrypoint_after)) return CMPR_ZERO_FACT;
    if (!protected_node(&facts->ancestor_before, expected_root_uid, S_IFDIR) ||
        !protected_node(&facts->ancestor_after, expected_root_uid, S_IFDIR) ||
        !protected_node(&facts->root_before, expected_root_uid, S_IFDIR) ||
        !protected_node(&facts->root_after, expected_root_uid, S_IFDIR) ||
        !protected_node(&facts->entrypoint_before, expected_root_uid, S_IFREG) ||
        !protected_node(&facts->entrypoint_after, expected_root_uid, S_IFREG)) return CMPR_OWNER_OR_MODE_INVALID;
    if (memcmp(&facts->ancestor_before, &facts->ancestor_after, sizeof(facts->ancestor_before)) != 0 ||
        memcmp(&facts->root_before, &facts->root_after, sizeof(facts->root_before)) != 0 ||
        memcmp(&facts->entrypoint_before, &facts->entrypoint_after, sizeof(facts->entrypoint_before)) != 0) return CMPR_VNODE_DRIFT;
    if (facts->process_before.pid <= 0 || facts->process_before.euid == expected_root_uid ||
        facts->process_before.euid != distinct_service_uid || facts->process_before.egid != distinct_service_uid) return CMPR_SAME_UID;
    if (memcmp(&facts->process_before, &facts->process_after, sizeof(facts->process_before)) != 0) return CMPR_PROCESS_DRIFT;
    if (memcmp(facts->code_identity_before, facts->code_identity_after, 32) != 0) return CMPR_CODE_IDENTITY_DRIFT;
    if (facts->process_before.process_start == 0 ||
        memcmp(facts->code_identity_before, zero_code_identity, 32) == 0) return CMPR_PENDING_LIVE_PRIMITIVE;
    return CMPR_LOCAL_NONAUTHORITATIVE_READY;
}

int cmpr_collect_descriptor_facts(int ancestor_fd, uint32_t expected_root_uid,
                                  uint32_t distinct_service_uid,
                                  struct cmpr_collected_facts *out) {
    struct stat ancestor_before, ancestor_after, root_before, root_after, entry_before, entry_after;
    int root_fd, entry_fd;
    if (out == NULL || ancestor_fd < 0) return CMPR_INVALID_DESCRIPTOR;
    memset(out, 0, sizeof(*out)); out->protocol_version = CMPR_PROTOCOL_VERSION;
    if (fstat(ancestor_fd, &ancestor_before) != 0 || !S_ISDIR(ancestor_before.st_mode)) return CMPR_INVALID_DESCRIPTOR;
    root_fd = openat(ancestor_fd, CMPR_FIXED_GENERATION_ROOT, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) return errno == ELOOP ? CMPR_SYMLINK_REJECTED : CMPR_PENDING_LIVE_PRIMITIVE;
    if (fstat(root_fd, &root_before) != 0 || !S_ISDIR(root_before.st_mode)) { close(root_fd); return CMPR_INVALID_DESCRIPTOR; }
#if defined(CMPR_TESTING)
    if (hook_is("ancestor_owner")) ancestor_before.st_uid = test_mismatched_uid(expected_root_uid);
    if (hook_is("root_owner")) root_before.st_uid = test_mismatched_uid(expected_root_uid);
#endif
    if ((uint32_t)ancestor_before.st_uid != expected_root_uid || (ancestor_before.st_mode & 0022) != 0 ||
        (uint32_t)root_before.st_uid != expected_root_uid || expected_root_uid == distinct_service_uid ||
        (root_before.st_mode & 0022) != 0) { close(root_fd); return CMPR_OWNER_OR_MODE_INVALID; }
    entry_fd = openat(root_fd, CMPR_FIXED_ENTRYPOINT, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (entry_fd < 0) { int result = errno == ELOOP ? CMPR_SYMLINK_REJECTED : CMPR_PENDING_LIVE_PRIMITIVE; close(root_fd); return result; }
    if (fstat(entry_fd, &entry_before) != 0 || !S_ISREG(entry_before.st_mode)) { close(entry_fd); close(root_fd); return CMPR_INVALID_DESCRIPTOR; }
#if defined(CMPR_TESTING)
    if (hook_is("entrypoint_owner")) entry_before.st_uid = test_mismatched_uid(expected_root_uid);
#endif
    if ((uint32_t)entry_before.st_uid != expected_root_uid || (entry_before.st_mode & 0022) != 0) { close(entry_fd); close(root_fd); return CMPR_OWNER_OR_MODE_INVALID; }
    copy_stat(&out->ancestor_before, &ancestor_before);
    copy_stat(&out->root_before, &root_before);
    copy_stat(&out->entrypoint_before, &entry_before);
    out->process_before.pid = (int32_t)getpid(); out->process_before.euid = (uint32_t)geteuid();
    out->process_before.egid = (uint32_t)getegid();
#if defined(__APPLE__)
    /* A launchd service must replace this source-local zero with an
       audit-token-bound process-start observation. */
    out->process_before.process_start = 0;
#else
    out->process_before.process_start = 0;
#endif
#if defined(CMPR_TESTING)
    if (hook_is("live_witness_missing")) {
        out->process_before.euid = distinct_service_uid;
        out->process_before.egid = distinct_service_uid;
    } else if (hook_is("ancestor_vnode_drift")) {
        if (fchmod(ancestor_fd, (ancestor_before.st_mode & 0777) ^ 0100) != 0) { close(entry_fd); close(root_fd); return CMPR_INVALID_DESCRIPTOR; }
    } else if (hook_is("root_vnode_drift")) {
        if (fchmod(root_fd, (root_before.st_mode & 0777) ^ 0100) != 0) { close(entry_fd); close(root_fd); return CMPR_INVALID_DESCRIPTOR; }
    } else if (hook_is("entrypoint_vnode_drift")) {
        if (fchmod(entry_fd, (entry_before.st_mode & 0777) ^ 0100) != 0) { close(entry_fd); close(root_fd); return CMPR_INVALID_DESCRIPTOR; }
    }
#endif
    if (fstat(entry_fd, &entry_after) != 0 || fstat(root_fd, &root_after) != 0 || fstat(ancestor_fd, &ancestor_after) != 0) { close(entry_fd); close(root_fd); return CMPR_INVALID_DESCRIPTOR; }
    close(entry_fd); close(root_fd); out->process_after = out->process_before;
    copy_stat(&out->ancestor_after, &ancestor_after);
    copy_stat(&out->root_after, &root_after);
    copy_stat(&out->entrypoint_after, &entry_after);
    /* No caller-filled struct can cross this boundary. The source build lacks
       audit-token, process-start, and code-sign collection, so it stays pending. */
    return validate_collected_facts(out, expected_root_uid, distinct_service_uid);
}
