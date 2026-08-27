/*
 * One-shot, nonprinting macOS role-reader qualification runner.
 *
 * The runner accepts no request parameters.  It invokes only the two fixed,
 * installed role readers and only their sacrificial probe slots.  Secret
 * bytes exist solely in a locked, bounded parent buffer, are classified, and
 * are immediately overwritten.  Output is a fixed redacted pass/fail matrix.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <Security/SecBase.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <signal.h>
#include <sys/acl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PROBE_DIRECTORY "/private/var/root/trading-desk-keychain-role-probe-v1"
#define RUNNER_NAME "trading-keychain-role-probe-runner-v1"
#define EXPECTED_PATH PROBE_DIRECTORY "/" RUNNER_NAME
#define EXPECTED_IDENTIFIER \
    "com.jawndiego.trading-desk.keychain-role-probe-runner.v1"

#define EXECUTOR_READER \
    "/opt/trading-desk/libexec/trading-keychain-reader-executor-v1"
#define CONTROL_READER \
    "/opt/trading-desk/libexec/trading-keychain-reader-control-v1"
#define EXECUTOR_IDENTIFIER \
    "com.jawndiego.trading-desk.keychain-reader.executor.v1"
#define CONTROL_IDENTIFIER \
    "com.jawndiego.trading-desk.keychain-reader.control.v1"
#define EXECUTOR_SHA256 \
    "8694d14a94ee00a2ac039b7d5cd26c4184e13840aabe1cac2b0d084a629e0ff7"
#define CONTROL_SHA256 \
    "2ce4ba34366b67b0280302e042ffae67547cb39924353c62f88f5782b9dc52e9"

#define EXECUTOR_PROBE_SLOT "probe-executor"
#define CONTROL_PROBE_SLOT "probe-control"
#define SECRET_HEX_LENGTH 64U
#define CAPTURE_LENGTH (SECRET_HEX_LENGTH + 1U)
#define HASH_BUFFER_LENGTH 4096U
#define PROBE_TIMEOUT_MILLISECONDS 3000U
#define CHILD_WATCHDOG_SECONDS 3U
#define POLL_SLICE_MILLISECONDS 25
#define CHILD_EXEC_DENIED 126
#define CHILD_INTERNAL_FAILURE 125
#define READER_DENIED 70

struct reader_contract {
    const char *path;
    const char *identifier;
    const char *sha256;
    const char *slot;
    gid_t installed_gid;
};

struct probe_case {
    const char *matrix_line_pass;
    const char *matrix_line_fail;
    uid_t uid;
    gid_t gid;
    const struct reader_contract *reader;
    bool expect_secret;
};

struct capture_state {
    unsigned char bytes[CAPTURE_LENGTH];
};

static const struct reader_contract EXECUTOR_CONTRACT = {
    EXECUTOR_READER,
    EXECUTOR_IDENTIFIER,
    EXECUTOR_SHA256,
    EXECUTOR_PROBE_SLOT,
    (gid_t)451,
};

static const struct reader_contract CONTROL_CONTRACT = {
    CONTROL_READER,
    CONTROL_IDENTIFIER,
    CONTROL_SHA256,
    CONTROL_PROBE_SLOT,
    (gid_t)452,
};

static const struct probe_case PROBE_CASES[] = {
    {
        "executor->executor-probe expected-allow=PASS\n",
        "executor->executor-probe expected-allow=FAIL\n",
        (uid_t)451,
        (gid_t)451,
        &EXECUTOR_CONTRACT,
        true,
    },
    {
        "control->control-probe expected-allow=PASS\n",
        "control->control-probe expected-allow=FAIL\n",
        (uid_t)452,
        (gid_t)452,
        &CONTROL_CONTRACT,
        true,
    },
    {
        "root->executor-probe expected-deny=PASS\n",
        "root->executor-probe expected-deny=FAIL\n",
        (uid_t)0,
        (gid_t)0,
        &EXECUTOR_CONTRACT,
        false,
    },
    {
        "root->control-probe expected-deny=PASS\n",
        "root->control-probe expected-deny=FAIL\n",
        (uid_t)0,
        (gid_t)0,
        &CONTROL_CONTRACT,
        false,
    },
    {
        "research->executor-probe expected-deny=PASS\n",
        "research->executor-probe expected-deny=FAIL\n",
        (uid_t)450,
        (gid_t)450,
        &EXECUTOR_CONTRACT,
        false,
    },
    {
        "research->control-probe expected-deny=PASS\n",
        "research->control-probe expected-deny=FAIL\n",
        (uid_t)450,
        (gid_t)450,
        &CONTROL_CONTRACT,
        false,
    },
    {
        "desktop->executor-probe expected-deny=PASS\n",
        "desktop->executor-probe expected-deny=FAIL\n",
        (uid_t)501,
        (gid_t)20,
        &EXECUTOR_CONTRACT,
        false,
    },
    {
        "desktop->control-probe expected-deny=PASS\n",
        "desktop->control-probe expected-deny=FAIL\n",
        (uid_t)501,
        (gid_t)20,
        &CONTROL_CONTRACT,
        false,
    },
    {
        "executor->control-probe expected-deny=PASS\n",
        "executor->control-probe expected-deny=FAIL\n",
        (uid_t)451,
        (gid_t)451,
        &CONTROL_CONTRACT,
        false,
    },
    {
        "control->executor-probe expected-deny=PASS\n",
        "control->executor-probe expected-deny=FAIL\n",
        (uid_t)452,
        (gid_t)452,
        &EXECUTOR_CONTRACT,
        false,
    },
};

extern char **environ;

static void secure_zero(void *value, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)value;
    while (length > 0U) {
        *cursor++ = 0U;
        --length;
    }
}

static bool write_all(int descriptor, const char *value, size_t length)
{
    size_t offset = 0U;
    while (offset < length) {
        ssize_t written = write(descriptor, value + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

static bool emit_line(const char *line)
{
    return write_all(STDOUT_FILENO, line, strlen(line));
}

static bool has_extended_acl(const char *path)
{
    acl_t acl;
    acl_entry_t entry;
    struct stat value;
    int status;
    errno = 0;
    acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        return errno != ENOENT || lstat(path, &value) != 0;
    }
    status = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    (void)acl_free(acl);
    return status == 1 || status == -1;
}

static bool secure_directory(const char *path, mode_t exact_mode)
{
    struct stat value;
    if (lstat(path, &value) != 0 || !S_ISDIR(value.st_mode) ||
        value.st_uid != 0 || value.st_gid != 0 || has_extended_acl(path)) {
        return false;
    }
    if (exact_mode != 0U) {
        return (value.st_mode & 07777U) == exact_mode;
    }
    return (value.st_mode & 0022U) == 0U;
}

static bool secure_regular_file(
    const char *path, gid_t expected_gid, mode_t expected_mode)
{
    char resolved[PATH_MAX];
    struct stat value;
    if (realpath(path, resolved) == NULL || strcmp(resolved, path) != 0 ||
        lstat(path, &value) != 0 || !S_ISREG(value.st_mode)) {
        return false;
    }
    return value.st_uid == 0 && value.st_gid == expected_gid &&
           value.st_nlink == 1 && (value.st_mode & 07777U) == expected_mode &&
           !has_extended_acl(path);
}

static bool signed_code_matches(const char *path, const char *identifier)
{
    CFURLRef url = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    CFStringRef expected_identifier = NULL;
    CFStringRef actual_identifier;
    OSStatus status;
    bool matches = false;

    url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
    expected_identifier = CFStringCreateWithCString(
        kCFAllocatorDefault, identifier, kCFStringEncodingUTF8);
    if (url == NULL || expected_identifier == NULL) {
        goto cleanup;
    }
    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (status != errSecSuccess || code == NULL) {
        goto cleanup;
    }
    status = SecStaticCodeCheckValidity(
        code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL);
    if (status != errSecSuccess) {
        goto cleanup;
    }
    status = SecCodeCopySigningInformation(
        code, kSecCSSigningInformation, &information);
    if (status != errSecSuccess || information == NULL) {
        goto cleanup;
    }
    actual_identifier = (CFStringRef)CFDictionaryGetValue(
        information, kSecCodeInfoIdentifier);
    if (actual_identifier == NULL ||
        CFGetTypeID(actual_identifier) != CFStringGetTypeID()) {
        goto cleanup;
    }
    matches = CFStringCompare(actual_identifier, expected_identifier, 0) ==
              kCFCompareEqualTo;

cleanup:
    if (information != NULL) {
        CFRelease(information);
    }
    if (code != NULL) {
        CFRelease(code);
    }
    if (expected_identifier != NULL) {
        CFRelease(expected_identifier);
    }
    if (url != NULL) {
        CFRelease(url);
    }
    return matches;
}

static bool constant_time_hex_equal(const char *left, const char *right)
{
    size_t index;
    volatile unsigned char difference = 0U;
    for (index = 0U; index < CC_SHA256_DIGEST_LENGTH * 2U; ++index) {
        difference |= (unsigned char)left[index] ^ (unsigned char)right[index];
    }
    return difference == 0U;
}

static bool hash_file_matches(const char *path, const char *expected_hex)
{
    static const char hexadecimal[] = "0123456789abcdef";
    struct stat before;
    struct stat after;
    struct stat path_after;
    CC_SHA256_CTX context;
    unsigned char buffer[HASH_BUFFER_LENGTH];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    char actual_hex[CC_SHA256_DIGEST_LENGTH * 2U + 1U];
    ssize_t received;
    size_t index;
    int descriptor = -1;
    bool matches = false;

    secure_zero(&context, sizeof(context));
    secure_zero(buffer, sizeof(buffer));
    secure_zero(digest, sizeof(digest));
    secure_zero(actual_hex, sizeof(actual_hex));
    descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_uid != 0 || before.st_nlink != 1 ||
        CC_SHA256_Init(&context) != 1) {
        goto cleanup;
    }
    while ((received = read(descriptor, buffer, sizeof(buffer))) > 0) {
        if (CC_SHA256_Update(&context, buffer, (CC_LONG)received) != 1) {
            goto cleanup;
        }
        secure_zero(buffer, sizeof(buffer));
    }
    if (received != 0 || CC_SHA256_Final(digest, &context) != 1 ||
        fstat(descriptor, &after) != 0 || lstat(path, &path_after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid || before.st_gid != after.st_gid ||
        before.st_nlink != after.st_nlink ||
        before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
        before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
        before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec ||
        after.st_dev != path_after.st_dev || after.st_ino != path_after.st_ino ||
        after.st_size != path_after.st_size || after.st_mode != path_after.st_mode ||
        after.st_uid != path_after.st_uid || after.st_gid != path_after.st_gid ||
        after.st_nlink != path_after.st_nlink) {
        goto cleanup;
    }
    for (index = 0U; index < sizeof(digest); ++index) {
        actual_hex[index * 2U] = hexadecimal[digest[index] >> 4U];
        actual_hex[index * 2U + 1U] = hexadecimal[digest[index] & 0x0fU];
    }
    actual_hex[CC_SHA256_DIGEST_LENGTH * 2U] = '\0';
    matches = constant_time_hex_equal(actual_hex, expected_hex);

cleanup:
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    secure_zero(&context, sizeof(context));
    secure_zero(buffer, sizeof(buffer));
    secure_zero(digest, sizeof(digest));
    secure_zero(actual_hex, sizeof(actual_hex));
    return matches;
}

static bool probe_directory_is_single_purpose(void)
{
    DIR *directory = NULL;
    struct dirent *entry;
    bool found_runner = false;
    bool valid = true;

    directory = opendir(PROBE_DIRECTORY);
    if (directory == NULL) {
        return false;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!found_runner && strcmp(entry->d_name, RUNNER_NAME) == 0) {
            found_runner = true;
        } else {
            valid = false;
        }
    }
    if (errno != 0) {
        valid = false;
    }
    (void)closedir(directory);
    return valid && found_runner;
}

static bool secure_self(void)
{
    char raw_path[PATH_MAX];
    char resolved[PATH_MAX];
    uint32_t size = (uint32_t)sizeof(raw_path);
    const char *const ancestors[] = {"/", "/private", "/private/var", "/private/var/root"};
    size_t index;

    if (_NSGetExecutablePath(raw_path, &size) != 0 ||
        realpath(raw_path, resolved) == NULL || strcmp(resolved, EXPECTED_PATH) != 0 ||
        !secure_regular_file(EXPECTED_PATH, (gid_t)0, (mode_t)0500) ||
        !secure_directory(PROBE_DIRECTORY, (mode_t)0700) ||
        !probe_directory_is_single_purpose() ||
        !signed_code_matches(EXPECTED_PATH, EXPECTED_IDENTIFIER)) {
        return false;
    }
    for (index = 0U; index < sizeof(ancestors) / sizeof(ancestors[0]); ++index) {
        if (!secure_directory(ancestors[index], (mode_t)0)) {
            return false;
        }
    }
    return true;
}

static bool secure_reader(const struct reader_contract *reader)
{
    const char *const ancestors[] = {
        "/", "/opt", "/opt/trading-desk", "/opt/trading-desk/libexec"};
    size_t index;

    if (!secure_regular_file(reader->path, reader->installed_gid, (mode_t)0510) ||
        !hash_file_matches(reader->path, reader->sha256) ||
        !signed_code_matches(reader->path, reader->identifier)) {
        return false;
    }
    for (index = 0U; index < sizeof(ancestors) / sizeof(ancestors[0]); ++index) {
        if (!secure_directory(ancestors[index], (mode_t)0)) {
            return false;
        }
    }
    return true;
}

static bool exact_root_identity(void)
{
    return getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0;
}

static bool empty_environment(void)
{
    return environ != NULL && environ[0] == NULL;
}

static bool fixed_foreground_terminal_descriptors(void)
{
    struct stat descriptors[3];
    int descriptor;
    for (descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO; ++descriptor) {
        if (fstat(descriptor, &descriptors[descriptor]) != 0 ||
            !S_ISCHR(descriptors[descriptor].st_mode) || !isatty(descriptor)) {
            return false;
        }
    }
    if (descriptors[0].st_rdev != descriptors[1].st_rdev ||
        descriptors[0].st_rdev != descriptors[2].st_rdev ||
        tcgetpgrp(STDIN_FILENO) != getpgrp()) {
        return false;
    }
    return true;
}

static bool decimal_descriptor_name(const char *name, int *value)
{
    unsigned int parsed = 0U;
    size_t index = 0U;
    if (name == NULL || name[0] == '\0') {
        return false;
    }
    while (name[index] != '\0') {
        unsigned char current = (unsigned char)name[index];
        if (current < (unsigned char)'0' || current > (unsigned char)'9' ||
            parsed > ((unsigned int)INT_MAX - (unsigned int)(current - '0')) / 10U) {
            return false;
        }
        parsed = parsed * 10U + (unsigned int)(current - '0');
        ++index;
    }
    *value = (int)parsed;
    return true;
}

static bool only_standard_and_optional_descriptor_open(int optional_descriptor)
{
    DIR *directory = NULL;
    struct dirent *entry;
    bool seen[3] = {false, false, false};
    bool optional_seen = false;
    bool valid = true;
    int enumeration_descriptor;

    directory = opendir("/dev/fd");
    if (directory == NULL) {
        return false;
    }
    enumeration_descriptor = dirfd(directory);
    if (enumeration_descriptor < 0) {
        (void)closedir(directory);
        return false;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        int descriptor;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!decimal_descriptor_name(entry->d_name, &descriptor)) {
            valid = false;
            continue;
        }
        if (descriptor == enumeration_descriptor) {
            continue;
        }
        if (descriptor >= STDIN_FILENO && descriptor <= STDERR_FILENO &&
            !seen[descriptor]) {
            seen[descriptor] = true;
        } else if (optional_descriptor > STDERR_FILENO &&
                   descriptor == optional_descriptor && !optional_seen) {
            optional_seen = true;
        } else {
            valid = false;
        }
    }
    if (errno != 0) {
        valid = false;
    }
    (void)closedir(directory);
    return valid && seen[0] && seen[1] && seen[2] &&
           (optional_descriptor <= STDERR_FILENO || optional_seen);
}

static bool only_standard_descriptors_open(void)
{
    return only_standard_and_optional_descriptor_open(-1);
}

static bool exact_child_identity(uid_t uid, gid_t gid)
{
    gid_t group = gid;
    gid_t actual_groups[2];
    int count;

    if (setgroups(1, &group) != 0 || setgid(gid) != 0 || setuid(uid) != 0 ||
        getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
        return false;
    }
    count = getgroups((int)(sizeof(actual_groups) / sizeof(actual_groups[0])), actual_groups);
    return count == 1 && actual_groups[0] == gid;
}

static bool exact_null_descriptor(int descriptor)
{
    struct stat opened;
    struct stat current;
    return fstat(descriptor, &opened) == 0 && stat("/dev/null", &current) == 0 &&
           S_ISCHR(opened.st_mode) && S_ISCHR(current.st_mode) &&
           opened.st_rdev == current.st_rdev;
}

static bool block_signals(sigset_t *previous)
{
    sigset_t all_signals;
    return sigfillset(&all_signals) == 0 &&
           sigprocmask(SIG_BLOCK, &all_signals, previous) == 0;
}

static bool unblock_all_child_signals(void)
{
    sigset_t empty;
    return sigemptyset(&empty) == 0 &&
           sigprocmask(SIG_SETMASK, &empty, NULL) == 0;
}

static bool default_child_watchdog_signal(void)
{
    struct sigaction action;
    secure_zero(&action, sizeof(action));
    action.sa_handler = SIG_DFL;
    return sigemptyset(&action.sa_mask) == 0 &&
           sigaction(SIGALRM, &action, NULL) == 0;
}

static void child_exec_probe(
    const struct probe_case *probe, int pipe_read, int pipe_write,
    int null_descriptor)
{
    char *const child_environment[] = {NULL};
    char *const child_argv[] = {
        (char *)probe->reader->path,
        (char *)"read",
        (char *)probe->reader->slot,
        NULL,
    };
    const int inherited_descriptors[] = {pipe_read, pipe_write, null_descriptor};
    size_t descriptor_index;
    int saved_errno;

    if (!default_child_watchdog_signal() ||
        alarm(CHILD_WATCHDOG_SECONDS) != 0U ||
        !unblock_all_child_signals()) {
        _exit(CHILD_INTERNAL_FAILURE);
    }
    if (dup2(null_descriptor, STDIN_FILENO) < 0 ||
        dup2(pipe_write, STDOUT_FILENO) < 0 ||
        dup2(null_descriptor, STDERR_FILENO) < 0) {
        _exit(CHILD_INTERNAL_FAILURE);
    }
    for (descriptor_index = 0U;
         descriptor_index < sizeof(inherited_descriptors) / sizeof(inherited_descriptors[0]);
         ++descriptor_index) {
        if (inherited_descriptors[descriptor_index] > STDERR_FILENO) {
            (void)close(inherited_descriptors[descriptor_index]);
        }
    }
    for (descriptor_index = 0U;
         descriptor_index < sizeof(inherited_descriptors) / sizeof(inherited_descriptors[0]);
         ++descriptor_index) {
        errno = 0;
        if (inherited_descriptors[descriptor_index] > STDERR_FILENO &&
            (fcntl(inherited_descriptors[descriptor_index], F_GETFD) != -1 ||
             errno != EBADF)) {
            _exit(CHILD_INTERNAL_FAILURE);
        }
    }
    (void)umask(077);
    if (!exact_child_identity(probe->uid, probe->gid)) {
        _exit(CHILD_INTERNAL_FAILURE);
    }
    execve(probe->reader->path, child_argv, child_environment);
    saved_errno = errno;
    _exit(saved_errno == EACCES || saved_errno == EPERM
              ? CHILD_EXEC_DENIED
              : CHILD_INTERNAL_FAILURE);
}

static bool monotonic_milliseconds(uint64_t *value)
{
    struct timespec current;
    uint64_t seconds;
    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0 || current.tv_sec < 0 ||
        current.tv_nsec < 0) {
        return false;
    }
    seconds = (uint64_t)current.tv_sec;
    if (seconds > (UINT64_MAX - 999U) / 1000U) {
        return false;
    }
    *value = seconds * 1000U + (uint64_t)current.tv_nsec / 1000000U;
    return true;
}

static void kill_and_reap(pid_t child, int *status)
{
    pid_t result;
    if (child <= 0) {
        return;
    }
    (void)kill(child, SIGKILL);
    do {
        result = waitpid(child, status, 0);
    } while (result < 0 && errno == EINTR);
}

static bool canonical_nonzero_secret(const unsigned char *value, size_t length)
{
    size_t index;
    unsigned char nonzero = 0U;
    if (length != SECRET_HEX_LENGTH) {
        return false;
    }
    for (index = 0U; index < SECRET_HEX_LENGTH; ++index) {
        unsigned char current = value[index];
        if (!((current >= (unsigned char)'0' && current <= (unsigned char)'9') ||
              (current >= (unsigned char)'a' && current <= (unsigned char)'f'))) {
            return false;
        }
        nonzero |= (unsigned char)(current != (unsigned char)'0');
    }
    return nonzero != 0U;
}

static bool run_probe_once(
    const struct probe_case *probe, struct capture_state *capture)
{
    int pipe_descriptors[2] = {-1, -1};
    int null_descriptor = -1;
    int status = 0;
    int flags;
    pid_t child = -1;
    pid_t wait_result;
    size_t received = 0U;
    uint64_t started;
    uint64_t now;
    uint64_t deadline;
    bool child_done = false;
    bool eof = false;
    bool timed_out = false;
    bool io_failed = false;
    bool canonical = false;
    bool passed = false;
    bool signals_blocked = false;
    sigset_t previous_signals;

    secure_zero(capture, sizeof(*capture));
    if (!block_signals(&previous_signals)) {
        goto cleanup;
    }
    signals_blocked = true;
    if (!only_standard_descriptors_open() ||
        !monotonic_milliseconds(&started) ||
        started > UINT64_MAX - PROBE_TIMEOUT_MILLISECONDS) {
        goto cleanup;
    }
    deadline = started + PROBE_TIMEOUT_MILLISECONDS;
    if (pipe(pipe_descriptors) != 0) {
        goto cleanup;
    }
    if (fcntl(pipe_descriptors[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pipe_descriptors[1], F_SETFD, FD_CLOEXEC) != 0) {
        goto cleanup;
    }
    null_descriptor = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (null_descriptor < 0 || !exact_null_descriptor(null_descriptor)) {
        goto cleanup;
    }
    if (!monotonic_milliseconds(&now) || now >= deadline) {
        timed_out = true;
        goto cleanup;
    }
    child = fork();
    if (child < 0) {
        goto cleanup;
    }
    if (child == 0) {
        child_exec_probe(
            probe, pipe_descriptors[0], pipe_descriptors[1], null_descriptor);
    }

    (void)close(pipe_descriptors[1]);
    pipe_descriptors[1] = -1;
    (void)close(null_descriptor);
    null_descriptor = -1;
    flags = fcntl(pipe_descriptors[0], F_GETFL);
    if (flags < 0 || fcntl(pipe_descriptors[0], F_SETFL, flags | O_NONBLOCK) != 0 ||
        !only_standard_and_optional_descriptor_open(pipe_descriptors[0])) {
        io_failed = true;
        goto stop_child;
    }

    while (!child_done || !eof) {
        struct pollfd poll_descriptor;
        int poll_timeout = POLL_SLICE_MILLISECONDS;
        int poll_result;

        while (!eof && received < sizeof(capture->bytes)) {
            ssize_t current = read(
                pipe_descriptors[0], capture->bytes + received,
                sizeof(capture->bytes) - received);
            if (current > 0) {
                received += (size_t)current;
                continue;
            }
            if (current == 0) {
                eof = true;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                io_failed = true;
            }
            break;
        }
        if (received == sizeof(capture->bytes) || io_failed) {
            goto stop_child;
        }

        if (!child_done) {
            wait_result = waitpid(child, &status, WNOHANG);
            if (wait_result == child) {
                child_done = true;
            } else if (wait_result < 0 && errno == EINTR) {
                continue;
            } else if (wait_result < 0) {
                io_failed = true;
                goto stop_child;
            }
        }
        if (!monotonic_milliseconds(&now)) {
            io_failed = true;
            goto stop_child;
        }
        if (now >= deadline) {
            timed_out = true;
            goto stop_child;
        }
        if (child_done && eof) {
            break;
        }
        if (deadline - now < (uint64_t)poll_timeout) {
            poll_timeout = (int)(deadline - now);
        }
        poll_descriptor.fd = pipe_descriptors[0];
        poll_descriptor.events = POLLIN | POLLHUP;
        poll_descriptor.revents = 0;
        poll_result = poll(&poll_descriptor, 1, poll_timeout);
        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result < 0) {
            io_failed = true;
            goto stop_child;
        }
    }

    canonical = canonical_nonzero_secret(capture->bytes, received);
    secure_zero(capture, sizeof(*capture));
    if (!child_done || !WIFEXITED(status)) {
        goto cleanup;
    }
    if (probe->expect_secret) {
        passed = WEXITSTATUS(status) == 0 && received == SECRET_HEX_LENGTH && canonical;
    } else {
        passed = received == 0U &&
                 (WEXITSTATUS(status) == READER_DENIED ||
                  WEXITSTATUS(status) == CHILD_EXEC_DENIED);
    }
    goto cleanup;

stop_child:
    if (!child_done) {
        kill_and_reap(child, &status);
        child_done = true;
    }

cleanup:
    if (child > 0 && !child_done) {
        kill_and_reap(child, &status);
    }
    if (pipe_descriptors[0] >= 0) {
        (void)close(pipe_descriptors[0]);
    }
    if (pipe_descriptors[1] >= 0) {
        (void)close(pipe_descriptors[1]);
    }
    if (null_descriptor >= 0) {
        (void)close(null_descriptor);
    }
    secure_zero(capture, sizeof(*capture));
    if (signals_blocked &&
        sigprocmask(SIG_SETMASK, &previous_signals, NULL) != 0) {
        passed = false;
    }
    (void)timed_out;
    (void)io_failed;
    return passed;
}

int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};
    struct capture_state capture;
    size_t index;
    bool all_passed = true;
    bool output_ok = true;
    bool locked = false;

    (void)umask(077);
    secure_zero(&capture, sizeof(capture));
    if (setrlimit(RLIMIT_CORE, &no_core) != 0 ||
        mlock(&capture, sizeof(capture)) != 0) {
        (void)emit_line("preflight=FAIL\n");
        return 70;
    }
    locked = true;
    if (argc != 1 || argv == NULL || argv[0] == NULL || argv[1] != NULL ||
        !exact_root_identity() || !empty_environment() ||
        !fixed_foreground_terminal_descriptors() ||
        !only_standard_descriptors_open() || !secure_self() ||
        !secure_reader(&EXECUTOR_CONTRACT) || !secure_reader(&CONTROL_CONTRACT) ||
        !only_standard_descriptors_open()) {
        output_ok = emit_line("preflight=FAIL\n");
        all_passed = false;
        goto cleanup;
    }

    for (index = 0U; index < sizeof(PROBE_CASES) / sizeof(PROBE_CASES[0]); ++index) {
        bool passed = run_probe_once(&PROBE_CASES[index], &capture);
        passed = passed && only_standard_descriptors_open();
        const char *line = passed ? PROBE_CASES[index].matrix_line_pass
                                  : PROBE_CASES[index].matrix_line_fail;
        output_ok = emit_line(line) && output_ok;
        all_passed = all_passed && passed;
    }
    output_ok = emit_line(all_passed ? "overall=PASS\n" : "overall=FAIL\n") && output_ok;

cleanup:
    secure_zero(&capture, sizeof(capture));
    if (locked) {
        (void)munlock(&capture, sizeof(capture));
    }
    return all_passed && output_ok ? 0 : 70;
}
