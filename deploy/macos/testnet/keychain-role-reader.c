/*
 * Read-only, role-compiled macOS System Keychain helper.
 *
 * Build this source twice with exactly one of TRADING_HELPER_EXECUTOR or
 * TRADING_HELPER_CONTROL.  The resulting hardened Mach-O is the application
 * trusted by the six generic-password items.  It never provisions, updates,
 * deletes, lists, or selects arbitrary Keychain records.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <mach-o/dyld.h>
#include <sys/acl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYSTEM_KEYCHAIN "/Library/Keychains/System.keychain"
#define MAX_SECRET_BYTES 64U

#if defined(TRADING_HELPER_EXECUTOR) && defined(TRADING_HELPER_CONTROL)
#error "select exactly one helper role"
#elif defined(TRADING_HELPER_EXECUTOR)
#define EXPECTED_UID ((uid_t)451)
#define EXPECTED_GID ((gid_t)451)
#define EXPECTED_PATH "/opt/trading-desk/libexec/trading-keychain-reader-executor-v1"
#define EXPECTED_IDENTIFIER "com.jawndiego.trading-desk.keychain-reader.executor.v1"
static const char *const ROLE_NAME = "executor";
#elif defined(TRADING_HELPER_CONTROL)
#define EXPECTED_UID ((uid_t)452)
#define EXPECTED_GID ((gid_t)452)
#define EXPECTED_PATH "/opt/trading-desk/libexec/trading-keychain-reader-control-v1"
#define EXPECTED_IDENTIFIER "com.jawndiego.trading-desk.keychain-reader.control.v1"
static const char *const ROLE_NAME = "control";
#else
#error "select TRADING_HELPER_EXECUTOR or TRADING_HELPER_CONTROL"
#endif

struct credential_slot {
    const char *name;
    const char *service;
    const char *account;
};

#if defined(TRADING_HELPER_EXECUTOR)
static const struct credential_slot SLOTS[] = {
    {"signer", "com.jawndiego.trading-desk.testnet-signer", "hyperliquid-api-wallet"},
    {"recovery", "com.jawndiego.trading-desk.testnet-recovery", "recovery-hmac"},
    {"probe-executor", "com.jawndiego.trading-desk.testnet-probe-executor", "sacrificial-probe-executor-v1"},
};
#else
static const struct credential_slot SLOTS[] = {
    {"approval", "com.jawndiego.trading-desk.testnet-approval", "approval-hmac"},
    {"grant", "com.jawndiego.trading-desk.testnet-grant", "grant-hmac"},
    {"probe-control", "com.jawndiego.trading-desk.testnet-probe-control", "sacrificial-probe-control-v1"},
};
#endif

extern char **environ;

static int fail(const char *message)
{
    (void)fprintf(stderr, "keychain reader unavailable: %s\n", message);
    return 70;
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

static bool secure_directory(const char *path)
{
    struct stat value;
    if (lstat(path, &value) != 0 || !S_ISDIR(value.st_mode)) {
        return false;
    }
    if (value.st_uid != 0 || value.st_gid != 0 || (value.st_mode & 0022) != 0) {
        return false;
    }
    return !has_extended_acl(path);
}

static bool secure_self_path(void)
{
    char raw_path[PATH_MAX];
    char resolved[PATH_MAX];
    uint32_t size = (uint32_t)sizeof(raw_path);
    struct stat value;
    const char *const ancestors[] = {"/", "/opt", "/opt/trading-desk", "/opt/trading-desk/libexec"};
    size_t index;

    if (_NSGetExecutablePath(raw_path, &size) != 0 || realpath(raw_path, resolved) == NULL) {
        return false;
    }
    if (strcmp(resolved, EXPECTED_PATH) != 0 || lstat(EXPECTED_PATH, &value) != 0) {
        return false;
    }
    if (!S_ISREG(value.st_mode) || value.st_uid != 0 || value.st_gid != EXPECTED_GID ||
        value.st_nlink != 1 || (value.st_mode & 07777) != 0510 || has_extended_acl(EXPECTED_PATH)) {
        return false;
    }
    for (index = 0; index < sizeof(ancestors) / sizeof(ancestors[0]); ++index) {
        if (!secure_directory(ancestors[index])) {
            return false;
        }
    }
    return true;
}

static bool clean_process_environment(void)
{
    char **cursor;
    for (cursor = environ; cursor != NULL && *cursor != NULL; ++cursor) {
        if (strncmp(*cursor, "DYLD_", 5) == 0 || strncmp(*cursor, "LD_", 3) == 0) {
            return false;
        }
    }
    return true;
}

static bool exact_role_identity(void)
{
    gid_t groups[32];
    int count;
    int index;
    if (getuid() != EXPECTED_UID || geteuid() != EXPECTED_UID ||
        getgid() != EXPECTED_GID || getegid() != EXPECTED_GID) {
        return false;
    }
    count = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
    if (count < 0) {
        return false;
    }
    for (index = 0; index < count; ++index) {
        if (groups[index] == 0) {
            return false;
        }
    }
    return true;
}

static bool safe_descriptors(void)
{
    struct stat input;
    struct stat null_device;
    struct stat output;
    if (fstat(STDIN_FILENO, &input) != 0 || stat("/dev/null", &null_device) != 0 ||
        fstat(STDOUT_FILENO, &output) != 0) {
        return false;
    }
    if (!S_ISCHR(input.st_mode) || input.st_rdev != null_device.st_rdev) {
        return false;
    }
    return S_ISFIFO(output.st_mode) && !isatty(STDOUT_FILENO);
}

static const struct credential_slot *find_slot(const char *name)
{
    size_t index;
    for (index = 0; index < sizeof(SLOTS) / sizeof(SLOTS[0]); ++index) {
        if (strcmp(name, SLOTS[index].name) == 0) {
            return &SLOTS[index];
        }
    }
    return NULL;
}

static bool canonical_secret(const unsigned char *value, UInt32 length)
{
    UInt32 index;
    bool nonzero = false;
    if (value == NULL || length != MAX_SECRET_BYTES) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        unsigned char current = value[index];
        bool decimal = current >= (unsigned char)'0' && current <= (unsigned char)'9';
        bool lower_hex = current >= (unsigned char)'a' && current <= (unsigned char)'f';
        if (!decimal && !lower_hex) {
            return false;
        }
        nonzero = nonzero || current != (unsigned char)'0';
    }
    return nonzero;
}

static bool write_all(int descriptor, const unsigned char *value, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, value + offset, length - offset);
        if (written <= 0) {
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

static void secure_zero(void *value, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)value;
    while (length > 0) {
        *cursor++ = 0;
        --length;
    }
}

int main(int argc, char **argv)
{
    const struct credential_slot *slot;
    struct rlimit no_core = {0, 0};
    SecKeychainRef keychain = NULL;
    void *password_data = NULL;
    UInt32 password_length = 0;
    OSStatus status;
    int result = 70;

    (void)umask(077);
    if (setrlimit(RLIMIT_CORE, &no_core) != 0 || !clean_process_environment() ||
        !exact_role_identity() || !secure_self_path() || !safe_descriptors()) {
        return fail("identity or installation invariant");
    }
    if (argc != 3 || strcmp(argv[1], "read") != 0 || (slot = find_slot(argv[2])) == NULL) {
        return fail("unsupported request");
    }

    status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) {
        return fail("Keychain interaction policy unavailable");
    }
    status = SecKeychainOpen(SYSTEM_KEYCHAIN, &keychain);
    if (status != errSecSuccess || keychain == NULL) {
        return fail("System Keychain unavailable");
    }
    status = SecKeychainFindGenericPassword(
        keychain,
        (UInt32)strlen(slot->service), slot->service,
        (UInt32)strlen(slot->account), slot->account,
        &password_length, &password_data, NULL);
    if (status != errSecSuccess || !canonical_secret(password_data, password_length)) {
        result = fail("credential unavailable");
        goto cleanup;
    }
    if (!write_all(STDOUT_FILENO, password_data, password_length)) {
        result = fail("credential pipe unavailable");
        goto cleanup;
    }
    result = 0;

cleanup:
    if (password_data != NULL) {
        secure_zero(password_data, password_length);
        (void)SecKeychainItemFreeContent(NULL, password_data);
    }
    if (keychain != NULL) {
        CFRelease(keychain);
    }
    (void)ROLE_NAME;
    (void)EXPECTED_IDENTIFIER;
    return result;
}
