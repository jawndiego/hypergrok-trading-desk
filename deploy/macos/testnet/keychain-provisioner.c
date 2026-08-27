/*
 * One-shot, attended macOS System Keychain provisioner.
 *
 * This program has no caller-selected operation, path, label, account, or
 * trusted application.  Each invocation creates one of four fixed TESTNET
 * generic-password items, with its initial ACL bound to the matching installed
 * role reader.
 * It has no Keychain search, read, update, delete, export, or list path.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <Security/SecAccess.h>
#include <Security/SecCode.h>
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecRandom.h>
#include <Security/SecStaticCode.h>
#include <Security/SecTrustedApplication.h>
#include <mach-o/dyld.h>
#include <readpassphrase.h>
#include <sys/acl.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
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
#define PROVISIONING_DIRECTORY "/private/var/root/trading-desk-keychain-provisioning-v1"
#define EXPECTED_PATH PROVISIONING_DIRECTORY "/trading-keychain-provisioner-v1"
#define EXPECTED_IDENTIFIER "com.jawndiego.trading-desk.keychain-provisioner.v1"
#define EXECUTOR_READER "/opt/trading-desk/libexec/trading-keychain-reader-executor-v1"
#define CONTROL_READER "/opt/trading-desk/libexec/trading-keychain-reader-control-v1"
#define EXECUTOR_IDENTIFIER "com.jawndiego.trading-desk.keychain-reader.executor.v1"
#define CONTROL_IDENTIFIER "com.jawndiego.trading-desk.keychain-reader.control.v1"
#define EXECUTOR_SHA256 "42e583ee40d48546a92bf40bf650fa576ec3d86455bf663cc3760b90d050df27"
#define CONTROL_SHA256 "da10752940f726258f4e2439b657db0c2f3fefcb3c30ef6a1eaa69df3da8e194"
#define SECRET_HEX_LENGTH 64U
#define RANDOM_LENGTH 32U
#define INPUT_LENGTH 1024U
#define HASH_BUFFER_LENGTH 4096U

struct credential_slot {
    const char *name;
    const char *service;
    const char *account;
    const char *reader_path;
    const char *reader_identifier;
    const char *reader_sha256;
    gid_t reader_gid;
    bool supplied_by_operator;
};

static const struct credential_slot SLOTS[] = {
    {
        "signer",
        "com.jawndiego.trading-desk.testnet-signer",
        "hyperliquid-api-wallet",
        EXECUTOR_READER,
        EXECUTOR_IDENTIFIER,
        EXECUTOR_SHA256,
        (gid_t)451,
        true,
    },
    {
        "recovery",
        "com.jawndiego.trading-desk.testnet-recovery",
        "recovery-hmac",
        EXECUTOR_READER,
        EXECUTOR_IDENTIFIER,
        EXECUTOR_SHA256,
        (gid_t)451,
        false,
    },
    {
        "approval",
        "com.jawndiego.trading-desk.testnet-approval",
        "approval-hmac",
        CONTROL_READER,
        CONTROL_IDENTIFIER,
        CONTROL_SHA256,
        (gid_t)452,
        false,
    },
    {
        "grant",
        "com.jawndiego.trading-desk.testnet-grant",
        "grant-hmac",
        CONTROL_READER,
        CONTROL_IDENTIFIER,
        CONTROL_SHA256,
        (gid_t)452,
        false,
    },
    {
        "probe-executor",
        "com.jawndiego.trading-desk.testnet-probe-executor",
        "sacrificial-probe-executor-v1",
        EXECUTOR_READER,
        EXECUTOR_IDENTIFIER,
        EXECUTOR_SHA256,
        (gid_t)451,
        false,
    },
    {
        "probe-control",
        "com.jawndiego.trading-desk.testnet-probe-control",
        "sacrificial-probe-control-v1",
        CONTROL_READER,
        CONTROL_IDENTIFIER,
        CONTROL_SHA256,
        (gid_t)452,
        false,
    },
};

struct sensitive_state {
    char first_input[INPUT_LENGTH];
    char second_input[INPUT_LENGTH];
    char confirmation[SECRET_HEX_LENGTH + 1U];
    char secret[SECRET_HEX_LENGTH + 1U];
    unsigned char random_bytes[RANDOM_LENGTH];
    unsigned char hash_buffer[HASH_BUFFER_LENGTH];
    unsigned char hash_bytes[CC_SHA256_DIGEST_LENGTH];
    char hash_hex[CC_SHA256_DIGEST_LENGTH * 2U + 1U];
};

extern char **environ;

static bool constant_time_equal(const char *left, const char *right);

static void secure_zero(void *value, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)value;
    while (length > 0U) {
        *cursor++ = 0U;
        --length;
    }
}

static int fail(void)
{
    static const char message[] = "keychain provisioner unavailable\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1U);
    return 70;
}

static int success(void)
{
    static const char message[] =
        "one fixed TESTNET System Keychain item created\n";
    return write(STDERR_FILENO, message, sizeof(message) - 1U) ==
                   (ssize_t)(sizeof(message) - 1U)
               ? 0
               : 70;
}

static bool has_extended_acl(const char *path)
{
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    acl_entry_t entry;
    int status;
    if (acl == NULL) {
        return true;
    }
    status = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    (void)acl_free(acl);
    return status == 1 || status == -1;
}

static bool secure_directory(const char *path, mode_t exact_mode)
{
    struct stat value;
    if (lstat(path, &value) != 0 || !S_ISDIR(value.st_mode) || value.st_uid != 0 ||
        value.st_gid != 0 || has_extended_acl(path)) {
        return false;
    }
    if (exact_mode != 0U) {
        return (value.st_mode & 07777U) == exact_mode;
    }
    return (value.st_mode & 0022U) == 0U;
}

static bool secure_regular_file(
    const char *path, uid_t expected_uid, gid_t expected_gid, mode_t exact_mode)
{
    struct stat value;
    char resolved[PATH_MAX];
    if (realpath(path, resolved) == NULL || strcmp(path, resolved) != 0 ||
        lstat(path, &value) != 0 || !S_ISREG(value.st_mode)) {
        return false;
    }
    return value.st_uid == expected_uid && value.st_gid == expected_gid &&
           value.st_nlink == 1 && (value.st_mode & 07777U) == exact_mode &&
           !has_extended_acl(path);
}

static bool signed_code_matches(const char *path, const char *identifier)
{
    CFURLRef url = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    CFStringRef actual_identifier;
    CFStringRef expected_identifier = NULL;
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

static bool hash_file_matches(
    const char *path, const char *expected_hex, struct sensitive_state *state)
{
    static const char hexadecimal[] = "0123456789abcdef";
    struct stat before;
    struct stat after;
    struct stat path_after;
    CC_SHA256_CTX context;
    ssize_t received;
    size_t index;
    int descriptor = -1;
    bool matches = false;

    descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_uid != 0 || before.st_nlink != 1) {
        goto cleanup;
    }
    if (CC_SHA256_Init(&context) != 1) {
        goto cleanup;
    }
    while ((received = read(descriptor, state->hash_buffer,
                            sizeof(state->hash_buffer))) > 0) {
        if (CC_SHA256_Update(&context, state->hash_buffer, (CC_LONG)received) != 1) {
            secure_zero(&context, sizeof(context));
            goto cleanup;
        }
        secure_zero(state->hash_buffer, sizeof(state->hash_buffer));
    }
    if (received != 0 || CC_SHA256_Final(state->hash_bytes, &context) != 1) {
        secure_zero(&context, sizeof(context));
        goto cleanup;
    }
    secure_zero(&context, sizeof(context));
    if (fstat(descriptor, &after) != 0 || lstat(path, &path_after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
        before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
        before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
        before.st_gid != after.st_gid || before.st_nlink != after.st_nlink ||
        after.st_dev != path_after.st_dev || after.st_ino != path_after.st_ino ||
        after.st_size != path_after.st_size || after.st_mode != path_after.st_mode ||
        after.st_uid != path_after.st_uid || after.st_gid != path_after.st_gid ||
        after.st_nlink != path_after.st_nlink) {
        goto cleanup;
    }
    for (index = 0U; index < sizeof(state->hash_bytes); ++index) {
        unsigned char value = state->hash_bytes[index];
        state->hash_hex[index * 2U] = hexadecimal[value >> 4U];
        state->hash_hex[index * 2U + 1U] = hexadecimal[value & 0x0fU];
    }
    state->hash_hex[CC_SHA256_DIGEST_LENGTH * 2U] = '\0';
    matches = constant_time_equal(state->hash_hex, expected_hex);

cleanup:
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    secure_zero(state->hash_buffer, sizeof(state->hash_buffer));
    secure_zero(state->hash_bytes, sizeof(state->hash_bytes));
    secure_zero(state->hash_hex, sizeof(state->hash_hex));
    return matches;
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
        !secure_regular_file(EXPECTED_PATH, (uid_t)0, (gid_t)0, (mode_t)0500) ||
        !secure_directory(PROVISIONING_DIRECTORY, (mode_t)0700) ||
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

static bool secure_system_keychain(void)
{
    struct stat value;
    char resolved[PATH_MAX];
    const char *const ancestors[] = {"/", "/Library", "/Library/Keychains"};
    size_t index;

    if (realpath(SYSTEM_KEYCHAIN, resolved) == NULL ||
        strcmp(resolved, SYSTEM_KEYCHAIN) != 0 ||
        lstat(SYSTEM_KEYCHAIN, &value) != 0 || !S_ISREG(value.st_mode) ||
        value.st_uid != 0 || value.st_gid != 0 || value.st_nlink != 1 ||
        (value.st_mode & 0022U) != 0U || has_extended_acl(SYSTEM_KEYCHAIN)) {
        return false;
    }
    for (index = 0U; index < sizeof(ancestors) / sizeof(ancestors[0]); ++index) {
        if (!secure_directory(ancestors[index], (mode_t)0)) {
            return false;
        }
    }
    return true;
}

static bool secure_reader(const struct credential_slot *slot, struct sensitive_state *state)
{
    const char *const ancestors[] = {"/", "/opt", "/opt/trading-desk", "/opt/trading-desk/libexec"};
    size_t index;
    if (!secure_regular_file(
            slot->reader_path, (uid_t)0, slot->reader_gid, (mode_t)0510) ||
        !hash_file_matches(slot->reader_path, slot->reader_sha256, state) ||
        !signed_code_matches(slot->reader_path, slot->reader_identifier)) {
        return false;
    }
    for (index = 0U; index < sizeof(ancestors) / sizeof(ancestors[0]); ++index) {
        if (!secure_directory(ancestors[index], (mode_t)0)) {
            return false;
        }
    }
    return true;
}

static const struct credential_slot *find_slot(const char *name)
{
    size_t index;
    for (index = 0U; index < sizeof(SLOTS) / sizeof(SLOTS[0]); ++index) {
        if (strcmp(name, SLOTS[index].name) == 0) {
            return &SLOTS[index];
        }
    }
    return NULL;
}

static bool exact_root_identity(void)
{
    return getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0;
}

static bool empty_environment(void)
{
    return environ != NULL && environ[0] == NULL;
}

static bool fixed_terminal_descriptors(void)
{
    struct stat descriptors[3];
    int descriptor_limit;
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
    descriptor_limit = getdtablesize();
    if (descriptor_limit < 3) {
        return false;
    }
    for (descriptor = STDERR_FILENO + 1; descriptor < descriptor_limit; ++descriptor) {
        errno = 0;
        if (fcntl(descriptor, F_GETFD) != -1 || errno != EBADF) {
            return false;
        }
    }
    return true;
}

static bool normalize_signer(const char *input, char output[SECRET_HEX_LENGTH + 1U])
{
    size_t length = strnlen(input, INPUT_LENGTH);
    size_t offset = 0U;
    size_t index;
    unsigned char nonzero = 0U;

    secure_zero(output, SECRET_HEX_LENGTH + 1U);
    if (length == INPUT_LENGTH) {
        return false;
    }
    if (length == SECRET_HEX_LENGTH + 2U && input[0] == '0' &&
        (input[1] == 'x' || input[1] == 'X')) {
        offset = 2U;
    } else if (length != SECRET_HEX_LENGTH) {
        return false;
    }
    for (index = 0U; index < SECRET_HEX_LENGTH; ++index) {
        unsigned char value = (unsigned char)input[index + offset];
        if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
            output[index] = (char)value;
        } else if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
            output[index] = (char)value;
        } else if (value >= (unsigned char)'A' && value <= (unsigned char)'F') {
            output[index] = (char)(value + ((unsigned char)'a' - (unsigned char)'A'));
        } else {
            secure_zero(output, SECRET_HEX_LENGTH + 1U);
            return false;
        }
        nonzero |= (unsigned char)(output[index] != '0');
    }
    output[SECRET_HEX_LENGTH] = '\0';
    if (nonzero == 0U) {
        secure_zero(output, SECRET_HEX_LENGTH + 1U);
        return false;
    }
    return true;
}

static bool constant_time_equal(const char *left, const char *right)
{
    size_t index;
    const volatile unsigned char *left_bytes =
        (const volatile unsigned char *)left;
    const volatile unsigned char *right_bytes =
        (const volatile unsigned char *)right;
    volatile unsigned char difference = 0U;
    for (index = 0U; index < SECRET_HEX_LENGTH; ++index) {
        difference |= left_bytes[index] ^ right_bytes[index];
    }
    return difference == 0U;
}

static bool generate_hex_secret(struct sensitive_state *state)
{
    static const char hexadecimal[] = "0123456789abcdef";
    unsigned int attempt;
    size_t index;
    unsigned char nonzero;

    for (attempt = 0U; attempt < 8U; ++attempt) {
        secure_zero(state->random_bytes, sizeof(state->random_bytes));
        if (SecRandomCopyBytes(
                kSecRandomDefault, sizeof(state->random_bytes), state->random_bytes) != 0) {
            return false;
        }
        nonzero = 0U;
        for (index = 0U; index < sizeof(state->random_bytes); ++index) {
            unsigned char value = state->random_bytes[index];
            nonzero |= value;
            state->secret[index * 2U] = hexadecimal[value >> 4U];
            state->secret[index * 2U + 1U] = hexadecimal[value & 0x0fU];
        }
        state->secret[SECRET_HEX_LENGTH] = '\0';
        secure_zero(state->random_bytes, sizeof(state->random_bytes));
        if (nonzero != 0U) {
            return true;
        }
    }
    secure_zero(state->secret, sizeof(state->secret));
    return false;
}

static bool read_confirmed_signer(struct sensitive_state *state)
{
    bool valid_first;
    bool valid_second;

    if (readpassphrase(
            "TESTNET API-wallet private key: ", state->first_input,
            sizeof(state->first_input), RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
        return false;
    }
    valid_first = normalize_signer(state->first_input, state->secret);
    secure_zero(state->first_input, sizeof(state->first_input));
    if (!valid_first) {
        return false;
    }
    if (readpassphrase(
            "Repeat TESTNET API-wallet private key: ", state->second_input,
            sizeof(state->second_input), RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
        return false;
    }
    valid_second = normalize_signer(state->second_input, state->confirmation);
    secure_zero(state->second_input, sizeof(state->second_input));
    if (!valid_second ||
        !constant_time_equal(state->secret, state->confirmation)) {
        secure_zero(state->confirmation, sizeof(state->confirmation));
        return false;
    }
    secure_zero(state->confirmation, sizeof(state->confirmation));
    return true;
}

static bool create_item(
    SecKeychainRef keychain, const struct credential_slot *slot, const char *secret)
{
    SecTrustedApplicationRef trusted_application = NULL;
    CFArrayRef trusted_list = NULL;
    SecAccessRef access = NULL;
    SecKeychainItemRef item = NULL;
    CFStringRef descriptor = NULL;
    SecKeychainAttribute attributes[2];
    SecKeychainAttributeList attribute_list;
    OSStatus status;
    bool created = false;

    status = SecTrustedApplicationCreateFromPath(
        slot->reader_path, &trusted_application);
    if (status != errSecSuccess || trusted_application == NULL) {
        goto cleanup;
    }
    {
        const void *values[] = {trusted_application};
        trusted_list = CFArrayCreate(
            kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
    }
    descriptor = CFStringCreateWithCString(
        kCFAllocatorDefault, slot->service, kCFStringEncodingUTF8);
    if (trusted_list == NULL || descriptor == NULL) {
        goto cleanup;
    }
    status = SecAccessCreate(descriptor, trusted_list, &access);
    if (status != errSecSuccess || access == NULL) {
        goto cleanup;
    }

    attributes[0].tag = kSecServiceItemAttr;
    attributes[0].length = (UInt32)strlen(slot->service);
    attributes[0].data = (void *)slot->service;
    attributes[1].tag = kSecAccountItemAttr;
    attributes[1].length = (UInt32)strlen(slot->account);
    attributes[1].data = (void *)slot->account;
    attribute_list.count = 2U;
    attribute_list.attr = attributes;

    status = SecKeychainItemCreateFromContent(
        kSecGenericPasswordItemClass, &attribute_list,
        (UInt32)SECRET_HEX_LENGTH, secret, keychain, access, &item);
    /* errSecDuplicateItem is deliberately a terminal failure.  No existing
     * item is queried, read, modified, replaced, or deleted. */
    if (status == errSecDuplicateItem) {
        created = false;
    } else {
        created = status == errSecSuccess && item != NULL;
    }

cleanup:
    if (item != NULL) {
        CFRelease(item);
    }
    if (access != NULL) {
        CFRelease(access);
    }
    if (descriptor != NULL) {
        CFRelease(descriptor);
    }
    if (trusted_list != NULL) {
        CFRelease(trusted_list);
    }
    if (trusted_application != NULL) {
        CFRelease(trusted_application);
    }
    return created;
}

int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};
    struct sensitive_state state;
    SecKeychainRef keychain = NULL;
    OSStatus status;
    const struct credential_slot *slot = NULL;
    bool locked = false;
    int result = 70;

    (void)umask(077);
    secure_zero(&state, sizeof(state));
    if (setrlimit(RLIMIT_CORE, &no_core) != 0 || mlock(&state, sizeof(state)) != 0) {
        return fail();
    }
    locked = true;
    if (argc != 2 || argv == NULL || argv[0] == NULL || argv[1] == NULL ||
        (slot = find_slot(argv[1])) == NULL || !exact_root_identity() ||
        !empty_environment() || !fixed_terminal_descriptors() || !secure_self() ||
        !secure_system_keychain() || !secure_reader(slot, &state)) {
        goto cleanup;
    }
    if (slot->supplied_by_operator) {
        if (!read_confirmed_signer(&state)) {
            goto cleanup;
        }
    } else if (!generate_hex_secret(&state)) {
        goto cleanup;
    }

    status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) {
        goto cleanup;
    }
    status = SecKeychainOpen(SYSTEM_KEYCHAIN, &keychain);
    if (status != errSecSuccess || keychain == NULL) {
        goto cleanup;
    }
    if (!create_item(keychain, slot, state.secret)) {
        goto cleanup;
    }
    result = success();

cleanup:
    if (keychain != NULL) {
        CFRelease(keychain);
    }
    secure_zero(&state, sizeof(state));
    if (locked) {
        (void)munlock(&state, sizeof(state));
    }
    if (result != 0) {
        result = fail();
    }
    return result;
}
