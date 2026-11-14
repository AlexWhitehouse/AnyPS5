#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libSceLibreSsl/libSceLibreSsl.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "LibreSSL3 cipher suites check failed at line %u\n", location.line());
    std::abort();
}

int attempts = 0;
int failAt = 0;
int liveBlocks = 0;

void* APS5_VABI Allocate_nid_no_patch(std::size_t bytes) {
    if (++attempts == failAt) return nullptr;
    void* result = std::malloc(bytes);
    if (result) ++liveBlocks;
    return result;
}

void APS5_VABI Release_nid_no_patch(void* pointer) {
    if (pointer) --liveBlocks;
    std::free(pointer);
}

void* APS5_VABI Reallocate_nid_no_patch(void* pointer, std::size_t bytes) {
    if (++attempts == failAt) return nullptr;
    void* result = std::realloc(pointer, bytes);
    if (result && !pointer) ++liveBlocks;
    return result;
}

void* APS5_VABI UnexpectedCalloc_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected calloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void CheckList(void* list, std::initializer_list<std::uint64_t> ids) {
    auto* stack = static_cast<LibreSslStack*>(list);
    Require(stack != nullptr);
    Require(stack->num == static_cast<int>(ids.size()));
    int index = 0;
    for (auto id : ids) {
        const auto* cipher = reinterpret_cast<const LibreSsl3Cipher*>(stack->data[index++]);
        Require(SSL_CIPHER_get_id_nid_postfix(cipher) == id);
    }
}

void Clear(LibreSsl3SslCtx& ctx) {
    sk_free_nid_postfix(static_cast<LibreSslStack*>(ctx.cipherList));
    sk_free_nid_postfix(static_cast<LibreSslStack*>(ctx.cipherListTls13));
    ctx = {};
}

template<typename TAction> void RequireInvalid(TAction action) {
    try { action(); } catch (const std::invalid_argument&) { return; }
    Require(false);
}

void TestSuites() {
    LibreSsl3SslCtx ctx {};
    const char* names[] = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"};
    const char* aliases[] = {"AEAD-AES128-GCM-SHA256", "AEAD-AES256-GCM-SHA384", "AEAD-CHACHA20-POLY1305-SHA256"};
    const std::uint64_t encryption[] = {0x400, 0x800, 0x1000};
    for (int i = 0; i < 3; ++i) {
        for (const char* name : {names[i], aliases[i]}) {
            Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, name) == 1);
            CheckList(ctx.cipherListTls13, {0x03001301u + i});
            CheckList(ctx.cipherList, {0x03001301u + i});
            auto* stack = static_cast<LibreSslStack*>(ctx.cipherList);
            const auto* cipher = reinterpret_cast<const LibreSsl3Cipher*>(stack->data[0]);
            Require(cipher->valid == 1 && std::strcmp(cipher->name, names[i]) == 0);
            Require(cipher->keyExchange == 0x400 && cipher->authentication == 0x400);
            Require(cipher->encryption == encryption[i] && cipher->mac == 0x40 && cipher->protocol == 8);
            Require(cipher->strengthFlags == 0x80 && cipher->extraFlags == (i == 1 ? 0x100 : 0x80));
            Require(cipher->strengthBits == (i == 0 ? 128 : 256) && cipher->algorithmBits == cipher->strengthBits);
        }
    }
    Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "TLS_AES_256_GCM_SHA384:AEAD-AES128-GCM-SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") == 1);
    CheckList(ctx.cipherListTls13, {0x03001302, 0x03001301, 0x03001303, 0x03001301});
    CheckList(ctx.cipherList, {0x03001302, 0x03001301, 0x03001303, 0x03001301});
    auto* before = ctx.cipherList;
    auto* before13 = ctx.cipherListTls13;
    for (const char* invalid : {"unknown", ":", ":TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256:", "TLS_AES_128_GCM_SHA256::TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256:unknown", "tls_aes_128_gcm_sha256", " TLS_AES_128_GCM_SHA256"}) {
        ERR_clear_error_nid_postfix();
        Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, invalid) == 0);
        Require(ctx.cipherList == before && ctx.cipherListTls13 == before13);
        CheckList(ctx.cipherList, {0x03001302, 0x03001301, 0x03001303, 0x03001301});
        Require(ERR_get_error_nid_postfix() == ((20u << 24) | (0xfffu << 12) | 185u));
        Require(ERR_get_error_nid_postfix() == 0);
    }
    for (const char* skipped : {"", "TLS_AES_128_CCM_SHA256", "AEAD-AES128-CCM-SHA256", "TLS_AES_128_CCM_8_SHA256", "AEAD-AES128-CCM-8-SHA256"}) {
        Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, skipped) == 1);
        CheckList(ctx.cipherListTls13, {});
        CheckList(ctx.cipherList, {});
        Require(ERR_get_error_nid_postfix() == 0);
    }
    Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "TLS_AES_128_CCM_SHA256:TLS_AES_256_GCM_SHA384:AEAD-AES128-CCM-8-SHA256:AEAD-AES128-GCM-SHA256") == 1);
    CheckList(ctx.cipherList, {0x03001302, 0x03001301});
    RequireInvalid([&] { SSL_CTX_set_ciphersuites_nid_postfix(&ctx, nullptr); });
    RequireInvalid([] { SSL_CTX_set_ciphersuites_nid_postfix(nullptr, ""); });
    RequireInvalid([] { SSL_CTX_set_ciphersuites_nid_postfix(nullptr, nullptr); });
    CheckList(ctx.cipherList, {0x03001302, 0x03001301});
    Clear(ctx);
}

void TestMerge() {
    LibreSsl3Cipher first {}, second {}, old13 {}, combinedProtocol {};
    first.id = 0x03000035;
    first.protocol = 1;
    second.id = 0x0300c02f;
    second.protocol = 4;
    old13.id = 0x03001303;
    old13.protocol = 8;
    combinedProtocol.id = 0x03000001;
    combinedProtocol.protocol = 9;
    LibreSsl3SslCtx ctx {};
    auto* list = sk_new_nid_postfix(nullptr);
    Require(list != nullptr);
    for (auto* cipher : {&first, &old13, &second, &old13, &combinedProtocol, &first}) Require(sk_push_nid_postfix(list, cipher) != 0);
    ctx.cipherList = list;
    Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "TLS_AES_128_GCM_SHA256") == 1);
    CheckList(ctx.cipherList, {0x03001301, first.id, second.id, combinedProtocol.id, first.id});
    CheckList(ctx.cipherListTls13, {0x03001301});
    auto* merged = static_cast<LibreSslStack*>(ctx.cipherList);
    Require(reinterpret_cast<void*>(merged->data[1]) == &first);
    Require(reinterpret_cast<void*>(merged->data[2]) == &second);
    Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") == 1);
    CheckList(ctx.cipherList, {0x03001302, 0x03001303, first.id, second.id, combinedProtocol.id, first.id});
    Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "") == 1);
    CheckList(ctx.cipherList, {first.id, second.id, combinedProtocol.id, first.id});
    Clear(ctx);
}

void TestAllocationFailures() {
    for (int failure = 1; failure <= 5; ++failure) {
        LibreSsl3SslCtx ctx {};
        Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "TLS_AES_128_GCM_SHA256") == 1);
        void* before = ctx.cipherList;
        void* before13 = ctx.cipherListTls13;
        attempts = 0;
        failAt = failure;
        ERR_clear_error_nid_postfix();
        Require(SSL_CTX_set_ciphersuites_nid_postfix(&ctx, "TLS_AES_256_GCM_SHA384") == 0);
        failAt = 0;
        Require(ctx.cipherList == before);
        CheckList(ctx.cipherList, {0x03001301});
        if (failure <= 3) {
            Require(ctx.cipherListTls13 == before13);
            CheckList(ctx.cipherListTls13, {0x03001301});
            Require(ERR_get_error_nid_postfix() == ((20u << 24) | (0xfffu << 12) | 185u));
        } else {
            Require(ctx.cipherListTls13 != before13);
            CheckList(ctx.cipherListTls13, {0x03001302});
            Require(ERR_get_error_nid_postfix() == 0);
        }
        Clear(ctx);
        Require(liveBlocks == 0);
    }
}

}

int main() {
    std::array<void*, 10> api {
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Release_nid_no_patch), reinterpret_cast<void*>(UnexpectedCalloc_nid_no_patch),
        reinterpret_cast<void*>(Reallocate_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch), reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    TestSuites();
    TestMerge();
    TestAllocationFailures();
    Require(liveBlocks == 0);
    std::puts("LibreSSL3 cipher suites tests passed");
}
