#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <source_location>
#include <stdexcept>

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "LibreSSL3 verified chain/QUIC check failed at line %u\n", location.line());
    std::abort();
}

template <typename T>
auto Bytes(const T& object) {
    std::array<unsigned char, sizeof(T)> bytes;
    std::memcpy(bytes.data(), &object, sizeof(object));
    return bytes;
}

template <typename T>
struct Guarded {
    std::uint64_t before = 0x123456789abcdef0;
    T value{};
    std::uint64_t after = 0xfedcba9876543210;
};

template <typename TFunction>
void Throws(TFunction function) {
    bool threw = false;
    try {
        function();
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    Require(threw);
}

void Check() {
    Guarded<LibreSsl3Ssl> ssl;
    Guarded<LibreSsl3Ssl3State> state;
    std::memset(&state.value, 0xa5, sizeof(state.value));
    auto savedSsl = Bytes(ssl);
    Require(SSL_get0_verified_chain_nid_postfix(&ssl.value) == nullptr);
    Require(Bytes(ssl) == savedSsl);
    ssl.value.s3 = &state.value;
    ssl.value.references = 17;
    savedSsl = Bytes(ssl);
    Guarded<LibreSsl3Stack> chain;
    chain.value.num = 29;
    const auto savedChain = Bytes(chain);
    for (auto* expected : {static_cast<LibreSsl3Stack*>(nullptr), &chain.value}) {
        std::memcpy(reinterpret_cast<unsigned char*>(&state.value) + 520, &expected, sizeof(expected));
        const auto savedState = Bytes(state);
        Require(SSL_get0_verified_chain_nid_postfix(&ssl.value) == expected);
        Require(Bytes(state) == savedState);
        Require(Bytes(ssl) == savedSsl);
        Require(Bytes(chain) == savedChain);
    }
    std::array<std::uint8_t, 6> binary{0, 0xff, 0x42, 0, 0x80, 0};
    const auto savedBinary = binary;
    for (auto* params : {static_cast<std::uint8_t*>(nullptr), binary.data()}) {
        for (std::size_t length : {std::size_t{0}, binary.size(), std::size_t{0x123456789abcdef}}) {
            std::memcpy(reinterpret_cast<unsigned char*>(&state.value) + 1000, &params, sizeof(params));
            std::memcpy(reinterpret_cast<unsigned char*>(&state.value) + 1008, &length, sizeof(length));
            const auto savedState = Bytes(state);
            Guarded<const std::uint8_t*> outParams;
            Guarded<std::size_t> outLength;
            auto expectedParams = outParams;
            auto expectedLength = outLength;
            expectedParams.value = params;
            expectedLength.value = length;
            SSL_get_peer_quic_transport_params_nid_postfix(&ssl.value, &outParams.value, &outLength.value);
            Require(Bytes(outParams) == Bytes(expectedParams));
            Require(Bytes(outLength) == Bytes(expectedLength));
            Require(Bytes(state) == savedState);
            Require(Bytes(ssl) == savedSsl);
            Require(binary == savedBinary);
        }
    }
    Guarded<const std::uint8_t*> outParams;
    Guarded<std::size_t> outLength;
    const auto savedParams = Bytes(outParams);
    const auto savedLength = Bytes(outLength);
    const auto savedState = Bytes(state);
    Throws([] { SSL_get0_verified_chain_nid_postfix(nullptr); });
    Throws([&] { SSL_get_peer_quic_transport_params_nid_postfix(nullptr, &outParams.value, &outLength.value); });
    Throws([&] { SSL_get_peer_quic_transport_params_nid_postfix(&ssl.value, nullptr, &outLength.value); });
    Throws([&] { SSL_get_peer_quic_transport_params_nid_postfix(&ssl.value, &outParams.value, nullptr); });
    Throws([&] { SSL_get_peer_quic_transport_params_nid_postfix(&ssl.value, nullptr, nullptr); });
    Require(Bytes(state) == savedState);
    Require(Bytes(ssl) == savedSsl);
    ssl.value.s3 = nullptr;
    savedSsl = Bytes(ssl);
    Throws([&] { SSL_get_peer_quic_transport_params_nid_postfix(&ssl.value, &outParams.value, &outLength.value); });
    Require(Bytes(outParams) == savedParams);
    Require(Bytes(outLength) == savedLength);
    Require(Bytes(ssl) == savedSsl);
}

}

int main() {
    try {
        Check();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "LibreSSL3 verified chain/QUIC unexpected exception: %s\n", error.what());
        return 1;
    }
}
