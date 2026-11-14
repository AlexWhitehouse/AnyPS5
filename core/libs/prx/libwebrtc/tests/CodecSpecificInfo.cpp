#include "prx/libwebrtc/libwebrtc.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "libwebrtc CodecSpecificInfo check failed at line %u\n", location.line());
    std::abort();
}

struct GuardedInfo {
    std::array<unsigned char, 16> before;
    WebRtcCodecSpecificInfo object;
    std::array<unsigned char, 16> after;
};

static_assert(offsetof(GuardedInfo, object) == 16);
static_assert(offsetof(GuardedInfo, after) == 2080);

}

int main() {
    for (unsigned char poison : {0x81, 0xa5, 0xff}) {
        GuardedInfo storage;
        std::memset(&storage, poison, sizeof(storage));
        _ZN6webrtc17CodecSpecificInfoC1Ev_nid_postfix(&storage.object);
        Require(storage.object.codecType == 0);
        for (auto byte : storage.object.codecSpecific) Require(byte == 0);
        Require(storage.object.endOfPicture);
        Require(!storage.object.genericFrameInfo.engaged);
        Require(!storage.object.templateStructure.engaged);
        Require(!storage.object.scalabilityMode.engaged);
        Require(!storage.object.frameInstrumentationData.engaged);
        auto* bytes = reinterpret_cast<const unsigned char*>(&storage.object);
        for (auto [offset, size] : std::array<std::array<std::size_t, 2>, 4>{{{1640, 208}, {1856, 128}, {1992, 1}, {2000, 56}}}) {
            for (std::size_t index = 0; index < size; ++index) Require(bytes[offset + index] == poison);
            Require(bytes[offset + size] == 0);
        }
        Require(bytes[1632] == 1);
        for (auto byte : storage.before) Require(byte == poison);
        for (auto byte : storage.after) Require(byte == poison);
    }
    try {
        _ZN6webrtc17CodecSpecificInfoC1Ev_nid_postfix(nullptr);
        Require(false);
    } catch (const std::invalid_argument&) {
    }
    return 0;
}
