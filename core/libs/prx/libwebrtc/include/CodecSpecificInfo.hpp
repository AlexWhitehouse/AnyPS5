#pragma once

#include <cstddef>
#include <cstdint>

template <std::size_t TSize, std::size_t TAlignment>
struct WebRtcCodecSpecificOptional {
    union {
        char nullState;
        alignas(TAlignment) unsigned char value[TSize];
    } storage;
    bool engaged;
};

struct WebRtcCodecSpecificInfo {
    std::int32_t codecType;
    alignas(8) unsigned char codecSpecific[1624];
    bool endOfPicture;
    WebRtcCodecSpecificOptional<208, 8> genericFrameInfo;
    WebRtcCodecSpecificOptional<128, 8> templateStructure;
    WebRtcCodecSpecificOptional<1, 1> scalabilityMode;
    WebRtcCodecSpecificOptional<56, 8> frameInstrumentationData;
};

static_assert(sizeof(WebRtcCodecSpecificInfo) == 2064);
static_assert(alignof(WebRtcCodecSpecificInfo) == 8);
static_assert(offsetof(WebRtcCodecSpecificInfo, codecType) == 0);
static_assert(offsetof(WebRtcCodecSpecificInfo, codecSpecific) == 8);
static_assert(offsetof(WebRtcCodecSpecificInfo, endOfPicture) == 1632);
static_assert(offsetof(WebRtcCodecSpecificInfo, genericFrameInfo) == 1640);
static_assert(offsetof(WebRtcCodecSpecificInfo, templateStructure) == 1856);
static_assert(offsetof(WebRtcCodecSpecificInfo, scalabilityMode) == 1992);
static_assert(offsetof(WebRtcCodecSpecificInfo, frameInstrumentationData) == 2000);
static_assert(sizeof(decltype(WebRtcCodecSpecificInfo::genericFrameInfo)) == 216);
static_assert(offsetof(decltype(WebRtcCodecSpecificInfo::genericFrameInfo), engaged) == 208);
static_assert(sizeof(decltype(WebRtcCodecSpecificInfo::templateStructure)) == 136);
static_assert(offsetof(decltype(WebRtcCodecSpecificInfo::templateStructure), engaged) == 128);
static_assert(sizeof(decltype(WebRtcCodecSpecificInfo::scalabilityMode)) == 2);
static_assert(offsetof(decltype(WebRtcCodecSpecificInfo::scalabilityMode), engaged) == 1);
static_assert(sizeof(decltype(WebRtcCodecSpecificInfo::frameInstrumentationData)) == 64);
static_assert(offsetof(decltype(WebRtcCodecSpecificInfo::frameInstrumentationData), engaged) == 56);
