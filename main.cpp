#include "main.h"
#include "mainhash_api.h"
using namespace CryptoObfuscated;

int ultra_secure_hash(const uint8_t* data, int datalen, int bits, uint8_t* outbuf, int outbuflen) {
    UltraSecureHash::OutputSize outsize;
    switch(bits) {
        case 256: outsize = UltraSecureHash::OutputSize::BITS_256; break;
        case 512: outsize = UltraSecureHash::OutputSize::BITS_512; break;
        case 1024: outsize = UltraSecureHash::OutputSize::BITS_1024; break;
        case 2048: outsize = UltraSecureHash::OutputSize::BITS_2048; break;
        case 4096: outsize = UltraSecureHash::OutputSize::BITS_4096; break;
        default: return -1;
    }
    std::vector<uint8_t> input(data, data + datalen);
    UltraSecureHash hasher(outsize);
    std::vector<uint8_t> hash = hasher.ComputeHash(input);
    if ((int)hash.size() > outbuflen) return -2;
    std::copy(hash.begin(), hash.end(), outbuf);
    return (int)hash.size();
}
