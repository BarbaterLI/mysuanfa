#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

class SHA3 {
public:
    enum class Bits {
        SHA224 = 224,
        SHA256 = 256,
        SHA384 = 384,
        SHA512 = 512
    };

    explicit SHA3(Bits bits = Bits::SHA256) : bitLen(static_cast<int>(bits)) {
        rate = 1600 - 2 * bitLen;
        outputLength = bitLen / 8;
        reset();
    }

    void reset() {
        for (auto& lane : state) lane = 0;
        buffer.clear();
        buffer.reserve((1600 - 2 * bitLen) / 8);
        pos = 0;
    }

    void update(const uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            buffer.push_back(data[i]);
            if (buffer.size() == rate / 8) {
                absorb();
                buffer.clear();
            }
        }
    }

    void update(const std::string& str) {
        update(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

    std::vector<uint8_t> digest() {
        // Padding
        buffer.push_back(0x06);
        while (buffer.size() % (rate / 8) != 0) {
            buffer.push_back(0x00);
        }
        buffer.back() |= 0x80;
        absorb();

        // Squeeze
        std::vector<uint8_t> output;
        output.reserve(outputLength);
        for (int i = 0; i < outputLength; i += 8) {
            for (int j = 0; j < 8 && (i + j) < outputLength; ++j) {
                output.push_back((state[j] >> (8 * j)) & 0xFF);
            }
            if (i + 8 < outputLength) {
                keccakF();
            }
        }

        reset();
        return output;
    }

    static std::string toString(const std::vector<uint8_t>& hash) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : hash) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

private:
    static constexpr int LANE_SIZE = 64;
    static constexpr int NUM_LANES = 25;
    uint64_t state[NUM_LANES] = {0};
    std::vector<uint8_t> buffer;
    int pos = 0;
    int rate;
    int bitLen;
    int outputLength;

    void absorb() {
        for (size_t i = 0; i < buffer.size(); i += 8) {
            uint64_t word = 0;
            for (int j = 0; j < 8 && (i + j) < buffer.size(); ++j) {
                word |= static_cast<uint64_t>(buffer[i + j]) << (8 * j);
            }
            state[i / 8] ^= word;
        }
        keccakF();
    }

    void keccakF() {
        static constexpr uint64_t RC[24] = {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        for (int round = 0; round < 24; ++round) {
            // Theta step
            uint64_t C[5], D[5];
            for (int i = 0; i < 5; ++i) {
                C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }
            for (int i = 0; i < 5; ++i) {
                D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
            }
            for (int i = 0; i < 5; ++i) {
                for (int j = 0; j < 5; ++j) {
                    state[i + 5 * j] ^= D[i];
                }
            }

            // Rho and Pi steps
            uint64_t B[NUM_LANES];
            for (int i = 0; i < 5; ++i) {
                for (int j = 0; j < 5; ++j) {
                    B[j + 5 * ((2 * i + 3 * j) % 5)] = ROTL64(state[i + 5 * j], ROTATION_CONSTS[i][j]);
                }
            }

            // Chi step
            for (int i = 0; i < 5; ++i) {
                for (int j = 0; j < 5; ++j) {
                    state[i + 5 * j] = B[i + 5 * j] ^ ((~B[(i + 1) % 5 + 5 * j]) & B[(i + 2) % 5 + 5 * j]);
                }
            }

            // Iota step
            state[0] ^= RC[round];
        }
    }

    static constexpr int ROTATION_CONSTS[5][5] = {
        {0, 36, 3, 41, 18},
        {1, 44, 10, 45, 2},
        {62, 6, 43, 15, 61},
        {28, 55, 25, 21, 56},
        {27, 20, 39, 8, 14}
    };

    static uint64_t ROTL64(uint64_t x, int y) {
        return (x << y) | (x >> (64 - y));
    }
};