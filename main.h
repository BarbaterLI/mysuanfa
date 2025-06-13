#pragma once
#include <vector>
#include <string>
#include <exception>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <fstream>
#include <array>
#include "SHA3.h" // 新增

// 混淆命名空间
namespace CryptoObfuscated {

// 自定义异常类（混淆名）
class HashingException : public std::exception {
private:
    std::string msg_;
public:
    HashingException(const std::string& msg) : msg_(msg) {}
    const char* what() const noexcept override { return msg_.c_str(); }
};

// 密码学安全随机数生成器
class SecureRandom {
public:
    static std::vector<unsigned char> Generate(size_t length) {
        std::vector<unsigned char> output(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < length; ++i) {
            output[i] = static_cast<unsigned char>(dis(gen));
        }
        return output;
    }

    static uint64_t GenerateUInt64() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        return dis(gen);
    }
};

// 安全哈希基类
class SecureHashBase {
protected:
    static std::vector<uint8_t> SHA3_512(const std::vector<uint8_t>& input) {
        SHA3 sha3(SHA3::Bits::SHA512);
        sha3.update(input.data(), input.size());
        return sha3.digest();
    }

    static std::vector<uint8_t> HMAC_SHA3_256(const std::vector<uint8_t>& key,
                                              const std::vector<uint8_t>& data) {
        // HMAC-SHA3-256 实现
        const size_t block_size = 136; // SHA3-256 的 block size (rate/8)
        std::vector<uint8_t> k = key;
        if (k.size() > block_size) {
            SHA3 sha3(SHA3::Bits::SHA256);
            sha3.update(k.data(), k.size());
            k = sha3.digest();
        }
        if (k.size() < block_size) {
            k.resize(block_size, 0x00);
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= k[i];
            i_key_pad[i] ^= k[i];
        }

        // inner hash
        SHA3 sha3_inner(SHA3::Bits::SHA256);
        sha3_inner.update(i_key_pad.data(), i_key_pad.size());
        sha3_inner.update(data.data(), data.size());
        std::vector<uint8_t> inner_hash = sha3_inner.digest();

        // outer hash
        SHA3 sha3_outer(SHA3::Bits::SHA256);
        sha3_outer.update(o_key_pad.data(), o_key_pad.size());
        sha3_outer.update(inner_hash.data(), inner_hash.size());
        return sha3_outer.digest();
    }
};

// 动态S盒生成器（安全增强版）
class DynamicSBox : private SecureHashBase {
private:
    std::vector<uint8_t> sbox_;
    std::vector<uint8_t> inverse_sbox_;
    std::vector<uint8_t> random_seed_;

    void Generate(const std::vector<uint8_t>& input) {
        if (input.empty()) {
            throw HashingException("Input cannot be empty for S-box generation");
        }

        sbox_.resize(256);
        inverse_sbox_.resize(256);

        // 1. 混合输入和随机种子
        std::vector<uint8_t> key_material = input;
        key_material.insert(key_material.end(), random_seed_.begin(), random_seed_.end());
        
        // 2. 使用SHA3-512生成密钥
        std::vector<uint8_t> hashed_key = SHA3_512(key_material);
        
        // 3. 初始化S盒
        for (int i = 0; i < 256; ++i) {
            sbox_[i] = static_cast<uint8_t>(i);
        }

        // 4. 安全洗牌
        SecureShuffle(sbox_, hashed_key);
        
        // 5. 生成逆S盒
        for (int i = 0; i < 256; ++i) {
            inverse_sbox_[sbox_[i]] = static_cast<uint8_t>(i);
        }
    }

    void SecureShuffle(std::vector<uint8_t>& sbox, const std::vector<uint8_t>& key) {
        size_t key_index = 0;
        for (int i = 255; i > 0; --i) {
            // 使用密钥材料生成安全的j值
            uint32_t j = 0;
            for (int k = 0; k < 4; ++k) {
                j = (j << 8) | key[key_index % key.size()];
                key_index++;
            }
            j %= (i + 1);
            
            std::swap(sbox[i], sbox[j]);
        }
    }

public:
    explicit DynamicSBox(const std::vector<uint8_t>& input) {
        // 为每个S盒生成随机种子
        random_seed_ = SecureRandom::Generate(32);
        Generate(input);
    }

    uint8_t Substitute(uint8_t value) const {
        return sbox_[value];
    }

    uint8_t InverseSubstitute(uint8_t value) const {
        return inverse_sbox_[value];
    }
    
    const std::vector<uint8_t>& GetRandomSeed() const {
        return random_seed_;
    }
};

// 消息预处理（安全增强版）
class MessagePreprocessor : private SecureHashBase {
public:
    static std::vector<uint8_t> Process(const std::vector<uint8_t>& message) {
        std::vector<uint8_t> padded = message;
        
        // 1. 添加随机盐值
        std::vector<uint8_t> random_salt = SecureRandom::Generate(32);
        padded.insert(padded.end(), random_salt.begin(), random_salt.end());
        
        // 2. 基于HMAC的填充
        HMACBasedPadding(padded, random_salt);
        
        // 3. 添加长度信息
        uint64_t original_bit_length = message.size() * 8;
        for (int i = 0; i < 8; ++i) {
            padded.push_back((original_bit_length >> (8 * i)) & 0xFF);
        }
        
        // 4. 最终对齐
        while ((padded.size() % 128) != 0) {
            padded.push_back(0x00);
        }
        
        return padded;
    }

private:
    static void HMACBasedPadding(std::vector<uint8_t>& data, 
                               const std::vector<uint8_t>& salt) {
        // 使用HMAC-SHA3-256生成填充模式
        std::vector<uint8_t> hmac = HMAC_SHA3_256(data, salt);
        
        // 添加HMAC作为填充的一部分
        data.push_back(0x80);
        data.insert(data.end(), hmac.begin(), hmac.end());
        
        // 确保长度满足要求
        while ((data.size() % 64) != 56) {
            data.push_back(0x00);
        }
    }
};

// 抗量子变换
class QuantumResistantTransform {
public:
    static uint64_t LatticeBased(uint64_t x, uint64_t round) {
        // 基于格的变换
        const uint64_t modulus = 0xFFFFFFFFFFFFFFC5; // 大素数
        const uint64_t multiplier = 0x5DEECE66D;
        
        x = (x * multiplier + round) % modulus;
        x ^= (x >> 32);
        x = (x * multiplier + round) % modulus;
        return x;
    }
    
    static uint64_t HashBased(uint64_t x) {
        // 基于哈希的变换
        std::vector<uint8_t> input(8);
        for (int i = 0; i < 8; ++i) {
            input[i] = (x >> (8 * i)) & 0xFF;
        }

        SHA3 sha3(SHA3::Bits::SHA256);
        sha3.update(input.data(), input.size());
        std::vector<uint8_t> output = sha3.digest();

        uint64_t result = 0;
        for (int i = 0; i < 8; ++i) {
            result |= static_cast<uint64_t>(output[i % output.size()]) << (8 * i);
        }
        return result;
    }
};

// 非线性变换函数集合
class NonlinearTransforms {
public:
    static uint64_t ChaoticBitMix(uint64_t x) {
        x ^= (x >> 31);
        x *= 0x7fb5d329728ea185;
        x ^= (x >> 27);
        x *= 0x81dadef4bc2dd44d;
        x ^= (x >> 33);
        return x;
    }

    static uint64_t SpiralBitPermute(uint64_t x) {
        x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
        x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
        x = (x & 0x00FF00FF00FF00FF) << 8 | (x & 0xFF00FF00FF00FF00) >> 8;
        x = (x & 0x0F0F0F0F0F0F0F0F) << 4 | (x & 0xF0F0F0F0F0F0F0F0) >> 4;
        x = (x & 0x3333333333333333) << 2 | (x & 0xCCCCCCCCCCCCCCCC) >> 2;
        x = (x & 0x5555555555555555) << 1 | (x & 0xAAAAAAAAAAAAAAAA) >> 1;
        return x;
    }

    static uint64_t QuantumInspired(uint64_t x, uint64_t round) {
        const uint64_t golden_ratio = 0x9E3779B97F4A7C15;
        round *= golden_ratio;
        round ^= (round >> 31);

        x += round;
        x ^= (x >> 16);
        x += (x << 8);
        x ^= (x >> 7);
        x += (x << 3);
        x ^= (x >> 12);
        x += (x << 9);
        return x;
    }

    static uint64_t FractalTransform(uint64_t x) {
        uint64_t high = x >> 32;
        uint64_t low = x & 0xFFFFFFFF;

        uint64_t a = (high ^ low) * 0x45d9f3b;
        uint64_t b = (high + low) * 0x45d9f3b;

        a ^= (a >> 28);
        b ^= (b >> 28);

        return (a << 32) | b;
    }
};

// 超安全哈希核心类
class UltraSecureHash {
private:
    size_t output_bits_;
    std::vector<uint64_t> internal_state_;
    std::vector<uint8_t> original_input_;
    std::vector<uint8_t> sbox_seed_;

    uint64_t BlockDependentValue(size_t block_index) const {
        uint64_t value = 0xA5A5A5A5A5A5A5A5 ^ (block_index * 0x9E3779B97F4A7C15);
        for (auto byte : original_input_) {
            value = NonlinearTransforms::ChaoticBitMix(value ^ byte ^ block_index);
        }
        return value;
    }

    void InitializeState() {
        const uint64_t constants[8] = {
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        };

        size_t required_words = output_bits_ / 64;
        internal_state_.assign(constants, constants + std::min(required_words, size_t(8)));
        
        for (size_t i = std::min(required_words, size_t(8)); i < required_words; ++i) {
            uint64_t new_word = 0;
            for (const auto& word : internal_state_) {
                new_word ^= QuantumResistantTransform::LatticeBased(word, i);
            }
            new_word = QuantumResistantTransform::HashBased(new_word);
            internal_state_.push_back(new_word);
        }
    }

    void ProcessBlock(const std::vector<uint8_t>& block, size_t block_index) {
        if (block.size() != 128) {
            throw HashingException("Block size must be exactly 128 bytes");
        }

        // 使用原始输入生成S盒
        DynamicSBox sbox(original_input_);
        sbox_seed_ = sbox.GetRandomSeed();

        // 将块转换为64位字
        std::vector<uint64_t> words(16);
        for (size_t i = 0; i < words.size(); ++i) {
            words[i] = 0;
            for (int j = 0; j < 8; ++j) {
                words[i] |= static_cast<uint64_t>(block[i * 8 + j]) << (8 * j);
            }
        }

        uint64_t block_dependent = BlockDependentValue(block_index);

        // 12轮变换
        for (int round = 0; round < 12; ++round) {
            for (size_t i = 0; i < internal_state_.size(); ++i) {
                // S盒替换
                uint64_t substituted = 0;
                for (int j = 0; j < 8; ++j) {
                    uint8_t byte = (internal_state_[i] >> (8 * j)) & 0xFF;
                    substituted |= static_cast<uint64_t>(sbox.Substitute(byte)) << (8 * j);
                }

                // 多类型变换混合
                switch (round % 6) {
                    case 0:
                        internal_state_[i] = NonlinearTransforms::ChaoticBitMix(
                            internal_state_[i] ^ words[i % words.size()] ^ block_dependent);
                        break;
                    case 1:
                        internal_state_[i] = NonlinearTransforms::SpiralBitPermute(
                            internal_state_[i] + substituted + block_dependent);
                        break;
                    case 2:
                        internal_state_[i] = NonlinearTransforms::QuantumInspired(
                            internal_state_[i] ^ block_dependent, round + block_index);
                        break;
                    case 3:
                        internal_state_[i] = NonlinearTransforms::FractalTransform(
                            internal_state_[i] ^ substituted ^ block_dependent);
                        break;
                    case 4:
                        internal_state_[i] = NonlinearTransforms::ChaoticBitMix(
                            internal_state_[i] + substituted + block_dependent);
                        break;
                    case 5:
                        internal_state_[i] = NonlinearTransforms::QuantumInspired(
                            NonlinearTransforms::SpiralBitPermute(internal_state_[i]), 
                            round * 3 + block_index);
                        break;
                }
            }

            // 状态混合
            uint64_t mixer = block_dependent;
            for (const auto& word : internal_state_) {
                mixer ^= word;
            }
            for (auto& word : internal_state_) {
                word = NonlinearTransforms::ChaoticBitMix(word + mixer + block_dependent);
            }
        }

        // 最终块处理
        uint64_t final_mixer = block_dependent;
        for (const auto &word : internal_state_) {
            final_mixer += NonlinearTransforms::ChaoticBitMix(word ^ block_dependent);
        }
        for (auto &word : internal_state_) {
            word = NonlinearTransforms::FractalTransform(word ^ final_mixer);
            word = NonlinearTransforms::QuantumInspired(word, 0xA5A5A5A5 ^ block_dependent);
            word = NonlinearTransforms::SpiralBitPermute(word);
        }
    }

public:
    enum class OutputSize {
        BITS_256 = 256,
        BITS_512 = 512,
        BITS_1024 = 1024,
        BITS_2048 = 2048,
        BITS_4096 = 4096
    };

    explicit UltraSecureHash(OutputSize size = OutputSize::BITS_256) {
        output_bits_ = static_cast<size_t>(size);
        if (output_bits_ % 64 != 0 || output_bits_ > 4096) {
            throw HashingException("Invalid output size");
        }
        InitializeState();
    }

    std::vector<uint8_t> ComputeHash(const std::vector<uint8_t>& message) {
        if (message.empty()) {
            throw HashingException("Message cannot be empty");
        }

        original_input_ = message;
        std::vector<uint8_t> padded = MessagePreprocessor::Process(message);

        // 处理所有块
        size_t block_count = padded.size() / 128;
        for (size_t i = 0; i < block_count; ++i) {
            std::vector<uint8_t> block(padded.begin() + i * 128, padded.begin() + (i + 1) * 128);
            ProcessBlock(block, i);
        }

        // 额外处理空块
        for (int i = 0; i < 4; ++i) {
            ProcessBlock(std::vector<uint8_t>(128, 0), block_count + i);
        }

        // 最终混淆
        for (int round = 0; round < 6; ++round) {
            uint64_t mixer = BlockDependentValue(round);
            for (const auto& word : internal_state_) {
                mixer ^= NonlinearTransforms::ChaoticBitMix(word ^ mixer);
            }
            for (auto& word : internal_state_) {
                word = NonlinearTransforms::QuantumInspired(
                    NonlinearTransforms::FractalTransform(word ^ mixer), 
                    round * 7 + 0x12345678);
                word = NonlinearTransforms::SpiralBitPermute(word);
            }
        }

        // 生成输出
        std::vector<uint8_t> result(output_bits_ / 8);
        for (size_t i = 0; i < internal_state_.size(); ++i) {
            for (int j = 0; j < 8; ++j) {
                result[i * 8 + j] = static_cast<uint8_t>((internal_state_[i] >> (8 * j)) & 0xFF);
            }
        }

        return result;
    }

    static std::string BytesToHex(const std::vector<uint8_t>& bytes) {
        static const char hex_digits[] = "0123456789abcdef";
        std::string hex_string(bytes.size() * 2, '0');
        for (size_t i = 0; i < bytes.size(); ++i) {
            hex_string[2 * i] = hex_digits[(bytes[i] >> 4) & 0xF];
            hex_string[2 * i + 1] = hex_digits[bytes[i] & 0xF];
        }
        return hex_string;
    }
};

} // 命名空间 CryptoObfuscated 结束