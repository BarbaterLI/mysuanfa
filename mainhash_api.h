#pragma once
#include <stdint.h>
#ifdef _WIN32
#define DLL_EXPORT extern "C" __declspec(dllexport)
#else
#define DLL_EXPORT extern "C"
#endif

// 计算哈希，输入为字节流，输出为字节流，bits为输出位数（256/512/1024/2048/4096）
DLL_EXPORT int ultra_secure_hash(const uint8_t* data, int datalen, int bits, uint8_t* outbuf, int outbuflen);
