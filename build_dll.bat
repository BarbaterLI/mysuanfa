@echo off
setlocal

REM 编译 main.cpp 为 DLL，假设 main.cpp 实现了 main.h 的所有类
g++ -std=c++17 -I. -shared -fPIC -o mainhash.dll main.cpp SHA3.cpp

if %errorlevel% neq 0 (
    echo DLL编译失败！
    exit /b %errorlevel%
) else (
    echo 编译成功，生成 mainhash.dll
)
