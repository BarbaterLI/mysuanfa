@echo off
setlocal

REM ���� main.cpp Ϊ DLL������ main.cpp ʵ���� main.h ��������
g++ -std=c++17 -I. -shared -fPIC -o mainhash.dll main.cpp SHA3.cpp

if %errorlevel% neq 0 (
    echo DLL����ʧ�ܣ�
    exit /b %errorlevel%
) else (
    echo ����ɹ������� mainhash.dll
)
