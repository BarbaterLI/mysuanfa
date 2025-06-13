@echo off
setlocal

REM ���� zhuangku.cpp��������ǰĿ¼�µ� main.h
if exist ico.ico (
    echo IDI_ICON1 ICON "ico.ico" > zhuangku.rc
    windres zhuangku.rc zhuangku_res.o
    g++ -std=c++17 -I. -o zhuangku.exe zhuangku.cpp zhuangku_res.o
) else (
    g++ -std=c++17 -I. -o zhuangku.exe zhuangku.cpp
)

if %errorlevel% neq 0 (
    echo ����ʧ�ܣ�
    exit /b %errorlevel%
) else (
    echo ����ɹ������� zhuangku.exe
    REM ʹ��UPXѹ����ִ���ļ�
    "C:\upx\upx-4.2.4-win64\upx.exe" --best --lzma zhuangku.exe
    if %errorlevel% neq 0 (
        echo UPXѹ��ʧ�ܣ�
        exit /b %errorlevel%
    ) else (
        echo UPXѹ���ɹ���
    )
)

REM PyInstaller ��� mainhash_gui.py ʱ�Զ���ͼ��
if exist mainhash_gui.py (
    if exist ico.ico (
        echo ����������������PyQt����:
        echo pyinstaller --onefile --noconsole --add-binary "mainhash.dll;." --icon ico.ico mainhash_gui.py
    ) else (
        echo ����������������PyQt����:
        echo pyinstaller --onefile --noconsole --add-binary "mainhash.dll;." mainhash_gui.py
    )
)
