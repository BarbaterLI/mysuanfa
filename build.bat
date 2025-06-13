@echo off
setlocal

REM 编译 zhuangku.cpp，包含当前目录下的 main.h
if exist ico.ico (
    echo IDI_ICON1 ICON "ico.ico" > zhuangku.rc
    windres zhuangku.rc zhuangku_res.o
    g++ -std=c++17 -I. -o zhuangku.exe zhuangku.cpp zhuangku_res.o
) else (
    g++ -std=c++17 -I. -o zhuangku.exe zhuangku.cpp
)

if %errorlevel% neq 0 (
    echo 编译失败！
    exit /b %errorlevel%
) else (
    echo 编译成功，生成 zhuangku.exe
    REM 使用UPX压缩可执行文件
    "C:\upx\upx-4.2.4-win64\upx.exe" --best --lzma zhuangku.exe
    if %errorlevel% neq 0 (
        echo UPX压缩失败！
        exit /b %errorlevel%
    ) else (
        echo UPX压缩成功！
    )
)

REM PyInstaller 打包 mainhash_gui.py 时自动加图标
if exist mainhash_gui.py (
    if exist ico.ico (
        echo 建议用如下命令打包PyQt程序:
        echo pyinstaller --onefile --noconsole --add-binary "mainhash.dll;." --icon ico.ico mainhash_gui.py
    ) else (
        echo 建议用如下命令打包PyQt程序:
        echo pyinstaller --onefile --noconsole --add-binary "mainhash.dll;." mainhash_gui.py
    )
)
