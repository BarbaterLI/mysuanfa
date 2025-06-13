import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit,
    QFileDialog, QHBoxLayout, QMessageBox, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QFont, QPalette, QColor
import ctypes
import os

DLL_PATH = os.path.join(os.path.dirname(__file__), "mainhash.dll")
ICON_PATH = os.path.join(os.path.dirname(__file__), "ico.ico")

# 多语言字典
LANGS = {
    "en": {
        "title": "UltraSecureHash Hash Tool",
        "input_label": "String:",
        "input_placeholder": "Enter string to hash",
        "bits_label": "Output bits:",
        "hash_btn": "Hash String",
        "file_btn": "Hash File",
        "about_btn": "About",
        "result_label": "Hash Result (hex):",
        "file_empty": "File is empty",
        "file_hash": "File: {fname}\nHash:\n{hash}",
        "hash_failed": "Hash failed: {err}",
        "file_hash_failed": "File hash failed: {err}",
        "please_input": "Please input string",
        "about": (
            "<b>UltraSecureHash Hash Tool</b><br>"
            "Version: 1.0<br><br>"
            "Author: <a href='https://github.com/BarbaterLI'>https://github.com/BarbaterLI</a><br>"
            "Algorithm Project: <a href='https://github.com/BarbaterLI/mysuanfa/'>https://github.com/BarbaterLI/mysuanfa/</a><br>"
            "Built with: PyQt6<br>"
            "Email: chatchina01osGPT@outlook.com<br>"
            "WeChat: windzi101001<br><br>"
            "This tool is based on a custom C++ DLL for ultra-secure hashing, supports multiple output lengths, and can hash strings and files.<br><br>"
            "Copyright &copy; 2025"
        )
    },
    "cn": {
        "title": "UltraSecureHash 哈希计算工具",
        "input_label": "字符串：",
        "input_placeholder": "请输入要哈希的字符串",
        "bits_label": "输出位数：",
        "hash_btn": "计算字符串哈希",
        "file_btn": "选择文件并计算哈希",
        "about_btn": "关于",
        "result_label": "哈希结果（十六进制）：",
        "file_empty": "文件为空",
        "file_hash": "文件: {fname}\n哈希:\n{hash}",
        "hash_failed": "哈希失败: {err}",
        "file_hash_failed": "文件哈希失败: {err}",
        "please_input": "请输入字符串",
        "about": (
            "<b>UltraSecureHash 哈希计算工具</b><br>"
            "版本：1.0<br><br>"
            "作者：<a href='https://github.com/BarbaterLI'>https://github.com/BarbaterLI</a><br>"
            "算法项目：<a href='https://github.com/BarbaterLI/mysuanfa/'>https://github.com/BarbaterLI/mysuanfa/</a><br>"
            "程序构建：PyQt6<br>"
            "邮箱：chatchina01osGPT@outlook.com<br>"
            "微信：windzi101001<br><br>"
            "本工具基于自定义C++ DLL实现超安全哈希算法，支持多种输出长度，可用于字符串和文件的哈希计算。<br><br>"
            "Copyright &copy; 2025"
        )
    },
    "jp": {
        "title": "UltraSecureHash ハッシュツール",
        "input_label": "文字列：",
        "input_placeholder": "ハッシュする文字列を入力してください",
        "bits_label": "出力ビット数：",
        "hash_btn": "文字列をハッシュ",
        "file_btn": "ファイルをハッシュ",
        "about_btn": "情報",
        "result_label": "ハッシュ結果（16進）：",
        "file_empty": "ファイルが空です",
        "file_hash": "ファイル: {fname}\nハッシュ:\n{hash}",
        "hash_failed": "ハッシュ失敗: {err}",
        "file_hash_failed": "ファイルハッシュ失敗: {err}",
        "please_input": "文字列を入力してください",
        "about": (
            "<b>UltraSecureHash ハッシュツール</b><br>"
            "バージョン: 1.0<br><br>"
            "作者: <a href='https://github.com/BarbaterLI'>https://github.com/BarbaterLI</a><br>"
            "アルゴリズムプロジェクト: <a href='https://github.com/BarbaterLI/mysuanfa/'>https://github.com/BarbaterLI/mysuanfa/</a><br>"
            "プログラム構築: PyQt6<br>"
            "メール: chatchina01osGPT@outlook.com<br>"
            "WeChat: windzi101001<br><br>"
            "本ツールはカスタムC++ DLLによる超安全なハッシュアルゴリズムを実装し、複数の出力長をサポートし、文字列やファイルのハッシュ計算が可能です。<br><br>"
            "Copyright &copy; 2025"
        )
    },
    "fr": {
        "title": "UltraSecureHash Outil de Hachage",
        "input_label": "Chaîne :",
        "input_placeholder": "Entrez la chaîne à hacher",
        "bits_label": "Bits de sortie :",
        "hash_btn": "Hacher la chaîne",
        "file_btn": "Hacher un fichier",
        "about_btn": "À propos",
        "result_label": "Résultat du hachage (hex) :",
        "file_empty": "Le fichier est vide",
        "file_hash": "Fichier : {fname}\nHachage :\n{hash}",
        "hash_failed": "Échec du hachage : {err}",
        "file_hash_failed": "Échec du hachage du fichier : {err}",
        "please_input": "Veuillez saisir une chaîne",
        "about": (
            "<b>UltraSecureHash Outil de Hachage</b><br>"
            "Version : 1.0<br><br>"
            "Auteur : <a href='https://github.com/BarbaterLI'>https://github.com/BarbaterLI</a><br>"
            "Projet d'algorithme : <a href='https://github.com/BarbaterLI/mysuanfa/'>https://github.com/BarbaterLI/mysuanfa/</a><br>"
            "Construit avec : PyQt6<br>"
            "Email : chatchina01osGPT@outlook.com<br>"
            "WeChat : windzi101001<br><br>"
            "Cet outil est basé sur une DLL C++ personnalisée pour un hachage ultra-sécurisé, prend en charge plusieurs longueurs de sortie, et peut hacher des chaînes et des fichiers.<br><br>"
            "Copyright &copy; 2025"
        )
    }
}

def get_system_language():
    import locale
    # 兼容Python 3.15及以后，避免getdefaultlocale弃用警告
    try:
        lang = locale.getlocale()[0]
        if lang is None:
            lang = locale.getpreferredencoding(False)
    except Exception:
        lang = None
    if not lang:
        lang = "en"
    lang = lang.lower()
    if lang.startswith("zh"):
        return "cn"
    if lang.startswith("ja"):
        return "jp"
    if lang.startswith("fr"):
        return "fr"
    return "en"

def get_system_dark_mode():
    # Windows 10/11 dark mode detection
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return value == 0
    except Exception:
        return False

class MainHashDLL:
    def __init__(self, dll_path):
        try:
            self.dll = ctypes.CDLL(dll_path)
        except Exception as e:
            raise RuntimeError(f"加载DLL失败: {e}")
        try:
            self.dll.ultra_secure_hash.argtypes = [
                ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
                ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int
            ]
            self.dll.ultra_secure_hash.restype = ctypes.c_int
        except Exception as e:
            raise RuntimeError(f"设置DLL参数失败: {e}")

    def hash(self, data: bytes, bits: int) -> bytes:
        if not data:
            raise ValueError("输入数据不能为空")
        if bits not in (256, 512, 1024, 2048, 4096):
            raise ValueError("输出位数必须为256/512/1024/2048/4096")
        outlen = bits // 8
        outbuf = (ctypes.c_uint8 * outlen)()
        try:
            ret = self.dll.ultra_secure_hash(
                (ctypes.c_uint8 * len(data)).from_buffer_copy(data),
                len(data), bits, outbuf, outlen
            )
        except Exception as e:
            raise RuntimeError(f"DLL调用异常: {e}")
        if ret <= 0:
            raise RuntimeError("哈希失败或输出缓冲区过小")
        return bytes(outbuf[:ret])

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.lang = get_system_language()
        self.tr = LANGS.get(self.lang, LANGS["en"])

        self.setWindowTitle(self.tr["title"])
        self.resize(700, 400)
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        # 自动切换明暗模式
        if get_system_dark_mode():
            self.set_dark_palette()
        else:
            self.set_light_palette()

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(18, 18, 18, 18)

        # 标题
        title = QLabel(self.tr["title"])
        title.setFont(QFont("微软雅黑", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title)

        # 输入区
        input_layout = QHBoxLayout()
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText(self.tr["input_placeholder"])
        input_layout.addWidget(QLabel(self.tr["input_label"]))
        input_layout.addWidget(self.input_edit)
        main_layout.addLayout(input_layout)

        # 输出位数和按钮区
        opts_layout = QHBoxLayout()
        self.bits_combo = QComboBox()
        self.bits_combo.addItems(["256", "512", "1024", "2048", "4096"])
        opts_layout.addWidget(QLabel(self.tr["bits_label"]))
        opts_layout.addWidget(self.bits_combo)

        self.hash_btn = QPushButton(self.tr["hash_btn"])
        self.file_btn = QPushButton(self.tr["file_btn"])
        self.about_btn = QPushButton(self.tr["about_btn"])
        opts_layout.addWidget(self.hash_btn)
        opts_layout.addWidget(self.file_btn)
        opts_layout.addWidget(self.about_btn)
        main_layout.addLayout(opts_layout)

        # 结果区
        main_layout.addWidget(QLabel(self.tr["result_label"]))
        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setFont(QFont("Consolas", 10))
        main_layout.addWidget(self.result_edit)

        # 拉伸
        main_layout.addSpacerItem(QSpacerItem(10, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # 信号连接
        self.hash_btn.clicked.connect(self.do_hash)
        self.file_btn.clicked.connect(self.do_file_hash)
        self.about_btn.clicked.connect(self.show_about)

        try:
            self.hasher = MainHashDLL(DLL_PATH)
        except Exception as e:
            self.result_edit.setPlainText(str(e))
            self.hash_btn.setEnabled(False)
            self.file_btn.setEnabled(False)

    def set_dark_palette(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(20, 20, 20))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 45))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Highlight, QColor(38, 79, 120))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
        self.setPalette(palette)

    def set_light_palette(self):
        self.setPalette(QApplication.palette())

    def do_hash(self):
        text = self.input_edit.text()
        bits = int(self.bits_combo.currentText())
        if not text:
            self.result_edit.setPlainText(self.tr["please_input"])
            return
        try:
            hash_bytes = self.hasher.hash(text.encode("utf-8"), bits)
            hexstr = hash_bytes.hex()
            self.result_edit.setPlainText(hexstr)
        except Exception as e:
            self.result_edit.setPlainText(self.tr["hash_failed"].format(err=e))

    def do_file_hash(self):
        fname, _ = QFileDialog.getOpenFileName(self, self.tr["file_btn"])
        if not fname:
            return
        bits = int(self.bits_combo.currentText())
        try:
            with open(fname, "rb") as f:
                data = f.read()
            if not data:
                self.result_edit.setPlainText(self.tr["file_empty"])
                return
            hash_bytes = self.hasher.hash(data, bits)
            hexstr = hash_bytes.hex()
            self.result_edit.setPlainText(self.tr["file_hash"].format(fname=fname, hash=hexstr))
        except Exception as e:
            self.result_edit.setPlainText(self.tr["file_hash_failed"].format(err=e))

    def show_about(self):
        about_text = (
            "<b>UltraSecureHash 哈希计算工具</b><br>"
            "版本：1.0<br><br>"
            "作者：<a href='https://github.com/BarbaterLI'>https://github.com/BarbaterLI</a><br>"
            "算法项目：<a href='https://github.com/BarbaterLI/mysuanfa/'>https://github.com/BarbaterLI/mysuanfa/</a><br>"
            "程序构建：PyQt6<br>"
            "邮箱：chatchina01osGPT@outlook.com<br>"
            "微信：windzi101001<br><br>"
            "本工具基于自定义C++ DLL实现超安全哈希算法，支持多种输出长度，可用于字符串和文件的哈希计算。<br><br>"
            "Copyright &copy; 2025<br>"
        )
        QMessageBox.about(self, self.tr["about_btn"], about_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
