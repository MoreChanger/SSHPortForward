import PyInstaller.__main__
import os

# 获取当前目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 直接使用 ICO 文件
icon_path = os.path.join(current_dir, 'src', 'data', 'icon.ico')

# 检查图标文件是否存在
if not os.path.exists(icon_path):
    print(f"警告: 图标文件不存在: {icon_path}")
    icon_path = None

PyInstaller.__main__.run([
    'src/main.py',
    '--name=SSH隧道管理器',
    '--windowed',
    '--onefile',
    '--clean',
    '--noconfirm',
    # 添加数据文件
    '--add-data=src/data/icon.ico;.',
    # 指定工作目录
    '--workpath=build',
    '--distpath=dist',
    # UPX优化设置
    '--upx-dir=tools/upx',
    # 明确指定需要的模块
    '--hidden-import=PyQt5.sip',
    '--hidden-import=PyQt5.QtWidgets',
    '--hidden-import=PyQt5.QtCore',
    '--hidden-import=PyQt5.QtGui',
    '--hidden-import=paramiko',
    '--hidden-import=cryptography.fernet',
    '--hidden-import=cryptography.hazmat.primitives',
    '--hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2',
    # 收集必要的子模块
    '--collect-submodules=PyQt5.QtWidgets',
    '--collect-submodules=paramiko',
    '--collect-submodules=cryptography.fernet',
    # 排除不需要的标准库模块
    '--exclude-module=unittest',
    '--exclude-module=pdb',
    '--exclude-module=difflib',
    '--exclude-module=doctest',
    '--exclude-module=pydoc',
    '--exclude-module=xml',
    # 添加图标
    f'--icon={icon_path}' if icon_path else None,
])