import paramiko
import time
import socket
import threading
import select
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QPushButton, 
                           QVBoxLayout, QHBoxLayout, QWidget, QLabel, QLineEdit, 
                           QGridLayout, QInputDialog, QMessageBox, QComboBox, 
                           QSystemTrayIcon, QMenu, QAction, QStyle, QTableWidget, 
                           QTableWidgetItem, QDialog, QFormLayout, QDialogButtonBox, 
                           QSpinBox, QFileDialog, QTextBrowser)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
import sys
import json
import os
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
from datetime import datetime

# 修改get_app_path函数
def get_app_path(relative_path):
    """获取应用资源的绝对路径"""
    if getattr(sys, 'frozen', False):
        # 如果是打包后的可执行文件
        base_path = os.path.dirname(sys.executable)
    else:
        # 如果是开发环境
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
    # 根据文件类型确定存储位置
    if relative_path in ['config.json', 'history.json', 'settings.json', 'encryption.key', 'icon.ico']:
        return os.path.join(base_path, 'data', relative_path)
    elif relative_path.endswith('.log'):
        return os.path.join(base_path, 'logs', relative_path)
    else:
        return os.path.join(base_path, relative_path)

# 修改setup_logger函数
def setup_logger():
    """配置日志系统"""
    try:
        # 创建logs目录（如果不存在）
        logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
        
        # 生成日志文件名（使用当前日期）
        log_filename = os.path.join(logs_dir, f'ssh_tunnel_{datetime.now().strftime("%Y%m%d")}.log')
        
        # 配置日志格式
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    except Exception as e:
        print(f"设置日志系统失败: {str(e)}")
        return logging.getLogger(__name__)

# 创建logger实例
logger = setup_logger()

class SSHTunnelThread(QThread):
    status_signal = pyqtSignal(str)
    connection_failed_signal = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.ssh = None
        self.transport = None
        self.reconnect_count = 0  # 重连次数计数
        self.max_reconnects = 5   # 最大重连次数
        self.connect_timeout = 30  # 连接超时时间（秒）

    def reverse_forward_tunnel(self, server_port, remote_host, remote_port, transport):
        try:
            transport.request_port_forward('', server_port)
            self.status_signal.emit(f"正在监听端口 {server_port}...")
            while self.running:
                chan = transport.accept(1000)
                if chan is None:
                    continue
                self.status_signal.emit(f"收到新的连接请求，正在转发到 {remote_host}:{remote_port}")
                thr = threading.Thread(target=self.handler, args=(chan, remote_host, remote_port))
                thr.daemon = True
                thr.start()
        except Exception as e:
            self.status_signal.emit(f'反向端口转发错误: {str(e)}')
            raise e

    def handler(self, chan, host, port):
        try:
            sock = socket.socket()
            sock.connect((host, port))
        except Exception as e:
            self.status_signal.emit(f'转发目标连接失败: {str(e)}')
            chan.close()
            return

        while self.running:
            try:
                r, w, x = select.select([sock, chan], [], [], 1)
                if sock in r:
                    data = sock.recv(1024)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    sock.send(data)
            except Exception as e:
                self.status_signal.emit(f'数据转发错误: {str(e)}')
                break
        
        chan.close()
        sock.close()

    def run(self):
        logger.info("SSH隧道线程启动")
        self.running = True
        self.reconnect_count = 0
        
        while self.running and self.reconnect_count < self.max_reconnects:
            try:
                logger.info("正在建立SSH连接...")
                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                self.ssh.connect(
                    hostname=self.ssh_host,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=self.connect_timeout  # 添加超时置
                )
                
                self.status_signal.emit("SSH连接已建立")
                self.status_signal.emit(f"正在建立反向隧道 {self.ssh_host}:{self.local_port} -> {self.remote_host}:{self.remote_port}")
                
                self.transport = self.ssh.get_transport()
                self.reverse_forward_tunnel(self.local_port, self.remote_host, self.remote_port, self.transport)
                
            except Exception as e:
                logger.error(f"SSH连接错误: {str(e)}")
                self.reconnect_count += 1
                if self.running and self.reconnect_count < self.max_reconnects:
                    wait_time = min(5 * self.reconnect_count, 30)
                    self.status_signal.emit(f"连接失败 ({self.reconnect_count}/{self.max_reconnects})，{wait_time}秒后重试...")
                    time.sleep(wait_time)
                else:
                    self.status_signal.emit(f"达到最大重试次数 ({self.max_reconnects})，停止重连")
                    self.running = False
                    self.connection_failed_signal.emit()
            finally:
                if self.ssh:
                    self.ssh.close()

    def stop(self):
        """停止隧道线程"""
        logger.info("正在停止SSH隧道线程...")
        self.running = False
        try:
            if self.transport:
                # 先尝试取消端口转发
                try:
                    self.transport.cancel_port_forward('', self.local_port)
                    logger.info(f"已取消端口转发: {self.local_port}")
                except Exception as e:
                    logger.error(f"取消端口转发失败: {str(e)}")
                
                # 关闭transport
                try:
                    self.transport.close()
                    logger.info("已关闭transport")
                except Exception as e:
                    logger.error(f"关闭transport失败: {str(e)}")
            
            if self.ssh:
                try:
                    self.ssh.close()
                    logger.info("已关闭SSH连接")
                except Exception as e:
                    logger.error(f"关闭SSH连接失败: {str(e)}")
        except Exception as e:
            logger.error(f"停止隧道时发生错误: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        logger.info("初始化应用程序...")
        super().__init__()
        
        # 确保data目录存在
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        # 初始化加密
        self.init_encryption()
        
        # 配置文件路径
        self.config_file = get_app_path('config.json')
        self.history_file = get_app_path('history.json')
        self.configs = self.load_configs()
        self.history = self.load_history()
        
        # 设置窗口图标
        icon_path = get_app_path('icon.ico')
        icon = QIcon(icon_path)
        if not icon.isNull():
            self.setWindowIcon(icon)
        else:
            logger.warning("未找到图标文件，使用系统默认图标")
            self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        self.setWindowTitle("SSH 隧道管理器")
        self.setGeometry(100, 100, 600, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f6fa;
            }
            QLabel {
                font-size: 14px;
                color: #2f3542;
                padding: 5px;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #dcdde1;
                border-radius: 5px;
                background-color: white;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 2px solid #70a1ff;
            }
            QPushButton {
                background-color: #70a1ff;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #1e90ff;
            }
            QPushButton:pressed {
                background-color: #5352ed;
            }
            QTextEdit {
                border: 2px solid #dcdde1;
                border-radius: 5px;
                padding: 5px;
                background-color: white;
                font-family: "Consolas", monospace;
                font-size: 13px;
            }
            QLabel[class="section-header"] {
                font-size: 16px;
                font-weight: bold;
                color: #2f3542;
                padding: 10px 5px;
            }
        """)
        
        # 创建中心部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # 创建表单布局
        form_layout = QGridLayout()
        form_layout.setSpacing(10)
        
        # SSH 配置
        ssh_header = QLabel("SSH 配置")
        ssh_header.setProperty('class', 'section-header')
        form_layout.addWidget(ssh_header, 0, 0, 1, 2)
        
        form_layout.addWidget(QLabel("SSH 主机:"), 1, 0)
        self.ssh_host = QLineEdit()
        self.ssh_host.setPlaceholderText("例如: example.com")
        form_layout.addWidget(self.ssh_host, 1, 1)
        
        form_layout.addWidget(QLabel("SSH 用户:"), 2, 0)
        self.ssh_user = QLineEdit()
        self.ssh_user.setPlaceholderText("例如: root")
        form_layout.addWidget(self.ssh_user, 2, 1)
        
        form_layout.addWidget(QLabel("SSH 密码:"), 3, 0)
        self.ssh_password = QLineEdit()
        self.ssh_password.setPlaceholderText("输入密码")
        self.ssh_password.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.ssh_password, 3, 1)
        
        # 端口转发配置
        tunnel_header = QLabel("端口转发配置")
        tunnel_header.setProperty('class', 'section-header')
        form_layout.addWidget(tunnel_header, 4, 0, 1, 2)
        
        form_layout.addWidget(QLabel("本地端口:"), 5, 0)
        self.local_port = QLineEdit()
        self.local_port.setPlaceholderText("例如: 5054")
        form_layout.addWidget(self.local_port, 5, 1)
        
        form_layout.addWidget(QLabel("远程主机:"), 6, 0)
        self.remote_host = QLineEdit()
        self.remote_host.setPlaceholderText("例如: 192.168.1.100")
        form_layout.addWidget(self.remote_host, 6, 1)
        
        form_layout.addWidget(QLabel("远程端口:"), 7, 0)
        self.remote_port = QLineEdit()
        self.remote_port.setPlaceholderText("例如: 5054")
        form_layout.addWidget(self.remote_port, 7, 1)
        
        # 创建一个容器来包装表单
        form_container = QWidget()
        form_container.setLayout(form_layout)
        form_container.setStyleSheet("""
            QWidget {
                background-color: white;
                border-radius: 10px;
            }
        """)
        main_layout.addWidget(form_container)
        
        # 修改状态标题和指示器部分
        status_layout = QHBoxLayout()
        status_header = QLabel("运行状态")
        status_header.setProperty('class', 'section-header')
        status_layout.addWidget(status_header)
        
        # 添加状态指示点
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(10, 10)
        self.status_indicator.setStyleSheet("""
            QLabel {
                background-color: #ff4444;
                border-radius: 5px;
                margin: 8px;
                min-width: 10px;
                min-height: 10px;
                max-width: 10px;
                max-height: 10px;
                border: 1px solid rgba(0, 0, 0, 0.1);
            }
        """)
        status_layout.addWidget(self.status_indicator)
        status_layout.addStretch()  # 添加弹性空间
        main_layout.addLayout(status_layout)
        
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMinimumHeight(200)
        main_layout.addWidget(self.status_text)
        
        # 修改按钮布局
        button_layout = QHBoxLayout()
        
        # 创建一个菜单按钮
        menu_btn = QPushButton("菜单")
        menu = QMenu(self)
        
        # 添加配置导入/导出选项
        import_action = QAction("导入配置", self)
        import_action.triggered.connect(self.import_configs)
        menu.addAction(import_action)
        
        export_action = QAction("导出配置", self)
        export_action.triggered.connect(self.export_configs)
        menu.addAction(export_action)
        
        # 添加分隔线
        menu.addSeparator()
        
        # 添加连接历史选项
        history_action = QAction("连接历史", self)
        history_action.triggered.connect(self.show_connection_history)
        menu.addAction(history_action)
        
        # 添加连接设置选项
        settings_action = QAction("连接设置", self)
        settings_action.triggered.connect(self.show_connection_settings)
        menu.addAction(settings_action)
        
        menu_btn.setMenu(menu)
        button_layout.addWidget(menu_btn)
        
        # 添加清空所有数的按钮
        clear_all_btn = QPushButton("清空所有")
        clear_all_btn.clicked.connect(self.clear_all_fields)
        button_layout.addWidget(clear_all_btn)
        
        self.toggle_button = QPushButton("启动隧道")
        button_layout.addWidget(self.toggle_button)
        
        main_layout.addLayout(button_layout)
        
        # 创建闪烁定器
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.blink_status)
        self.blink_state = True
        
        # 创建SSH隧道线程
        self.tunnel_thread = SSHTunnelThread()
        self.tunnel_thread.status_signal.connect(self.update_status)
        self.tunnel_thread.connection_failed_signal.connect(self.handle_connection_failed)
        
        # 连接按钮点击事件
        self.toggle_button.clicked.connect(self.toggle_tunnel)
        
        self.tunnel_running = False
        
        # 在创建表单之前加配置选择器
        config_layout = QHBoxLayout()
        config_layout.addWidget(QLabel("配置:"))
        self.config_combo = QComboBox()
        self.config_combo.addItem("新建配置")
        for name in self.configs.keys():
            self.config_combo.addItem(name)
        self.config_combo.currentTextChanged.connect(self.load_config)
        config_layout.addWidget(self.config_combo)
        
        # 添加保存配置按
        save_btn = QPushButton("保存配置")
        save_btn.clicked.connect(self.save_config)
        config_layout.addWidget(save_btn)
        
        # 添加删除配置按钮
        delete_btn = QPushButton("删除配置")
        delete_btn.clicked.connect(self.delete_config)
        config_layout.addWidget(delete_btn)
        
        main_layout.addLayout(config_layout)
        
        # 加载后使用的配置
        last_config = self.get_last_config()
        if last_config:
            self.config_combo.setCurrentText(last_config)
            self.load_config(last_config)
        
        # 在__init__尾添加托盘初始化
        self.init_tray()
        logger.info("应用程序初始化完成")
        
        # 添加接历史记录
        self.connection_history = []
        self.load_connection_history()
        
        # 添加设置
        self.settings = {
            'max_reconnects': 5,
            'connect_timeout': 30
        }
        self.load_settings()
        
        # 在配置管理菜单中添加导入/导出选项
        config_menu = QMenu("配置管理", self)
        
        # 导入配置
        import_action = QAction("导入配置", self)
        import_action.triggered.connect(self.import_configs)
        config_menu.addAction(import_action)
        
        # 导出配置
        export_action = QAction("导出配置", self)
        export_action.triggered.connect(self.export_configs)
        config_menu.addAction(export_action)
        
        # 添加连接历史记录查看
        history_action = QAction("连接历史", self)
        history_action.triggered.connect(self.show_connection_history)
        config_menu.addAction(history_action)
        
        # 添加连接设置
        settings_action = QAction("连接设置", self)
        settings_action.triggered.connect(self.show_connection_settings)
        config_menu.addAction(settings_action)

        # 创建菜单栏
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #f5f6fa;
                border-bottom: 1px solid #dcdde1;
            }
            QMenuBar::item {
                padding: 8px 15px;
                color: #2f3542;
            }
            QMenuBar::item:selected {
                background-color: #70a1ff;
                color: white;
            }
            QMenuBar::item:pressed {
                background-color: #1e90ff;
                color: white;
            }
        """)
        
        # 添加帮助菜单
        help_menu = menubar.addMenu('帮助')
        help_menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #dcdde1;
            }
            QMenu::item {
                padding: 8px 25px;
                color: #2f3542;
            }
            QMenu::item:selected {
                background-color: #70a1ff;
                color: white;
            }
        """)
        
        # 添加使用说明菜单项
        usage_action = QAction('使用说明', self)
        usage_action.triggered.connect(self.show_help)
        help_menu.addAction(usage_action)
        
        # 添加关于菜单
        about_action = QAction('关于', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def init_encryption(self):
        """初始化加密密钥"""
        # encryption.key 放在src目录下
        key_file = get_app_path('encryption.key')
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            # 生成新密钥
            salt = b'fixed_salt'  # 在实际应用中应该使用随机salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self.key = base64.urlsafe_b64encode(kdf.derive(b"your_secret_password"))
            # 保存密钥
            with open(key_file, 'wb') as f:
                f.write(self.key)
        
        self.fernet = Fernet(self.key)

    def encrypt_password(self, password):
        """加密密码"""
        if not password:
            return ""
        return self.fernet.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """解密密码"""
        if not encrypted_password:
            return ""
        try:
            return self.fernet.decrypt(encrypted_password.encode()).decode()
        except:
            return ""

    def load_configs(self):
        """从文件加载所有配置"""
        logger.debug(f"尝试从 {self.config_file} 加载配置")
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    configs = json.load(f)
                    logger.info(f"成功加载配置: {configs}")
                    return configs
            except Exception as e:
                logger.error(f"加载配置文件出错: {str(e)}")
                return {}
        logger.warning(f"配置文件 {self.config_file} 不存在")
        return {}

    def save_configs(self):
        """保存所有配置到文件"""
        logger.debug(f"正在保存配置到 {self.config_file}")
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.configs, f, ensure_ascii=False, indent=2)
            logger.info("配置保存功")
        except Exception as e:
            logger.error(f"保存配置文件时出错: {str(e)}")

    def load_history(self):
        """从history.json加历记录"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {"last_config": None, "recent_configs": []}
        return {"last_config": None, "recent_configs": []}

    def save_history(self):
        """保存历史记录到history.json"""
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)

    def get_last_config(self):
        """获取后使用的配置名称"""
        return self.history.get("last_config")

    def save_last_config(self, name):
        """保存后使用的配置名称"""
        self.history["last_config"] = name
        
        # 更新最近使用的配置列表
        recent = self.history.get("recent_configs", [])
        if name in recent:
            recent.remove(name)
        recent.insert(0, name)
        # 只保留最近10个配置
        self.history["recent_configs"] = recent[:10]
        
        self.save_history()

    def save_config(self):
        """保存当前配置"""
        # 检查必要的字段
        remote_host = self.remote_host.text().strip()
        remote_port = self.remote_port.text().strip()
        
        if not remote_host or not remote_port:
            QMessageBox.warning(self, '错误', '请至少填写远程主机和端口')
            return
        
        # 自动生成默认配置名称
        default_name = f"{remote_host}_{remote_port}"
        
        # 如果同名配置已存在，添加数字后缀
        base_name = default_name
        counter = 1
        while default_name in self.configs:
            default_name = f"{base_name}_{counter}"
            counter += 1
        
        name, ok = QInputDialog.getText(self, '保存置', '请输入配置名称:', 
                                      text=default_name)
        
        if ok:
            if not name.strip():  # 如果用户清空了，使用默认名称
                name = default_name
            
            config = {
                'ssh_host': self.ssh_host.text(),
                'ssh_user': self.ssh_user.text(),
                'ssh_password': self.encrypt_password(self.ssh_password.text()),  # 加密密码
                'local_port': self.local_port.text(),
                'remote_host': remote_host,
                'remote_port': remote_port
            }
            self.configs[name] = config
            self.save_configs()
            
            # 更新配置下拉框
            if self.config_combo.findText(name) == -1:
                self.config_combo.addItem(name)
            self.config_combo.setCurrentText(name)
            self.save_last_config(name)
            
            QMessageBox.information(self, '成功', '配置已保存')

    def load_config(self, name):
        """加载选中的配置"""
        if name == "新建配置" or name not in self.configs:
            self.ssh_host.clear()
            self.ssh_user.clear()
            self.ssh_password.clear()
            self.local_port.clear()
            self.remote_host.clear()
            self.remote_port.clear()
            return
        
        config = self.configs[name]
        self.ssh_host.setText(config['ssh_host'])
        self.ssh_user.setText(config['ssh_user'])
        self.ssh_password.setText(self.decrypt_password(config['ssh_password']))  # 解密码
        self.local_port.setText(config['local_port'])
        self.remote_host.setText(config['remote_host'])
        self.remote_port.setText(config['remote_port'])
        self.save_last_config(name)

    def delete_config(self):
        """删除当前配置"""
        name = self.config_combo.currentText()
        if name == "新建配":
            return
            
        reply = QMessageBox.question(self, '确认删除', 
                                   f'确定要删除配置 "{name}" 吗？',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.configs.pop(name, None)
            self.save_configs()
            self.config_combo.removeItem(self.config_combo.findText(name))
            self.config_combo.setCurrentText("新建配置")
            QMessageBox.information(self, '功', '配置已删除')

    def toggle_tunnel(self):
        if not self.tunnel_running:
            # 验证输入
            logger.debug("正在验证输入参数...")
            if not self.ssh_host.text().strip():
                logger.warning("SSH主机为空")
                QMessageBox.warning(self, '错误', 'SSH主机不能为空')
                return
            if not self.ssh_user.text().strip():
                logger.warning("SSH用户为空")
                QMessageBox.warning(self, '错误', 'SSH用户不能为空')
                return
            if not self.ssh_password.text().strip():
                logger.warning("SSH密码为空")
                QMessageBox.warning(self, '错误', 'SSH密码不能为空')
                return
            if not self.local_port.text().strip():
                logger.warning("本地端口为空")
                QMessageBox.warning(self, '错误', '本地端口不能为空')
                return
            if not self.remote_host.text().strip():
                logger.warning("远程主机为")
                QMessageBox.warning(self, '错误', '远程主机不能空')
                return
            if not self.remote_port.text().strip():
                logger.warning("远程端口为空")
                QMessageBox.warning(self, '错误', '远程端口不能为空')
                return
            
            # 验证端号格式
            try:
                local_port = int(self.local_port.text())
                remote_port = int(self.remote_port.text())
                if not (0 < local_port < 65536 and 0 < remote_port < 65536):
                    QMessageBox.warning(self, '错误', '端口号必须在1-65535之间')
                    return
            except ValueError:
                QMessageBox.warning(self, '错误', '端口号必须是数字')
                return
            
            try:
                # 清空状态文本
                self.status_text.clear()
                
                # 创建新隧道线程
                logger.debug("创建新的隧道线程")
                self.tunnel_thread = SSHTunnelThread()
                self.tunnel_thread.status_signal.connect(self.update_status)
                
                # 更新SSH连接参数
                self.tunnel_thread.ssh_host = self.ssh_host.text()
                self.tunnel_thread.ssh_user = self.ssh_user.text()
                self.tunnel_thread.ssh_password = self.ssh_password.text()
                self.tunnel_thread.local_port = int(self.local_port.text())
                self.tunnel_thread.remote_host = self.remote_host.text()
                self.tunnel_thread.remote_port = int(self.remote_port.text())
                
                # 设置重连和超时参数
                self.tunnel_thread.max_reconnects = self.settings['max_reconnects']
                self.tunnel_thread.connect_timeout = self.settings['connect_timeout']
                
                # 启动隧道
                self.tunnel_running = True
                self.toggle_button.setText("停止隧道")
                self.update_tray_status()
                
                # 启动隧道线程
                self.tunnel_thread.start()
                
                # 启动闪烁
                self.blink_timer.start(500)
                
                # 添加连接历史记录
                self.add_connection_history(self.config_combo.currentText())
                
                logger.info("隧道已启动")
                
            except Exception as e:
                logger.error(f"启动隧道失败: {str(e)}")
                self.tunnel_running = False
                self.toggle_button.setText("启动隧道")
                self.update_tray_status()
                QMessageBox.critical(self, '错误', f'启动隧道失败: {str(e)}')
                return
            
        else:
            try:
                logger.info("正在停止SSH隧道...")
                # 先更新状态，防止重复触发
                self.tunnel_running = False
                self.toggle_button.setText("启动隧道")
                self.update_tray_status()

                # 先尝试正常停止
                if hasattr(self, 'tunnel_thread') and self.tunnel_thread is not None:
                    logger.info("正在尝试正常停止隧道...")
                    self.tunnel_thread.stop()  # 先尝试正常停止
                    if not self.tunnel_thread.wait(1000):  # 等待1秒
                        logger.warning("正常停止超时，强制终止线程")
                        self.tunnel_thread.terminate()  # 如果超时则强制终止
                    self.tunnel_thread = None  # 清除线程对象

                # 停止闪烁，显示红色
                self.blink_timer.stop()
                self.status_indicator.setStyleSheet("""
                    QLabel {
                        background-color: #ff4444;
                        border-radius: 5px;
                        margin: 8px;
                        min-width: 10px;
                        min-height: 10px;
                        max-width: 10px;
                        max-height: 10px;
                        border: 1px solid rgba(0, 0, 0, 0.1);
                    }
                """)
                
                self.update_status("隧道已停止")
                logger.info("隧道已停止")
                
            except Exception as e:
                logger.error(f"停止隧道失败: {str(e)}")
                QMessageBox.critical(self, '错误', f'停止隧道失败: {str(e)}')

    def update_status(self, message):
        """更新状态信息"""
        logger.info(f"状态更新: {message}")
        self.status_text.append(message)
        # 自动滚动到底部
        self.status_text.verticalScrollBar().setValue(
            self.status_text.verticalScrollBar().maximum()
        )

    def blink_status(self):
        """状态指示点闪烁效果"""
        if self.blink_state:
            self.status_indicator.setStyleSheet("""
                QLabel {
                    background-color: #00E676;  /* 更亮的绿色 */
                    border-radius: 5px;
                    margin: 8px;
                    min-width: 10px;
                    min-height: 10px;
                    max-width: 10px;
                    max-height: 10px;
                    border: 1px solid rgba(0, 0, 0, 0.1);
                }
            """)
        else:
            self.status_indicator.setStyleSheet("""
                QLabel {
                    background-color: #2E7D32;  /* 更暗的绿色 */
                    border-radius: 5px;
                    margin: 8px;
                    min-width: 10px;
                    min-height: 10px;
                    max-width: 10px;
                    max-height: 10px;
                    border: 1px solid rgba(0, 0, 0, 0.1);
                }
            """)
        self.blink_state = not self.blink_state

    def closeEvent(self, event):
        """处理窗口关闭事件"""
        if self.tunnel_running:
            msgBox = QMessageBox()
            msgBox.setWindowTitle('确认')
            msgBox.setText("隧道正在运行中，请选择操作：")
            msgBox.setInformativeText("• 最小化到托盘 - 程序将在后台继续运行\n"
                                     "• 直接关闭 - 停止隧道并退出程序\n"
                                     "• 取消 - 返回程序")
            
            # 创建自定义按钮
            minimize_btn = msgBox.addButton('最小化到托盘', QMessageBox.YesRole)
            close_btn = msgBox.addButton('直接关闭', QMessageBox.NoRole)
            cancel_btn = msgBox.addButton('取消', QMessageBox.RejectRole)
            
            # 设置默按钮为"最小化到托盘"
            msgBox.setDefaultButton(minimize_btn)
            msgBox.setEscapeButton(cancel_btn)
            
            # 设置对话框样式
            msgBox.setStyleSheet("""
                QMessageBox {
                    background-color: #f5f6fa;
                }
                QLabel {
                    color: #2f3542;
                    font-size: 14px;
                    padding: 10px;
                }
                QPushButton {
                    background-color: #70a1ff;
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                    font-size: 13px;
                    min-width: 100px;
                    margin: 5px;
                }
                QPushButton:hover {
                    background-color: #1e90ff;
                }
                QPushButton:pressed {
                    background-color: #5352ed;
                }
                QPushButton:focus {
                    outline: none;
                    border: 2px solid #70a1ff;
                }
            """)
            
            msgBox.exec()
            
            clicked_button = msgBox.clickedButton()
            
            if clicked_button == minimize_btn:
                event.ignore()
                self.hide()
                self.tray_icon.showMessage(
                    "SSH隧道管理器",
                    "程序已最小化到系统托盘，双击托盘图标可以重新显示窗口",
                    QSystemTrayIcon.Information,
                    2000
                )
            elif clicked_button == close_btn:
                self.force_quit()
            else:  # clicked_button == cancel_btn or clicked_button is None
                event.ignore()
                return
        else:
            msgBox = QMessageBox()
            msgBox.setWindowTitle('确认')
            msgBox.setText("选择操作：")
            msgBox.setInformativeText("• 最小化到托盘 - 程序将在后台运行\n"
                                     "• 直接关闭 - 退出程序")
            
            # 创建自义按钮
            minimize_btn = msgBox.addButton('最小化到托盘', QMessageBox.YesRole)
            close_btn = msgBox.addButton('直接关闭', QMessageBox.NoRole)
            cancel_btn = msgBox.addButton('取消', QMessageBox.RejectRole)
            
            # 设置默认按钮为"最小化到托盘"
            msgBox.setDefaultButton(minimize_btn)
            msgBox.setEscapeButton(cancel_btn)
            
            # 设置对话框样式
            msgBox.setStyleSheet("""
                QMessageBox {
                    background-color: #f5f6fa;
                }
                QLabel {
                    color: #2f3542;
                    font-size: 14px;
                    padding: 10px;
                }
                QPushButton {
                    background-color: #70a1ff;
                    color: white;
                    padding: 8px 15px;
                    border: none;
                    border-radius: 4px;
                    font-size: 13px;
                    min-width: 100px;
                    margin: 5px;
                }
                QPushButton:hover {
                    background-color: #1e90ff;
                }
                QPushButton:pressed {
                    background-color: #5352ed;
                }
                QPushButton:focus {
                    outline: none;
                    border: 2px solid #70a1ff;
                }
            """)
            
            msgBox.exec()
            
            clicked_button = msgBox.clickedButton()
            
            if clicked_button == minimize_btn:
                event.ignore()
                self.hide()
                self.tray_icon.showMessage(
                    "SSH隧道管理器",
                    "程序已最小化到系统托盘，双击托盘图标可以重新显示窗口",
                    QSystemTrayIcon.Information,
                    2000
                )
            elif clicked_button == close_btn:
                self.force_quit()
            else:  # clicked_button == cancel_btn or clicked_button is None
                event.ignore()
                return

    # 添加清空所有字段的方法
    def clear_all_fields(self):
        """清空所有输入框"""
        self.ssh_host.clear()
        self.ssh_user.clear()
        self.ssh_password.clear()
        self.local_port.clear()
        self.remote_host.clear()
        self.remote_port.clear()
        
        # 配置选择器设置"新建配置"
        self.config_combo.setCurrentText("新建配置")
        
        # 清空状态文本
        self.status_text.clear()
        
        # 如果正在运行，停止隧道
        if self.tunnel_running:
            self.toggle_tunnel()
        
        QMessageBox.information(self, '成功', '所有参数已清空')

    def init_tray(self):
        """初始化系统托盘"""
        logger.info("初始化系统托盘...")
        try:
            self.tray_icon = QSystemTrayIcon(self)
            logger.info("托盘图标对象创建成功")
            
            icon_path = get_app_path('icon.ico')
            logger.info(f"尝试加载图标: {icon_path}")
            
            icon = QIcon(icon_path)
            if not icon.isNull():
                logger.info("图标加载成功")
                self.tray_icon.setIcon(icon)
            else:
                logger.warning("使用系统默认图标")
                self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
            
            # 创建托盘菜单
            logger.info("正在创建托盘菜单...")
            tray_menu = QMenu()
            
            # 添加状态显示（不可点击）
            status_action = QAction("状态: 未连接", self)
            status_action.setEnabled(False)
            self.tray_status_action = status_action  # 保存引用以便后续更新
            tray_menu.addAction(status_action)
            
            # 添加分隔线
            tray_menu.addSeparator()
            
            # 显示主窗口
            show_action = QAction("显示主窗口", self)
            show_action.triggered.connect(self.show_and_activate)
            tray_menu.addAction(show_action)
            
            # 添加隧道控制子菜单
            tunnel_menu = QMenu("隧道控制", self)
            
            # 启动/停止隧道
            self.toggle_tunnel_action = QAction("启动隧道", self)
            self.toggle_tunnel_action.triggered.connect(self.toggle_tunnel_from_tray)
            tunnel_menu.addAction(self.toggle_tunnel_action)
            
            # 重启隧道
            restart_action = QAction("重启隧道", self)
            restart_action.triggered.connect(self.restart_tunnel)
            tunnel_menu.addAction(restart_action)
            
            tray_menu.addMenu(tunnel_menu)
            
            # 添加配置管理子菜单
            config_menu = QMenu("配置管理", self)
            
            # 重新加载配置
            reload_config_action = QAction("重新加载配置", self)
            reload_config_action.triggered.connect(self.reload_configs)
            config_menu.addAction(reload_config_action)
            
            # 快速切换配置子菜单
            self.switch_config_menu = QMenu("切换配置", self)
            self.update_switch_config_menu()  # 初始化配置列表
            config_menu.addMenu(self.switch_config_menu)
            
            tray_menu.addMenu(config_menu)
            
            # 添加分隔线
            tray_menu.addSeparator()
            
            # 退出程序
            quit_action = QAction("退出", self)
            quit_action.triggered.connect(self.force_quit)
            tray_menu.addAction(quit_action)
            
            logger.info("在设置盘菜单...")
            self.tray_icon.setContextMenu(tray_menu)
            
            logger.info("正在连接托盘图标事件...")
            self.tray_icon.activated.connect(self.tray_icon_activated)
            
            logger.info("正在显示托盘图标...")
            self.tray_icon.show()
            
            if self.tray_icon.isVisible():
                logger.info("托盘图标显示成功")
            else:
                logger.warning("托盘图标可能未正确示")
            
        except Exception as e:
            logger.error(f"初始化系统托失败: {str(e)}", exc_info=True)
            
    def tray_icon_activated(self, reason):
        """处理托盘图标的激活事件"""
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isHidden():
                self.show()
                self.activateWindow()  # 激活窗口
            else:
                self.hide()

    def hideEvent(self, event):
        """窗口隐时的事件"""
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            event.accept()
            # 确保托盘图标可见
            self.tray_icon.show()
            # 保存当前配置
            name = self.config_combo.currentText()
            if name != "新建配置":
                self.save_last_config(name)
        else:
            event.ignore()

    def force_quit(self):
        """强制退出程序"""
        try:
            logger.info("正在退出程序...")
            self.blink_timer.stop()  # 停止闪烁定时器
            self.tray_icon.hide()  # 隐藏托盘图标
            
            # 检查并停止隧道线程
            if hasattr(self, 'tunnel_thread') and self.tunnel_thread is not None:
                try:
                    self.tunnel_thread.stop()
                    if not self.tunnel_thread.wait(3000):  # 等待最多3秒
                        logger.warning("线程停止超时，强制终止")
                        self.tunnel_thread.terminate()
                except Exception as e:
                    logger.error(f"停止隧道线程失败: {str(e)}")
            
            # 保存最后使用的配置
            name = self.config_combo.currentText()
            if name != "新建配置":
                self.save_last_config(name)
            
            logger.info("程序退出")
            QApplication.quit()  # 退出应用
            
        except Exception as e:
            logger.error(f"程序退出时发生错误: {str(e)}")
            QApplication.quit()  # 确保程序能够退出

    # 添加新的辅助方法
    def show_and_activate(self):
        """显示并激活主窗口"""
        self.show()
        self.activateWindow()
        self.raise_()

    def toggle_tunnel_from_tray(self):
        """从托盘菜单触发隧道开关"""
        try:
            if self.tunnel_running:
                # 使用主界面的停止逻辑
                self.toggle_tunnel()
            else:
                # 如果隧道未运行，先检查是否有有效配置
                if not self.ssh_host.text().strip():
                    QMessageBox.warning(self, '错误', '请先配置SSH连接参数')
                    self.show()  # 显示主窗口
                    return
                self.toggle_tunnel()  # 使用主窗口的启动方法
            
        except Exception as e:
            logger.error(f"托盘菜单操作失败: {str(e)}")
            QMessageBox.critical(self, '错误', f'操作失败: {str(e)}')

    def restart_tunnel(self):
        """重启隧道"""
        logger.info("正在重启隧道...")
        if self.tunnel_running:
            self.toggle_tunnel()  # 停止隧道
            time.sleep(1)  # 等待1秒
            self.toggle_tunnel()  # 重新启动隧道
        else:
            self.toggle_tunnel()  # 直接启动隧道

    def reload_configs(self):
        """重新加载配置文件"""
        try:
            logger.info("正在重新加载配置文件...")
            
            # 如果隧道正在运行，先停止
            if self.tunnel_running:
                logger.info("停止当前运行的隧道")
                self.toggle_tunnel()
            
            # 重新加载配置
            self.configs = self.load_configs()
            
            # 更新配置下拉框
            self.config_combo.clear()
            self.config_combo.addItem("新建配置")
            for name in self.configs.keys():
                self.config_combo.addItem(name)
            
            # 更新托盘菜单
            self.update_switch_config_menu()
            
            # 如果有最后使用的配置，加载它
            last_config = self.get_last_config()
            if last_config and last_config in self.configs:
                self.config_combo.setCurrentText(last_config)
                self.load_config(last_config)
            
            logger.info("配置重新加载完成")
            QMessageBox.information(self, '成功', '配置已重新加载')
            
        except Exception as e:
            error_msg = f"重新加载配置失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, '错误', error_msg)

    def update_switch_config_menu(self):
        """更新配置切换菜单"""
        try:
            logger.debug("更新配置切换菜单")
            self.switch_config_menu.clear()
            for config_name in self.configs.keys():
                action = QAction(config_name, self)
                # 使用 lambda 时捕获当前值
                action.triggered.connect(
                    lambda checked, name=config_name: self.switch_config(name)
                )
                self.switch_config_menu.addAction(action)
            logger.debug("配置切换菜单更新完成")
        except Exception as e:
            logger.error(f"更新配置切换菜单失败: {str(e)}")

    def switch_config(self, config_name):
        """切换到指定配置"""
        try:
            logger.info(f"切换到配置: {config_name}")
            
            # 如果隧道正在运行，先停止
            if self.tunnel_running:
                logger.info("停止当前运行的隧道")
                self.toggle_tunnel()
            
            # 切换配置
            self.config_combo.setCurrentText(config_name)
            self.load_config(config_name)
            logger.info("配置切换完成")
            
        except Exception as e:
            error_msg = f"切换配置失败: {str(e)}"
            logger.error(error_msg)
            QMessageBox.critical(self, '错误', error_msg)

    def update_tray_status(self):
        """更新托盘菜单中的状态显示"""
        try:
            if self.tunnel_running and hasattr(self, 'tunnel_thread') and self.tunnel_thread is not None:
                self.tray_status_action.setText(f"状态: 已连接 ({self.ssh_host.text()})")
                self.toggle_tunnel_action.setText("停止隧道")
            else:
                self.tray_status_action.setText("状态: 未连接")
                self.toggle_tunnel_action.setText("启动隧道")
                self.tunnel_running = False  # 确保状态一致
            logger.debug(f"托盘状态更新: running={self.tunnel_running}")
        except Exception as e:
            logger.error(f"更新托盘状态失败: {str(e)}")

    def import_configs(self):
        """导入配置"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择配置文件", "", "JSON文件 (*.json)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    imported_configs = json.load(f)
                
                # 合并配置
                for name, config in imported_configs.items():
                    if name in self.configs:
                        reply = QMessageBox.question(
                            self, '配置已存在',
                            f'配置 "{name}" 已存在，是否覆盖？',
                            QMessageBox.Yes | QMessageBox.No
                        )
                        if reply == QMessageBox.No:
                            continue
                    self.configs[name] = config
                
                # 保存配置
                self.save_configs()
                
                # 更新配置下拉框
                self.config_combo.clear()
                self.config_combo.addItem("新建配置")
                for name in self.configs.keys():
                    self.config_combo.addItem(name)
                
                # 更新托盘菜单中的配置列表
                self.update_switch_config_menu()
                
                logger.info(f"成功从 {file_path} 导入配置")
                QMessageBox.information(self, '成功', '配置导入成功')
            except Exception as e:
                error_msg = f'导入配置失败: {str(e)}'
                logger.error(error_msg)
                QMessageBox.warning(self, '错误', error_msg)

    def export_configs(self):
        """导出配置"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "保存配置文件", "", "JSON文件 (*.json)"
            )
            if file_path:
                try:
                    # 确保文件名以 .json 结
                    if not file_path.endswith('.json'):
                        file_path += '.json'
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.configs, f, ensure_ascii=False, indent=2)
                    QMessageBox.information(self, '成功', '配置导出成功')
                    logger.info(f"配置成功导出到: {file_path}")
                except Exception as e:
                    error_msg = f'导出配置失败: {str(e)}'
                    logger.error(error_msg)
                    QMessageBox.warning(self, '错误', error_msg)
        except Exception as e:
            error_msg = f'打开文件对话框失败: {str(e)}'
            logger.error(error_msg)
            QMessageBox.critical(self, '错误', error_msg)

    def add_connection_history(self, config_name):
        """添加连接历史记录"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_entry = {
            'timestamp': timestamp,
            'config_name': config_name,
            'ssh_host': self.ssh_host.text(),
            'local_port': self.local_port.text(),
            'remote_host': self.remote_host.text(),
            'remote_port': self.remote_port.text()
        }
        self.connection_history.insert(0, history_entry)
        # 只保留最近50记录
        self.connection_history = self.connection_history[:50]
        self.save_connection_history()

    def show_connection_history(self):
        """显示连接历史记录"""
        # 创建话框并移除问号按钮
        self.history_dialog = QDialog(self)
        self.history_dialog.setWindowFlags(self.history_dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)  # 移除问号按钮
        self.history_dialog.setWindowTitle("连接历史记录")
        self.history_dialog.setMinimumWidth(600)
        
        layout = QVBoxLayout()
        
        # 创建表格
        self.history_table = QTableWidget()  # 保存为实例变量以便在其他方法中访问
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["时间", "配置名称", "SSH主机", "本地端口", "程地址"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        
        # 更新表格数据
        self.update_history_table()
        
        layout.addWidget(self.history_table)
        
        # 添加清空历史按钮
        clear_btn = QPushButton("清空历史")
        clear_btn.clicked.connect(self.clear_connection_history)
        layout.addWidget(clear_btn)
        
        self.history_dialog.setLayout(layout)
        self.history_dialog.exec_()

    def update_history_table(self):
        """更新历史记录表格"""
        self.history_table.setRowCount(len(self.connection_history))
        for i, entry in enumerate(self.connection_history):
            self.history_table.setItem(i, 0, QTableWidgetItem(entry['timestamp']))
            self.history_table.setItem(i, 1, QTableWidgetItem(entry['config_name']))
            self.history_table.setItem(i, 2, QTableWidgetItem(entry['ssh_host']))
            self.history_table.setItem(i, 3, QTableWidgetItem(entry['local_port']))
            self.history_table.setItem(i, 4, QTableWidgetItem(f"{entry['remote_host']}:{entry['remote_port']}"))

    def show_connection_settings(self):
        """显示连接设置对话框"""
        dialog = QDialog(self)
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)  # 移除问号按钮
        dialog.setWindowTitle("连接设置")
        
        layout = QFormLayout()
        
        # 最大重连次数设置
        reconnect_spin = QSpinBox()
        reconnect_spin.setRange(1, 100)
        reconnect_spin.setValue(self.settings['max_reconnects'])
        layout.addRow("最大重连次数:", reconnect_spin)
        
        # 连接超时设置
        timeout_spin = QSpinBox()
        timeout_spin.setRange(5, 300)
        timeout_spin.setValue(self.settings['connect_timeout'])
        layout.addRow("连接超时(秒):", timeout_spin)
        
        # 按钮
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            self.settings['max_reconnects'] = reconnect_spin.value()
            self.settings['connect_timeout'] = timeout_spin.value()
            self.save_settings()
            QMessageBox.information(self, '成', '设置已保存')

    def load_connection_history(self):
        """加载连接历史记录"""
        history_file = get_app_path('connection_history.json')
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r', encoding='utf-8') as f:
                    self.connection_history = json.load(f)
            except:
                self.connection_history = []

    def save_connection_history(self):
        """保存连接历史记录"""
        history_file = get_app_path('connection_history.json')
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(self.connection_history, f, ensure_ascii=False, indent=2)

    def clear_connection_history(self):
        """清空连接历史记录"""
        reply = QMessageBox.question(
            self, '确认',
            '确定要清空所有连接历史记录？',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.connection_history = []
            self.save_connection_history()
            # 更新格显示
            self.update_history_table()
            QMessageBox.information(self, '成功', '历史记录已清空')

    def load_settings(self):
        """加载设置"""
        settings_file = get_app_path('settings.json')
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r', encoding='utf-8') as f:
                    saved_settings = json.load(f)
                    self.settings.update(saved_settings)
            except:
                pass

    def save_settings(self):
        """保存设置"""
        settings_file = get_app_path('settings.json')
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, ensure_ascii=False, indent=2)

    def show_help(self):
        """显示帮助信"""
        help_text = """
        <h3>SSH隧道管理器使用帮助</h3>
        
        <p><b>基本功能：</b></p>
        <ul>
            <li>创建和管理SSH反向隧道连接</li>
            <li>保存和加载多个连接配置</li>
            <li>查看连接历史记录</li>
            <li>自动重连和状态监控</li>
        </ul>

        <p><b>配置说明：</b></p>
        <ul>
            <li>SSH主机：远程SSH服务器的地址</li>
            <li>SSH用户：SSH登录用户名</li>
            <li>SSH密码：SSH登录密码</li>
            <li>本地端口：在SSH服务器上监听的端口</li>
            <li>远程主机：需要转发到的目标主机地址</li>
            <li>远程端口：需要转发到的目标主机端口</li>
        </ul>

        <p><b>主要功能：</b></p>
        <ul>
            <li>配置管理：
                <ul>
                    <li>保存配置：保存当前的连接参数</li>
                    <li>导入配置：从文件导入配置</li>
                    <li>导出配置：将配置导出到文件</li>
                    <li>删除配置：删除选中的配置</li>
                </ul>
            </li>
            <li>连接管理：
                <ul>
                    <li>启动/停止隧道</li>
                    <li>自动重连（可配置重试次数）</li>
                    <li>连接状态监控</li>
                </ul>
            </li>
            <li>系统托盘：
                <ul>
                    <li>最小化到托盘继续运行</li>
                    <li>托盘菜单快速操作</li>
                    <li>状态指示和通知</li>
                </ul>
            </li>
        </ul>

        <p><b>其他功能：</b></p>
        <ul>
            <li>连接历史记录</li>
            <li>连接超时设置</li>
            <li>密码加密存储</li>
            <li>详细的状态日志</li>
        </ul>

        <p><b>快捷作：</b></p>
        <ul>
            <li>双击托盘图标：显示/隐藏主窗口</li>
            <li>右键托盘图标：显示快捷菜单</li>
            <li>菜单按钮：快速问所有功能</li>
        </ul>
        """
        
        help_dialog = QDialog(self)
        help_dialog.setWindowFlags(help_dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)  # 移除问号按
        help_dialog.setWindowTitle("使用帮助")
        help_dialog.setMinimumSize(500, 600)
        
        layout = QVBoxLayout()
        
        # 创建文本浏览器来显示帮助信息
        text_browser = QTextBrowser()
        text_browser.setHtml(help_text)
        text_browser.setOpenExternalLinks(True)
        layout.addWidget(text_browser)
        
        # 添加关闭按钮
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(help_dialog.close)
        layout.addWidget(close_btn)
        
        help_dialog.setLayout(layout)
        help_dialog.exec_()

    def show_about(self):
        """显示关于信息"""
        about_text = """
        <h3>SSH隧道管理器</h3>
        <p>版本：1.0.0</p>
        <p>一个简单易用的SSH反向隧道管理工具</p>
        <p>主要功能：</p>
        <ul>
            <li>SSH反向隧道管理</li>
            <li>多配置支持</li>
            <li>自动重连</li>
            <li>系统托盘</li>
        </ul>
        """
        
        QMessageBox.about(self, "关于", about_text)

    def handle_connection_failed(self):
        """处理连接失败的情况"""
        logger.info("处理连接失败")
        self.tunnel_running = False
        self.toggle_button.setText("启动隧道")
        
        # 停止闪烁，显示红色
        self.blink_timer.stop()
        self.status_indicator.setStyleSheet("""
            QLabel {
                background-color: #ff4444;
                border-radius: 5px;
                margin: 8px;
                min-width: 10px;
                min-height: 10px;
                max-width: 10px;
                max-height: 10px;
                border: 1px solid rgba(0, 0, 0, 0.1);
            }
        """)
        
        # 更新托盘状态
        self.update_tray_status()

def load_config():
    """加载主配置文件"""
    try:
        # config.json 放在src目录下
        with open(get_app_path('config.json'), 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print("错误：找不到config.json文件")
        return None
    except json.JSONDecodeError:
        print("错误：config.json格式不正确")
        return None

def main():
    # 在程序开始时加载配置
    config = load_config()
    if config is None:
        return
    
    # 使用配置参数
    # 现有代码...

if __name__ == '__main__':
    logger.info("程序启动")
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
