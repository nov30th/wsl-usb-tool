#!/usr/bin/env python3

'''
@Author: HOHO``, Nov30th
@Github: https://github.com/nov30th/wsl-usb-tool/
'''

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import time
import sys
import re
import signal
import os
import queue
from concurrent.futures import ThreadPoolExecutor
import atexit
import ctypes
import platform


class PrivilegeManager:
    """权限管理类"""

    @staticmethod
    def detect_environment():
        """检测运行环境"""
        try:
            # 检查是否在WSL中
            with open('/proc/version', 'r') as f:
                version_info = f.read().lower()
                if 'microsoft' in version_info or 'wsl' in version_info:
                    return 'wsl'
        except (FileNotFoundError, OSError):
            pass

        # 检查是否在Windows中
        if platform.system() == 'Windows':
            return 'windows'
        elif platform.system() == 'Linux':
            return 'linux'
        else:
            return 'unknown'

    @staticmethod
    def is_admin_windows():
        """检查Windows下是否有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def is_admin_linux():
        """检查Linux/WSL下是否有root权限"""
        return os.geteuid() == 0

    @staticmethod
    def request_admin_windows():
        """在Windows下请求管理员权限"""
        if PrivilegeManager.is_admin_windows():
            return True

        try:
            # 使用ShellExecuteW以管理员身份重新启动
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                " ".join(sys.argv),
                None,
                1
            )
            return False  # 返回False表示需要重启
        except Exception as e:
            messagebox.showerror("错误", f"无法获取管理员权限: {e}")
            return False

    @staticmethod
    def request_admin_linux():
        """在Linux/WSL下请求sudo权限"""
        if PrivilegeManager.is_admin_linux():
            return True

        try:
            # 检查是否可以使用sudo
            result = subprocess.run(['sudo', '-n', 'true'],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                return True

            # 尝试获取sudo权限
            result = subprocess.run(['sudo', '-v'], timeout=30)
            return result.returncode == 0
        except Exception as e:
            messagebox.showerror("错误", f"无法获取sudo权限: {e}")
            return False

    @staticmethod
    def ensure_privileges():
        """确保程序有足够的权限运行"""
        env = PrivilegeManager.detect_environment()

        if env == 'windows':
            if not PrivilegeManager.is_admin_windows():
                messagebox.showinfo("权限提升",
                                    "此程序需要管理员权限来管理USB设备。\n"
                                    "点击确定后，系统将提示您授予管理员权限。")

                if not PrivilegeManager.request_admin_windows():
                    sys.exit(0)  # 程序将以管理员权限重新启动

        elif env in ['wsl', 'linux']:
            if not PrivilegeManager.is_admin_linux():
                # 在WSL中，通常需要Windows端的usbipd有权限
                # 这里主要是提醒用户
                messagebox.showwarning("权限提醒",
                                       "在WSL环境中使用此程序，请确保：\n"
                                       "1. Windows端的usbipd已安装\n"
                                       "2. 在Windows端以管理员权限运行相关命令\n"
                                       "3. 或在WSL中使用sudo运行此程序")

        return env


class USBDeviceManager:
    def __init__(self, root):
        self.root = root
        self.root.title("WSL USB Device Manager")
        self.root.geometry("900x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 检测环境和权限
        self.environment = PrivilegeManager.ensure_privileges()

        # 存储已附加的设备信息
        self.attached_devices = {}  # {busid: {'process': process, 'device_name': name, 'thread': thread}}
        self.running = True

        # 线程池用于处理异步操作
        self.executor = ThreadPoolExecutor(max_workers=5)

        # 消息队列用于线程间通信
        self.message_queue = queue.Queue()

        # 创建界面
        self.create_widgets()

        # 启动消息处理线程
        self.message_thread = threading.Thread(target=self.process_messages, daemon=True)
        self.message_thread.start()

        # 注册程序退出清理函数
        atexit.register(self.cleanup_on_exit)

        # 显示环境信息
        self.show_environment_info()

        # 初始加载设备列表
        self.refresh_devices()

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # 标题和环境信息
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        header_frame.columnconfigure(1, weight=1)

        title_label = ttk.Label(header_frame, text="WSL USB Device Manager",
                                font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, sticky=tk.W)

        # 环境和权限状态
        self.env_status_var = tk.StringVar()
        env_label = ttk.Label(header_frame, textvariable=self.env_status_var,
                              font=("Arial", 9), foreground="blue")
        env_label.grid(row=0, column=1, sticky=tk.E)

        # 设备列表框架
        list_frame = ttk.LabelFrame(main_frame, text="USB设备列表", padding="5")
        list_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        # 设备列表
        columns = ("BUSID", "VID:PID", "DEVICE", "STATE")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)

        # 列标题
        self.tree.heading("BUSID", text="Bus ID")
        self.tree.heading("VID:PID", text="VID:PID")
        self.tree.heading("DEVICE", text="设备名称")
        self.tree.heading("STATE", text="状态")

        # 列宽
        self.tree.column("BUSID", width=80)
        self.tree.column("VID:PID", width=100)
        self.tree.column("DEVICE", width=400)
        self.tree.column("STATE", width=150)

        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))

        # 按钮
        ttk.Button(button_frame, text="刷新设备", command=self.refresh_devices).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="绑定并附加", command=self.bind_attach_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="分离", command=self.detach_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="分离所有", command=self.detach_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="检查权限", command=self.check_privileges).pack(side=tk.LEFT, padx=(0, 5))

        # 添加连接状态指示
        self.connection_frame = ttk.LabelFrame(main_frame, text="连接状态", padding="5")
        self.connection_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        self.connection_text = tk.Text(self.connection_frame, height=3, wrap=tk.WORD, state=tk.DISABLED)
        self.connection_text.pack(fill=tk.BOTH, expand=True)

        # 状态框架
        status_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="5")
        status_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)

        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(status_frame, height=8, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 双击事件
        self.tree.bind("<Double-1>", self.on_double_click)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))

    def show_environment_info(self):
        """显示环境信息"""
        env_text = f"环境: {self.environment.upper()}"

        if self.environment == 'windows':
            is_admin = PrivilegeManager.is_admin_windows()
            privilege_text = "管理员" if is_admin else "普通用户"
            env_text += f" | 权限: {privilege_text}"
        elif self.environment in ['wsl', 'linux']:
            is_root = PrivilegeManager.is_admin_linux()
            privilege_text = "root" if is_root else "普通用户"
            env_text += f" | 权限: {privilege_text}"

        self.env_status_var.set(env_text)
        self.log_message(f"检测到运行环境: {env_text}")

    def check_privileges(self):
        """检查当前权限状态"""
        env = self.environment

        if env == 'windows':
            is_admin = PrivilegeManager.is_admin_windows()
            status = "管理员权限" if is_admin else "普通用户权限"
            color = "green" if is_admin else "red"

            if not is_admin:
                if messagebox.askyesno("权限不足",
                                       "当前没有管理员权限，USB设备管理可能失败。\n"
                                       "是否以管理员权限重新启动程序？"):
                    PrivilegeManager.request_admin_windows()

        elif env in ['wsl', 'linux']:
            is_root = PrivilegeManager.is_admin_linux()
            status = "root权限" if is_root else "普通用户权限"
            color = "green" if is_root else "orange"

            if not is_root:
                messagebox.showinfo("权限提示",
                                    "当前没有root权限。\n"
                                    "如果遇到权限问题，请使用 'sudo python3 usb_manager.py' 运行")

        self.log_message(f"权限检查: {status}")
        self.show_environment_info()

    def update_connection_status(self):
        """更新连接状态显示"""
        self.connection_text.config(state=tk.NORMAL)
        self.connection_text.delete(1.0, tk.END)

        if self.attached_devices:
            status_text = f"已连接设备 ({len(self.attached_devices)}):\n"
            for busid, info in self.attached_devices.items():
                device_name = info.get('device_name', 'Unknown')
                status_text += f"• {busid}: {device_name}\n"
        else:
            status_text = "无已连接设备"

        self.connection_text.insert(tk.END, status_text)
        self.connection_text.config(state=tk.DISABLED)

    def log_message(self, message):
        """添加日志消息"""
        self.message_queue.put(('log', message))

    def _log_message_ui(self, message):
        """在UI线程中添加日志消息"""
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, full_message)
        self.log_text.see(tk.END)
        self.update_connection_status()
        self.root.update_idletasks()

    def process_messages(self):
        """处理消息队列"""
        while self.running:
            try:
                message_type, message = self.message_queue.get(timeout=0.1)
                if message_type == 'log':
                    self.root.after(0, lambda m=message: self._log_message_ui(m))
                elif message_type == 'refresh':
                    self.root.after(0, self.refresh_devices)
                elif message_type == 'status':
                    self.root.after(0, lambda s=message: self.status_var.set(s))
            except queue.Empty:
                continue
            except Exception as e:
                print(f"消息处理错误: {e}")

    def run_command(self, command, timeout=30, use_sudo=False):
        """运行命令，根据环境选择合适的方式"""
        try:
            if self.environment == 'windows':
                # Windows环境，使用PowerShell
                full_command = f'powershell.exe "{command}"'
            else:
                # Linux/WSL环境
                if use_sudo and not PrivilegeManager.is_admin_linux():
                    full_command = f'sudo {command}'
                else:
                    full_command = command

            result = subprocess.run(full_command, shell=True, capture_output=True,
                                    text=True, timeout=timeout)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "命令超时"
        except Exception as e:
            return False, "", str(e)

    def run_command_async(self, command, use_sudo=False):
        """异步运行命令，返回进程对象"""
        try:
            if self.environment == 'windows':
                full_command = f'powershell.exe "{command}"'
            else:
                if use_sudo and not PrivilegeManager.is_admin_linux():
                    full_command = f'sudo {command}'
                else:
                    full_command = command

            process = subprocess.Popen(full_command, shell=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True)
            return process
        except Exception as e:
            self.log_message(f"启动异步命令失败: {e}")
            return None

    def refresh_devices(self):
        """刷新USB设备列表"""
        self.message_queue.put(('status', '刷新设备列表...'))
        self.log_message("正在刷新USB设备列表...")

        # 清空现有列表
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 获取设备列表
        success, output, error = self.run_command("usbipd list")

        if not success:
            self.log_message(f"获取设备列表失败: {error}")
            if "usbipd" in error.lower() and "not found" in error.lower():
                self.log_message("提示: 请确保已安装usbipd工具")
                self.log_message("Windows安装: winget install usbipd")
            self.message_queue.put(('status', '获取设备列表失败'))
            return

        # 解析输出
        lines = output.strip().split('\n')
        if len(lines) < 2:
            self.log_message("没有找到USB设备")
            self.message_queue.put(('status', '没有找到USB设备'))
            return

        device_count = 0
        for line in lines[1:]:  # 跳过标题行
            line = line.strip()
            if not line or line.startswith('-'):
                continue

            # 解析设备信息
            parts = line.split()
            if len(parts) >= 3:
                busid = parts[0]
                vid_pid = parts[1] if parts[1] != 'n/a' else 'N/A'

                # 设备名称可能包含空格，所以需要特殊处理
                device_start = line.find(parts[1]) + len(parts[1])
                remaining = line[device_start:].strip()

                # 查找状态
                if remaining:
                    words = remaining.split()
                    if len(words) >= 2:
                        possible_states = ['Not shared', 'Shared', 'Attached']
                        state = 'Unknown'
                        device_name = remaining

                        for possible_state in possible_states:
                            if remaining.endswith(possible_state):
                                state = possible_state
                                device_name = remaining[:-len(possible_state)].strip()
                                break

                        # 检查是否由我们的程序管理
                        if busid in self.attached_devices:
                            state = 'Attached (管理中)'
                        elif 'Attached' in remaining:
                            state = 'Attached to WSL'
                        elif 'Shared' in remaining:
                            state = 'Shared'
                        elif 'Not shared' in remaining:
                            state = 'Not shared'
                    else:
                        device_name = remaining
                        state = 'Unknown'
                else:
                    device_name = 'Unknown Device'
                    state = 'Unknown'

                # 添加到树形视图
                self.tree.insert("", tk.END, values=(busid, vid_pid, device_name, state))
                device_count += 1

        self.log_message(f"找到 {device_count} 个USB设备")
        self.message_queue.put(('status', f'找到 {device_count} 个设备'))

    def get_selected_device(self):
        """获取选中的设备"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个设备")
            return None

        item = self.tree.item(selection[0])
        return item['values']

    def maintain_device_connection(self, busid, device_name):
        """维持设备连接的后台线程"""
        self.log_message(f"开始维持设备连接: {device_name} ({busid})")

        while self.running and busid in self.attached_devices:
            # 启动附加命令
            process = self.run_command_async(f"usbipd attach --wsl --busid {busid} -a")
            if not process:
                self.log_message(f"无法启动设备 {busid} 的连接进程")
                break

            # 保存进程引用
            if busid in self.attached_devices:
                self.attached_devices[busid]['process'] = process

            try:
                # 等待进程结束（可能因为设备断开或用户操作）
                stdout, stderr = process.communicate()

                if not self.running or busid not in self.attached_devices:
                    break

                if process.returncode != 0:
                    self.log_message(f"设备 {busid} 连接中断: {stderr.strip()}")
                    # 如果是意外断开，等待一段时间后重试
                    time.sleep(2)
                    self.log_message(f"尝试重新连接设备 {busid}...")
                else:
                    self.log_message(f"设备 {busid} 连接正常结束")
                    break

            except Exception as e:
                self.log_message(f"维持设备 {busid} 连接时发生错误: {e}")
                time.sleep(2)

        # 清理
        if busid in self.attached_devices:
            del self.attached_devices[busid]

        self.log_message(f"停止维持设备连接: {device_name} ({busid})")
        self.message_queue.put(('refresh', None))

    def bind_attach_selected(self):
        """绑定并附加选中的设备"""
        device = self.get_selected_device()
        if not device:
            return

        busid = device[0]
        device_name = device[2]

        if busid in self.attached_devices:
            messagebox.showinfo("信息", f"设备 {busid} 已经在管理中")
            return

        def bind_attach_task():
            self.log_message(f"正在绑定设备: {device_name} ({busid})")
            self.message_queue.put(('status', f'绑定设备 {busid}...'))

            # 先绑定设备
            success, output, error = self.run_command(f"usbipd bind --busid {busid}")
            if not success:
                self.log_message(f"绑定失败: {error}")
                if "access" in error.lower() or "permission" in error.lower():
                    self.log_message("提示: 可能需要管理员权限，请点击'检查权限'按钮")
                self.root.after(0, lambda: messagebox.showerror("错误", f"绑定设备失败:\n{error}"))
                return

            self.log_message(f"设备 {busid} 绑定成功，开始维持连接...")

            # 将设备添加到管理列表
            self.attached_devices[busid] = {
                'device_name': device_name,
                'process': None,
                'thread': None
            }

            # 启动维持连接的线程
            maintain_thread = threading.Thread(
                target=self.maintain_device_connection,
                args=(busid, device_name),
                daemon=True
            )
            self.attached_devices[busid]['thread'] = maintain_thread
            maintain_thread.start()

            self.message_queue.put(('refresh', None))

        # 在后台线程中执行绑定操作
        self.executor.submit(bind_attach_task)

    def detach_selected(self):
        """分离选中的设备"""
        device = self.get_selected_device()
        if not device:
            return

        busid = device[0]
        device_name = device[2]

        self.detach_device(busid, device_name)

    def detach_device(self, busid, device_name=""):
        """分离指定设备"""

        def detach_task():
            self.log_message(f"正在分离设备: {device_name} ({busid})")
            self.message_queue.put(('status', f'分离设备 {busid}...'))

            # 先停止维持连接的进程
            if busid in self.attached_devices:
                device_info = self.attached_devices[busid]
                process = device_info.get('process')

                if process and process.poll() is None:
                    try:
                        # 终止进程
                        process.terminate()
                        # 等待进程结束
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                    except Exception as e:
                        self.log_message(f"终止进程时出错: {e}")

                # 从管理列表中移除
                del self.attached_devices[busid]

            # 分离设备
            success, output, error = self.run_command(f"usbipd detach --busid {busid}")
            if not success:
                self.log_message(f"分离失败: {error}")
            else:
                self.log_message(f"设备 {busid} 已分离")

            # 解绑设备
            success, output, error = self.run_command(f"usbipd unbind --busid {busid}")
            if not success:
                self.log_message(f"解绑失败: {error}")
            else:
                self.log_message(f"设备 {busid} 已解绑")

            self.message_queue.put(('refresh', None))

        # 在后台线程中执行分离操作
        self.executor.submit(detach_task)

    def detach_all(self):
        """分离所有已附加的设备"""
        if not self.attached_devices:
            self.log_message("没有已附加的设备")
            return

        if not messagebox.askyesno("确认", f"确定要分离所有 {len(self.attached_devices)} 个已附加的设备吗？"):
            return

        devices_to_detach = list(self.attached_devices.keys())
        for busid in devices_to_detach:
            device_info = self.attached_devices.get(busid, {})
            device_name = device_info.get('device_name', '')
            self.detach_device(busid, device_name)

    def on_double_click(self, event):
        """双击事件处理"""
        device = self.get_selected_device()
        if not device:
            return

        busid = device[0]
        state = device[3]

        if busid in self.attached_devices or "Attached" in state:
            self.detach_selected()
        else:
            self.bind_attach_selected()

    def cleanup_on_exit(self):
        """程序退出时的清理工作"""
        if not self.running:
            return

        self.running = False

        if self.attached_devices:
            print(f"程序退出，正在清理 {len(self.attached_devices)} 个设备...")
            devices_to_detach = list(self.attached_devices.keys())

            for busid in devices_to_detach:
                device_info = self.attached_devices.get(busid, {})
                device_name = device_info.get('device_name', '')
                process = device_info.get('process')

                # 停止维持连接的进程
                if process and process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    except Exception:
                        pass

                # 分离和解绑设备
                try:
                    if self.environment == 'windows':
                        subprocess.run(f'powershell.exe "usbipd detach --busid {busid}"',
                                       shell=True, timeout=5, capture_output=True)
                        subprocess.run(f'powershell.exe "usbipd unbind --busid {busid}"',
                                       shell=True, timeout=5, capture_output=True)
                    else:
                        subprocess.run(f'usbipd detach --busid {busid}',
                                       shell=True, timeout=5, capture_output=True)
                        subprocess.run(f'usbipd unbind --busid {busid}',
                                       shell=True, timeout=5, capture_output=True)
                    print(f"已清理设备: {busid}")
                except Exception as e:
                    print(f"清理设备 {busid} 时出错: {e}")

            self.attached_devices.clear()
            print("设备清理完成")

        # 关闭线程池
        try:
            self.executor.shutdown(wait=False)
        except Exception:
            pass

    def on_closing(self):
        """程序关闭时的处理"""
        if self.attached_devices:
            if messagebox.askyesno("确认关闭",
                                   f"检测到 {len(self.attached_devices)} 个已附加的设备。\n关闭程序时是否自动分离所有设备？"):
                self.cleanup_on_exit()
        else:
            self.running = False

        self.root.destroy()


def main():
    # 检查是否安装了usbipd
    try:
        env = PrivilegeManager.detect_environment()
        if env == 'windows':
            test_command = 'powershell.exe "usbipd --version"'
        else:
            test_command = 'usbipd --version'

        result = subprocess.run(test_command, shell=True, capture_output=True,
                                text=True, timeout=10)
        if result.returncode != 0:
            print("错误: 未检测到usbipd工具")
            if env == 'windows':
                print("请在Windows中安装usbipd:")
                print("winget install usbipd")
            else:
                print("请安装usbipd工具")
            sys.exit(1)
    except Exception as e:
        print(f"错误: 无法检查usbipd: {e}")
        sys.exit(1)

    # 创建并运行GUI
    root = tk.Tk()
    app = USBDeviceManager(root)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.cleanup_on_exit()


if __name__ == "__main__":
    main()
