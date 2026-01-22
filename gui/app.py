#!/usr/bin/env python3
# GUI 主应用

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import time

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.automation.device_manager import DeviceManager
from src.instrumentation.frida_injector import FridaInjector
from src.main import MobilePrivacyAuditor

class PrivacyAuditGUI:
    """隐私审计系统 GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("移动应用隐私审计系统")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # 设置主题
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # 初始化组件
        self.init_components()
        
        # 初始化队列用于线程间通信
        self.log_queue = queue.Queue()
        
        # 初始化设备管理器
        self.device_manager = DeviceManager()
        
        # 初始化审计器
        self.auditor = None
        
        # 初始化线程
        self.audit_thread = None
        self.log_thread = None
        self.env_prep_thread = None
        self.is_auditing = False
        self.is_preparing_env = False
        
        # 启动日志更新线程
        self.start_log_thread()
        
        # 自动准备环境（包括启动模拟器）
        self.prepare_environment()
    
    def init_components(self):
        """初始化 GUI 组件"""
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建顶部标签
        self.title_label = ttk.Label(
            self.main_frame, 
            text="移动应用隐私审计系统", 
            font=("SimHei", 16, "bold")
        )
        self.title_label.pack(pady=10)
        
        # 创建主内容框架（使用网格布局）
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧配置面板
        self.config_frame = ttk.LabelFrame(self.content_frame, text="配置", padding="10")
        self.config_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=5, pady=5, ipady=10)
        
        # 右侧日志面板
        self.log_frame = ttk.LabelFrame(self.content_frame, text="日志", padding="10")
        self.log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设备选择
        ttk.Label(self.config_frame, text="设备:", font=("SimHei", 10, "bold")).pack(anchor=tk.W, pady=5)
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(self.config_frame, textvariable=self.device_var, width=40)
        self.device_combo.pack(fill=tk.X, pady=5)
        self.refresh_device_btn = ttk.Button(
            self.config_frame, 
            text="刷新设备", 
            command=self.refresh_devices
        )
        self.refresh_device_btn.pack(fill=tk.X, pady=5)
        
        # 应用配置
        ttk.Label(self.config_frame, text="应用配置:", font=("SimHei", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        # APK 路径
        ttk.Label(self.config_frame, text="APK 路径:").pack(anchor=tk.W)
        self.apk_path_var = tk.StringVar()
        self.apk_path_entry = ttk.Entry(self.config_frame, textvariable=self.apk_path_var, width=40)
        self.apk_path_entry.pack(fill=tk.X, pady=2)
        self.browse_apk_btn = ttk.Button(
            self.config_frame, 
            text="浏览", 
            command=self.browse_apk
        )
        self.browse_apk_btn.pack(fill=tk.X, pady=2)
        
        # 包名
        ttk.Label(self.config_frame, text="包名:").pack(anchor=tk.W)
        self.package_var = tk.StringVar()
        self.package_entry = ttk.Entry(self.config_frame, textvariable=self.package_var, width=40)
        self.package_entry.pack(fill=tk.X, pady=2)
        
        # 审计控制
        ttk.Label(self.config_frame, text="审计控制:", font=("SimHei", 10, "bold")).pack(anchor=tk.W, pady=5)
        self.control_frame = ttk.Frame(self.config_frame)
        self.control_frame.pack(fill=tk.X, pady=5)
        
        self.start_btn = ttk.Button(
            self.control_frame, 
            text="开始审计", 
            command=self.start_audit, 
            style="Accent.TButton"
        )
        self.start_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        self.stop_btn = ttk.Button(
            self.control_frame, 
            text="停止审计", 
            command=self.stop_audit, 
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=2)
        
        # 报告管理
        ttk.Label(self.config_frame, text="报告管理:", font=("SimHei", 10, "bold")).pack(anchor=tk.W, pady=5)
        self.view_report_btn = ttk.Button(
            self.config_frame, 
            text="查看报告", 
            command=self.view_reports
        )
        self.view_report_btn.pack(fill=tk.X, pady=2)
        
        # 日志显示
        self.log_text = tk.Text(self.log_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 日志滚动条
        self.log_scrollbar = ttk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=self.log_scrollbar.set)
        
        # 设置日志文本样式
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("warn", foreground="orange")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("alert", foreground="purple", font=("SimHei", 10, "bold"))
    
    def prepare_environment(self):
        """准备环境（包括启动模拟器）"""
        if self.is_preparing_env:
            return
        
        self.is_preparing_env = True
        self.log("[INFO] 开始准备环境...", "info")
        
        # 启动环境准备线程
        self.env_prep_thread = threading.Thread(target=self._do_prepare_environment)
        self.env_prep_thread.daemon = True
        self.env_prep_thread.start()
    
    def _do_prepare_environment(self):
        """实际执行环境准备的方法"""
        try:
            # 导入 MobilePrivacyAuditor
            from src.main import MobilePrivacyAuditor
            
            # 创建审计器实例
            auditor = MobilePrivacyAuditor()
            
            # 准备环境
            success = auditor.prepare_environment()
            
            if success:
                self.log("[INFO] 环境准备完成", "info")
            else:
                self.log("[ERROR] 环境准备失败", "error")
            
            # 刷新设备列表
            self.root.after(0, self.refresh_devices)
        except Exception as e:
            self.log(f"[ERROR] 环境准备过程中发生错误: {e}", "error")
        finally:
            self.is_preparing_env = False
    
    def refresh_devices(self):
        """刷新设备列表"""
        try:
            # 获取设备列表
            code, stdout, stderr = self.device_manager.run_adb_command("devices")
            devices = []
            
            if code == 0:
                for line in stdout.strip().split('\n')[1:]:
                    if line.strip():
                        device_info = line.strip().split('\t')
                        if len(device_info) >= 2 and device_info[1] == "device":
                            devices.append(device_info[0])
            
            # 更新下拉框
            self.device_combo['values'] = devices
            if devices:
                self.device_combo.current(0)
                self.log("[INFO] 设备列表已更新", "info")
            else:
                self.log("[WARN] 未检测到设备，请连接 Android 设备或启动模拟器", "warn")
        except Exception as e:
            self.log(f"[ERROR] 刷新设备列表失败: {e}", "error")
    
    def browse_apk(self):
        """浏览 APK 文件"""
        file_path = filedialog.askopenfilename(
            title="选择 APK 文件",
            filetypes=[("APK 文件", "*.apk"), ("所有文件", "*.*")]
        )
        if file_path:
            self.apk_path_var.set(file_path)
            # 尝试从 APK 文件名中提取包名
            apk_name = os.path.basename(file_path)
            if apk_name.endswith('.apk'):
                package_name = apk_name[:-4].replace('_', '.')
                self.package_var.set(package_name)
    
    def start_audit(self):
        """开始审计"""
        # 验证配置
        apk_path = self.apk_path_var.get()
        package_name = self.package_var.get()
        
        if not apk_path and not package_name:
            messagebox.showerror("错误", "请提供 APK 路径或包名")
            return
        
        # 更新按钮状态
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # 清空日志
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # 启动审计线程
        self.is_auditing = True
        self.audit_thread = threading.Thread(target=self.run_audit, args=(apk_path, package_name))
        self.audit_thread.daemon = True
        self.audit_thread.start()
        
        self.log("[INFO] 审计开始...", "info")
    
    def run_audit(self, apk_path, package_name):
        """运行审计"""
        try:
            # 导入 MobilePrivacyAuditor
            from src.main import MobilePrivacyAuditor
            
            # 创建审计器实例
            auditor = MobilePrivacyAuditor()
            self.auditor = auditor
            
            # 运行审计
            success = auditor.run_audit(apk_path=apk_path, package_name=package_name)
            
            if success:
                self.log("[INFO] 审计完成", "info")
            else:
                self.log("[ERROR] 审计失败", "error")
        except Exception as e:
            self.log(f"[ERROR] 审计过程中发生错误: {e}", "error")
        finally:
            # 更新按钮状态
            self.is_auditing = False
            self.root.after(0, self.on_audit_finished)
    
    def stop_audit(self):
        """停止审计"""
        self.is_auditing = False
        self.log("[INFO] 正在停止审计...", "info")
        
        # 停止审计器
        if self.auditor:
            # 这里可以添加停止审计器的逻辑
            pass
    
    def on_audit_finished(self):
        """审计完成后的回调"""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("[INFO] 审计已停止", "info")
    
    def view_reports(self):
        """查看报告"""
        reports_dir = os.path.join("data", "reports")
        if not os.path.exists(reports_dir):
            messagebox.showinfo("提示", "暂无审计报告")
            return
        
        # 打开报告目录
        try:
            if sys.platform == "win32":
                os.startfile(reports_dir)
            else:
                os.system(f"open {reports_dir}")
        except Exception as e:
            self.log(f"[ERROR] 打开报告目录失败: {e}", "error")
    
    def log(self, message, level="info"):
        """记录日志"""
        self.log_queue.put((message, level))
    
    def start_log_thread(self):
        """启动日志更新线程"""
        self.log_thread = threading.Thread(target=self.update_log, daemon=True)
        self.log_thread.start()
    
    def update_log(self):
        """更新日志显示"""
        while True:
            try:
                message, level = self.log_queue.get(block=False)
                timestamp = time.strftime("%H:%M:%S")
                log_message = f"[{timestamp}] {message}\n"
                
                # 更新日志文本
                self.root.after(0, lambda msg=log_message, lvl=level: self._append_log(msg, lvl))
                
                # 标记任务完成
                self.log_queue.task_done()
            except queue.Empty:
                time.sleep(0.1)
            except Exception as e:
                print(f"Error in log thread: {e}")
                time.sleep(0.1)
    
    def _append_log(self, message, level):
        """追加日志到文本框"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message, level)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def on_closing(self):
        """关闭窗口时的处理"""
        if self.is_auditing:
            if messagebox.askokcancel("确认", "审计正在进行中，确定要关闭吗？"):
                self.stop_audit()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """主函数"""
    root = tk.Tk()
    app = PrivacyAuditGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
