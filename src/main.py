#!/usr/bin/env python3
# 主程序入口与编排器

import os
import sys
import time
import argparse
import subprocess
import json
import threading
from datetime import datetime

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 定义日志上下文类
class Context:
    """
    日志上下文类
    """
    def __init__(self):
        self.log = self
    
    def info(self, msg):
        print(f"[INFO] {msg}")
    
    def warn(self, msg):
        print(f"[WARN] {msg}")
    
    def error(self, msg):
        print(f"[ERROR] {msg}")
    
    def alert(self, msg):
        print(f"[ALERT] {msg}")

# 全局上下文
ctx = Context()

from src.automation.device_manager import DeviceManager
from src.instrumentation.frida_injector import FridaInjector
from src.automation.appium_driver import AppiumDriver

class MobilePrivacyAuditor:
    def __init__(self):
        self.device_manager = DeviceManager()
        self.frida_injector = None
        self.appium_driver = None
        self.mitm_process = None
        self.output_dir = self._create_output_dir()
        self.canary_data = []
        self.avd_name = "Security_AVD"  # 默认 AVD 名称
    
    def prepare_environment(self):
        """
        [关键] 环境恢复与准备全流程
        """
        # 1. 检查设备在线状态
        device_id = self.device_manager.get_device_id()
        
        if not device_id:
            ctx.log.info(f"未检测到在线设备，尝试启动 AVD: {self.avd_name}")
            # 自动启动模拟器
            if self.device_manager.start_emulator(self.avd_name):
                if not self.device_manager.wait_for_device():
                    ctx.log.error("模拟器启动超时，请检查配置")
                    return False
            else:
                ctx.log.error("启动模拟器失败，请检查 AVD 配置")
                return False
        else:
            ctx.log.info(f"检测到在线设备: {device_id}")
        
        # 2. 恢复 Root 和 Remount
        if not self.device_manager.ensure_root():
            ctx.log.warn("无法获取 Root 权限，部分功能可能受限")
        
        # 3. 启动 Frida Server
        if not self.device_manager.start_frida_server():
            ctx.log.warn("Frida Server 启动失败，无法进行 Hook")
        
        # 4. 设置全局代理
        self.setup_proxy()
        return True
    
    def _create_output_dir(self):
        """
        创建输出目录
        :return: 输出目录路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("data", "reports", timestamp)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def load_config(self, config_file=None):
        """
        加载配置文件
        :param config_file: 配置文件路径
        :return: 配置字典
        """
        config = {
            "appium_caps": "config/appium_caps.json",
            "frida_hooks": "config/frida_hooks.js",
            "ssl_unpinning": "src/instrumentation/ssl_unpinning.js",
            "mitm_addon": "src/network/mitm_addon.py"
        }
        return config
    
    def start_mitmproxy(self):
        """
        启动 Mitmproxy
        """
        try:
            mitm_addon = os.path.join("src", "network", "mitm_addon.py")
            log_file = os.path.join(self.output_dir, "mitmproxy.log")
            config_file = os.path.join("config", "mitmproxy_config.yaml")
            
            # 使用配置文件启动 Mitmproxy
            cmd = ["mitmdump", "-s", mitm_addon, "--set", f"console_eventlog={log_file}", "--config", config_file]
            ctx.log.info(f"[*] Starting mitmproxy with command: {' '.join(cmd)}")
            
            # 启动 Mitmproxy 进程
            self.mitm_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(3)  # 等待 Mitmproxy 启动
            
            # 检查是否启动成功
            if self.mitm_process.poll() is not None:
                ctx.log.error("[!] Mitmproxy failed to start")
                return False
            
            ctx.log.info("[+] Mitmproxy started successfully")
            return True
        except Exception as e:
            ctx.log.error(f"[!] Error starting mitmproxy: {e}")
            return False
    
    def stop_mitmproxy(self):
        """
        停止 Mitmproxy
        """
        if self.mitm_process:
            try:
                self.mitm_process.terminate()
                self.mitm_process.wait(timeout=5)
                ctx.log.info("[+] Mitmproxy stopped successfully")
            except Exception as e:
                ctx.log.error(f"[!] Error stopping mitmproxy: {e}")
            finally:
                self.mitm_process = None
    
    def setup_proxy(self):
        """
        设置设备代理到 Mitmproxy
        """
        try:
            # 获取主机 IP（假设 Mitmproxy 运行在本地）
            import socket
            host_ip = socket.gethostbyname(socket.gethostname())
            
            # 使用 DeviceManager 中已经修复的 setup_proxy 方法
            if self.device_manager.setup_proxy(host_ip, 8080):
                ctx.log.info(f"[+] Proxy set to {host_ip}:8080")
                return True
            else:
                ctx.log.error("[!] Failed to set proxy")
                return False
        except Exception as e:
            ctx.log.error(f"[!] Error setting up proxy: {e}")
            return False
    
    def reset_proxy(self):
        """
        重置设备代理设置
        """
        try:
            # 使用 DeviceManager 中已经修复的 reset_proxy 方法
            if self.device_manager.reset_proxy():
                ctx.log.info("[+] Proxy reset")
                return True
            else:
                ctx.log.error("[!] Failed to reset proxy")
                return False
        except Exception as e:
            ctx.log.error(f"[!] Error resetting proxy: {e}")
            return False
    
    def run_audit(self, apk_path=None, package_name=None):
        """
        运行完整的隐私审计流程
        :param apk_path: APK 文件路径
        :param package_name: 应用包名
        """
        try:
            ctx.log.info("="*60)
            ctx.log.info("[*] Starting Mobile Privacy Audit")
            ctx.log.info("="*60)
            
            # 1. 环境准备与恢复
            ctx.log.info("[*] Step 1: Environment Preparation")
            if not self.prepare_environment():
                ctx.log.error("[!] Environment preparation failed")
                return False
            
            # 2. 设备准备
            ctx.log.info("[*] Step 2: Device Preparation")
            device_id = self.device_manager.get_device_id()
            if not device_id:
                ctx.log.error("[!] No device found. Please connect an Android device or start an emulator.")
                return False
            ctx.log.info(f"[+] Found device: {device_id}")
            
            # 3. 安装应用（如果提供了 APK 路径）
            if apk_path:
                ctx.log.info("[*] Step 3: Installing App")
                success, message = self.device_manager.install_apk(apk_path)
                if success:
                    ctx.log.info(f"[+] App installed successfully: {message}")
                    # 获取包名
                    if not package_name:
                        package_name = self.device_manager.get_app_package_name(apk_path)
                        if not package_name:
                            ctx.log.error("[!] Failed to get package name from APK")
                            return False
                else:
                    ctx.log.error(f"[!] Failed to install app: {message}")
                    return False
            
            if not package_name:
                ctx.log.error("[!] Package name is required")
                return False
            
            # 4. 启动 Mitmproxy
            ctx.log.info("[*] Step 4: Starting Mitmproxy")
            if not self.start_mitmproxy():
                return False
            
            # 5. 启动 Frida 注入
            ctx.log.info("[*] Step 5: Starting Frida Injection")
            self.frida_injector = FridaInjector()
            
            # 加载 SSL Pinning 绕过脚本
            additional_scripts = ["src/instrumentation/ssl_unpinning.js"]
            
            # 注入到目标应用
            if not self.frida_injector.spawn_and_inject(package_name, additional_scripts):
                ctx.log.error("[!] Failed to inject Frida script")
                self.stop_mitmproxy()
                self.reset_proxy()
                return False
            
            # 6. 启动 Appium 自动化（可选）
            ctx.log.info("[*] Step 6: Starting Appium Automation")
            try:
                self.appium_driver = AppiumDriver()
                self.appium_driver.start_session()
                # 执行随机 UI 遍历
                self.appium_driver.random_walk(duration=300)  # 5分钟
            except Exception as e:
                ctx.log.warn(f"[*] Appium automation failed (optional): {e}")
            
            # 7. 等待审计完成
            ctx.log.info("[*] Step 7: Running Audit...")
            ctx.log.info("[*] Press Ctrl+C to stop the audit")
            
            # 保持运行，直到用户中断
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            ctx.log.info("[*] Audit stopped by user")
        except Exception as e:
            ctx.log.error(f"[!] Error during audit: {e}")
        finally:
            # 清理资源
            ctx.log.info("[*] Step 8: Cleaning Up")
            
            # 停止 Appium
            if self.appium_driver:
                try:
                    self.appium_driver.stop_session()
                except Exception as e:
                    ctx.log.error(f"[!] Error stopping Appium: {e}")
            
            # 停止 Frida
            if self.frida_injector:
                try:
                    self.frida_injector.detach()
                except Exception as e:
                    ctx.log.error(f"[!] Error detaching Frida: {e}")
            
            # 重置代理
            self.reset_proxy()
            
            # 停止 Mitmproxy
            self.stop_mitmproxy()
            
            # 生成报告
            self.generate_report()
            
            ctx.log.info("="*60)
            ctx.log.info("[*] Audit completed")
            ctx.log.info(f"[*] Report generated at: {self.output_dir}")
            ctx.log.info("="*60)
    
    def generate_report(self):
        """
        生成审计报告
        """
        try:
            report_path = os.path.join(self.output_dir, "audit_report.json")
            
            # 收集数据
            report_data = {
                "timestamp": datetime.now().isoformat(),
                "output_dir": self.output_dir,
                "canary_data": self.frida_injector.get_canary_data() if self.frida_injector else [],
                "hook_results": self.frida_injector.get_hook_results() if self.frida_injector else []
            }
            
            # 写入报告文件
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            
            ctx.log.info(f"[+] Report generated: {report_path}")
        except Exception as e:
            ctx.log.error(f"[!] Error generating report: {e}")

def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description="Mobile Privacy Auditor")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--package", help="Package name of the app")
    parser.add_argument("--config", help="Path to config file")
    
    args = parser.parse_args()
    
    auditor = MobilePrivacyAuditor()
    auditor.run_audit(apk_path=args.apk, package_name=args.package)

if __name__ == "__main__":
    main()