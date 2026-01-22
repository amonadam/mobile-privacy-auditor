import subprocess
import time
import os

class DeviceManager:
    def __init__(self):
        self.adb_path = "F:\\Android\\SDK\\platform-tools\\adb.exe"
    
    def run_adb_command(self, command, shell=False):
        """执行 ADB 命令并返回结果"""
        cmd = [self.adb_path]
        if shell:
            cmd.extend(["shell"])
        cmd.extend(command.split())
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return -1, "", str(e)
    
    def get_device_id(self):
        """获取设备 ID"""
        code, stdout, stderr = self.run_adb_command("devices")
        if code == 0:
            lines = stdout.strip().split('\n')[1:]
            for line in lines:
                if 'device' in line:
                    return line.split('\t')[0]
        return None
    
    def get_root(self):
        """获取 Root 权限"""
        code, stdout, stderr = self.run_adb_command("root")
        return code == 0
    
    def remount(self):
        """重挂载系统分区为可写"""
        # 首先获取 Root 权限
        if not self.get_root():
            return False
        
        # 禁用 AVB 验证
        code, stdout, stderr = self.run_adb_command("shell avbctl disable-verification", shell=True)
        if code != 0:
            print("警告: 无法禁用 AVB 验证")
        
        # 禁用 Verity 校验
        code, stdout, stderr = self.run_adb_command("disable-verity")
        if code != 0:
            print("警告: 无法禁用 Verity 校验")
        
        # 重启设备
        self.reboot()
        time.sleep(30)  # 等待设备重启
        
        # 再次获取 Root 权限并尝试 remount
        if not self.get_root():
            return False
        
        code, stdout, stderr = self.run_adb_command("remount")
        return code == 0
    
    def install_apk(self, apk_path):
        """安装 APK 文件"""
        if not os.path.exists(apk_path):
            return False, "APK 文件不存在"
        
        code, stdout, stderr = self.run_adb_command(f"install -r {apk_path}")
        if code == 0:
            return True, "安装成功"
        else:
            return False, stderr
    
    def uninstall_app(self, package_name):
        """卸载应用"""
        code, stdout, stderr = self.run_adb_command(f"uninstall {package_name}")
        return code == 0
    
    def reboot(self):
        """重启设备"""
        code, stdout, stderr = self.run_adb_command("reboot")
        return code == 0
    
    def push_file(self, local_path, remote_path):
        """推送文件到设备"""
        if not os.path.exists(local_path):
            return False, "本地文件不存在"
        
        code, stdout, stderr = self.run_adb_command(f"push {local_path} {remote_path}")
        if code == 0:
            return True, "推送成功"
        else:
            return False, stderr
    
    def pull_file(self, remote_path, local_path):
        """从设备拉取文件"""
        code, stdout, stderr = self.run_adb_command(f"pull {remote_path} {local_path}")
        if code == 0:
            return True, "拉取成功"
        else:
            return False, stderr
    
    def get_app_package_name(self, apk_path):
        """获取 APK 的包名"""
        try:
            # 使用 aapt 命令获取包名
            # 注意：需要确保 aapt 在 PATH 中
            cmd = ["aapt", "dump", "badging", apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('package:'):
                        # 提取包名
                        parts = line.split(' ')
                        for part in parts:
                            if part.startswith('name='):
                                return part.split('=')[1].strip("'")
            return None
        except Exception:
            return None
    
    def is_app_installed(self, package_name):
        """检查应用是否已安装"""
        code, stdout, stderr = self.run_adb_command(f"shell pm list packages {package_name}")
        return package_name in stdout
    
    def clear_app_data(self, package_name):
        """清除应用数据"""
        code, stdout, stderr = self.run_adb_command(f"shell pm clear {package_name}")
        return code == 0
    
    def start_activity(self, package_name, activity_name):
        """启动应用的指定 Activity"""
        code, stdout, stderr = self.run_adb_command(f"shell am start -n {package_name}/{activity_name}")
        return code == 0
    
    def stop_app(self, package_name):
        """停止应用"""
        code, stdout, stderr = self.run_adb_command(f"shell am force-stop {package_name}")
        return code == 0
    
    def list_avds(self):
        """列出所有可用的 AVD"""
        try:
            # 查找 emulator 可执行文件
            emulator_path = "F:\\Android\\SDK\\emulator\\emulator.exe"
            if not os.path.exists(emulator_path):
                # 尝试在环境变量中查找
                import shutil
                emulator_path = shutil.which("emulator")
                if not emulator_path:
                    return []
            
            result = subprocess.run([emulator_path, "-list-avds"], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return [avd.strip() for avd in result.stdout.strip().split('\n') if avd.strip()]
            return []
        except Exception:
            return []
    
    def start_emulator(self, avd_name):
        """启动 Android 模拟器（带特权参数）"""
        try:
            # 查找 emulator 可执行文件
            emulator_path = "F:\\Android\\SDK\\emulator\\emulator.exe"
            if not os.path.exists(emulator_path):
                # 尝试在环境变量中查找
                import shutil
                emulator_path = shutil.which("emulator")
                if not emulator_path:
                    return False
            
            # 启动模拟器（后台运行）
            cmd = [emulator_path, "-avd", avd_name, "-writable-system", "-no-snapshot-load"]
            print(f"[INFO] 启动模拟器命令: {' '.join(cmd)}")
            
            # 后台启动模拟器
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return True
        except Exception as e:
            print(f"[ERROR] 启动模拟器失败: {e}")
            return False
    
    def wait_for_device(self, timeout=60):
        """等待设备就绪"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            device_id = self.get_device_id()
            if device_id:
                print(f"[INFO] 设备已就绪: {device_id}")
                return True
            print("[INFO] 等待设备就绪...")
            time.sleep(5)
        return False
    
    def ensure_root(self):
        """恢复 ADB Root 权限与系统挂载"""
        try:
            # 获取 Root 权限
            print("[INFO] 获取 ADB Root 权限...")
            code, stdout, stderr = self.run_adb_command("root")
            if code != 0:
                print(f"[ERROR] 获取 Root 权限失败: {stderr}")
                return False
            
            # 等待 adbd 重启
            time.sleep(3)
            
            # 重挂载系统分区
            print("[INFO] 重挂载系统分区...")
            code, stdout, stderr = self.run_adb_command("remount")
            if code != 0:
                print(f"[ERROR] 重挂载系统分区失败: {stderr}")
                return False
            
            # 设置全局代理
            print("[INFO] 设置全局代理...")
            code, stdout, stderr = self.run_adb_command("shell settings put global http_proxy 10.0.2.2:8080", shell=True)
            if code != 0:
                print(f"[ERROR] 设置代理失败: {stderr}")
                # 即使设置代理失败，也继续执行，因为这不是致命错误
            else:
                print("[INFO] 代理已设置为 10.0.2.2:8080")
            
            print("[INFO] Root 权限与系统挂载已恢复")
            return True
        except Exception as e:
            print(f"[ERROR] 恢复 Root 权限失败: {e}")
            return False
    
    def start_frida_server(self):
        """启动 Frida Server（设备端）"""
        try:
            # 检查 Frida Server 是否存在
            frida_server_path = "data/local/tmp/frida-server"
            code, stdout, stderr = self.run_adb_command(f"ls {frida_server_path}", shell=True)
            if code != 0:
                print(f"[ERROR] Frida Server 未找到: {stderr}")
                return False
            
            # 设置 SELinux 为宽容模式
            print("[INFO] 设置 SELinux 为宽容模式...")
            # 尝试不同的方式执行需要 root 权限的命令
            try:
                # 尝试方式 1: 使用 su 0 (指定用户 ID 为 0，即 root)
                cmd = [self.adb_path, "shell", "su", "0", "setenforce", "0"]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
                if result.returncode != 0:
                    # 尝试方式 2: 使用 su --command
                    cmd = [self.adb_path, "shell", "su", "--command", "setenforce 0"]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
                    if result.returncode != 0:
                        print(f"[WARN] 设置 SELinux 失败: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("[WARN] 设置 SELinux 超时，跳过此步骤")
            except Exception as e:
                print(f"[WARN] 设置 SELinux 失败: {e}")
            
            # 启动 Frida Server
            print("[INFO] 启动 Frida Server...")
            try:
                # 尝试方式 1: 直接在 /data/local/tmp 目录执行
                cmd = [self.adb_path, "shell", "./data/local/tmp/frida-server", "&"]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
                if result.returncode != 0:
                    # 尝试方式 2: 使用 su 0
                    cmd = [self.adb_path, "shell", "su", "0", "./data/local/tmp/frida-server", "&"]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
                    if result.returncode != 0:
                        print(f"[ERROR] 启动 Frida Server 失败: {result.stderr}")
                        return False
            except subprocess.TimeoutExpired:
                print("[INFO] Frida Server 启动命令已发送（超时，可能已在后台运行）")
            except Exception as e:
                print(f"[ERROR] 启动 Frida Server 失败: {e}")
                return False
            
            # 等待 Frida Server 启动
            time.sleep(3)
            print("[INFO] Frida Server 已启动")
            return True
        except Exception as e:
            print(f"[ERROR] 启动 Frida Server 失败: {e}")
            return False
    
    def setup_proxy(self, host_ip, port=8080):
        """设置设备代理"""
        try:
            # 直接使用 subprocess 执行命令
            cmd = [self.adb_path, "shell", "settings", "put", "global", "http_proxy", f"{host_ip}:{port}"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                print(f"[INFO] 代理已设置为 {host_ip}:{port}")
                return True
            else:
                print(f"[ERROR] 设置代理失败: {result.stderr}")
                return False
        except Exception as e:
            print(f"[ERROR] 设置代理失败: {e}")
            return False
    
    def reset_proxy(self):
        """重置设备代理"""
        try:
            # 直接使用 subprocess 执行命令
            cmd = [self.adb_path, "shell", "settings", "put", "global", "http_proxy", ":0"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                print("[INFO] 代理已重置")
                return True
            else:
                print(f"[ERROR] 重置代理失败: {result.stderr}")
                return False
        except Exception as e:
            print(f"[ERROR] 重置代理失败: {e}")
            return False
