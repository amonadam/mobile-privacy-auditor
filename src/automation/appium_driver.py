#!/usr/bin/env python3
# UI 自动化控制逻辑

import os
import time
import random
import json
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class AppiumDriver:
    def __init__(self):
        self.driver = None
        self.appium_caps = self.load_appium_caps()
        self.session_start_time = None
        # 定义需要自动点击的按钮文本关键词
        self.auto_accept_keywords = [
            "允许", "Allow", "同意", "Agree", "确定", "OK", 
            "仅使用期间允许", "While using the app", 
            "跳过", "Skip", "我知道了", "I know"
        ]
        # 定义需要拒绝的关键词 (如升级提示)
        self.auto_deny_keywords = [
            "取消", "Cancel", "以后再说", "Later", "不更新"
        ]
    
    def load_appium_caps(self):
        """
        加载 Appium 配置
        :return: Appium 配置字典
        """
        caps_file = os.path.join("config", "appium_caps.json")
        try:
            with open(caps_file, "r", encoding="utf-8") as f:
                caps = json.load(f)
            return caps
        except Exception as e:
            print(f"Error loading appium_caps.json: {e}")
            # 默认配置
            return {
                "platformName": "Android",
                "automationName": "UiAutomator2",
                "deviceName": "Android Device",
                "noReset": True,
                "fullReset": False,
                "newCommandTimeout": 600
            }
    
    def start_session(self):
        """
        启动 Appium 会话
        """
        try:
            print("[*] Starting Appium session...")
            # 添加自动授予权限的配置
            self.appium_caps["autoGrantPermissions"] = True
            self.driver = webdriver.Remote("http://localhost:4723/wd/hub", self.appium_caps)
            self.session_start_time = time.time()
            print("[+] Appium session started successfully")
            return True
        except Exception as e:
            print(f"[!] Error starting Appium session: {e}")
            return False
    
    def handle_system_dialogs(self):
        """
        [关键改进] 扫描并处理系统弹窗、权限请求和常见干扰
        """
        try:
            # 查找所有按钮类型的元素
            buttons = self.driver.find_elements(AppiumBy.CLASS_NAME, "android.widget.Button")
            for btn in buttons:
                text = btn.text
                if any(k in text for k in self.auto_accept_keywords):
                    print(f"[*] 自动点击弹窗按钮: {text}")
                    btn.click()
                    return True # 处理了一次，返回
                elif any(k in text for k in self.auto_deny_keywords):
                    print(f"[*] 自动关闭干扰弹窗: {text}")
                    btn.click()
                    return True
        except:
            pass
        return False
    
    def stop_session(self):
        """
        停止 Appium 会话
        """
        if self.driver:
            try:
                self.driver.quit()
                print("[+] Appium session stopped successfully")
            except Exception as e:
                print(f"[!] Error stopping Appium session: {e}")
    
    def random_walk(self, duration=300):
        """
        随机 UI 遍历
        :param duration: 遍历持续时间（秒）
        """
        if not self.driver:
            print("[!] Appium driver not initialized")
            return
        
        end_time = time.time() + duration
        actions_count = 0
        
        print(f"[*] Starting random UI walk for {duration} seconds")
        
        while time.time() < end_time:
            try:
                # 1. 优先处理弹窗
                if self.handle_system_dialogs():
                    time.sleep(1)
                    continue
                    
                # 2. 获取当前页面的所有可点击元素
                clickable_elements = self._get_clickable_elements()
                
                if clickable_elements:
                    # 随机选择一个元素点击
                    element = random.choice(clickable_elements)
                    # 简单的坐标过滤，防止点击到顶部状态栏
                    loc = element.location
                    if loc['y'] > 100: 
                        self._safe_click(element)
                        actions_count += 1
                        
                        # 随机等待时间
                        wait_time = random.uniform(0.5, 2.0)
                        time.sleep(wait_time)
                else:
                    # 如果没有可点击元素，尝试滑动
                    self.swipe("up")
                    time.sleep(1.0)
                    
                # 每 10 次操作后打印状态
                if actions_count % 10 == 0:
                    elapsed = time.time() - self.session_start_time
                    remaining = max(0, duration - (time.time() - (self.session_start_time + duration - end_time)))
                    print(f"[*] Actions performed: {actions_count}, Elapsed: {elapsed:.1f}s, Remaining: {remaining:.1f}s")
                    
            except Exception as e:
                print(f"[!] Error during random walk: {e}")
                # 遇到错误时尝试返回
                self._safe_back()
                time.sleep(1.0)
        
        print(f"[+] Random UI walk completed. Total actions: {actions_count}")
    
    def _get_clickable_elements(self):
        """
        获取当前页面的所有可点击元素
        :return: 可点击元素列表
        """
        clickable_elements = []
        try:
            # 查找所有可点击的元素
            elements = self.driver.find_elements(
                AppiumBy.XPATH,
                "//*[@clickable='true' or @enabled='true']"
            )
            
            # 过滤掉不可见或太小的元素
            for element in elements:
                if element.is_displayed():
                    try:
                        size = element.size
                        if size.get('width', 0) > 10 and size.get('height', 0) > 10:
                            clickable_elements.append(element)
                    except Exception:
                        pass
        except Exception as e:
            print(f"[!] Error getting clickable elements: {e}")
        
        return clickable_elements
    
    def _safe_click(self, element):
        """
        安全点击元素
        :param element: 要点击的元素
        """
        try:
            # 滚动到元素可见
            self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
            time.sleep(0.5)
            # 点击元素
            element.click()
            print("[+] Clicked element")
        except Exception as e:
            print(f"[!] Error clicking element: {e}")
    
    def _safe_back(self):
        """
        安全返回
        """
        try:
            self.driver.back()
            print("[+] Pressing back button")
        except Exception as e:
            print(f"[!] Error pressing back button: {e}")
    
    def fill_form(self, form_data=None):
        """
        填充表单
        :param form_data: 表单数据字典
        """
        if not self.driver:
            print("[!] Appium driver not initialized")
            return
        
        if not form_data:
            # 默认表单数据
            form_data = {
                "email": "test@example.com",
                "password": "test123456",
                "name": "Test User",
                "phone": "13800138000"
            }
        
        print("[*] Filling form data")
        
        for field, value in form_data.items():
            try:
                # 尝试通过各种方式查找输入框
                xpath_patterns = [
                    f"//*[@text='{field}']/following-sibling::*",
                    f"//*[@hint='{field}']",
                    f"//*[@content-desc='{field}']",
                    f"//*[@id='{field}']",
                    f"//*[contains(@text, '{field}')]/following-sibling::*"
                ]
                
                element = None
                for pattern in xpath_patterns:
                    try:
                        elements = self.driver.find_elements(AppiumBy.XPATH, pattern)
                        if elements:
                            for elem in elements:
                                if elem.is_displayed() and elem.is_enabled():
                                    element = elem
                                    break
                            if element:
                                break
                    except Exception:
                        pass
                
                if element:
                    element.clear()
                    element.send_keys(value)
                    print(f"[+] Filled {field}: {value}")
                    time.sleep(0.5)
            except Exception as e:
                print(f"[!] Error filling {field}: {e}")
    
    def swipe(self, direction="up", duration=500):
        """
        执行滑动操作
        :param direction: 滑动方向（up, down, left, right）
        :param duration: 滑动持续时间（毫秒）
        """
        if not self.driver:
            print("[!] Appium driver not initialized")
            return
        
        try:
            size = self.driver.get_window_size()
            width = size.get('width', 0)
            height = size.get('height', 0)
            
            if direction == "up":
                start_x, start_y = width // 2, height * 3 // 4
                end_x, end_y = width // 2, height // 4
            elif direction == "down":
                start_x, start_y = width // 2, height // 4
                end_x, end_y = width // 2, height * 3 // 4
            elif direction == "left":
                start_x, start_y = width * 3 // 4, height // 2
                end_x, end_y = width // 4, height // 2
            elif direction == "right":
                start_x, start_y = width // 4, height // 2
                end_x, end_y = width * 3 // 4, height // 2
            else:
                print(f"[!] Invalid direction: {direction}")
                return
            
            self.driver.swipe(start_x, start_y, end_x, end_y, duration)
            print(f"[+] Swiped {direction}")
        except Exception as e:
            print(f"[!] Error swiping: {e}")
    
    def get_current_activity(self):
        """
        获取当前活动
        :return: 当前活动名称
        """
        if not self.driver:
            return None
        
        try:
            activity = self.driver.current_activity
            return activity
        except Exception as e:
            print(f"[!] Error getting current activity: {e}")
            return None
    
    def get_page_source(self):
        """
        获取当前页面源代码
        :return: 页面源代码
        """
        if not self.driver:
            return None
        
        try:
            source = self.driver.page_source
            return source
        except Exception as e:
            print(f"[!] Error getting page source: {e}")
            return None
