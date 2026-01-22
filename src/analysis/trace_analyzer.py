import re

class StackTraceAnalyzer:
    def __init__(self):
        # 常见第三方 SDK 的包名特征库
        # 实际生产环境中，这个库应该更大，或者从外部 JSON 加载
        self.sdk_signatures = {
            "com.google.android.gms.ads": "Google AdMob",
            "com.facebook.ads": "Facebook Audience Network",
            "com.unity3d.ads": "Unity Ads",
            "com.bytedance.sdk": "Pangle (穿山甲)",
            "com.kwad.sdk": "Kuaishou Ads (快手)",
            "cn.jpush.android": "JPush (极光推送)",
            "com.umeng": "Umeng (友盟)",
            "com.tencent.bugly": "Bugly",
            "com.aliyun": "Aliyun SDK",
            "io.flutter": "Flutter Engine",
            "com.airbnb.lottie": "Lottie Animation"
        }

    def analyze(self, stack_trace):
        """
        分析堆栈，返回 (调用者类型, 详细归因)
        类型: 'SDK' 或 'App'
        """
        if not stack_trace:
            return "Unknown", "No Stack Trace"

        lines = stack_trace.strip().split('\n')
        
        # 1. 自底向上遍历堆栈，寻找第一个非系统类
        # 我们关注是谁"发起"了调用，而不是系统底层框架
        relevant_frame = None
        for line in lines:
            # 跳过 Android 系统、Java 基础类、Frida 注入代码
            if any(x in line for x in [
                "android.", "java.", "com.android.internal", 
                "dalvik.", "io.frida", "de.robv.android.xposed"
            ]):
                continue
            relevant_frame = line.strip()
            break
        
        if not relevant_frame:
            return "System", "Android Framework"

        # 2. 匹配 SDK 指纹
        for package_prefix, sdk_name in self.sdk_signatures.items():
            if package_prefix in relevant_frame:
                return "Third-Party SDK", sdk_name

        # 3. 如果不是已知 SDK，默认为 App 自身代码
        # 提取包名或类名作为归因
        match = re.search(r'at\s+([a-zA-Z0-9_$.]+)', relevant_frame)
        caller = match.group(1) if match else relevant_frame
        return "App Business Logic", caller

    def correlate(self, injection_logs, leak_logs):
        """
        关联分析：将 Frida 的注入记录与 Mitmproxy 的泄露记录匹配
        """
        correlated_report = []
        
        # 将注入日志转为字典，Key 为金丝雀值
        injections = {entry['canary']: entry for entry in injection_logs}

        for leak in leak_logs:
            # 检查泄露数据中是否包含已知的金丝雀
            leak_data_str = str(leak.get('data', ''))
            matched_canary = None
            
            for canary_val in injections.keys():
                if canary_val in leak_data_str:
                    matched_canary = canary_val
                    break
            
            report_item = {
                "risk_level": "HIGH" if matched_canary else "MEDIUM",
                "leak_type": leak['type'],
                "network_info": {
                    "url": leak['url'],
                    "method": leak['method']
                },
                "evidence": leak['data']
            }

            if matched_canary:
                # 关联成功！这是确凿的证据
                injection_info = injections[matched_canary]
                attribution_type, owner = self.analyze(injection_info.get('stack_trace'))
                
                report_item['source_analysis'] = {
                    "api_called": injection_info['api'],
                    "caller_type": attribution_type,
                    "caller_owner": owner, # 具体是哪个 SDK
                    "call_time": injection_info['timestamp']
                }
                report_item['description'] = f"检测到 {owner} 调用了 {injection_info['api']} 并通过网络明文传输。"
            else:
                report_item['description'] = "检测到疑似敏感数据传输 (正则匹配)。"
                report_item['source_analysis'] = None

            correlated_report.append(report_item)
            
        return correlated_report
