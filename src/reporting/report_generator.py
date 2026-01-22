import os
import json
import sys
# 引入新的分析器
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.trace_analyzer import StackTraceAnalyzer

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.analyzer = StackTraceAnalyzer()

    def generate_html_report(self, metadata, leak_log="privacy_leaks.jsonl", injection_log="injection_logs.jsonl"):
        # 1. 读取原始日志
        leaks = self._read_jsonl(leak_log)
        injections = self._read_jsonl(injection_log)
        
        # 2. 执行关联分析 (Core Functionality)
        correlated_data = self.analyzer.correlate(injections, leaks)
        
        # 3. 生成 HTML
        self._write_html(metadata, correlated_data)

    def _read_jsonl(self, filepath):
        data = []
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    try: data.append(json.loads(line))
                    except: pass
        return data

    def _write_html(self, metadata, report_items):
        html = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <title>深度隐私审计报告: {metadata.get('package_name')}</title>
            <style>
                body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }}
                .container {{ max-width: 1100px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .summary {{ padding: 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }}
                .card {{ margin: 20px; border: 1px solid #e1e4e8; border-radius: 6px; }}
                .card-header {{ padding: 10px 15px; background: #f8f9fa; border-bottom: 1px solid #e1e4e8; font-weight: bold; display: flex; justify-content: space-between; }}
                .card-body {{ padding: 15px; }}
                .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; color: white; }}
                .bg-red {{ background-color: #e74c3c; }}
                .bg-orange {{ background-color: #f39c12; }}
                .bg-blue {{ background-color: #3498db; }}
                .attribution-box {{ background: #fff3cd; color: #856404; padding: 10px; margin-top: 10px; border-left: 4px solid #ffeeba; }}
                code {{ background: #f8f9fa; color: #e83e8c; padding: 2px 4px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin:0">移动应用隐私合规深度审计报告</h1>
                </div>
                <div class="summary">
                    <div>
                        <p><strong>目标应用:</strong> {metadata.get('package_name')}</p>
                        <p><strong>审计时间:</strong> {metadata.get('timestamp')}</p>
                    </div>
                    <div style="text-align: right">
                        <p><strong>高危风险:</strong> {len([x for x in report_items if x['risk_level']=='HIGH'])}</p>
                    </div>
                </div>
                
                <div style="padding: 0 20px;">
                    <h2>审计详情</h2>
        """

        if not report_items:
            html += "<p style='padding:20px; color:green'>✅ 未发现隐私泄露风险。</p>"

        for item in report_items:
            risk_class = "bg-red" if item['risk_level'] == "HIGH" else "bg-orange"
            
            html += f"""
            <div class="card">
                <div class="card-header">
                    <span>{item['leak_type']}</span>
                    <span class="badge {risk_class}">{item['risk_level']}</span>
                </div>
                <div class="card-body">
                    <p><strong>URL:</strong> <code>{item['network_info']['method']} {item['network_info']['url']}</code></p>
                    <p><strong>泄露数据:</strong> {item['evidence']}</p>
            """
            
            # 这里的归因分析是最大的亮点
            if item.get('source_analysis'):
                sa = item['source_analysis']
                html += f"""
                    <div class="attribution-box">
                        <strong>⚠️ 归因分析 (Root Cause):</strong><br>
                        该数据由 <strong>{sa['caller_owner']}</strong> ({sa['caller_type']}) 
                        调用 API <code>{sa['api_called']}</code> 获取。<br>
                    </div>
                """
            else:
                html += """<div style="color:#999; font-size:12px; margin-top:10px;">(未匹配到 API 调用源，可能是文件读取或静态硬编码数据)</div>"""

            html += "</div></div>"

        html += """</div></div></body></html>"""

        output_path = os.path.join(self.output_dir, "deep_audit_report.html")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[SUCCESS] 深度报告已生成: {output_path}")
