#!/usr/bin/env python3
"""
analyze_log.py - MC 服务器日志 AI 分析（CachyOS 适配版）

依赖:
    pip install --user openai pyyaml

用法:
    python3 analyze_log.py filtered_xxx.log
    python3 analyze_log.py filtered_xxx.log --no-cache
"""

import os
import sys
import json
import re
import hashlib
import argparse
import yaml
from datetime import datetime
from collections import defaultdict

# ═══════════════════════════════════════════════════════
#  配置区（CachyOS 路径风格）
# ═══════════════════════════════════════════════════════

# AI API 配置
AI_API_KEY = os.environ.get("AI_API_KEY", "sk-your-api-key-here")
AI_API_BASE = os.environ.get("AI_API_BASE", "https://api.deepseek.com/v1")
AI_MODEL = os.environ.get("AI_MODEL", "deepseek-chat")

# 目录配置（建议放在 MC 服务器目录旁边）
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) or "."
RAW_LOG_DIR = os.path.join(BASE_DIR, "raw_logs")
FILTERED_DIR = os.path.join(BASE_DIR, "filtered_logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
CACHE_DIR = os.path.join(BASE_DIR, "cache")

# ═══════════════════════════════════════════════════════


def ensure_dirs():
    for d in [RAW_LOG_DIR, FILTERED_DIR, REPORT_DIR, CACHE_DIR]:
        os.makedirs(d, exist_ok=True)


def parse_yaml_header(filepath):
    """解析日志文件的 YAML 文件头"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        # 提取 YAML front matter
        m = re.match(r'^---\s*\n(.*?)\n---', content, re.DOTALL)
        if m:
            return yaml.safe_load(m.group(1)) or {}
    except Exception as e:
        pass
    return {}


def compute_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_cache_path(log_hash):
    return os.path.join(CACHE_DIR, f"analysis_{log_hash}.json")


def load_cache(log_hash):
    path = get_cache_path(log_hash)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def save_cache(log_hash, data):
    path = get_cache_path(log_hash)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def parse_log_content(filepath):
    """解析过滤后的日志内容"""
    players = set()
    sessions = defaultdict(list)
    deaths = []
    advancements = []
    commands = []
    errors = []
    warnings = []
    
    current_player = None
    join_time = None
    
    # 读取文件（跳过 YAML 头）
    lines = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        in_header = True
        header_seen = 0
        for line in f:
            if in_header:
                if line.startswith('---'):
                    header_seen += 1
                    if header_seen >= 2:
                        in_header = False
                    continue
                continue
            lines.append(line.rstrip('\n\r'))
    
    for line in lines:
        if not line:
            continue
        
        time_match = re.match(r'\[(\d{2}:\d{2}:\d{2})\]', line)
        timestamp = time_match.group(1) if time_match else "??:??:??"
        
        # 玩家加入
        m = re.search(r'\]\s*:\s*(\w+)\s+joined the game', line)
        if m:
            players.add(m.group(1))
            join_time = timestamp
            current_player = m.group(1)
            continue
        
        # 玩家离开
        m = re.search(r'\]\s*:\s*(\w+)\s+left the game', line)
        if m:
            name = m.group(1)
            if current_player == name and join_time:
                sessions[name].append((join_time, timestamp))
            current_player = None
            join_time = None
            continue
        
        # 断线
        m = re.search(r'\]\s*:\s*(\w+)\s+lost connection:', line)
        if m:
            name = m.group(1)
            if current_player == name and join_time:
                sessions[name].append((join_time, timestamp))
            current_player = None
            join_time = None
            continue
        
        # 登录
        m = re.search(r'\]\s*:\s*(\w+)\[.*?\] logged in with entity id', line)
        if m:
            players.add(m.group(1))
            continue
        
        # 死亡
        for pattern in [
            (r'\]\s*:\s*(\w+)\s+was killed', '死亡'),
            (r'\]\s*:\s*(\w+)\s+was slain', '被击杀'),
            (r'\]\s*:\s*\[(\w+):\s*Killed\s+(\w+)\]', None),
        ]:
            m = re.search(pattern[0], line)
            if m:
                if pattern[1]:
                    deaths.append((timestamp, m.group(1), pattern[1]))
                else:
                    deaths.append((timestamp, m.group(2), f"被 {m.group(1)} 击杀"))
                break
        
        # 进度
        m = re.search(r'\]\s*:\s*(\w+)\s+has made the advancement\s+\[(.+?)\]', line)
        if m:
            advancements.append((timestamp, m.group(1), m.group(2)))
            continue
        
        # 命令
        m = re.search(r'\]\s*:\s*\[(\w+):\s*(/\S+)', line)
        if m:
            commands.append((timestamp, m.group(1), m.group(2)))
            continue
        m = re.search(r'\]\s*:\s*\[(\w+):\s*(Set the \w+)', line)
        if m:
            commands.append((timestamp, m.group(1), m.group(2)))
            continue
        
        # 错误/警告
        if '/ERROR]' in line:
            errors.append((timestamp, line[:200]))
        elif '/WARN]' in line:
            warnings.append((timestamp, line[:200]))
    
    return {
        'players': sorted(players),
        'sessions': dict(sessions),
        'deaths': deaths,
        'advancements': advancements,
        'commands': commands,
        'errors': errors,
        'warnings': warnings,
    }


def analyze_with_ai(log_data, file_header):
    """调用 AI API"""
    
    activity_lines = []
    for p in log_data['players']:
        sessions = log_data['sessions'].get(p, [])
        total_min = 0
        for s in sessions:
            try:
                h1, m1, s1 = s[0].split(':')
                h2, m2, s2 = s[1].split(':')
                t1 = int(h1)*60 + int(m1)
                t2 = int(h2)*60 + int(m2)
                if t2 >= t1:
                    total_min += t2 - t1
            except:
                pass
        activity_lines.append(f"- {p}: 在线 {len(sessions)} 次, 约 {total_min} 分钟")
    
    time_range = f"{file_header.get('time_range_start', '??')} ~ {file_header.get('time_range_end', '??')}"
    
    prompt = f"""你是一个 Minecraft 服务器运维助手，请根据以下日志摘要分析服务器运行状况。

## 基本信息
- 日志时间范围: {time_range}
- 在线玩家 ({len(log_data['players'])}人): {', '.join(log_data['players'])}

## 玩家活动
{chr(10).join(activity_lines)}

## 事件统计
- 死亡事件: {len(log_data['deaths'])} 次
- 进度解锁: {len(log_data['advancements'])} 个
- 执行命令: {len(log_data['commands'])} 条
- 错误信息: {len(log_data['errors'])} 条
- 警告信息: {len(log_data['warnings'])} 条

## 死亡详情
{chr(10).join([f'- [{d[0]}] {d[1]} {d[2]}' for d in log_data['deaths']]) if log_data['deaths'] else '（无）'}

## 进度解锁
{chr(10).join([f'- [{a[0]}] {a[1]}: {a[2]}' for a in log_data['advancements']]) if log_data['advancements'] else '（无）'}

## 命令记录
{chr(10).join([f'- [{c[0]}] {c[1]}: {c[2]}' for c in log_data['commands']]) if log_data['commands'] else '（无）'}

## 重要错误
{chr(10).join([f'- [{e[0]}] {e[1]}' for e in log_data['errors'][-10:]]) if log_data['errors'] else '（无）'}

---

请用 Markdown 格式输出分析报告，包含以下章节：
# MC 服务器运行报告
## 📊 概览
## 👥 玩家动态
## ⚠️ 异常事件分析
## ☠️ 死亡记录
## 🏆 进度解锁
## 📝 总结与建议

要求：简洁、中文、直观。如果没问题就说"服务器运行正常"。
"""
    
    try:
        from openai import OpenAI
    except ImportError:
        print("错误: 需要安装 openai 库")
        print("       pip install --user openai")
        sys.exit(1)
    
    if not AI_API_KEY or AI_API_KEY.startswith("sk-your"):
        print("错误: 请设置 AI API Key")
        print("       export AI_API_KEY='sk-xxx'")
        print("       或编辑脚本中的 AI_API_KEY 变量")
        sys.exit(1)
    
    client = OpenAI(api_key=AI_API_KEY, base_url=AI_API_BASE)
    
    print(f"[analyze_log] 🤖 调用 AI 模型 {AI_MODEL} ...")
    
    response = client.chat.completions.create(
        model=AI_MODEL,
        messages=[
            {"role": "system", "content": "你是专业的 MC 服务器运维分析助手。简洁准确地分析。"},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3,
        max_tokens=2000,
    )
    
    result = response.choices[0].message.content
    usage = {
        'prompt_tokens': response.usage.prompt_tokens if response.usage else 0,
        'completion_tokens': response.usage.completion_tokens if response.usage else 0,
        'total_tokens': response.usage.total_tokens if response.usage else 0,
        'model': AI_MODEL,
    }
    
    return result, usage


def build_markdown_report(log_data, ai_analysis, file_header, usage_info=None):
    now = datetime.now()
    log_hash = file_header.get('content_hash', 'unknown')
    source_file = file_header.get('source_file', 'unknown')
    
    cost_est = 0
    if usage_info:
        cost_est = (usage_info['prompt_tokens'] * 0.14 + 
                    usage_info['completion_tokens'] * 0.28) / 1_000_000
    
    header = f"""---
type: mc_server_analysis_report
generated_at: "{now.strftime('%Y-%m-%d %H:%M:%S')}"
source_log_hash: "{log_hash}"
source_file: "{source_file}"
ai_model: "{usage_info.get('model', 'N/A') if usage_info else 'N/A'}"
prompt_tokens: {usage_info.get('prompt_tokens', 0) if usage_info else 0}
completion_tokens: {usage_info.get('completion_tokens', 0) if usage_info else 0}
total_tokens: {usage_info.get('total_tokens', 0) if usage_info else 0}
estimated_cost_usd: {cost_est:.6f}
player_count: {len(log_data['players'])}
death_count: {len(log_data['deaths'])}
advancement_count: {len(log_data['advancements'])}
error_count: {len(log_data['errors'])}
---

"""
    
    body = f"""# 🎮 MC 服务器运行报告

**日志源**: `{source_file}`  
**日志哈希**: `{log_hash}`  
**分析时间**: {now.strftime('%Y-%m-%d %H:%M:%S')}  
**AI 模型**: {usage_info.get('model', 'N/A') if usage_info else 'N/A'}  
**Token 消耗**: {usage_info.get('total_tokens', 0) if usage_info else 0}  
**预估费用**: ${cost_est:.6f}

---

{ai_analysis}
"""
    
    return header + body


def main():
    parser = argparse.ArgumentParser(description='MC 日志 AI 分析（CachyOS 版）')
    parser.add_argument('logfile', nargs='?', help='过滤后的日志文件')
    parser.add_argument('--no-cache', action='store_true', help='忽略缓存')
    parser.add_argument('--no-ai', action='store_true', help='仅统计，不调 AI')
    parser.add_argument('--auto', action='store_true', help='自动模式：找最新过滤日志')
    
    args = parser.parse_args()
    
    ensure_dirs()
    
    # 自动找最新过滤日志
    if args.auto or not args.logfile:
        filtered_files = sorted(
            [f for f in os.listdir(FILTERED_DIR) if f.endswith('.log')],
            reverse=True
        )
        if not filtered_files:
            print("错误: filtered_logs/ 目录没有 .log 文件")
            sys.exit(1)
        args.logfile = os.path.join(FILTERED_DIR, filtered_files[0])
        print(f"[analyze_log] 自动选择最新过滤日志: {args.logfile}")
    
    if not os.path.exists(args.logfile):
        print(f"错误: 文件不存在: {args.logfile}")
        sys.exit(1)
    
    # 解析文件头
    print(f"[analyze_log] 解析文件头...")
    header = parse_yaml_header(args.logfile)
    log_hash = header.get('content_hash') or compute_file_hash(args.logfile)
    print(f"  日志哈希: {log_hash[:16]}...")
    
    # 检查缓存
    cached = None if args.no_cache else load_cache(log_hash)
    if cached and not args.no_ai:
        print(f"[analyze_log] ✅ 缓存命中！跳过 AI 调用")
        ai_analysis = cached['analysis']
        usage_info = cached.get('usage')
        log_data = parse_log_content(args.logfile)
    else:
        log_data = parse_log_content(args.logfile)
        
        if args.no_ai:
            ai_analysis = "（AI 分析已跳过）"
            usage_info = None
        else:
            ai_analysis, usage_info = analyze_with_ai(log_data, header)
            save_cache(log_hash, {
                'analysis': ai_analysis,
                'usage': usage_info,
                'analyzed_at': datetime.now().isoformat(),
                'log_hash': log_hash,
            })
    
    # 生成报告
    report = build_markdown_report(log_data, ai_analysis, header, usage_info)
    
    today = datetime.now().strftime("%Y%m%d")
    hash_prefix = log_hash[:12]
    report_filename = f"report_{today}_{hash_prefix}.md"
    report_path = os.path.join(REPORT_DIR, report_filename)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"[analyze_log] ✅ 报告: {report_path}")
    
    # 摘要
    print(f"\n{'='*50}")
    print(f"  玩家: {', '.join(log_data['players']) if log_data['players'] else '无'}")
    print(f"  死亡: {len(log_data['deaths'])} | 进度: {len(log_data['advancements'])} | 命令: {len(log_data['commands'])}")
    print(f"  错误: {len(log_data['errors'])} | 警告: {len(log_data['warnings'])}")
    if usage_info:
        print(f"  Token: {usage_info['total_tokens']} (输入{usage_info['prompt_tokens']}+输出{usage_info['completion_tokens']})")
        cost = usage_info['prompt_tokens']*0.14/1e6 + usage_info['completion_tokens']*0.28/1e6
        print(f"  费用: ${cost:.6f}")
    if cached:
        print(f"  📌 来自缓存，0 Token 消耗")
    print(f"{'='*50}")
    
    return report_path


if __name__ == '__main__':
    main()
