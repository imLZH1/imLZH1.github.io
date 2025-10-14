#!/usr/bin/env python3
"""
自动生成RSS订阅文件feed.xml的脚本
根据nav.json文件中的笔记结构生成符合RSS 2.0标准的订阅文件
"""

import json
import os
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom

def load_nav_data():
    """加载nav.json文件"""
    try:
        with open('nav.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print("错误: 找不到nav.json文件")
        return None
    except json.JSONDecodeError:
        print("错误: nav.json文件格式不正确")
        return None

def generate_feed(nav_data):
    """根据nav.json数据生成RSS feed"""
    
    # 获取当前时间
    current_time = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
    
    # 创建RSS根元素
    rss = ET.Element('rss', version='2.0')
    channel = ET.SubElement(rss, 'channel')
    
    # 频道基本信息
    ET.SubElement(channel, 'title').text = "imLZH1's Blog - CTF Writeups and Pwn Tips"
    ET.SubElement(channel, 'link').text = "https://imLZH1.github.io"
    ET.SubElement(channel, 'description').text = "分享CTF题解、Pwn技巧、二进制安全研究"
    ET.SubElement(channel, 'language').text = "zh-cn"
    ET.SubElement(channel, 'lastBuildDate').text = current_time
    ET.SubElement(channel, 'generator').text = "Python RSS Generator"
    
    # 添加网站图标
    ET.SubElement(channel, 'image').text = "https://imLZH1.github.io/favicon.ico"
    
    # 遍历所有目录和笔记，生成文章项
    for category, notes in nav_data.items():
        for note in notes:
            # 构建文章URL
            note_url = f"https://imLZH1.github.io/#/{category}/{note['note_name']}"
            
            # 创建文章项
            item = ET.SubElement(channel, 'item')
            ET.SubElement(item, 'title').text = note['note_name']
            ET.SubElement(item, 'link').text = note_url
            ET.SubElement(item, 'guid').text = note_url
            
            # 生成文章描述
            if category == 'LEA':
                description = f"个人博客页面 - {note['note_name']}"
            elif category == 'pwn-tips':
                description = f"Pwn技术技巧 - {note['note_name']}"
            else:
                description = f"CTF Writeups - {note['note_name']}"
            
            ET.SubElement(item, 'description').text = description
            
            # 使用当前时间作为发布时间（实际应该使用文件修改时间）
            ET.SubElement(item, 'pubDate').text = current_time
            
            # 添加分类标签
            ET.SubElement(item, 'category').text = category
    
    # 转换为格式化的XML
    rough_string = ET.tostring(rss, encoding='utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')

def save_feed(feed_content):
    """保存feed.xml文件"""
    try:
        with open('feed.xml', 'w', encoding='utf-8') as f:
            f.write(feed_content)
        print("✅ feed.xml 文件已成功生成！")
        return True
    except Exception as e:
        print(f"❌ 保存feed.xml时出错: {e}")
        return False

def print_statistics(nav_data):
    """打印生成统计信息"""
    total_notes = 0
    print("\n📊 RSS生成统计:")
    print("-" * 30)
    
    for category, notes in nav_data.items():
        note_count = len(notes)
        total_notes += note_count
        print(f"  {category}: {note_count} 篇文章")
    
    print("-" * 30)
    print(f"  总计: {total_notes} 篇文章")
    print(f"  目录数: {len(nav_data)} 个")
    print(f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """主函数"""
    print("🚀 开始生成 RSS feed.xml...")
    print("=" * 50)
    
    # 加载nav.json数据
    nav_data = load_nav_data()
    if not nav_data:
        return
    
    print("✅ nav.json 文件加载成功")
    
    # 生成RSS内容
    feed_content = generate_feed(nav_data)
    
    # 保存feed.xml文件
    if save_feed(feed_content):
        # 打印统计信息
        print_statistics(nav_data)
        
        print("\n🎉 RSS feed.xml 生成完成！")
        print("💡 提示: 读者现在可以通过RSS阅读器订阅您的博客")
        
        # 显示使用说明
        print("\n🔗 RSS订阅信息:")
        print(f"  RSS地址: https://imLZH1.github.io/feed.xml")
        print(f"  博客地址: https://imLZH1.github.io")
        
        print("\n📱 支持的RSS阅读器:")
        print("  • Feedly (推荐)")
        print("  • Inoreader")
        print("  • Reeder (macOS/iOS)")
        print("  • Thunderbird")
        print("  • 其他支持RSS 2.0的阅读器")
        
        print("\n🔧 技术信息:")
        print("  • 格式: RSS 2.0")
        print("  • 编码: UTF-8")
        print("  • 语言: 中文")
        print("  • 包含所有文章和分类")
        
    else:
        print("❌ feed.xml 生成失败")

if __name__ == "__main__":
    main()
