#!/usr/bin/env python3
"""
自动生成sitemap.xml的脚本
根据nav.json文件中的笔记结构生成搜索引擎友好的sitemap
"""

import json
import os
from datetime import datetime
import urllib.parse

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

def generate_sitemap(nav_data):
    """根据nav.json数据生成sitemap.xml内容"""
    
    # 获取当前日期
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # sitemap头部
    sitemap = ['<?xml version="1.0" encoding="UTF-8"?>']
    sitemap.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    
    # 添加根URL
    sitemap.append('  <url>')
    sitemap.append('    <loc>https://imLZH1.github.io/</loc>')
    sitemap.append(f'    <lastmod>{current_date}</lastmod>')
    sitemap.append('    <changefreq>weekly</changefreq>')
    sitemap.append('    <priority>1.0</priority>')
    sitemap.append('  </url>')
    
    # 遍历所有目录和笔记
    for category, notes in nav_data.items():
        for note in notes:
            # 构建URL路径
            note_url = f"https://imLZH1.github.io/#/{category}/{note['note_name']}"
            
            sitemap.append('  <url>')
            sitemap.append(f'    <loc>{note_url}</loc>')
            sitemap.append(f'    <lastmod>{current_date}</lastmod>')
            
            # 根据目录设置不同的更新频率
            if category == 'LEA':
                changefreq = 'weekly'
                priority = '0.9'
            else:
                changefreq = 'monthly'
                priority = '0.8'
                
            sitemap.append(f'    <changefreq>{changefreq}</changefreq>')
            sitemap.append(f'    <priority>{priority}</priority>')
            sitemap.append('  </url>')
    
    # sitemap尾部
    sitemap.append('</urlset>')
    
    return '\n'.join(sitemap)

def save_sitemap(sitemap_content):
    """保存sitemap.xml文件"""
    try:
        with open('sitemap.xml', 'w', encoding='utf-8') as f:
            f.write(sitemap_content)
        print("✅ sitemap.xml 文件已成功生成！")
        return True
    except Exception as e:
        print(f"❌ 保存sitemap.xml时出错: {e}")
        return False

def print_statistics(nav_data):
    """打印生成统计信息"""
    total_notes = 0
    print("\n📊 生成统计:")
    print("-" * 30)
    
    for category, notes in nav_data.items():
        note_count = len(notes)
        total_notes += note_count
        print(f"  {category}: {note_count} 个笔记")
    
    print("-" * 30)
    print(f"  总计: {total_notes} 个笔记URL")
    print(f"  目录数: {len(nav_data)} 个")
    print(f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """主函数"""
    print("🚀 开始生成 sitemap.xml...")
    print("=" * 50)
    
    # 加载nav.json数据
    nav_data = load_nav_data()
    if not nav_data:
        return
    
    print("✅ nav.json 文件加载成功")
    
    # 生成sitemap内容
    sitemap_content = generate_sitemap(nav_data)
    
    # 保存sitemap文件
    if save_sitemap(sitemap_content):
        # 打印统计信息
        print_statistics(nav_data)
        
        print("\n🎉 sitemap.xml 生成完成！")
        print("💡 提示: 您可以将此文件提交给搜索引擎以加速收录")
        
        # 显示一些有用的信息
        print("\n🔗 重要URL:")
        print(f"  主页: https://imLZH1.github.io/")
        print(f"  sitemap: https://imLZH1.github.io/sitemap.xml")
        print(f"  robots.txt: https://imLZH1.github.io/robots.txt")
        
    else:
        print("❌ sitemap.xml 生成失败")

if __name__ == "__main__":
    main()
