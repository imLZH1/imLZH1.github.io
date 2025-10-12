import os
import sys
import json

# 根目录
doc_path = './_posts'
ln = []

def getdir(path):
    rel = []
    for fn in os.listdir(path):
        if os.path.isdir(os.path.join(path, fn)):
            rel.append(fn)
    return rel
# 递归遍历函数
def index_directory(path):
    json_dict = {}
    pds1 = getdir(path)
    for pds2 in pds1:
        js2 = []
        if pds2 == 'LEA':
            for i in os.listdir(f'{path}/{pds2}'):
                if i.endswith('.md'):
                    tmp = {'note_name':i[:-3],
                        'note_root': f'{path}/{pds2}/',
                        'note_src': f'{path}/{pds2}/{i}'}
                    js2.append(tmp)
        else:
            pds3 = getdir(path + '/' + pds2)
            for i in pds3:
                tmp = {'note_name':i,
                       'note_root': f'{path}/{pds2}/{i}/',
                       'note_src': f'{path}/{pds2}/{i}/{i}.md'}
                js2.append(tmp)
        json_dict.update({pds2:js2}) 
    return json_dict
    #for fn in os.listdir(path):
    #    # 判断是不是目录
    #    if os.path.isdir(os.path.join(path, fn)):
    #        tmp = os.listdir(doc_path + '/' + fn)
    #        print(fn,tmp)

    #    
    #    # 排除 assets 目录
    #    if 'assets' not in p:
    #        if os.path.isdir(p):
    #            # 如果是目录，递归调用
    #            #file_list.append(p)
    #            file_list.extend(index_directory(p))  # 递归调用子目录
    #        elif fn.endswith('.md'):
    #            # 如果是 .md 文件
    #            file_list.append(p)
    #return file_list

# 获取所有的 .md 文件和目录
ln = index_directory(doc_path)
open('nav.json','w',encoding='utf-8').write(json.dumps(ln, indent=4, ensure_ascii=False))

# 输出示例
'''
{
    "2025-writeups": [
        {
            "note_name": "2025-羊城杯pwn-writeups",
            "note_root": "./_posts/2025-writeups/",
            "note_src": "./_posts/2025-writeups/2025-羊城杯pwn-writeups.md"
        },
        {
            "note_name": "kernel_uaf",
            "note_root": "./_posts/2025-writeups/",
            "note_src": "./_posts/2025-writeups/kernel_uaf.md"
        }
    ],
    "LEA": [
        {
            "note_name": "about",
            "note_root": "./_posts/LEA/",
            "note_src": "./_posts/LEA/about.md"
        }
    ]
}
'''
