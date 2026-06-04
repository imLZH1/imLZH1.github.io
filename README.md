# Static Markdown Blog

Static Markdown Blog 是一个纯静态个人博客模板。它把文章保存在 `_posts` 目录中，通过浏览器端 JavaScript 加载 `nav.json` 和 Markdown 文件完成渲染；Python 脚本只负责生成导航、生成时间线，以及按需加密文章正文。

这个项目适合这些场景：

- 想把博客直接部署到 GitHub Pages、Cloudflare Pages、Nginx 静态目录。
- 想用 Markdown 写文章，不想维护复杂的构建链。
- 希望文章资源和正文放在同一个目录里，方便迁移和备份。
- 需要少量私密文章，用本地 key 加密后再发布密文。

## 核心能力

- 纯静态部署，不依赖 Node 构建流程。
- Markdown 渲染，支持代码高亮、图片资源路径修正、右侧目录。
- 左侧文章分类导航、搜索、阅读进度、暗色模式、移动端侧栏。
- 自动扫描 `_posts` 生成 `nav.json`。
- 自动生成 `_posts/LEA/Timeline.md` 时间线。
- Timeline 只收录带 YAML frontmatter 且有有效 `date` 的文章。
- 支持 AES-256-GCM 加密文章正文和本地资源文件。
- 前端通过文章 key 解锁 `encrypt: ok` 的加密文章。

## 工作方式

项目没有传统后端，也没有打包步骤。运行时浏览器先加载 `index.html`、`app.js` 和 `styles.css`，然后通过 `fetch` 获取 `nav.json` 和对应 Markdown 文件。

文章组织在 `_posts` 中：

- `_posts/LEA/index.md` 是 Overview 首页。
- `_posts/LEA/Timeline.md` 由 `main_update.py` 自动生成。
- `_posts/<category>/...` 是普通文章分类。

新增、删除或移动文章后，运行 `python main_update.py` 重新生成导航数据即可。

## 项目结构

```text
.
├── index.html              # 页面入口和站点基础 SEO 信息
├── app.js                  # 前端路由、Markdown 渲染、搜索、解密、交互逻辑
├── styles.css              # 全站样式
├── main_update.py          # 生成 nav.json 和 Timeline.md
├── enc_art.py              # 加密/解密文章正文
├── init_me.py              # 初始化站点身份或重置模板
├── nav.json                # 自动生成的导航数据
├── copywriting.json        # 左侧头像下方随机文案
├── _posts/                 # 页面和文章
│   ├── LEA/                # Overview、Timeline 等站点页面
│   └── <category>/         # 普通文章分类
├── assets/                 # 公共资源
├── imgs/                   # 头像、背景图等资源
└── prism*.js / marked*.js / purify*.js
```

## 关键文件

- `index.html`：站点标题、作者、SEO、侧栏基础结构。
- `app.js`：路由、加载文章、渲染 Markdown、目录、搜索、加密文章解锁。
- `styles.css`：整体 UI 样式。
- `main_update.py`：扫描 `_posts`，生成 `nav.json` 和 Timeline。
- `enc_art.py`：把 `encrypt: true` 文章加密成 `encrypt: ok`，并把本地资源打进密文包。
- `init_me.py`：修改站点 ID / 标题，或用 `--init` 重置为干净模板。
- `*_art_key.json`：本地加密 key 文件，文件名前缀是 32 位随机字符，已被 `.gitignore` 忽略，不能提交。

## 加密模型

加密文章采用“本地 key 解锁”模式。`enc_art.py` 会为每篇文章生成独立随机 AES key 和 IV，把正文和对应本地资源文件打包后加密，只把密文写入文章，把 key 写入本地 `*_art_key.json`。key 文件名会自动生成，例如 `AbC123..._art_key.json`，前缀是 32 位随机字符。

公开仓库中只会出现：

- YAML frontmatter
- `encrypt: ok`
- 加密 JSON，包括 `id`、`iv`、`tag`、`data`

不会提交：

- 明文正文
- 已打包的本地图片/附件明文
- AES key
- `*_art_key.json`

随机文件名可以避免固定路径 `/art_key.json` 被直接猜到，但它不是“可以公开部署 key 文件”的理由。手动上传网站目录时也要排除 `*_art_key.json`。如果 `*_art_key.json` 丢失，对应加密文章无法恢复，务必单独备份。

本地资源处理规则：

- Markdown/HTML 中引用到的相对路径资源会被打包加密。
- 如果文章目录下只有这一篇 `.md`，并且存在 `assets/` 目录，`assets/` 里的文件也会一起打包。
- `http://`、`https://`、`data:` 等远程或内联资源不会处理。
- 加密成功后，被打包的本地资源文件会从公开目录删除。
- 解密文章时，脚本会恢复正文和被打包的资源文件。

## 使用方法

### 初始化站点信息

只修改站点 ID 和标题：

```bash
python init_me.py "your_id" "your blog title"
```

例如：

```bash
python init_me.py "imLZH1" "imLZH1's Blog"
```

默认只更新：

- `index.html` 中的标题、作者、Open Graph、侧栏名字。
- `app.js` 中的浏览器标题后缀。

如果要把仓库重置成干净模板，并且已经备份旧文章和 `*_art_key.json`：

```bash
python init_me.py "your_id" "your blog title" --init
```

`--init` 会额外执行：

- 删除 `_posts` 下除了 `_posts/LEA/index.md` 以外的内容。
- 写入一个干净的默认 `_posts/LEA/index.md` 首页模板。
- 删除本地 `*_art_key.json`。
- 重新生成 `nav.json` 和 `_posts/LEA/Timeline.md`。

初始化后通常需要手动改：

- `_posts/LEA/index.md`
- `imgs/tx.png`
- `imgs/bg_img/`
- `copywriting.json`

### 写文章

文章放在 `_posts` 下，一级目录会成为分类。

推荐结构：

```text
_posts/<category>/<post-slug>/<post-slug>.md
_posts/<category>/<post-slug>/assets/image.png
```

也可以直接放在分类目录：

```text
_posts/<category>/<post-slug>.md
```

建议写 YAML frontmatter：

```markdown
---
title: 文章标题
date: 2026-05-09T00:00:00+08:00
lastmod: 2026-05-09T00:00:00+08:00
---
```

规则：

- 没有 `title` 时，导航使用文件名或目录名。
- 文件名以 `YYYY-MM-DD` 开头时，可以推断日期。
- Timeline 只收录有 YAML frontmatter 且能解析出 `date` 的文章。
- 没有 YAML 的文章仍出现在左侧 Notes，但不会进入 Timeline。

### 生成导航

新增、删除或移动文章后运行：

```bash
python main_update.py
```

脚本会更新：

- `nav.json`
- `_posts/LEA/Timeline.md`

### 本地预览

页面通过 `fetch` 加载 JSON 和 Markdown，建议使用本地 HTTP 服务：

```bash
python -m http.server 8000
```

打开：

```text
http://127.0.0.1:8000/#/overview
```

### 加密文章

先确保安装依赖：

```bash
python -m pip install cryptography
```

需要加密的文章写：

```markdown
---
title: 私密文章
date: 2026-06-04T12:00:00+08:00
encrypt: true
---

这里是需要加密的正文。
```

执行加密：

```bash
python enc_art.py enc
```

脚本会跳过没有 YAML、没有 `encrypt: true`、或已经 `encrypt: ok` 的文章。加密后文章会变成：

```markdown
---
title: 私密文章
date: 2026-06-04T12:00:00+08:00
encrypt: ok
---

{
  "v": 1,
  "id": "art_xxxxxxxxxxxxxxxxxxxx",
  "alg": "AES-256-GCM",
  "iv": "...",
  "tag": "...",
  "data": "..."
}
```

解密文章：

```bash
python enc_art.py dec
```

脚本会先列出可解密文章：

```text
Encrypted articles in AbC123xxxxxxxxxxxxxxxxxxxxxxxxxx_art_key.json:
  art_xxx | 文章标题 | _posts/category/post.md | 2026-06-04T12:00:00+08:00
  all | decrypt every listed article
Article id or all:
```

输入 `all` 解密全部，或输入指定 `art_xxx` 解密单篇。解密后文章恢复成 `encrypt: true`，并删除 `*_art_key.json` 里的对应 key。如果全部 key 都被删除，脚本会移除空的 key 文件。

修改加密文章后重新执行：

```bash
python enc_art.py enc
python main_update.py
```

前端访问 `encrypt: ok` 文章时会显示 key 输入框。输入 `*_art_key.json` 中对应文章的 `key` 后，浏览器用 WebCrypto 解密并按普通 Markdown 渲染。

### 部署

部署前建议：

```bash
python enc_art.py enc
python main_update.py
```

提交需要公开的文件：

- 新增或修改的文章
- `nav.json`
- `_posts/LEA/Timeline.md`
- 前端代码和样式

不要提交：

- `*_art_key.json`
- `__pycache__/`
- 本地临时文件

GitHub Pages 部署时保留 `.nojekyll`，这样 `_posts` 目录会按普通静态文件公开，不走 Jekyll 构建。

## 常用命令

```bash
# 修改站点身份和标题
python init_me.py "your_id" "your blog title"

# 重置成干净模板
python init_me.py "your_id" "your blog title" --init

# 生成导航和 Timeline
python main_update.py

# 加密 encrypt: true 的文章
python enc_art.py enc

# 解密文章
python enc_art.py dec

# 本地预览
python -m http.server 8000
```

## 无脑使用方法

- 第一次初始化基本信息

```py
py .\init_me.py 'name' 'title' --init
```

`_posts/LEA/index.md` 你的默认页面，可以完全自定义

`_posts/LEA/Timeline.md` 展示时间的 需要文章里面有 `YAML front-matter` 信息 `date`

可以在 `_posts/` 下面新建目录进行分类

当添加新文章后
你只需要执行

```bash
python main_update.py
```

如果需要加密文章，请详细阅读 `加密文章` 板块



## 技术栈

- Vanilla JavaScript
- Marked.js
- DOMPurify
- Prism.js
- Python 3
- cryptography

## License

代码按 [MIT License](LICENSE) 开源。博客文章和图片资源如无特别说明，版权归作者所有。
