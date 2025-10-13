// 思源风格博客 - 拖拽调整侧边栏宽度
class Resizer {
    constructor() {
        this.isResizing = false;
        this.currentResizer = null;
        this.startX = 0;
        this.startLeftWidth = 0;
        this.startRightWidth = 0;
        
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        const leftResizer = document.getElementById('resizer-left');
        const rightResizer = document.getElementById('resizer-right');
        
        // 左侧分隔条事件
        leftResizer.addEventListener('mousedown', (e) => {
            this.startResizing(e, 'left');
        });
        
        // 右侧分隔条事件
        rightResizer.addEventListener('mousedown', (e) => {
            this.startResizing(e, 'right');
        });

        // 鼠标移动和释放事件
        document.addEventListener('mousemove', (e) => {
            this.handleMouseMove(e);
        });

        document.addEventListener('mouseup', () => {
            this.stopResizing();
        });

        // 触摸事件支持
        leftResizer.addEventListener('touchstart', (e) => {
            this.startResizing(e, 'left');
        });
        
        rightResizer.addEventListener('touchstart', (e) => {
            this.startResizing(e, 'right');
        });

        document.addEventListener('touchmove', (e) => {
            this.handleMouseMove(e);
        });

        document.addEventListener('touchend', () => {
            this.stopResizing();
        });
    }

    startResizing(e, type) {
        this.isResizing = true;
        this.currentResizer = type;
        this.startX = this.getClientX(e);
        
        const leftSidebar = document.getElementById('sidebar-left');
        const rightSidebar = document.getElementById('sidebar-right');
        
        this.startLeftWidth = leftSidebar.offsetWidth;
        this.startRightWidth = rightSidebar.offsetWidth;
        
        // 添加拖拽样式
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        
        if (type === 'left') {
            document.getElementById('resizer-left').classList.add('dragging');
        } else {
            document.getElementById('resizer-right').classList.add('dragging');
        }
    }

    handleMouseMove(e) {
        if (!this.isResizing) return;
        
        e.preventDefault();
        const currentX = this.getClientX(e);
        const deltaX = currentX - this.startX;
        
        const leftSidebar = document.getElementById('sidebar-left');
        const rightSidebar = document.getElementById('sidebar-right');
        
        if (this.currentResizer === 'left') {
            // 调整左侧边栏宽度
            const newWidth = this.startLeftWidth + deltaX;
            const minWidth = 200;
            const maxWidth = 500;
            
            if (newWidth >= minWidth && newWidth <= maxWidth) {
                leftSidebar.style.width = `${newWidth}px`;
            }
        } else {
            // 调整右侧边栏宽度
            const newWidth = this.startRightWidth - deltaX;
            const minWidth = 200;
            const maxWidth = 400;
            
            if (newWidth >= minWidth && newWidth <= maxWidth) {
                rightSidebar.style.width = `${newWidth}px`;
            }
        }
    }

    stopResizing() {
        if (!this.isResizing) return;
        
        this.isResizing = false;
        this.currentResizer = null;
        
        // 移除拖拽样式
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        
        document.getElementById('resizer-left').classList.remove('dragging');
        document.getElementById('resizer-right').classList.remove('dragging');
        
        // 保存布局到localStorage
        this.saveLayout();
    }

    getClientX(e) {
        return e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
    }

    saveLayout() {
        const leftSidebar = document.getElementById('sidebar-left');
        const rightSidebar = document.getElementById('sidebar-right');
        
        const layout = {
            leftWidth: leftSidebar.style.width || leftSidebar.offsetWidth,
            rightWidth: rightSidebar.style.width || rightSidebar.offsetWidth
        };
        
        localStorage.setItem('blogLayout', JSON.stringify(layout));
    }

    loadLayout() {
        const savedLayout = localStorage.getItem('blogLayout');
        if (savedLayout) {
            const layout = JSON.parse(savedLayout);
            const leftSidebar = document.getElementById('sidebar-left');
            const rightSidebar = document.getElementById('sidebar-right');
            
            if (layout.leftWidth) {
                leftSidebar.style.width = typeof layout.leftWidth === 'number' 
                    ? `${layout.leftWidth}px` 
                    : layout.leftWidth;
            }
            
            if (layout.rightWidth) {
                rightSidebar.style.width = typeof layout.rightWidth === 'number'
                    ? `${layout.rightWidth}px`
                    : layout.rightWidth;
            }
        }
    }
}

// 暗色模式切换
class ThemeManager {
    constructor() {
        this.isDarkMode = localStorage.getItem('darkMode') === 'true';
        this.init();
    }

    init() {
        this.applyTheme();
        this.bindEvents();
        this.updateButtonText();
    }

    applyTheme() {
        if (this.isDarkMode) {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        this.updateButtonText();
    }

    bindEvents() {
        // 绑定暗色模式切换按钮事件
        const darkModeToggle = document.getElementById('dark-mode-toggle');
        if (darkModeToggle) {
            darkModeToggle.addEventListener('click', () => this.toggle());
        }
    }

    toggle() {
        this.isDarkMode = !this.isDarkMode;
        localStorage.setItem('darkMode', this.isDarkMode.toString());
        this.applyTheme();
    }

    updateButtonText() {
        const darkModeToggle = document.getElementById('dark-mode-toggle');
        if (darkModeToggle) {
            if (this.isDarkMode) {
                darkModeToggle.innerHTML = '☀️ 亮色模式';
                darkModeToggle.title = '切换到亮色模式';
            } else {
                darkModeToggle.innerHTML = '🌙 暗色模式';
                darkModeToggle.title = '切换到暗色模式';
            }
        }
    }
}

// 导航加载和文件管理
class NavManager {
    constructor() {
        this.navData = null;
        this.init();
    }

    async init() {
        await this.loadNavData();
        this.renderFileTree();
        this.bindEvents();
        
        // 延迟处理hash变化，确保DOM完全渲染
        setTimeout(() => {
            this.handleHashChange();
        }, 100);
        
        // 监听hash变化
        window.addEventListener('hashchange', () => {
            this.handleHashChange();
        });
    }

    async loadNavData() {
        try {
            const response = await fetch('nav.json');
            this.navData = await response.json();
        } catch (error) {
            console.error('加载导航数据失败:', error);
            this.navData = {};
        }
    }

    renderFileTree() {
        const fileTree = document.querySelector('.file-tree');
        fileTree.innerHTML = '';

        if (!this.navData || Object.keys(this.navData).length === 0) {
            fileTree.innerHTML = '<div class="empty-message">暂无笔记</div>';
            return;
        }

        for (const [category, notes] of Object.entries(this.navData)) {
            // 创建目录项
            const categoryItem = this.createCategoryItem(category, notes);
            fileTree.appendChild(categoryItem);
        }
    }

    createCategoryItem(category, notes) {
        const categoryDiv = document.createElement('div');
        categoryDiv.className = 'category-item';
        
        const categoryHeader = document.createElement('div');
        categoryHeader.className = 'category-header';
        categoryHeader.innerHTML = `
            <div class="category-icon">📁</div>
            <span class="category-name">${category}</span>
            <div class="expand-icon">▶</div>
        `;

        const notesContainer = document.createElement('div');
        notesContainer.className = 'notes-container';
        
        notes.forEach(note => {
            const noteItem = document.createElement('div');
            noteItem.className = 'note-item';
            noteItem.innerHTML = `
                <div class="note-icon">📄</div>
                <span class="note-name">${note.note_name}</span>
            `;
            noteItem.dataset.src = note.note_src;
            noteItem.dataset.root = note.note_root;
            notesContainer.appendChild(noteItem);
        });

        categoryDiv.appendChild(categoryHeader);
        categoryDiv.appendChild(notesContainer);

        return categoryDiv;
    }

    bindEvents() {
        // 目录展开/收起事件
        document.addEventListener('click', (e) => {
            if (e.target.closest('.category-header')) {
                const categoryHeader = e.target.closest('.category-header');
                const categoryItem = categoryHeader.parentElement;
                const notesContainer = categoryItem.querySelector('.notes-container');
                const expandIcon = categoryHeader.querySelector('.expand-icon');
                
                if (notesContainer.style.display === 'none' || !notesContainer.style.display) {
                    notesContainer.style.display = 'block';
                    expandIcon.textContent = '▼';
                    categoryItem.classList.add('expanded');
                } else {
                    notesContainer.style.display = 'none';
                    expandIcon.textContent = '▶';
                    categoryItem.classList.remove('expanded');
                }
            }

            // 笔记项点击事件
            if (e.target.closest('.note-item')) {
                const noteItem = e.target.closest('.note-item');
                const noteItems = document.querySelectorAll('.note-item');
                
                // 移除所有激活状态
                noteItems.forEach(item => item.classList.remove('active'));
                
                // 添加当前激活状态
                noteItem.classList.add('active');
                
                // 加载笔记内容并更新URL
                this.loadNoteContent(noteItem.dataset.src, true);
            }
        });
    }

    async loadNoteContent(noteSrc, updateURL = false) {
        try {
            const response = await fetch(noteSrc);
            if (!response.ok) throw new Error('文件不存在');
            
            const markdownContent = await response.text();
            
            // 获取对应的note_root
            const noteItem = document.querySelector(`.note-item[data-src="${noteSrc}"]`);
            const noteRoot = noteItem ? noteItem.dataset.root : './';
            
            this.renderMarkdown(markdownContent, noteSrc, noteRoot);
            
            // 如果需要更新URL，则更新hash
            if (updateURL) {
                this.updateURLForNote(noteSrc);
            }
        } catch (error) {
            console.error('加载笔记内容失败:', error);
            this.renderError('无法加载笔记内容');
        }
    }

    renderMarkdown(content, noteSrc, noteRoot) {
        const contentArea = document.querySelector('.markdown-body');
        const noteTitle = document.querySelector('.content-header h1');
        
        // 提取文件名作为标题
        const fileName = noteSrc.split('/').pop().replace('.md', '');
        noteTitle.textContent = fileName;
        
        // 使用marked.js解析Markdown，并处理资源路径
        const htmlContent = this.parseMarkdownWithMarked(content, noteRoot);
        contentArea.innerHTML = htmlContent;
        
        // 手动触发Prism.js代码高亮
        this.highlightCodeBlocks(contentArea);
        
        // 更新大纲导航
        this.updateOutline(contentArea);
    }

    highlightCodeBlocks(container) {
        // 手动调用Prism.js高亮所有代码块
        if (typeof Prism !== 'undefined') {
            // 查找所有代码块并手动高亮
            const codeBlocks = container.querySelectorAll('code[class*="language-"], pre code');
            codeBlocks.forEach(code => {
                const parent = code.parentElement;
                if (parent && parent.nodeName === 'PRE') {
                    // 确保有正确的类名
                    if (!parent.classList.contains('language-none')) {
                        const lang = code.className.replace('language-', '');
                        if (lang && Prism.languages[lang]) {
                            code.innerHTML = Prism.highlight(code.textContent, Prism.languages[lang], lang);
                        } else {
                            code.innerHTML = Prism.highlight(code.textContent, Prism.languages.plain, 'plain');
                        }
                    }
                    
                    // 为代码块添加复制按钮
                    this.addCopyButton(parent);
                }
            });
        }
    }

    addCopyButton(preElement) {
        // 检查是否已经添加了复制按钮
        if (preElement.querySelector('.code-copy-btn')) {
            return;
        }
        
        const copyButton = document.createElement('button');
        copyButton.className = 'code-copy-btn';
        copyButton.textContent = '复制';
        copyButton.title = '复制代码';
        
        copyButton.addEventListener('click', (e) => {
            e.stopPropagation();
            this.copyCode(preElement);
        });
        
        preElement.appendChild(copyButton);
    }

    copyCode(preElement) {
        const codeElement = preElement.querySelector('code');
        if (!codeElement) return;
        
        const codeText = codeElement.textContent || codeElement.innerText;
        
        // 使用现代Clipboard API复制文本
        navigator.clipboard.writeText(codeText).then(() => {
            // 显示复制成功提示
            this.showCopySuccess(preElement);
        }).catch(err => {
            // 降级方案：使用传统document.execCommand
            const textArea = document.createElement('textarea');
            textArea.value = codeText;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            // 显示复制成功提示
            this.showCopySuccess(preElement);
        });
    }

    showCopySuccess(preElement) {
        // 移除可能存在的旧提示
        const existingSuccess = preElement.querySelector('.copy-success');
        if (existingSuccess) {
            existingSuccess.remove();
        }
        
        // 创建成功提示
        const successElement = document.createElement('div');
        successElement.className = 'copy-success';
        successElement.textContent = '已复制!';
        
        preElement.appendChild(successElement);
        
        // 2秒后自动移除提示
        setTimeout(() => {
            if (successElement.parentElement === preElement) {
                successElement.remove();
            }
        }, 2000);
    }

    parseMarkdownWithMarked(markdown, noteRoot) {
        try {
            // 配置marked选项
            marked.setOptions({
                highlight: function(code, lang) {
                    // 使用Prism.js进行代码高亮
                    if (Prism.languages[lang]) {
                        return Prism.highlight(code, Prism.languages[lang], lang);
                    } else {
                        return code;
                    }
                },
                breaks: true, // 将\n转换为<br>
                gfm: true,    // 启用GitHub Flavored Markdown
            });
            
            // 使用marked解析Markdown
            const parsedHtml = marked.parse(markdown);
            
            // 处理资源文件路径
            const processedHtml = this.processResourcePaths(parsedHtml, noteRoot);
            
            // 使用DOMPurify进行安全过滤
            const cleanHtml = DOMPurify.sanitize(processedHtml);
            
            return cleanHtml;
        } catch (error) {
            console.error('Markdown解析错误:', error);
            return '<div class="error-message">Markdown解析错误</div>';
        }
    }

    processResourcePaths(html, noteRoot) {
        // 创建一个临时DOM元素来处理HTML
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = html;
        
        // 处理图片路径
        const images = tempDiv.querySelectorAll('img');
        images.forEach(img => {
            const src = img.getAttribute('src');
            if (src && !src.startsWith('http') && !src.startsWith('/') && !src.startsWith('data:')) {
                // 相对路径，转换为基于noteRoot的绝对路径
                const fullPath = this.resolvePath(src, noteRoot);
                img.setAttribute('src', fullPath);
            }
        });
        
        // 处理链接路径（如果有相对链接指向资源文件）
        const links = tempDiv.querySelectorAll('a');
        links.forEach(link => {
            const href = link.getAttribute('href');
            if (href && !href.startsWith('http') && !href.startsWith('/') && !href.startsWith('#') && 
                (href.endsWith('.png') || href.endsWith('.jpg') || href.endsWith('.jpeg') || href.endsWith('.gif') || href.endsWith('.svg'))) {
                // 相对路径的资源文件链接，转换为基于noteRoot的绝对路径
                const fullPath = this.resolvePath(href, noteRoot);
                link.setAttribute('href', fullPath);
            }
        });
        
        return tempDiv.innerHTML;
    }

    resolvePath(relativePath, noteRoot) {
        // 简单的路径解析：将相对路径与noteRoot组合
        if (relativePath.startsWith('./')) {
            relativePath = relativePath.substring(2);
        }
        
        // 确保noteRoot以斜杠结尾
        const baseRoot = noteRoot.endsWith('/') ? noteRoot : noteRoot + '/';
        
        return baseRoot + relativePath;
    }

    updateOutline(contentElement) {
        const outlineContainer = document.querySelector('.outline-container');
        const headings = contentElement.querySelectorAll('h1, h2, h3');
        
        if (headings.length === 0) {
            outlineContainer.innerHTML = '<div class="empty-outline">暂无大纲</div>';
            return;
        }

        let outlineHtml = '';
        headings.forEach((heading, index) => {
            const level = parseInt(heading.tagName.substring(1));
            const text = heading.textContent;
            outlineHtml += `
                <div class="outline-item level-${level}" data-index="${index}">
                    ${text}
                </div>
            `;
        });

        outlineContainer.innerHTML = outlineHtml;
        
        // 绑定大纲点击事件
        this.bindOutlineEvents(headings);
    }

    bindOutlineEvents(headings) {
        const outlineItems = document.querySelectorAll('.outline-item');
        outlineItems.forEach((item, index) => {
            item.addEventListener('click', () => {
                if (headings[index]) {
                    headings[index].scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    }

    loadDefaultHome() {
        // 查找LEA目录下的index.md文件
        const leaIndexNote = this.findLEAIndexNote();
        if (leaIndexNote) {
            // 模拟点击LEA/index.md笔记项
            const noteItem = document.querySelector(`.note-item[data-src="${leaIndexNote.note_src}"]`);
            if (noteItem) {
                noteItem.classList.add('active');
                this.loadNoteContent(leaIndexNote.note_src);
            }
        }
    }

    findLEAIndexNote() {
        if (!this.navData || !this.navData.LEA) return null;
        
        // 在LEA目录中查找index.md
        for (const note of this.navData.LEA) {
            if (note.note_name === 'index') {
                return note;
            }
        }
        return null;
    }

    // URL路由处理方法
    handleHashChange() {
        const hash = window.location.hash;
        
        if (hash && hash.startsWith('#/')) {
            // 解析hash并加载指定笔记
            const path = hash.substring(2); // 移除 '#/'
            this.loadNoteFromPath(path);
        } else {
            // 没有hash或hash为空，重定向到默认主页
            this.redirectToDefaultHome();
        }
    }
    
    loadNoteFromPath(path) {
        console.log('加载路径:', path);
        
        // 解析路径格式：目录/笔记名
        const parts = path.split('/');
        if (parts.length < 2) {
            console.warn('无效的URL路径格式:', path);
            this.loadDefaultHome();
            return;
        }
        
        const category = decodeURIComponent(parts[0]);
        const noteName = decodeURIComponent(parts[1]);
        
        console.log('查找笔记(解码后):', category, noteName);
        
        // 查找对应的笔记
        const note = this.findNoteByPath(category, noteName);
        if (note) {
            console.log('找到笔记:', note);
            
            // 激活对应的笔记项并加载内容
            const noteItem = document.querySelector(`.note-item[data-src="${note.note_src}"]`);
            if (noteItem) {
                console.log('找到笔记项:', noteItem);
                
                // 移除所有激活状态
                const noteItems = document.querySelectorAll('.note-item');
                noteItems.forEach(item => item.classList.remove('active'));
                
                // 添加当前激活状态
                noteItem.classList.add('active');
                
                // 加载笔记内容，但不更新URL（避免循环）
                this.loadNoteContent(note.note_src, false);
                
                // 展开对应的目录
                this.expandCategory(category);
            } else {
                console.warn('未找到对应的笔记项:', note.note_src);
                // 即使没有找到DOM元素，也直接加载笔记内容
                this.loadNoteContent(note.note_src, false);
            }
        } else {
            console.warn('未找到笔记:', category, noteName);
            this.loadDefaultHome();
        }
    }
    
    findNoteByPath(category, noteName) {
        console.log('查找笔记:', category, noteName);
        console.log('navData:', this.navData);
        
        if (!this.navData || !this.navData[category]) {
            console.log('目录不存在:', category);
            return null;
        }
        
        // 在指定目录中查找笔记
        for (const note of this.navData[category]) {
            console.log('检查笔记:', note.note_name, '==', noteName);
            if (note.note_name === noteName) {
                console.log('找到匹配的笔记:', note);
                return note;
            }
        }
        console.log('未找到匹配的笔记');
        return null;
    }
    
    expandCategory(category) {
        // 展开指定目录
        const categoryItems = document.querySelectorAll('.category-item');
        categoryItems.forEach(item => {
            const categoryName = item.querySelector('.category-name').textContent;
            if (categoryName === category) {
                const notesContainer = item.querySelector('.notes-container');
                const expandIcon = item.querySelector('.expand-icon');
                
                notesContainer.style.display = 'block';
                expandIcon.textContent = '▼';
                item.classList.add('expanded');
            }
        });
    }
    
    updateURLForNote(noteSrc) {
        // 从当前激活的笔记项获取目录和笔记名
        const activeNoteItem = document.querySelector('.note-item.active');
        if (activeNoteItem) {
            const category = activeNoteItem.closest('.category-item').querySelector('.category-name').textContent;
            const noteName = activeNoteItem.querySelector('.note-name').textContent;
            
            const newHash = `#/${category}/${noteName}`;
            if (window.location.hash !== newHash) {
                window.history.replaceState(null, null, newHash);
            }
        }
    }
    
    redirectToDefaultHome() {
        // 重定向到默认主页
        const defaultPath = 'LEA/index';
        const newHash = `#/${defaultPath}`;
        
        if (window.location.hash !== newHash) {
            window.location.hash = newHash;
        } else {
            // 如果已经是默认路径，则加载默认主页
            this.loadDefaultHome();
        }
    }

    renderError(message) {
        const contentArea = document.querySelector('.markdown-body');
        contentArea.innerHTML = `<div class="error-message">${message}</div>`;
    }
}

// 初始化应用
document.addEventListener('DOMContentLoaded', () => {
    new Resizer();
    new ThemeManager();
    new NavManager();
    
    // 加载保存的布局
    setTimeout(() => {
        new Resizer().loadLayout();
    }, 100);
});
