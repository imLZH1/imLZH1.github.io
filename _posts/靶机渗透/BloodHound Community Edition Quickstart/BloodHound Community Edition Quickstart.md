---
title: BloodHound Community Edition Quickstart
date: 2026-07-13T23:21:02+08:00
lastmod: 2026-07-14T00:09:44+08:00
---

# BloodHound Community Edition Quickstart

‍

windows PC - `docker Desktop`​  安装 `BloodHound Community Edition` (也可以直接kali，都用docker 版本)

wsl kali - 安装 `bloodhound-ce-python`- 收集信息导出压缩包

## kali 安装bloodhound-ce-python

- 安装

```py
$ mkdir /opt/bloodhound-ce-python
$ cd /opt/bloodhound-ce-python
$ python3 -m venv .venv

$ source .venv/bin/activate
$ pip install bloodhound-ce
$ deactivate
```

- 添加 `alias`

```ps1
# vim ~/.zshrc
alias bloodhound-ce-python='/opt/bloodhound-ce-python/.venv/bin/bloodhound-ce-python'
source ~/.zshrc
```

- 导出 一个zip压缩包

```py
bloodhound-ce-python -d sec.org -u lily -p 'mahalkita' \
-ns 192.168.111.10 \
-dc ad.sec.org \
--auth-method ntlm \
-c all --zip


# UDP 53 可能丢包或被过滤。直接让 BloodHound 使用 TCP DNS，并增加超时时间：
bloodhound-ce-python -d sec.org -u lily -p 'mahalkita' \
-ns 192.168.111.10 \
-dc ad.sec.org \
--auth-method ntlm \
--dns-tcp --dns-timeout 15 \
-c all --zip
```

![image](assets/image-20260713234313-g1gmenu.png)

‍

‍

## windows

- [BloodHound Community Edition Quickstart - SpecterOps](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart#explore-attack-paths)

‍

从 github 下载 cli

![image](assets/image-20260713233018-lp2ad3b.png)

- 我这里用 windows 就下载windows 版本，linux 就下 linux 版本

![image](assets/image-20260713233111-bhppw8k.png)

- 安装, 会自动下载docker 镜像 (执行的时候  windows docker desktop 要处于运行状态)

```py
.\bloodhound-cli.exe install 
```

![image](assets/image-20260713233444-1r6w1su.png)

‍

‍

‍

```bash
可用命令：
check       评估 Docker 环境，并按需下载必要的 YAML 文件。 
completion  生成指定 Shell 的自动补全脚本。
config      显示或调整配置。
containers  通过子命令管理 BloodHound 容器。
down        `containers down` 的快捷命令。
help        查看任意命令的帮助信息。
install     构建容器并执行 BloodHound 的首次设置。
logs        获取 BloodHound 服务的日志。
neo4j       将数据库后端设置为 Neo4j。
pg          将数据库后端设置为 PostgreSQL。
resetpwd    重置管理员密码。
running     列出正在运行的 BloodHound 服务。
uninstall   移除所有 BloodHound 容器、镜像及数据卷。
up          `containers up` 的快捷命令。
update      更新 BloodHound 容器镜像（如有可用更新）。
version     显示 BloodHound CLI 的版本信息。
```

## BloodHound CE 导入

- 关闭容器

```bash
.\bloodhound-cli.exe containers down
```

- 启动容器

```bash
.\bloodhound-cli.exe up
```

‍

- 使用完后 ，关闭并不保存数据

‍

```url
http://localhost:8080/ui/login
```

‍

![image](assets/image-20260713234244-r07y4mk.png)

- 选择 zip  ，然后点 upload  上传 数据，

![image](assets/image-20260713234431-gqmyh76.png)

等待个几秒， 然后刷新

![image](assets/image-20260713234558-ukw4800.png)

‍

## 使用示例1-Pathfinding

- Shadow Credentials

![image](assets/image-20260713234819-md3jhye.png)

```ps1
Start node       输入 user:moly
Destination Node 输入 user:cook
```

然后就会自动查指定两点之间的路径

user -> user

![image](assets/image-20260713234941-ryj0haw.png)

user -> Group

![image](assets/image-20260713235041-2qt85ra.png)

Group -> user

![image](assets/image-20260713235124-dmrurm0.png)

‍

## 使用示例2-自动查看进一步能够控制的对象

搜索 用户名 然后 点右边侧边栏的 `Outbound Object Control`

![image](assets/image-20260714000255-irinpje.png)

![image](assets/image-20260714000334-5lf2vl6.png)

‍

## 使用示例3-Cypher

例如：不知道目标是谁：自动寻找可利用路径

‍

![image](assets/image-20260713235251-61cgjfi.png)

先在 `Explore` 搜索已经控制的账户，例如：

```
MOLY@SEC.ORG
```

‍

![image](assets/image-20260713235316-yfmiz3l.png)

右击节点 点击 `Add to Owned`

![image](assets/image-20260713235348-oe7ytra.png)

然后进入：

```
Explore → Cypher → Saved Queries
```

![image](assets/image-20260713235624-susodim.png)

点其中一个 然后 点 `Run`

![image](assets/image-20260713235922-p3edqrh.png)

```TEXT
Shortest paths from Owned objects to Tier Zero
Shortest paths from Owned objects

从“已拥有”对象到“零级”（Tier Zero）的最短路径
从“已拥有”对象出发的最短路径
```

![image](assets/image-20260714000002-viasyhg.png)

‍

‍

## 使用示例4

‍

1. Owned → Tier Zero 自动路径

先把已经掌握的账户标记为 `Owned`，然后运行 Saved Queries 中与下面关键词有关的查询：

```
Owned
Tier Zero
Shortest Paths
High Value
```

这样可以自动回答：

```
当前已控制的账户
→ 能通过哪些组关系和 ACL
→ 到达哪些 Tier Zero 对象
```

比手动指定 `Moly → Cook` 更实用，因为你一开始可能并不知道最终目标是谁。
