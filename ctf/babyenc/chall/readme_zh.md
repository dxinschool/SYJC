# 選手須知

baby enc note

## 題目附件

賽題路徑：/challenge/chall

註：修復前請備份賽題附件到本地，否則修復後原始附件會被覆蓋！

## 選手環境

選手僅可透過sftp上傳修復文件至patch目錄，關鍵目錄功能如下：
```bash
challenge #題目附件，修復後會替換該目錄下賽題文件
flag      #flag檔案
patch     #patch目錄
```

## 修復步驟

1. 使用scp將修復文件上傳到指定路徑
```shell
scp -i /path/to/your_private_key.pem -s -P 22 /path/to/your_patched_file ctf@<server_ip>:/patch/patched
```

2. 新建version確認文件
```shell
scp -i /path/to/your_private_key.pem -s -P 22 /path/to/your_version_file ctf@<server_ip>:/patch/version
```
當patch目錄同時存在以下兩個檔案時，會進行patch：

```bash
patched # 修復後的賽題文件
version # 是否進行patch的標誌性文件
```

上傳修復文件至/patch目錄，重新命名為patched，然後通過創建version文件來確認是否進行patch，等待15s左右環境會自動進行替換同時清空patch目錄，替換後的文件可在/challenge下查看

## 修復說明

1. 應當針對漏洞點進行修復，與漏洞點無關函數不允許修改，同時應保持賽題服務正常以及交互邏輯不變
2. 須保持賽題文件大小不變，且允許修改最大位元組數為30位元組
