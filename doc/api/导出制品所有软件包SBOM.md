<!--
project: "SBOM Service"
title: 导出制品所有软件包SBOM
date: 2023-06-13
maintainer: huanceng
comment: ""
-->

# 导出制品所有软件包SBOM

## API接口

POST /sbom-api/exportAllPackageSbom

### 查询参数

`productName`: 制品名  string      *必需*

`spec`: 导出SBOM的协议   string  *必需*

`specVersion`: 导出SBOM协议的版本  string      *必需*

`format`: 导出SBOM的格式 string        *必需*


| spec可选值   | specVersion可选值 | format可选值    |
|-----------|----------------|--------------|
| cyclonedx | 1.4            | json<br/>xml |

### HTTP状态码

```text
200: OK
500: Internal Server Error
```

### 样例

#### 请求-1

POST
/sbom-api/exportAllPackageSbom?productName=harmonyos/os/3.1-Release/standard_hi3516.tar.gz&spec=cyclonedx&specVersion=1.4&format=json

#### 返回-1

[sample tar file](../assert/harmonyos_os_3.1-Release_standard_hi3516.tar.gz-cyclonedx-sbom.tar.gz)

#### 请求-2

POST
/sbom-api/exportAllPackageSbom?productName=harmonyos/os/3.1-Release/standard_hi3516.tar.gz&spec=spdx&specVersion=1.4&format=json

#### 返回-2

```
export all package sbom metadata failed
```

---

[返回目录](../../README.md)
