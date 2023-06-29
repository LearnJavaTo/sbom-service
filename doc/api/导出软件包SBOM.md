<!--
project: "SBOM Service"
title: 导出软件包SBOM
date: 2023-05-11
maintainer: huanceng
comment: ""
-->

# 导出软件包SBOM

## API接口

POST /sbom-api/exportPackageSbom

### 查询参数

`productName`: 制品名  string      *必需*

`packageName`: 软件包名       string        *必需*

`packageVersion`: 软件包版本       string        *必需*

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
/sbom-api/exportPackageSbom?productName=harmonyos/os/3.1-Release/standard_hi3516.tar.gz&spec=cyclonedx&specVersion=1.4&format=json&packageName=curl&packageVersion=monthly_20221018

#### 返回-1

```json
{
  "bomFormat" : "CycloneDX",
  "specVersion" : "1.4",
  "version" : 1,
  "serialNumber" : "urn:uuid:240936cb-4c07-47dd-8338-0516d792aada",
  "metadata" : {
    "timestamp" : "2023-03-22 18:46:39",
    "tools" : [ { } ],
    "manufacture" : {
      "name" : "OpenHarmony"
    },
    "component" : {
      "type" : "library",
      "name" : "curl",
      "supplier" : {
        "name" : "OpenHarmony"
      },
      "author" : "http://curl.haxx.se/",
      "group" : "openharmony",
      "version" : "monthly_20221018",
      "licenses" : [ {
        "expression" : "curl"
      } ],
      "copyright" : "Copyright (c) 1998, 1999 Kungliga Tekniska Hogskolan",
      "purl" : "pkg:gitee/openharmony/third_party_curl@monthly_20221018",
      "externalReferences" : [ {
        "url" : "http://curl.haxx.se/",
        "type" : "vcs"
      }, {
        "url" : "https://openharmony.gitee.com/openharmony/third_party_curl/tree/cf50e4285338c79c4a58a8dacbf4520ece4e6bb3",
        "type" : "distribution"
      } ],
      "components" : [ {
        "type" : "library",
        "name" : "curl",
        "version" : "7.78.0",
        "purl" : "pkg:generic/curl@7.78.0?download_url=http%3A%2F%2Fcurl.haxx.se%2F",
        "properties" : [ {
          "name" : "RelationCategory",
          "value" : "PROVIDE_MANAGER"
        } ]
      } ],
      "properties" : [ {
        "name" : "summary",
        "value" : null
      } ],
      "bom-ref" : "curl"
    },
    "licenses" : [ { } ]
  },
  "dependencies" : [ {
    "ref" : "urn:cdx:1d7ff5ed-2540-4234-9832-11896471d70d/1#c_utils"
  }, {
    "ref" : "urn:cdx:f30952e7-91c0-4401-8d75-6cc840007ba9/1#huks"
  }, {
    "ref" : "urn:cdx:a513535d-a33f-4ad5-a7fd-f19e0f71b291/1#zlib"
  } ]
}
```

#### 请求-2

POST
/sbom-api/exportPackageSbom?productName=harmonyos/os/3.1-Release/standard_hi3516.tar.gz&spec=cyclonedx&specVersion=1.4&format=json&packageName=bluetooth&packageVersion=monthly_20221018

#### 返回-2

```json
{
  "bomFormat" : "CycloneDX",
  "specVersion" : "1.4",
  "version" : 1,
  "serialNumber" : "urn:uuid:7af6f668-18fd-47bc-ac87-5750625e1443",
  "metadata" : {
    "timestamp" : "2023-03-22 18:46:39",
    "tools" : [ { } ],
    "manufacture" : {
      "name" : "OpenHarmony"
    },
    "component" : {
      "type" : "library",
      "name" : "bluetooth",
      "supplier" : {
        "name" : "OpenHarmony"
      },
      "author" : "OpenHarmony",
      "group" : "openharmony",
      "version" : "monthly_20221018",
      "licenses" : [ {
        "expression" : "Apache-2.0"
      } ],
      "purl" : "pkg:gitee/openharmony/communication_bluetooth@monthly_20221018",
      "externalReferences" : [ {
        "url" : "https://openharmony.gitee.com/openharmony/communication_bluetooth/tree/1107522f47957f3da3b16d85e61b3bc798be4122",
        "type" : "distribution"
      } ],
      "properties" : [ {
        "name" : "summary",
        "value" : null
      } ],
      "bom-ref" : "bluetooth"
    },
    "licenses" : [ { } ]
  },
  "dependencies" : [ {
    "ref" : "urn:cdx:d1eb69fa-9293-445b-984b-26560d9b6371/1#ability_base"
  }, {
    "ref" : "urn:cdx:b2a2525d-6b39-45e3-abeb-c8a9f487209c/1#access_token"
  }, {
    "ref" : "urn:cdx:7af6f668-18fd-47bc-ac87-5750625e1443/1#bluetooth"
  }, {
    "ref" : "urn:cdx:b28b6c85-ec99-4c53-b557-fc70192fc3e7/1#bounds_checking_function"
  }, {
    "ref" : "urn:cdx:1d7ff5ed-2540-4234-9832-11896471d70d/1#c_utils"
  }, {
    "ref" : "urn:cdx:a1d0e2e8-c912-4508-af56-ecd69987f9ae/1#call_manager"
  }, {
    "ref" : "urn:cdx:901c7249-bf59-40db-828d-22a837daef8a/1#core_service"
  }, {
    "ref" : "urn:cdx:05d2afb4-f828-4a9f-9a77-e8d00517ab96/1#eventhandler"
  }, {
    "ref" : "urn:cdx:0cba4181-ea2c-4137-b637-75a9c684e345/1#hdf_core"
  }, {
    "ref" : "urn:cdx:f30952e7-91c0-4401-8d75-6cc840007ba9/1#huks"
  }, {
    "ref" : "urn:cdx:c81cfca5-6ab6-4406-ac64-9551d88de78b/1#ipc"
  }, {
    "ref" : "urn:cdx:2ed68240-a21f-43fc-85d8-2fb73590d491/1#libuv"
  }, {
    "ref" : "urn:cdx:14714519-c34c-4bac-9ffe-cdac11ba9833/1#libxml2"
  }, {
    "ref" : "urn:cdx:2e5bbba1-fec1-4596-8c66-1879ad3cf572/1#napi"
  }, {
    "ref" : "urn:cdx:2718f9f0-e75d-4c64-a8ee-08cede9b1c01/1#safwk"
  }, {
    "ref" : "urn:cdx:0f0cf309-df2d-4deb-a114-4d04dda2ca8d/1#samgr"
  }, {
    "ref" : "urn:cdx:95995f9b-6a6a-4773-bd69-e1751974d3e2/1#state_registry"
  } ]
}
```

#### 请求-3

POST
/sbom-api/exportPackageSbom?productName=harmonyos/os/3.1-Release/standard_hi3516.tar.gz

#### 返回-3

```
export package sbom metadata failed
```

---

[返回目录](../../README.md)
