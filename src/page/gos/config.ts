// What Gosplugin's core answers to system.config: its modules, their methods with the data and result templates,
// as the core 1.3.42 listed them on the stand (docs/JOURNAL.md, 2026-11-17). Sites can read the templates from it.
export const CORE_CONFIG: unknown = [
  {
    "format": {
      "type": "core",
      "version": "1.3.42.0",
      "category": "gosuslugi.plugin",
      "description": "provides core functionality for plugin"
    },
    "dependencies": [
      {
        "format": {
          "type": "crypto",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": []
      },
      {
        "format": {
          "type": "esmart",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": []
      },
      {
        "format": {
          "type": "jacarta",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": []
      },
      {
        "format": {
          "type": "nmh",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": []
      },
      {
        "format": {
          "type": "rutoken",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": []
      },
      {
        "format": {
          "type": "system",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": []
      },
      {
        "format": {
          "type": "ws",
          "version": "",
          "category": "",
          "description": ""
        },
        "dependencies": [],
        "methods": [],
        "meta": [
          {
            "format": {
              "type": "ws",
              "version": "",
              "category": "protocol",
              "description": ""
            },
            "data": "ws://localhost:9001"
          }
        ]
      }
    ],
    "methods": [],
    "meta": [
      {
        "format": {
          "type": "nmh",
          "version": "",
          "category": "protocol",
          "description": ""
        },
        "data": ""
      }
    ]
  },
  {
    "format": {
      "type": "crypto",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides crypto operations for plugin"
    },
    "dependencies": [],
    "methods": [
      {
        "type": "addCertificate",
        "result": "container",
        "data": "{\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"container\":\"\",\"store\":\"\"}",
        "description": "Установить сертификат"
      },
      {
        "type": "certificateFields",
        "result": "",
        "data": "{\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"fields\":[]}",
        "description": "Получить данные сертификата"
      },
      {
        "type": "certificateRequest",
        "result": "{\"container\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"request\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"}}",
        "data": "{\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"subject\":\"\",\"subjectAlternativeNames\":\"\",\"extendedKeyUsageOids\":\"\",\"attributeOids\":\"\",\"certificatePolicies\":\"\",\"keyUsage\":\"\",\"publicKeyAlgorithmParamSet\":\"\",\"userPrincipalName\":\"\",\"validityPeriod\":\"\",\"validityPeriodUnits\":\"\",\"privateKeyValidityPeriod\":\"\",\"privateKeyValidityPeriodUnits\":\"\",\"identificationKind\":\"\",\"provider\":\"\",\"extended\":\"\"}",
        "description": "Создать запрос на выпуск сертификата"
      },
      {
        "type": "certificates",
        "result": "[]",
        "data": "{\"store\":\"\",\"fields\":{}}",
        "description": "Получить список сертификатов"
      },
      {
        "type": "deleteCertificate",
        "result": "",
        "data": "{\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"store\":\"\"}",
        "description": "Удалить сертификат"
      },
      {
        "type": "hash",
        "result": "{\"hash\":\"\",\"algorithm\":\"\"}",
        "data": "{\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"file\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"algorithm\":\"\"}",
        "description": "Получить хэш данных"
      },
      {
        "type": "normalize",
        "result": "",
        "data": "{\"file\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"algorithm\":\"\"}",
        "description": "Нормализовать XML документ"
      },
      {
        "type": "providers",
        "result": "[{\"name\":\"\",\"type\":\"\",\"version\":\"\",\"token\":\"\"}]",
        "data": "",
        "description": "Получить список криптопровайдеров"
      },
      {
        "type": "signature",
        "result": "[{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"}]",
        "data": "{\"files\":[],\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"type\":\"\",\"xml\":{\"type\":\"\",\"addKeyInfo\":\"\",\"referenceURI\":\"\",\"canonicalization\":\"\",\"elementToSignXPath\":\"\",\"signToElementXPath\":\"\",\"transforms\":[]},\"visualization\":{\"persistent\":\"\"}}",
        "description": "Получить прикрепленные / открепленные / xmldsig подписи"
      },
      {
        "type": "signatureV2",
        "result": "[{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"}]",
        "data": "{\"files\":[],\"certificate\":{\"content\":\"\",\"path\":\"\",\"contentEncoding\":\"\"},\"type\":\"\",\"xml\":{\"type\":\"\",\"addKeyInfo\":\"\",\"referenceURI\":\"\",\"canonicalization\":\"\",\"elementToSignXPath\":\"\",\"signToElementXPath\":\"\",\"transforms\":[]},\"visualization\":{\"persistent\":\"\"}}",
        "description": "Получить прикрепленные / открепленные / xmldsig подписи"
      },
      {
        "type": "tokens",
        "result": "[{\"store\":\" \",\"provider\":\" \",\"label\":\"\",\"serial\":\"\",\"model\":\"\",\"containers\":[],\"certificates\":[]}]",
        "data": "{\"store\":\"\",\"fields\":{}}",
        "description": "Получить список токенов"
      }
    ],
    "meta": []
  },
  {
    "format": {
      "type": "esmart",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides communication with esmart api"
    },
    "dependencies": [],
    "methods": [
      {
        "type": "test",
        "result": "esmart",
        "data": "",
        "description": "returns esmart"
      }
    ],
    "meta": []
  },
  {
    "format": {
      "type": "jacarta",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides communication with jacarta api"
    },
    "dependencies": [],
    "methods": [
      {
        "type": "test",
        "result": "jacarta",
        "data": "",
        "description": "returns jacarta"
      }
    ],
    "meta": []
  },
  {
    "format": {
      "type": "nmh",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides communication plugin-plugin.extension via google native messaging protocol"
    },
    "dependencies": [],
    "methods": [],
    "meta": []
  },
  {
    "format": {
      "type": "rutoken",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides communication with rutoken api"
    },
    "dependencies": [],
    "methods": [
      {
        "type": "test",
        "result": "rutoken",
        "data": "",
        "description": "returns rutoken"
      }
    ],
    "meta": []
  },
  {
    "format": {
      "type": "system",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides system operations for plugin"
    },
    "dependencies": [],
    "methods": [
      {
        "type": "cache",
        "result": "",
        "data": "",
        "description": "makes echo responce for enable / disable cache mode"
      },
      {
        "type": "close",
        "result": "",
        "data": "",
        "description": "makes request for stop communication between extension and plugin and closing plugin process"
      },
      {
        "type": "config",
        "result": "[]",
        "data": "",
        "description": "makes request for installed config info [ type, version ]"
      },
      {
        "type": "echo",
        "result": "",
        "data": "",
        "description": "makes echo responce"
      },
      {
        "type": "handshake",
        "result": "plugin handshake",
        "data": "",
        "description": "makes responce for communication request"
      },
      {
        "type": "ipConfig",
        "result": "[]",
        "data": "",
        "description": "makes request for get tcp/ip network parameters"
      },
      {
        "type": "lastError",
        "result": "",
        "data": "",
        "description": "returns last error info"
      }
    ],
    "meta": []
  },
  {
    "format": {
      "type": "ws",
      "version": "1.3.42.0",
      "category": "plugin",
      "description": "provides communication plugin-plugin.extension via websockets"
    },
    "dependencies": [],
    "methods": [],
    "meta": [
      {
        "format": {
          "type": "ws",
          "version": "",
          "category": "protocol",
          "description": ""
        },
        "data": "ws://localhost:9001"
      }
    ]
  }
];
