# Анализ: расширение, которое подменяет КриптоПро на Рутокен

Разбор первоисточников от 2026-09-23. Решения, принятые по его итогам, — в `CLAUDE.md` («Settled decisions»), этапы — в [`ROADMAP.md`](ROADMAP.md), текущее состояние — в [`STATUS.md`](STATUS.md).

## 1. Задача

Сайт рассчитан на связку **КриптоПро ЭЦП Browser plug-in + КриптоПро CSP**. У пользователя их нет, зато установлены
**Рутокен Плагин** и расширение **«Адаптер Рутокен Плагин»**, а в USB вставлен **Рутокен ЭЦП 2.0/3.0**.
Наше расширение должно сделать так, чтобы код сайта «видел» КриптоПро, а подпись, шифрование и работа с сертификатами
выполнялись Рутокен Плагином на устройстве.

## 2. Что изучено (первоисточники)

| Что | Версия | Откуда |
|---|---|---|
| `cadesplugin_api.js`, который сайты подключают к себе | 2.4.5 | cryptopro.ru |
| Расширение КриптоПро для Chrome (MV3) | 1.3.17, id `pfhgbfnnjiafkhfdkmpiflachepdcjod` | Chrome Web Store |
| `nmcades_plugin_api.js` из этого расширения | 1.3.17 | там же |
| Библиотека `crypto-pro` (обёртка, которой пользуются многие сайты) | 2.5.2 | npm |
| Расширение «Адаптер Рутокен Плагин» (MV3) | 1.1.0.0, id `ohedcglhbbfdgaogjhcclacoccbagkjg` | Chrome Web Store |
| Модуль-обёртка `rutoken` | 1.0.8 | npm |
| Документация API Рутокен Плагина | 4.12.3.0 | plugin.api.rutoken.ru |
| Рутокен Плагин для Linux (deb) | 4.12.3 | download.rutoken.ru |
| Fake Рутокен (SoftHSMv2, профиль `FAKE_RUTOKEN_ECP`) | v2.7.0-portable.42 | github.com/code-agent-43824/SoftHSMv2 |
| Демо-страница `cades_bes_sample.html` и её скрипты | `?v=319244` | cryptopro.ru |

## 3. Как устроен КриптоПро в браузере

```
Сайт ── cadesplugin_api.js ──► window.cadesplugin (Promise + константы + CreateObjectAsync)
             │
             │ <script src="chrome-extension://<id КриптоПро>/nmcades_plugin_api.js">
             ▼
   nmcades_plugin_api.js (в мире страницы) ──window.postMessage──► content.js расширения
                                                                        │ runtime port
                                                                        ▼
                                                   background.js ──native messaging──► nmcades (плагин) ──► КриптоПро CSP
```

Ключевые наблюдения из кода `cadesplugin_api.js` 2.4.5:

1. **Первая строка скрипта:** `if (window.cadesplugin && window.cadesplugin.LOG_LEVEL_DEBUG) return;`
   В старой версии, встроенной в `crypto-pro` 2.5.2, проверка ещё проще: `if (window.cadesplugin) return;`.
   Значит, если **наш объект `window.cadesplugin` уже существует до загрузки скрипта сайта, скрипт сайта ничего не делает**,
   и сайт работает с нашим объектом. Это главная точка подмены.
2. В современных браузерах (Chrome ≥ 42, Firefox ≥ 52, Edge, Яндекс, Opera ≥ 33, Safari ≥ 12) используется только
   асинхронный режим: `cadesplugin.CreateObjectAsync(name)`. Синхронный `CreateObject` (NPAPI/ActiveX) нужен лишь для IE,
   его можно не поддерживать.
3. Загрузка плагина = `window.cadesplugin` это Promise, который резолвится, когда плагин готов. Сайты пишут
   `cadesplugin.then(...)` или `await cadesplugin`, а затем `cadesplugin.async_spawn(function* () {...})`.
4. Соглашение асинхронного API (из `nmcades_plugin_api.js`), которое нужно повторить **в точности**:
   - каждый объект плагина — JS-объект с `objid`;
   - чтение свойства: `await obj.SubjectName` (геттер возвращает Promise);
   - запись свойства: `await obj.propset_Content(value)`;
   - метод: `await obj.SignCades(signer, type, detached)` возвращает Promise;
   - объекты в аргументах передаются по ссылке, `Date` превращается в строку ISO UTC;
   - ошибка = reject с объектом, у которого есть `message` (сайты вытаскивают код вида `0x8010006E` через
     `cadesplugin.getLastError(e)`).
5. Вспомогательные сообщения через `window.postMessage`, на которые сайты иногда рассчитывают:
   `cadesplugin_extension_version_request` → `cadesplugin_extension_version_response:<ver>`,
   `cadesplugin_extension_id_request` → `cadesplugin_extension_id_response:<id>`.
6. Константы (`CADESCOM_CADES_BES`, `CAPICOM_CURRENT_USER_STORE`, `CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256` и
   ещё ~300 штук) задаются самим `cadesplugin_api.js`. Так как скрипт сайта у нас не выполнится, **все константы должны
   быть в нашем объекте**. Их можно взять из `cadesplugin_api.js` как есть.

## 4. Как устроен Рутокен Плагин в браузере

```
content.js адаптера (document_start, все фреймы)
background.js адаптера регистрирует inject.js в мире страницы (world: MAIN, document_start, <all_urls>)
   │
   ▼
window["C3B7563B-BF85-45B7-88FC-7CFF1BD3C2DB"] = { initialize(), затем isPluginInstalled(), loadPlugin() }
   │ window.postMessage ◄──► content.js ◄──► background.js ──native messaging──► ru.rutoken.firewyrmhost ──► Рутокен Плагин ──► PKCS#11 ──► токен
```

Ключевые наблюдения:

1. **Адаптер Рутокен Плагина сам кладёт объект в мир страницы на любом сайте** (`<all_urls>`). Значит, наш код,
   исполняемый в мире страницы, может напрямую вызвать `initialize()` → `loadPlugin()` и получить объект `CryptoPlugin`
   — ровно так, как это делает официальная обёртка `rutoken.js`.
2. Подключиться к native host Рутокена напрямую из нашего расширения нельзя: манифест native host разрешает доступ
   только расширению Рутокена. Поэтому единственный путь без своих нативных компонентов — **через объект в мире страницы**.
3. API `CryptoPlugin` 4.12 (все методы асинхронные, возвращают Promise) покрывает основное:
   `enumerateDevices`, `getDeviceInfo`, `login`/`logout`, `enumerateCertificates`, `getCertificate` (PEM),
   `parseCertificate`, `getKeyByCertificate`, `sign` (CMS, CAdES-BES, CAdES-T; attached/detached; подпись готового
   хеша `DATA_FORMAT_HASH`; добавление подписи в существующий CMS), `verify`, `rawSign` (сырая подпись хеша),
   `digest` (ГОСТ 34.11-2012 256/512, SHA), `cmsEncrypt`/`cmsDecrypt` (ГОСТ 28147-89, Кузнечик, Магма),
   `generateKeyPair`, `createPkcs10`, `importCertificate`, `createTsRequest`/`verifyTsResponse`, `tokenMonitor`.
4. Почти все операции с ключом требуют `login(deviceId, pin)`. В КриптоПро PIN спрашивает сам CSP своим окном,
   поэтому **окно ввода PIN придётся делать нам**.

## 5. Предлагаемая архитектура

```
Наше расширение (MV3)
├── shim.js            мир страницы (world: MAIN), document_start, all_frames
│     └─ определяет window.cadesplugin раньше скрипта сайта
├── emulation/         эмуляция объектов CAdESCOM/CAPICOM с async-свойствами и propset_*
├── backend/rutoken    обёртка над window["C3B7563B-..."] и CryptoPlugin
├── asn1/              разбор сертификатов и CMS, форматирование «как у КриптоПро»
├── ui/                окно PIN, подтверждение подписи, выбор токена (изолированный мир или страница расширения)
├── background.js      настройки, список разрешённых сайтов, сеть (TSA/OCSP) для поздних этапов
└── popup/options      вкл/выкл на сайте, статус токена
```

Поток при подписи:

```
сайт: await cadesplugin → CreateObjectAsync("CAdESCOM.Store") → Open → Certificates → Item(1)
      CreateObjectAsync("CAdESCOM.CPSigner") → propset_Certificate(cert)
      CreateObjectAsync("CAdESCOM.CadesSignedData") → propset_Content(data) → SignCades(signer, CADES_BES)
наш shim:  Store      → enumerateDevices + enumerateCertificates(USER) + getCertificate на каждом токене
           Certificate→ наш объект поверх PEM (Thumbprint = SHA-1 от DER, SubjectName в формате КриптоПро, ...)
           SignCades  → окно PIN (если не залогинены) → подтверждение → login
                        → свой код собирает SignedData и подписанные атрибуты (как КриптоПро)
                        → digest(ГОСТ 34.11-2012) от атрибутов → rawSign(deviceId, keyId, хеш) → подпись в CMS
                        (простой путь через sign(...) не умеет атрибут «имя документа», см. раздел 9)
           результат  → Base64 в том же виде, что отдаёт КриптоПро
```

### Точки перехвата (в порядке надёжности)

1. **Основная.** Скрипт в мире страницы на `document_start` создаёт `window.cadesplugin` до любого кода сайта.
   `cadesplugin_api.js` сайта видит объект и выходит. Работает одинаково в Chrome и Firefox, не зависит от id
   расширения КриптоПро. Дополнительно можно закрепить свойство через `Object.defineProperty`, чтобы скрипт сайта
   без проверки не перезаписал его.
2. **Запасная** для сайтов со «своими» копиями загрузчика без ранней проверки: перехватить вставку
   `<script src="chrome-extension://…/nmcades_plugin_api.js">` и вместо загрузки выставить свой `cpcsp_chrome_nmcades`
   (у `nmcades_plugin_api.js` тоже есть ранний выход `if (window.cpcsp_chrome_nmcades) return;`).
3. **Крайняя.** Эмулировать протокол `postMessage` с `destination: "nmcades_<id>"`. Сложнее и хрупче, держим в резерве.

## 6. Сопоставление объектов КриптоПро и методов Рутокена

| Объект / метод КриптоПро | Чем реализуем | Сложность |
|---|---|---|
| `CAdESCOM.About`: `Version`, `PluginVersion`, `CSPVersion()`, `CSPName()` | Константы, достаточные для проверок версий на сайтах (`crypto-pro` проверяет минимальные версии) | Низкая |
| `CAdESCOM.Store`: `Open`, `Close`, `Certificates` | `enumerateDevices` + `enumerateCertificates(CERT_CATEGORY_USER)` + `getCertificate` | Низкая |
| `Certificates`: `Count`, `Item(i)` (с 1), `Find(type, query, validOnly)` | Свой поиск по SHA1, SubjectName, EKU, сроку действия | Средняя |
| `Certificate`: `SubjectName`, `IssuerName`, `SerialNumber`, `Thumbprint`, `ValidFromDate`, `ValidToDate`, `HasPrivateKey`, `GetInfo`, `Export`, `PublicKey().Algorithm`, `ExtendedKeyUsage().EKUs`, `KeyUsage` | Свой разбор ASN.1 (DER из PEM), SHA-1 через WebCrypto, `getKeyByCertificate` для `HasPrivateKey` | Средняя: главное точно повторить формат строк КриптоПро (`CN=…, ИНН=…, СНИЛС=…`), по ним сайты ищут сертификаты регулярками |
| `Certificate.IsValid()` | Проверка сроков; позже цепочка по списку корневых УЦ | Средняя (у КриптоПро проверка через хранилище ОС и CRL/OCSP) |
| `CAdESCOM.CPSigner`: `Certificate`, `Options`, `TSAAddress`, `AuthenticatedAttributes2`, `KeyPin`, `CheckCertificate` | Хранение параметров, передача в `sign` | Низкая |
| `CAdESCOM.CPAttribute` (время подписи, имя документа) | Время подписи = `addSignTime`. Произвольные подписанные атрибуты Рутокен не добавляет | Средняя: имя/описание документа пока не поддержать |
| `CadesSignedData.SignCades(signer, CADES_BES / PKCS7_TYPE, detached)` | `sign(...)` с `detached`, `addEssCert`, `addSignTime` | Низкая |
| `CadesSignedData.SignCades(..., CADES_T)` | `sign(...)` с `tspOptions` (Рутокен ходит к TSA сам, только HTTP) | Средняя |
| `CadesSignedData.SignCades(..., CADES_X_LONG_TYPE_1)` и `CADES_DEFAULT` (по документации КриптоПро это тоже X Long Type 1) | Рутокен так не умеет. Нужно достраивать атрибуты (метка времени, ссылки и значения сертификатов, ответы OCSP) своим ASN.1-кодом, сеть через background | Высокая |
| `CadesSignedData.CoSignCades` | `sign(...)` с опцией `CMS` (добавить подпись в готовый CMS) | Низкая |
| `CadesSignedData.VerifyCades`, `Signers` | `verify(...)` + свой разбор CMS для списка подписантов | Средняя |
| `CAdESCOM.HashedData`: `Algorithm`, `Hash`, `SetHashValue`, `Value` + `SignHash` | `digest(HASH_TYPE_GOST3411_12_256/512)` + `sign(..., DATA_FORMAT_HASH, {detached:true})` | Средняя: проверить порядок байт хеша |
| `CAdESCOM.RawSignature`: `SignHash`, `VerifyHash` | `rawSign` | Средняя: порядок байт подписи |
| `CAdESCOM.SignedXML` (XMLDSig, XAdES-BES) | Своя реализация на JS: канонизация XML, `digest`, `rawSign`, сборка `<Signature>` | Высокая |
| `CAdESCOM.CPEnvelopedData` (шифрование/расшифрование) | `cmsEncrypt` / `cmsDecrypt` | Средняя: проверить совместимость CMS и алгоритмов |
| `X509Enrollment.*` (генерация ключа, запрос, установка сертификата на порталах УЦ) | `generateKeyPair` + `createPkcs10` + `importCertificate` | Высокая: объёмная COM-модель CertEnroll |

## 7. Ограничения и риски

1. **Тип ключа на токене — главный риск.** Рутокен Плагин работает через PKCS#11 и видит только ключи, которые
   лежат на токене как объекты PKCS#11 (сгенерированы самим токеном, неизвлекаемые). Если на Рутокене записан
   **обычный контейнер КриптоПро** (файлы контейнера, криптография в программном CSP), Рутокен Плагин этот ключ
   не видит и подписать им не сможет. Ключи в режиме ФКН КриптоПро тоже не подойдут (там свой протокол).
   Итог: расширение будет работать только для сертификатов, выпущенных на ключ PKCS#11 на Рутокен ЭЦП 2.0/3.0.
   Рутокен Lite и Рутокен S без аппаратной криптографии не подходят вовсе. Целевой случай проекта — ключи PKCS#11
   (решение владельца, см. `CLAUDE.md`).
2. **Формат строк и чисел должен совпадать с КриптоПро.** Сайты парсят `SubjectName` регулярками, ждут
   `Thumbprint` в верхнем регистре, даты в определённом виде, Base64 с переводами строк или без. Нужны эталонные
   значения, снятые с настоящего КриптоПро.
3. **Кодировка данных.** У КриптоПро по умолчанию `ContentEncoding = CADESCOM_STRING_TO_UCS2LE`: строка перед
   подписью превращается в UTF-16LE. Если это не повторить, подпись будет от других байтов и не пройдёт проверку
   на сервере.
4. **Порядок байт в ГОСТ.** Хеш в `HashedData.Value`, сырая подпись в `RawSignature` и `SignatureValue` в XMLDSig
   у КриптоПро и у Рутокена могут идти в разном порядке. Проверяется тестовыми векторами.
5. **Нет поддержки у Рутокена:** CAdES-X Long Type 1, CAdES-A, произвольные подписанные атрибуты, XML-подпись,
   метка времени через HTTPS. Это всё придётся делать своим кодом.
6. **Проверка цепочки** (`IsValid`, `CheckCertificate`) у КриптоПро опирается на хранилища ОС и CRL/OCSP.
   Если проверять слишком строго, сайты не покажут сертификат в списке; если слишком мягко, пользователь узнает об
   ошибке только от сервера. На старте разумно проверять только сроки.
7. **PIN и безопасность.** Вызовы Рутокен Плагина идут через `window.postMessage` в мире страницы, так что сайт
   технически видит всё, что передаётся плагину, включая PIN. Так же устроены и сайты, работающие с Рутокен
   Плагином напрямую, это свойство самого адаптера Рутокена. Чтобы наше расширение не превратилось в способ для
   любого сайта подписывать без ведома пользователя, нужно: включение по сайтам (аналог «доверенных узлов» КриптоПро),
   окно PIN в изоляции от страницы, подтверждение каждой подписи с показом сертификата.
8. **Порядок загрузки.** Объект Рутокена появляется на `document_start` из чужого расширения. Наш `cadesplugin`
   должен резолвиться только после `loadPlugin()`, а при отсутствии адаптера отклоняться с текстом, который сайты
   ожидают от КриптоПро («Плагин недоступен», «Истекло время ожидания загрузки плагина»).
9. **Конфликт с настоящим КриптоПро.** Если у пользователя всё же стоит КриптоПро, наш shim перехватит сайт.
   Нужен выключатель по сайту и, возможно, автоматическое отключение при обнаружении расширения КриптоПро.
10. **Сайты не на cadesplugin.** Госуслуги (свой плагин IFCPlugin), СБИС, Контур.Плагин и т.п. используют другие
    API. В этот проект они не входят, пока не решим иначе.
11. **Юридическая сторона.** Мы не меняем сертификат и ключ, подпись делает сертифицированное средство Рутокен.
    Но `About.CSPName` и версии мы вернём такие, чтобы сайт пропустил проверку «установлен ли КриптоПро CSP».
    Требования конкретных информационных систем к средству подписи остаются на стороне пользователя.

## 8. Как тестировать без живых сайтов и без железа

Вместо физического токена — **fake Рутокен**: PKCS#11-модуль из форка
[`code-agent-43824/SoftHSMv2`](https://github.com/code-agent-43824/SoftHSMv2) с профилем `FAKE_RUTOKEN_ECP = true`.
По документации форка настоящий Рутокен Плагин 4.12.2.0 принимает этот модуль за Рутокен ECP: находит устройство,
логинится, перечисляет ключи и сертификаты, генерирует ключи, подписывает.

Отсюда стенд, на котором работает **вся настоящая цепочка**, кроме USB-устройства:

```
Chromium (Playwright) ── наше расширение
        │               └─ Адаптер Рутокен Плагин (CRX из Chrome Web Store)
        └─ native messaging ──► FireWyrmNativeMessageHost + libnpRutokenPlugin.so (deb 4.12.3 для Linux)
                                     └─ librtpkcs11ecp.so  ◄── подменён на libsofthsm2.so (fake Рутокен)
```

Факты, на которых это держится (проверено 2026-09-23, подробности в `JOURNAL.md`):

- Рутокен Плагин для Linux скачивается с `download.rutoken.ru` и **несёт свою копию** `librtpkcs11ecp.so` в
  `/opt/aktivco/rutokenplugin/` — её и подменяем.
- Манифест native host разрешает подключение только расширениям Рутокена (`allowed_origins`), поэтому адаптер
  загружаем с его родным id. Id расширения задаётся открытым ключом, а тот лежит в заголовке CRX.
- Портируемая сборка fake Рутокена и тест-кит (с утилитами OpenSC) скачиваются из релизов форка.

Остальное:

1. **Мок Рутокен Плагина** (объект с тем же API) — только для быстрых модульных тестов эмуляции; всё, что касается
   форматов и криптографии, проверяется на стенде.
2. **Целевая страница** — демо-страница КриптоПро (раздел 9). Её файлы не наши, в git не кладутся: скачиваются
   скриптом с проверкой SHA-256, чтобы тест не зависел от сети и замечал изменения страницы.
3. **Проверка результата** — независимым от Рутокена средством (кандидаты: OpenSSL с ГОСТ-движком, pygost) и
   сравнением структуры с подписями настоящего КриптоПро.
4. **Живой Рутокен ЭЦП 2.0/3.0** в настоящем Chrome — ручная проверка владельцем в конце этапа.

## 9. Что вызывает целевая страница

Первая цель — демо-страница КриптоПро
[`cades_bes_sample.html`](https://www.cryptopro.ru/sites/default/files/products/cades/demopage/cades_bes_sample.html).
Её код (`Code.js`, `async_code.js`, `load_extension.js` там же) при загрузке и подписи обращается к следующему.

**Загрузка и диагностика** (`CheckForPlugIn_Async`):
`CAdESCOM.About` → `PluginVersion` (объект версии, у него асинхронный `toString()`), `CSPVersion("", 80)` → объект с
`MajorVersion`, `MinorVersion`, `BuildVersion`, `CSPName(80)`; `cadesplugin.get_extension_version`,
`cadesplugin.get_extension_id`; `CAdESCOM.CPLicense` (`ValidTo`, `IsValid`, `FirstInstallDate`, `Type`) — ошибка здесь
перехватывается страницей и загрузку не ломает. Страница сама ходит на `api.cryptopro.ru` за списком версий.

**Список сертификатов** (`FillCertList_Async`): `CAdESCOM.Store` → `Open()` без аргументов (хранилище My), затем
`Open(CADESCOM_CONTAINER_STORE)` (ошибка перехватывается); `Certificates` → `Count`, `Item(i)`; у сертификата
`Thumbprint`, `SubjectName`, `ValidFromDate`, `ValidToDate`; `Close()`.

**Карточка сертификата** (`FillCertInfo_Async`): `SubjectName`, `IssuerName`, `ValidFromDate`, `ValidToDate`,
`Thumbprint`, `HasPrivateKey()`, `PublicKey()` → `Algorithm` → `FriendlyName`, `PrivateKey` → `ProviderName`,
`UniqueContainerName`, `PrivateKeyUsagePeriodFrom/To`, `IsValid()` → `Result`; `X509Enrollment.CCspInformation`
(`InitializeFromName`, `ControlKeyTimeValidity`, `ContainerByName`) — ошибки перехватываются.

**Подпись** (`SignCadesBES_Async`): `CAdESCOM.CPSigner`, два `CADESCOM.CPAttribute` — время подписи (`Value` = `Date`)
и **имя документа** (`CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME`), `AuthenticatedAttributes2.Add`,
`propset_Certificate`, `propset_CheckCertificate`, `propset_Options(CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY)`;
`CAdESCOM.CadesSignedData` → `propset_ContentEncoding(CADESCOM_BASE64_TO_BINARY)`, `propset_Content(base64)`,
по флажку `propset_DisplayData(1)`, `SignCades(signer, CADESCOM_CADES_BES | CADES_USE_OCSP_AUTHORIZED_POLICY, detached)`.

Отсюда следствие для подписи: метод `sign` Рутокен Плагина не умеет добавлять атрибут «имя документа», поэтому
подписанные атрибуты придётся собирать своим кодом, а у токена просить только подпись хеша (`rawSign`). По журналу
проекта SoftHSMv2 сам Рутокен Плагин устроен так же: CMS он строит сам, а токен лишь подписывает 32 байта.
