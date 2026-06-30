# LINE channel for Claude Code

把 LINE Messaging API 的訊息推進正在執行的本機 Claude Code session,並透過 LINE Reply / Push API 回覆 —— 讓你從 LINE 指揮 Claude、Claude 在你不在終端機前時把結果回到 LINE。

[Claude Code channels](https://code.claude.com/docs/en/channels) 的自建 channel(research preview,需 Claude Code v2.1.80+)。

## 特色

- **inbound**:1:1 與群組 / 多人聊天室的文字 + 圖片 / 影片 / 語音 / 檔案,推進 session
- **outbound 免費優先**:先用免費的 **Reply API**(replyToken,~60 秒內);逾時或失敗自動改用 **Push API**(計費),Push 超過每月免費額度則放棄不送
- **存取控制**:pairing / allowlist / disabled,只有你授權的來源能注入 session
- **群組自助授權**:在未授權群組 @ bot,會自動回該群 groupId + 授權指示(類比 1:1 配對)
- **群組歷史摘要**:已授權群組的訊息記進本機 SQLite,`get_history` 工具讓 Claude 撈指定時間段做摘要
- **群組名稱解析**:用 LINE getGroupSummary 取群組顯示名;群組訊息進 session 時帶 `group_name` 標籤屬性(消毒後),`get_history` 摘要冠群名表頭,並提供 `get_group_summary` 工具讓 Claude 只憑群組 ID 主動查群名
- **引用回覆解析**:使用者引用某則訊息時,自動帶出被引用訊息的發話者 + 內容給 Claude
- **群組媒體硬控制 + 引用取用**:群組媒體 / 檔案**不主動進 session**(背景記錄+即時存檔,不洗版);要針對某張圖 / 檔提問時,**引用**它 + @ bot,channel 帶 `quoted_file_path` 給 Claude Read。1:1 媒體照常 Read + 回
- **安全**:`x-line-signature` HMAC 驗章、媒體存檔路徑收斂(防 path traversal)、機密只存本機 `.env`

## 需求

- [Bun](https://bun.sh)
- 一個 LINE Messaging API channel(channel secret + long-lived channel access token)
- 對外的 HTTPS 端點,兩種擇一:(a) reverse proxy / 隧道(nginx / Caddy 等)終結 TLS 後轉發到本機 `/callback`;或 (b) 設 `LINE_TLS_CERT` / `LINE_TLS_KEY` 讓 server 直接以 Bun 原生 TLS 聽 HTTPS(免反代)

## 設定步驟

### 1. 建立 LINE Messaging API channel

在 [LINE Developers Console](https://developers.line.biz/) 建立 Provider → Messaging API channel,取得:
- **channel secret**(「Basic settings」分頁)
- **channel access token**(「Messaging API」分頁,發行 long-lived token)
- 若要用群組,開啟「Allow bot to join group chats」

### 2. 安裝 plugin

需先安裝 [Bun](https://bun.sh)(且 `bun` 在 PATH)。在 Claude Code 內加入 marketplace 並安裝:

```
/plugin marketplace add VizGS/claude-code-line-channel
/plugin install line@vizgs-tools
```

安裝後本 plugin 的 slash command 即可用。設定憑證:

```
/line:configure <channel-secret> <channel-access-token>
```

憑證會存到 `~/.claude/channels/line/.env`(權限 600)。

> **本機開發**:也可 `claude --plugin-dir <本 repo 路徑> …` 直接從本地目錄載入(免 marketplace,改動可熱重載)。
> `.mcp.json` 用 `${CLAUDE_PLUGIN_ROOT}/server.ts`,僅 plugin 形式載入時會代換(不支援舊的 bare `server:line` 啟動)。

### 3. 設定 webhook URL

讓 LINE 能以 HTTPS 打到本機 `/callback`,兩種擇一:
- **反代終結 TLS**:nginx / Caddy 等把公開 HTTPS 轉發到本機 `http://127.0.0.1:8788/callback`。
- **server 原生 TLS(免反代)**:設 `LINE_TLS_CERT` / `LINE_TLS_KEY`(+ 通常 `LINE_PORT=443`、`LINE_HOST=0.0.0.0`),server 直接聽 HTTPS。

然後在 LINE Console 把公開 URL(`https://<你的網域>/callback`)設為 webhook URL、開啟 Use webhook。

> 預設只綁 loopback(`127.0.0.1`)。要 server 直接對外(原生 TLS 或代理在別台)時,設 `LINE_HOST=0.0.0.0`(注意對外曝光)。綁 443 等特權埠需 root 或 `CAP_NET_BIND_SERVICE`。

### 4. 啟動 channel 並配對

自建 channel 不在官方 allowlist,啟動時需 dev flag + plugin 形式:

```bash
claude --dangerously-load-development-channels plugin:line@vizgs-tools
```

從 LINE 傳第一則訊息給你的 bot,會收到配對碼;在 Claude Code 執行:

```
/line:access pair <code>
```

之後你的訊息就會進 session,Claude 的 reply 會回到 LINE。

## 環境變數

| 變數 | 預設 | 說明 |
|------|------|------|
| `LINE_CHANNEL_SECRET` | (必填) | 驗 webhook 簽章 |
| `LINE_CHANNEL_ACCESS_TOKEN` | (必填) | 呼叫 Reply / Push / content API |
| `LINE_HOST` | `127.0.0.1` | 監聽介面 |
| `LINE_PORT` | `8788` | 監聽埠 |
| `LINE_MAX_MEDIA_BYTES` | `20971520` | 單一媒體大小上限(20MB) |
| `LINE_TLS_CERT` | (無) | 設了它 + `LINE_TLS_KEY` → server 直接以 Bun 原生 TLS 聽 HTTPS(免反代);用 fullchain.pem |
| `LINE_TLS_KEY` | (無) | 搭配 `LINE_TLS_CERT`;privkey.pem |
| `LINE_RETENTION_DAYS` | `0` | > 0 才自動清理:啟動 + 每 24h 清掉超過 N 天的歷史列與 inbox 檔(0 = 永久保留) |
| `LINE_DEFER_LONG_REPLIES` | `false` | 設 `true`:長任務延後送出而非走 Push(零 Push 額度,見下) |
| `LINE_INTERIM_MS` | `50000` | 任務逾此毫秒未回 → 先免費回「處理中」並延後答案 |
| `LINE_INTERIM_TEXT` | `處理中,稍後再傳一則訊息跟我要結果即可` | 「處理中」提示文字 |
| `LINE_TEAMMATE_ROUTING` | `false` | 設 `true`:每對話路由給獨立 teammate 隔離串味(見下;需 `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`) |

## 存取控制

見 [ACCESS.md](ACCESS.md)。用 `/line:access` 管理(`status` / `pair` / `allow` / `remove` / `policy` / `group-allow` / `group-remove` / `group-member-allow` / `group-member-remove`)。

群組存取分兩層:**群組授權**(群組在 `allowGroups`,該群被記錄供摘要)+ **成員授權**(該群清單內的 userId 才能驅動 bot)。

## 工具授權(permission relay)

Claude 遇到工具(Bash / Write / Edit 等)授權提示時,會把提示 **Push 給所有已授權者(allowFrom)**。
在 LINE 回覆「`y <code>`」核可、「`n <code>`」拒絕(`code` 為提示中的 5 碼 request_id)。需 Claude Code v2.1.81+。

- 只有已授權的 1:1 使用者能下裁決(群組訊息不會被當裁決)。
- 多人授權時,**任一授權者皆可核可任一請求**(裁決不綁定觸發者)。
- 無人值守也可改用 `--dangerously-skip-permissions`(僅在信任環境)。

## 群組功能

### 自助授權(兩層)

1. **群組自助授權**:bot 加入群組後,任何人在群組 **@ bot** 會收到「群組 ID:`Cxxx`。請執行 `/line:access group-allow Cxxx`…」。授權後該群被記錄(供摘要),但**成員清單仍空 → 還沒人能驅動 bot**。
2. **成員自助授權**:已授權群組裡,**非成員** @ bot 會收到「你的 userId:`Uxxx`。請執行 `/line:access group-member-allow Cxxx Uxxx`…」。把該 userId 加進該群清單後,他才能驅動 bot。

兩者皆即時生效(server 每次 webhook 重讀 `access.json`)。**群組預設需 @ 到 bot 才投遞**,未 @ 的訊息靜默丟棄、不洗版;若想讓某群「每句都進 session」(免 @),在 `access.json` 的 `groupSettings` 把該群設 `requireMention: false`(per-group,見 [ACCESS.md](ACCESS.md))。

### 歷史摘要(`get_history` 工具)

已授權群組的**每則訊息**(不論有無 @)、以及**授權的 1:1 訊息**,會記進本機 SQLite `~/.claude/channels/line/history.db`
(group_id / ts / user_id / user_name / type / text / message_id / file_path;1:1 以 userId 當 chat_id 存在 group_id 欄)。
使用者在群組或 1:1 要求摘要某時間段時,Claude 呼叫 `get_history` 工具撈出該段訊息再摘要、用 `reply` 回覆。

| 參數 | 說明 |
|------|------|
| `chat_id` | 群組 ID,或 1:1 的 userId(必填) |
| `minutes` | 取最近 N 分鐘(預設 60) |
| `since` / `until` | 指定範圍(ISO 8601 或毫秒);與 minutes 擇一 |
| `limit` | 最多筆數(預設 1000,上限 5000) |

- 群組發話者名字以 `getGroupMemberProfile`(讀取類 API,**不計訊息額度**)取得並快取;拿不到則退回只記 userId。**1:1 不解析名字**(只記 userId)。
- **只涵蓋 bot 在場 + 開始記錄之後**的訊息;更早的 LINE 無法補。歷史庫 / inbox 可設 `LINE_RETENTION_DAYS` 自動清理(預設 0 = 永久保留)。

### 群組名稱

群組(`chat_id` 以 `C` 開頭)的顯示名以 `getGroupSummary`(讀取類 API,**不計訊息額度**)取得並快取,出現在三處:

1. **inbound 標籤**:群組訊息進 session 時,`<channel>` 標籤帶 `group_name` 屬性,讓 Claude 以人類可讀名辨識是哪個群。群名是使用者可控字串,**經消毒(白名單字元 + 截 40 字)後才放進屬性**,維持「meta 不被標籤屬性注入」的不變式;送回 LINE 的純文字(授權提示等)則用原始群名。
2. **`get_group_summary` 工具**:Claude 只憑群組 ID(`C` 開頭)想知道群名時呼叫,回群名 + 頭像 URL。以「本 session 已互動來源」把關,與 `get_history` 同。
3. **自助授權提示 + `get_history` 表頭**:未授權群組 @ bot 的授權提示會夾入群名;`get_history` 摘要在最前面冠 `群組:<群名> (<群組 ID>)` 表頭。

> **多人聊天室(`R` 開頭)無此 API** —— LINE 不提供 room 名稱,上述各處對 room 一律退回只顯示 ID;1:1(`U` 開頭)亦無群名。

### 媒體處理(群組硬控制)

群組裡的圖片 / 影片 / 語音 / 檔案**不會主動推進 session**(避免每則媒體都觸發 Claude)。
但 channel 會在訊息進來的當下就**抓取並存檔**(LINE 媒體內容有保存期限,不能事後補抓),file_path 記進歷史庫。
要讓 Claude 看某張圖 / 某個檔,**引用**它 + @ bot 提問即可(見下)。1:1 的媒體則照常推進 session、可直接 Read 並回覆。

### 引用回覆

使用者用 LINE 的「引用」回覆某則訊息時,webhook 帶 `quotedMessageId`(LINE 只給 ID、不給內容)。
本 channel 以該 ID 從歷史庫查出被引用訊息:
- 引用**文字**:把「(引用 名字:「內容」)」帶進 session。
- 引用**媒體**:標籤帶 `quoted_file_path` 屬性指向存檔路徑,Claude Read 它即是那張圖 / 檔。

查不到(bot 開始記錄前的舊訊息)則照常投遞、不加前綴。群組與 1:1 訊息皆會記錄,故引用兩者開始記錄後的訊息都查得到。

## 多對話隔離(實驗性)

所有對話(多群組 + 多 1:1)預設**共用同一 session context**,主題可能串味。`single-harden`(出口白名單 + reply_to 綁定)已擋掉「回錯對象」(隱私洩漏),但「回錯內容(串味)」是共用 context 的結構限制。

設 `LINE_TEAMMATE_ROUTING=true` 可緩解:instructions 會指示主 session 把**每個對話路由給一個獨立具名 teammate**(各自 context),由 teammate 直接 `reply` 回 LINE → 答案在隔離 context 生成,串味在答案層被擋。

⚠️ **限制(知情再開)**:
- 需啟動 claude 時設 `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`(否則 spawn teammate 失敗 → bot 壞)
- **軟控制**:靠主 session 自律逐則路由,長 session / compaction 後可靠度會下降(非強制);要強制隔離需改用 Agent SDK 自管 per-conversation session(架構級改動)
- teammate 各自 context → token 成本 ≈ 對話數;`/resume` 或重啟會失去 teammates

## 免費策略與限制

- **Reply 免費、Push 計費**:長任務(Claude 做超過 ~60 秒)會逾時改走 Push,吃 LINE 每月免費額度;額度用罄則該則結果不送達(Claude 會收到 isError)。純秒回問答才完全免費。
- **零 Push 模式(`LINE_DEFER_LONG_REPLIES=true`)**:任務逾 `LINE_INTERIM_MS`(預設 50 秒)未回 → 先用免費 Reply 回「處理中」;答案延後到**使用者下次傳訊息**時,用新的免費 Reply 送出 → **完全不耗 Push 額度**。代價:長任務變「兩步」(問 → 收到「稍等」→ 再問一次 → 拿答案);秒回的短問答不受影響。
- 回覆超過 LINE 上限(單則 5000 字、單次 5 則)會被切塊,超量截斷。
- 群組存取為兩層:群組級(被記錄供摘要)+ 成員級(清單內成員才能驅動 bot)。

## 已知 follow-up(未實作)

- 影片 / 語音的 transcoding 狀態輪詢(目前直接取,未就緒則標記 unavailable)。
- 媒體大小以 `content-length` 預檢 + 實際 `byteLength` backstop 二次核驗(標頭缺失/不實時仍擋);尚未做 streaming 邊讀邊擋,故超大檔仍會整包讀進記憶體才被擋下。
- 群組發話者名字偶爾解析不到(profile API rate limit / 未識別成員)→ 退回 userId,摘要 / 引用前綴以「某人」呈現。
- 摘要 / 引用只涵蓋 bot 在場 + 開始記錄後的訊息(群組與 1:1 皆然,更早的查無)。
- 清理以「天數」為單位(`LINE_RETENTION_DAYS`),無容量上限 / 無 per-chat 配額。
