# LINE channel 存取控制

`~/.claude/channels/line/access.json` 控制誰能把訊息推進你的 Claude Code session。
這是必要的安全閘:任何人都能傳訊息給你的 LINE bot,但只有通過存取控制的來源才會被注入 session。

## 結構

```json
{
  "dmPolicy": "pairing",
  "allowFrom": ["U4af4980629..."],
  "allowGroups": { "Ca56f94637c...": ["U4af4980629...", "U..."] },
  "groupSettings": { "Ca56f94637c...": { "requireMention": false } },
  "pending": { "ab12cd": { "userId": "U...", "expiresAt": 1750000000000 } }
}
```

| 欄位 | 說明 |
|------|------|
| `dmPolicy` | 1:1 政策:`pairing`(預設)/ `allowlist` / `disabled` |
| `allowFrom` | 放行的 LINE userId 清單(1:1) |
| `allowGroups` | **map**:`groupId / roomId` → 該群「可驅動 bot」的成員 userId 清單(空清單=無人可驅動) |
| `groupSettings` | **map**:`groupId` → 該群行為設定 `{ requireMention }`(是否需 @ 才投遞;未設則預設 `true`) |
| `pending` | 配對碼 → `{ userId, expiresAt }`(由 server 產生,1 小時失效) |

> 舊版 `allowGroups` 為字串陣列;讀取時自動遷移成成員空的 map(`["C1"]` → `{"C1": []}`)。

## 1:1 政策

- **pairing(預設)**:未知使用者第一次傳訊息會收到一組配對碼(透過免費的 Reply 回覆)。
  你在終端機執行 `/line:access pair <code>` 後,該 userId 才被加入 `allowFrom` 放行。
- **allowlist**:只有 `allowFrom` 內的 userId 放行,其餘訊息**靜默丟棄**(不回任何東西)。
- **disabled**:所有 1:1 訊息一律丟棄。

## 群組 / 多人聊天室

存取分兩層:

1. **群組授權(群組級)**:groupId / roomId 是 `allowGroups` 的鍵 → 該群被處理(訊息記錄供摘要 / 引用)。不在 → 丟棄(被 @ 時回 groupId、並夾入群名供辨識,供自助授權)。
2. **成員授權(成員級)**:該群清單內的 userId 才能「驅動 bot 得到回應」。非清單成員 @ bot → 不投遞(被 @ 時回其 userId 供你授權,即「成員自助配對」)。**清單空 = 無人可驅動。**

兩者分工:**授權群組 = 這個群被記錄(供摘要 / 引用);成員清單 = 誰能命令 bot。** 所以摘要涵蓋全群對話,但只有清單成員能使喚 Claude。

其他:

- 群組文字**預設只在有 @ 到 bot** 時才投遞,這是 **per-group** 設定 —— `access.json` 的 `groupSettings[該群].requireMention`,未設則預設 `true`。想讓某群「每句都進 session」(免 @)就設 `false`:

  ```json
  {
    "allowGroups": { "Cxxx": ["Uxxx"] },
    "groupSettings": { "Cxxx": { "requireMention": false } }
  }
  ```

  (`groupSettings` 與 `allowGroups` 並排、各群獨立;沒列到的群一律走預設 `true`。)
- **群組媒體 / 檔案不主動投遞**(背景記錄+存檔);要讓 Claude 看某張圖,**引用**它 + @ bot(見 README「群組功能」)。
- 要讓 bot 收得到群組訊息,還需在 LINE Developers Console 開啟 **Allow bot to join group chats**。

## 管理

用 `/line:access` slash command 編輯(`status` / `pair` / `allow` / `remove` / `policy` /
`group-allow` / `group-remove` / `group-member-allow` / `group-member-remove`)。變更即時生效,不需重啟。
