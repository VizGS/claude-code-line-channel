---
name: configure
description: 設定 LINE channel 的 channel secret 與 access token
user-invocable: true
allowed-tools: Read, Write, Bash(mkdir *), Bash(chmod *)
---

# /line:configure

把 LINE channel secret 與 channel access token 存到 `~/.claude/channels/line/.env`。

用法:`/line:configure <channel-secret> <channel-access-token>`

執行步驟:

1. 從參數取得 channel secret 與 channel access token(兩者皆必填;缺則請使用者補)。
   - channel secret 在 LINE Developers Console 的 channel「Basic settings」分頁。
   - channel access token(long-lived)在「Messaging API」分頁發行。
2. 建立目錄 `~/.claude/channels/line`(`mkdir -p`)。
3. 寫入 `~/.claude/channels/line/.env`:

   ```
   LINE_CHANNEL_SECRET=<secret>
   LINE_CHANNEL_ACCESS_TOKEN=<token>
   ```

4. `chmod 600 ~/.claude/channels/line/.env`。
5. 回報已存好(只顯示遮罩後的值,例如前 4 後 4 碼),並提醒:需以
   `claude --dangerously-load-development-channels plugin:line@vizgs-tools`(或正式核可後的 `--channels`)
   重啟,server 才會讀到新憑證。

注意:絕不把 token / secret 原文回顯到對話或 log。
