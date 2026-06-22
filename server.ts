#!/usr/bin/env bun
/**
 * LINE channel for Claude Code。
 *
 * 把 LINE Messaging API 的 webhook 事件推進正在執行的 Claude Code session,並讓
 * Claude 透過 reply tool 經由 LINE Reply / Push API 回覆。含:webhook 驗章去重、
 * outbound 免費級聯(Reply→Push→額度用罄放棄)、存取控制(pairing / allowlist)、
 * 群組 mention 過濾、媒體(圖片 / 影片 / 語音 / 檔案)接收、工具授權 relay。
 */

import { createHmac, timingSafeEqual, randomBytes } from 'crypto';
import { mkdirSync, writeFileSync, readFileSync, renameSync, readdirSync, statSync, unlinkSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { Database } from 'bun:sqlite';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

// 狀態目錄(.env / access.json / inbox / history.db 皆在此)。
const STATE_DIR = join(homedir(), '.claude', 'channels', 'line');
const INBOX_DIR = join(STATE_DIR, 'inbox');

// 必須在讀取任何 env-based 設定「之前」載入 .env —— 否則下方 const 會在 .env 載入前求值、讀不到檔內設定。
// 僅在實際啟動 server(import.meta.main)時載入;被測試 import 時不載,避免污染測試環境。
if (import.meta.main) {
  loadDotEnv();
}

// 監聽介面與埠;由你的公開 HTTPS 端點(reverse proxy / 隧道)轉發進來。預設只綁
// loopback(代理在同一台);代理在別台才需把 LINE_HOST 設成 0.0.0.0 等對外介面。
const HOST = process.env.LINE_HOST ?? '127.0.0.1';
const PORT = Number(process.env.LINE_PORT ?? 8788);

// 直接以 Bun 原生 TLS 對外提供 HTTPS(免反向代理):兩者都設才啟用,server 直接聽 HTTPS。
// LINE_TLS_CERT 用「完整鏈」fullchain.pem(leaf + 中繼)、LINE_TLS_KEY 用 privkey.pem;未設則維持 plain HTTP(由前面的反代終結 TLS)。
const TLS_CERT = process.env.LINE_TLS_CERT;
const TLS_KEY = process.env.LINE_TLS_KEY;

// 任務逾此毫秒未回覆,自動用 token 送「處理中」提示(趁 LINE replyToken 仍有效),把答案延後到使用者下次傳訊息時免費送出。
// 設 0 可停用「處理中」提示但仍延後(token 逾時照樣 defer,只是不主動發提示)。
const INTERIM_MS = Number(process.env.LINE_INTERIM_MS ?? 50000);
const INTERIM_TEXT = process.env.LINE_INTERIM_TEXT ?? '處理中,稍後再傳一則訊息跟我要結果即可';

// token 不可用時的策略:設 LINE_DEFER_LONG_REPLIES=true 改為「延後」(回 deferred、零 Push);預設仍走 Push 級聯。
const DEFER_LONG_REPLIES = process.env.LINE_DEFER_LONG_REPLIES === 'true';

// 多對話路由模式:設 LINE_TEAMMATE_ROUTING=true 時,instructions 指示主 session 把每個對話路由給獨立 teammate(隔離串味)。
// 需另設 CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1;為軟控制(主 session 自律),長跑可靠度未保證。預設關閉。
const TEAMMATE_ROUTING = process.env.LINE_TEAMMATE_ROUTING === 'true';

// 歷史庫與 inbox 媒體的保留天數;設 > 0 才會自動清理超過 N 天的列與檔。預設 0 = 永久保留、不清。
const RETENTION_DAYS = Number(process.env.LINE_RETENTION_DAYS ?? 0);

// LINE 單則訊息上限 5000 字、單次最多 5 則。
const LINE_MAX_TEXT = 5000;
const LINE_MAX_MESSAGES = 5;

// 單一媒體大小上限(防大檔吃爆記憶體)。
const LINE_MAX_MEDIA_BYTES = Number(process.env.LINE_MAX_MEDIA_BYTES ?? 20 * 1024 * 1024);

/** LINE webhook 事件(僅取本外掛會用到的欄位)。 */
type LineSource = {
  type: 'user' | 'group' | 'room';
  userId?: string;
  groupId?: string;
  roomId?: string;
};

type LineMessageIn = {
  id: string;
  type: string;
  text?: string;
  fileName?: string;
  contentProvider?: { type?: string; originalContentUrl?: string };
  mention?: { mentionees?: { isSelf?: boolean }[] };
  quotedMessageId?: string;
};

type LineEvent = {
  type: string;
  webhookEventId: string;
  mode?: string;
  timestamp?: number;
  replyToken?: string;
  source?: LineSource;
  message?: LineMessageIn;
};

type LineWebhookBody = { destination?: string; events?: LineEvent[] };

/** 一則要推進 session 的 channel 訊息:content 是本文,meta 變成標籤屬性。 */
type ChannelMessage = { content: string; meta: Record<string, string> };

/** 收到一則可投遞訊息時的處理函式(預設推進 session,測試可注入 spy)。 */
type OnMessage = (msg: ChannelMessage, event: LineEvent) => Promise<void> | void;

/** 解析出的媒體資訊。 */
type MediaInfo = {
  kind: 'image' | 'video' | 'audio' | 'file';
  messageId: string;
  provider: 'line' | 'external';
  externalUrl?: string;
  fileName?: string;
};

/** 取媒體內容的結果。 */
type FetchedContent = { ok: boolean; status: number; bytes?: Uint8Array };

/** 媒體處理相依(預設打真 LINE content API + 寫檔,測試可注入)。 */
type MediaDeps = {
  fetchContent: (messageId: string) => Promise<FetchedContent>;
  saveFile: (messageId: string, bytes: Uint8Array, ext: string) => string;
};

/** handleCallback 的可選相依(測試注入群組設定、媒體相依、去重器、存取設定、送出相依)。 */
type HandleOptions = {
  requireMention?: boolean;
  mediaDeps?: MediaDeps;
  markSeen?: (id: string) => boolean;
  access?: Access;
  sendDeps?: SendDeps;
  onVerdict?: (verdict: { request_id: string; behavior: 'allow' | 'deny' }) => Promise<void> | void;
  persistAccess?: (access: Access) => void;
  logGroup?: (event: LineEvent) => Promise<void> | void;
  logDirect?: (event: LineEvent, filePath: string | undefined) => void;
  lookupQuote?: (messageId: string) => QuotedRow | null;
};

/** LINE 文字訊息物件。 */
type LineMessage = { type: 'text'; text: string };

/** 一次 LINE API 呼叫的結果(不丟例外,把錯誤訊息帶回供級聯判斷)。 */
type LineApiResult = { ok: boolean; status: number; message?: string };

/** outbound 送出所需的相依(預設打真 LINE API,測試可注入假的)。 */
type SendDeps = {
  reply: (replyToken: string, messages: LineMessage[]) => Promise<LineApiResult>;
  push: (to: string, messages: LineMessage[]) => Promise<LineApiResult>;
};

/** outbound 送出的結果。 */
type SendResult = { delivered: boolean; via?: 'reply' | 'push'; reason?: string };

/** 讀取 channel secret(呼叫時讀,方便測試覆寫 env)。 */
function channelSecret(): string {
  return process.env.LINE_CHANNEL_SECRET ?? '';
}

/** 讀取 channel access token(呼叫時讀)。 */
function accessToken(): string {
  return process.env.LINE_CHANNEL_ACCESS_TOKEN ?? '';
}

/**
 * 驗證 LINE webhook 簽章。LINE 用 channel secret 為金鑰、對「原始 request
 * body bytes」做 HMAC-SHA256 再 Base64,放在 x-line-signature header。
 *
 * @param {string} rawBody - 未經改動的原始 request body
 * @param {string | null} signature - x-line-signature header 值
 * @param {string} secret - channel secret
 *
 * @returns {boolean} 簽章相符為 true
 */
export function verifySignature(rawBody: string, signature: string | null, secret: string): boolean {
  if (!signature || !secret) {
    return false;
  }

  const expected = createHmac('sha256', secret).update(rawBody).digest('base64');
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);

  // 長度不同直接視為不符(timingSafeEqual 對不等長會丟例外)。
  if (a.length !== b.length) {
    return false;
  }

  return timingSafeEqual(a, b);
}

/**
 * 建立一個事件去重器。LINE 在 webhook 端點回應慢或失敗時會重送同一事件,
 * 用 webhookEventId 去重避免重複 push。
 *
 * @param {number} max - 記憶的事件 ID 上限(FIFO 淘汰)
 *
 * @returns {(id: string) => boolean} 傳入未見過的 ID 回 true,重複回 false
 */
export function createDedupe(max = 1000): (id: string) => boolean {
  const seen = new Set<string>();

  return (id: string): boolean => {
    if (seen.has(id)) {
      return false;
    }

    seen.add(id);

    if (seen.size > max) {
      const oldest = seen.values().next().value;

      if (oldest !== undefined) {
        seen.delete(oldest);
      }
    }

    return true;
  };
}

const markEventSeen = createDedupe();

/**
 * 依 source 型別取出回覆 / 推播要用的對話 ID:1:1 用 userId、群組用
 * groupId、多人聊天室用 roomId。
 *
 * @param {LineSource} [source] - 事件來源
 *
 * @returns {string | undefined} 對話 ID
 */
export function chatIdOf(source?: LineSource): string | undefined {
  if (!source) {
    return undefined;
  }

  if (source.type === 'group') {
    return source.groupId;
  }

  if (source.type === 'room') {
    return source.roomId;
  }

  return source.userId;
}

/**
 * 此訊息事件是否 @ 到本 bot(看 mentionees[].isSelf,不需知道自己的 userId)。
 *
 * @param {LineEvent} event - LINE 事件
 *
 * @returns {boolean} 有 @ 到 bot 為 true
 */
export function isMentioned(event: LineEvent): boolean {
  return event.message?.mention?.mentionees?.some(m => m.isSelf === true) ?? false;
}

/**
 * 判斷事件是否該投遞並回傳對話 ID:必須是 message 事件、取得到 chat_id;群組 /
 * 多人聊天室在 requireMention 開啟時還需 @ 到 bot。不可投遞回 null。
 *
 * @param {LineEvent} event - LINE 事件
 * @param {boolean} requireMention - 群組是否需 @ 才投遞
 *
 * @returns {string | null} 可投遞時的對話 ID,否則 null
 */
export function deliverableChatId(event: LineEvent, requireMention: boolean): string | null {
  if (event.type !== 'message') {
    return null;
  }

  const chatId = chatIdOf(event.source);

  if (!chatId) {
    return null;
  }

  const inGroup = event.source?.type === 'group' || event.source?.type === 'room';

  if (inGroup && requireMention && !isMentioned(event)) {
    return null;
  }

  return chatId;
}

/**
 * 組 channel 訊息的 meta。meta 的 key 只能是識別字(字母 / 數字 / 底線),
 * 否則會被 Claude Code 丟掉。
 *
 * @param {LineEvent} event - LINE 事件
 * @param {string} chatId - 對話 ID
 *
 * @returns {Record<string, string>} meta
 */
function buildMeta(event: LineEvent, chatId: string): Record<string, string> {
  // 不變式:meta value 只放平台產生的 ID(chat_id / message_id / user 等);使用者
  // 可控字串(如 fileName)只進 content 本文,不進 meta,避免標籤屬性注入。
  const meta: Record<string, string> = {
    chat_id: chatId,
    message_id: event.message?.id ?? '',
  };

  if (typeof event.timestamp === 'number' && Number.isFinite(event.timestamp)) {
    meta.ts = new Date(event.timestamp).toISOString();
  }

  if (event.source?.userId) {
    meta.user = event.source.userId;
  }

  return meta;
}

/**
 * 把一則 LINE 文字事件轉成要推進 session 的 channel 訊息;非文字、不可投遞
 * 回 null(媒體由 buildMediaMessage 處理)。
 *
 * @param {LineEvent} event - LINE webhook 事件
 * @param {boolean} requireMention - 群組是否需 @ 才投遞
 *
 * @returns {ChannelMessage | null} 可投遞訊息,否則 null
 */
export function eventToChannelMessage(event: LineEvent, requireMention = false): ChannelMessage | null {
  const chatId = deliverableChatId(event, requireMention);

  if (!chatId || event.message?.type !== 'text') {
    return null;
  }

  return { content: event.message.text ?? '', meta: buildMeta(event, chatId) };
}

/**
 * 從訊息事件解析媒體資訊;非媒體回 null。
 *
 * @param {LineEvent} event - LINE 事件
 *
 * @returns {MediaInfo | null} 媒體資訊,否則 null
 */
export function parseMedia(event: LineEvent): MediaInfo | null {
  const message = event.message;

  if (!message || (message.type !== 'image' && message.type !== 'video' && message.type !== 'audio' && message.type !== 'file')) {
    return null;
  }

  return {
    kind: message.type,
    messageId: message.id,
    provider: message.contentProvider?.type === 'external' ? 'external' : 'line',
    externalUrl: message.contentProvider?.originalContentUrl,
    fileName: message.fileName,
  };
}

/** 媒體種類對應的預設副檔名;從 fileName 取尾段時白名單收斂避免路徑注入。 */
function extForMedia(media: MediaInfo): string {
  const map: Record<MediaInfo['kind'], string> = { image: '.jpg', video: '.mp4', audio: '.m4a', file: '.bin' };

  if (media.fileName && media.fileName.includes('.')) {
    const ext = media.fileName.slice(media.fileName.lastIndexOf('.')).replace(/[^A-Za-z0-9.]/g, '');

    if (ext.length > 1 && ext.length <= 10) {
      return ext;
    }
  }

  return map[media.kind];
}

/** 媒體種類對應的中文標籤。 */
function labelForMedia(media: MediaInfo): string {
  const map: Record<MediaInfo['kind'], string> = { image: '圖片', video: '影片', audio: '語音', file: '檔案' };

  return map[media.kind];
}

/**
 * 把一則媒體事件轉成 channel 訊息:provider 為 line 時抓 content 存進 inbox 並把
 * 路徑放 meta.file_path;為 external 時把 originalContentUrl 放 meta.url。非媒體、
 * 不可投遞回 null。
 *
 * @param {LineEvent} event - LINE 事件
 * @param {boolean} requireMention - 群組是否需 @ 才投遞
 * @param {MediaDeps} deps - 取內容 / 存檔相依
 *
 * @returns {Promise<ChannelMessage | null>} 可投遞訊息,否則 null
 */
export async function buildMediaMessage(event: LineEvent, requireMention: boolean, deps: MediaDeps): Promise<ChannelMessage | null> {
  const chatId = deliverableChatId(event, requireMention);

  if (!chatId) {
    return null;
  }

  const media = parseMedia(event);

  if (!media) {
    return null;
  }

  const meta = buildMeta(event, chatId);
  meta.media_type = media.kind;
  const label = labelForMedia(media);

  // external:LINE 不提供二進位,只給 URL,交給 Claude 自行取用;缺 URL 則直接標
  // 無法取得,不去打對 external 注定失敗的 content API。
  if (media.provider === 'external') {
    if (media.externalUrl) {
      meta.url = media.externalUrl;

      return { content: `[使用者傳了${label},URL 見 url 屬性]`, meta };
    }

    meta.media_status = 'unavailable';

    return { content: `[使用者傳了${label},但無可用連結]`, meta };
  }

  const fetched = await deps.fetchContent(media.messageId);

  if (!fetched.ok || !fetched.bytes) {
    process.stderr.write(`line channel: 取媒體失敗 ${media.messageId} status=${fetched.status}\n`);
    meta.media_status = 'unavailable';

    return { content: `[使用者傳了${label},但取得失敗]`, meta };
  }

  const path = deps.saveFile(media.messageId, fetched.bytes, extForMedia(media));
  meta.file_path = path;
  const name = media.fileName ? `:${media.fileName}` : '';

  return { content: `[使用者傳了${label}${name},見 file_path]`, meta };
}

/**
 * 抓 line 媒體二進位存進 inbox,回傳本機路徑;非 line 媒體(external / 無)或抓取失敗回 null。
 * 供記錄群組媒體時即時取檔(LINE 媒體內容有保存期限,須在事件當下抓),日後引用該則可取用。
 *
 * @param {LineEvent} event - LINE 事件
 * @param {MediaDeps} deps - 取內容 / 存檔相依
 *
 * @returns {Promise<string | null>} 存檔路徑,否則 null
 */
export async function fetchAndSaveMedia(event: LineEvent, deps: MediaDeps): Promise<string | null> {
  const media = parseMedia(event);

  if (!media || media.provider !== 'line') {
    return null;
  }

  const fetched = await deps.fetchContent(media.messageId);

  if (!fetched.ok || !fetched.bytes) {
    process.stderr.write(`line channel: 記錄群組媒體取檔失敗 ${media.messageId} status=${fetched.status}\n`);

    return null;
  }

  return deps.saveFile(media.messageId, fetched.bytes, extForMedia(media));
}

/**
 * 把回覆文字切成 LINE 訊息陣列:單則上限 5000 字、最多 5 則;超過容量則在
 * 最後一則尾端標記截斷(避免免費的單次 Reply 被切成多則而溢出)。
 *
 * @param {string} text - 回覆文字
 *
 * @returns {LineMessage[]} LINE 文字訊息陣列(至少一則)
 */
export function chunkMessages(text: string): LineMessage[] {
  const chunks: string[] = [];
  // LINE 拒收空文字訊息;空輸入退回單一空白(正常入口 runReplyTool 已先擋空白文字)。
  let rest = text.length > 0 ? text : ' ';

  while (rest.length > LINE_MAX_TEXT && chunks.length < LINE_MAX_MESSAGES - 1) {
    chunks.push(rest.slice(0, LINE_MAX_TEXT));
    rest = rest.slice(LINE_MAX_TEXT);
  }

  if (rest.length > LINE_MAX_TEXT) {
    const note = '…(訊息過長,已截斷)';
    rest = rest.slice(0, LINE_MAX_TEXT - note.length) + note;
  }

  chunks.push(rest);

  return chunks.map(t => ({ type: 'text', text: t }));
}

/**
 * 暫存每則 inbound 訊息的 replyToken,供 outbound 的免費 Reply 使用。replyToken
 * 單次且約 60 秒失效,故僅保留有限筆數、FIFO 淘汰;另記每個對話最近一則訊息,
 * 讓 Claude 未指定 reply_to 時也能找到可用的 token。
 *
 * @param {number} max - 暫存的 replyToken 上限
 *
 * @returns {object} 含 stash / resolve / markUsed 的暫存器
 */
export function createReplyStore(max = 1000) {
  const byMessage = new Map<string, { replyToken: string; used: boolean; chatId?: string }>();
  const lastByChat = new Map<string, string>();

  return {
    stash(messageId: string, chatId: string | undefined, replyToken: string | undefined): void {
      if (replyToken) {
        byMessage.set(messageId, { replyToken, used: false, chatId });

        if (byMessage.size > max) {
          const oldest = byMessage.keys().next().value;

          if (oldest !== undefined) {
            byMessage.delete(oldest);
          }
        }
      }

      if (chatId) {
        lastByChat.set(chatId, messageId);
      }
    },

    resolve(chatId: string, replyTo?: string) {
      const messageId = replyTo ?? lastByChat.get(chatId);

      if (!messageId) {
        return undefined;
      }

      const entry = byMessage.get(messageId);

      if (!entry) {
        return undefined;
      }

      return { messageId, replyToken: entry.replyToken, used: entry.used };
    },

    markUsed(messageId: string): void {
      const entry = byMessage.get(messageId);

      if (entry) {
        entry.used = true;
      }
    },

    // 該 inbound 訊息的平台驗章過來源對話;供回覆以 reply_to 反查覆寫目的地(防回錯對象)。
    sourceChatOf(messageId: string): string | undefined {
      return byMessage.get(messageId)?.chatId;
    },

    // 本 session 是否曾收過此對話的訊息(出口白名單;lastByChat 不淘汰,久未互動仍在)。
    isKnownChat(chatId: string): boolean {
      return lastByChat.has(chatId);
    },
  };
}

const replyStore = createReplyStore();

type TimerHandle = ReturnType<typeof setTimeout>;

/**
 * 待回覆計時器:投遞訊息後 arm(per chat);Claude 在視窗內回覆則 disarm,逾時則觸發 onTimeout
 * (送「處理中」提示)。scheduler 可注入以利測試。
 *
 * @param {object} scheduler - 計時器相依(預設 setTimeout / clearTimeout)
 *
 * @returns {{ arm: Function; disarm: Function }} 計時器介面
 */
export function createInterimTimers(
  scheduler: { set: (cb: () => void, ms: number) => TimerHandle; clear: (h: TimerHandle) => void } = { set: setTimeout, clear: clearTimeout },
) {
  const timers = new Map<string, TimerHandle>();

  const disarm = (chatId: string): void => {
    const h = timers.get(chatId);

    if (h !== undefined) {
      scheduler.clear(h);
      timers.delete(chatId);
    }
  };

  return {
    arm(chatId: string, ms: number, onTimeout: () => void): void {
      disarm(chatId);
      timers.set(chatId, scheduler.set(() => {
        timers.delete(chatId);
        onTimeout();
      }, ms));
    },

    disarm,
  };
}

const interimTimers = createInterimTimers();

/**
 * outbound 級聯:先用免費的 Reply(token 未用過時),失敗或不可用就
 * 改用計費的 Push;Push 回「超過每月額度」(429)則放棄不送。
 *
 * @param {ReturnType<typeof createReplyStore>} store - replyToken 暫存器
 * @param {string} chatId - 對話 ID(userId / groupId / roomId)
 * @param {string} text - 回覆文字
 * @param {string | undefined} replyTo - 指定回覆的 inbound message_id(可省略)
 * @param {SendDeps} deps - Reply / Push 相依
 *
 * @returns {Promise<SendResult>} 送出結果
 */
export async function sendOutbound(
  store: ReturnType<typeof createReplyStore>,
  chatId: string,
  text: string,
  replyTo: string | undefined,
  deps: SendDeps,
  deferInsteadOfPush = DEFER_LONG_REPLIES,
): Promise<SendResult> {
  const messages = chunkMessages(text);

  // 目的地以平台驗章過的來源為準:有 reply_to 就用該則 inbound 訊息的真實來源,覆蓋 Claude 自陳的 chat_id。
  const dest = (replyTo && store.sourceChatOf(replyTo)) || chatId;

  // reply_to 的來源與 Claude 自陳 chat_id 不一致 → 記一筆供排查(Claude 在混雜 context 下可能指錯對象)。
  if (replyTo && dest !== chatId) {
    process.stderr.write(`line channel: 目的地以 reply_to 來源 (${dest}) 覆寫 chat_id (${chatId})\n`);
  }

  // 出口白名單:只送往本 session 真的收過訊息的對話;不在集合內視為回錯對象,擋下不送(reply 與 Push 兩條都吃)。
  if (!store.isKnownChat(dest)) {
    process.stderr.write(`line channel: 拒送 — 目的地不在本 session 已互動來源,疑回錯對象 (${dest})\n`);

    return { delivered: false, reason: '目的地不在已知對話(請確認 chat_id 或帶 reply_to)' };
  }

  const token = store.resolve(dest, replyTo);

  // 先用 replyToken(免費),只要還沒用過就試;是否過期由 LINE 的 API 回應決定(失敗才往下走 Push),不在本機猜視窗。
  if (token && !token.used) {
    const replied = await deps.reply(token.replyToken, messages);
    store.markUsed(token.messageId);

    if (replied.ok) {
      return { delivered: true, via: 'reply' };
    }
  }

  // token 不可用(逾時 / 已用):延後模式下不送、不耗 Push 額度,由 Claude 在使用者下次傳訊息時用新 token 重送。
  if (deferInsteadOfPush) {
    return { delivered: false, reason: 'deferred' };
  }

  // Reply 不可用或失敗 → 改用 Push(計費)。
  const pushed = await deps.push(dest, messages);

  if (pushed.ok) {
    process.stderr.write(`line channel: 以 Push 送出(計費)to ${dest}\n`);

    return { delivered: true, via: 'push' };
  }

  // Push 回「超過每月額度」就放棄不送;鎖 429 + 子字串,避免 LINE 措辭微調或誤
  // 把 rate limit(訊息為 'rate limit')當成額度用罄。
  if (pushed.status === 429 && (pushed.message ?? '').toLowerCase().includes('monthly limit')) {
    return { delivered: false, reason: 'monthly-quota' };
  }

  return { delivered: false, reason: `push-${pushed.status}` };
}

/**
 * 對 LINE Messaging API 發 POST,回傳結果(不丟例外,把錯誤訊息帶回供級聯判斷)。
 *
 * @param {string} url - API 端點
 * @param {unknown} body - request body
 *
 * @returns {Promise<LineApiResult>} 呼叫結果
 */
export async function lineApiPost(url: string, body: unknown): Promise<LineApiResult> {
  let res: Response;

  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken()}` },
      body: JSON.stringify(body),
    });
  } catch (err) {
    // 網路層失敗(連線重置 / DNS / timeout)也收斂成結果,讓級聯能往 Push 走。
    process.stderr.write(`line channel: LINE API 連線失敗 ${String(err)}\n`);

    return { ok: false, status: 0, message: 'network-error' };
  }

  if (res.ok) {
    return { ok: true, status: res.status };
  }

  let message: string | undefined;
  try {
    message = ((await res.json()) as { message?: string }).message;
  } catch {
    message = undefined;
  }

  process.stderr.write(`line channel: LINE API ${res.status} ${message ?? ''}\n`);

  return { ok: false, status: res.status, message };
}

const lineDeps: SendDeps = {
  reply: (replyToken, messages) => lineApiPost('https://api.line.me/v2/bot/message/reply', { replyToken, messages }),
  push: (to, messages) => lineApiPost('https://api.line.me/v2/bot/message/push', { to, messages }),
};

/** 是否該為此次投遞啟動 interim 計時器:延後模式開、有 replyToken、interim 視窗 > 0。 */
export function shouldArmInterim(deferEnabled: boolean, replyToken: string | undefined, interimMs: number): boolean {
  return deferEnabled && !!replyToken && interimMs > 0;
}

/** interim 計時器逾時:用該 chat 仍有效的 token 送「處理中」提示並標記 token 已用(答案因而延後)。store/deps 可注入供測試。 */
export function sendInterim(chatId: string, store: ReturnType<typeof createReplyStore> = replyStore, deps: SendDeps = lineDeps): void {
  const token = store.resolve(chatId);

  if (token && !token.used) {
    store.markUsed(token.messageId);
    void deps.reply(token.replyToken, [{ type: 'text', text: INTERIM_TEXT }]);
  }
}

/**
 * 從 LINE content API 取一則訊息的二進位內容(不丟例外)。
 *
 * @param {string} messageId - 訊息 ID
 * @param {number} maxBytes - 大小上限(預設 LINE_MAX_MEDIA_BYTES;可注入以利測試)
 *
 * @returns {Promise<FetchedContent>} 取得結果
 */
export async function fetchLineContent(messageId: string, maxBytes = LINE_MAX_MEDIA_BYTES): Promise<FetchedContent> {
  try {
    const res = await fetch(`https://api-data.line.me/v2/bot/message/${encodeURIComponent(messageId)}/content`, {
      headers: { authorization: `Bearer ${accessToken()}` },
    });

    if (!res.ok) {
      return { ok: false, status: res.status };
    }

    // 先以 content-length 預檢(若有);此標頭可能缺失或不實,故下方再以實際 byteLength backstop。
    const declared = Number(res.headers.get('content-length') ?? 0);

    if (declared > maxBytes) {
      process.stderr.write(`line channel: 媒體過大(${declared} bytes)略過 ${messageId}\n`);

      return { ok: false, status: 413 };
    }

    const bytes = new Uint8Array(await res.arrayBuffer());

    // backstop:content-length 缺失(declared=0)或不實時,以實際大小再核一次上限,避免回傳超量 bytes。
    if (bytes.byteLength > maxBytes) {
      process.stderr.write(`line channel: 媒體實際過大(${bytes.byteLength} bytes)略過 ${messageId}\n`);

      return { ok: false, status: 413 };
    }

    return { ok: true, status: res.status, bytes };
  } catch (err) {
    process.stderr.write(`line channel: 取媒體連線失敗 ${String(err)}\n`);

    return { ok: false, status: 0 };
  }
}

/** 把外部來的 ID 收斂成安全檔名片段(白名單 + 長度上限,避免 path traversal 與超長檔名)。 */
export function safeId(id: string): string {
  const cleaned = id.replace(/[^A-Za-z0-9_-]/g, '');

  return (cleaned.length > 0 ? cleaned : 'unknown').slice(0, 100);
}

/** 把媒體二進位存進 inbox,回傳本機路徑。 */
function saveInbox(messageId: string, bytes: Uint8Array, ext: string): string {
  mkdirSync(INBOX_DIR, { recursive: true, mode: 0o700 });
  const path = join(INBOX_DIR, `${safeId(messageId)}${ext}`);
  writeFileSync(path, bytes);

  return path;
}

const lineMediaDeps: MediaDeps = { fetchContent: fetchLineContent, saveFile: saveInbox };

/**
 * 存取控制設定。allowGroups:groupId → 該群「可驅動 bot」的成員 userId 清單(空=無人可驅動)。
 * groupSettings:groupId → 該群行為設定(目前只有 requireMention:是否需 @ 才投遞,未設則預設 true)。
 */
type Access = {
  dmPolicy: 'pairing' | 'allowlist' | 'disabled';
  allowFrom: string[];
  allowGroups: Record<string, string[]>;
  groupSettings: Record<string, { requireMention?: boolean }>;
  pending: Record<string, { userId: string; expiresAt: number }>;
};

const DEFAULT_ACCESS: Access = { dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: {}, pending: {} };
const ACCESS_FILE = join(STATE_DIR, 'access.json');
const PAIR_TTL_MS = 3600_000;

/**
 * 把外部 access.json 內容正規化成安全的 Access:壞型別欄位退回安全預設,避免
 * 結構正確性錯誤(如 allowFrom 非陣列)讓 gate 噴錯或誤放行。
 *
 * @param {unknown} parsed - JSON.parse 後的內容
 *
 * @returns {Access} 正規化後的存取設定
 */
export function normalizeAccess(parsed: unknown): Access {
  const p = (parsed ?? {}) as Partial<Access>;
  const policy = p.dmPolicy;

  return {
    dmPolicy: policy === 'allowlist' || policy === 'disabled' || policy === 'pairing' ? policy : 'pairing',
    allowFrom: Array.isArray(p.allowFrom) ? p.allowFrom.filter(x => typeof x === 'string') : [],
    allowGroups: normalizeAllowGroups(p.allowGroups),
    groupSettings: normalizeGroupSettings(p.groupSettings),
    pending: p.pending && typeof p.pending === 'object' ? p.pending : {},
  };
}

/**
 * 正規化 allowGroups:舊格式(字串陣列)遷移成 map(成員空,strict);新格式(map)驗證
 * key 為 string、value 為 string[]。
 *
 * @param {unknown} raw - 原始 allowGroups
 *
 * @returns {Record<string, string[]>} groupId → 成員 userId 清單
 */
function normalizeAllowGroups(raw: unknown): Record<string, string[]> {
  // 無原型物件:避免 allowGroups['toString'] 等原型鏈鍵名被誤判為已授權群組(原型污染防護)。
  const out = Object.create(null) as Record<string, string[]>;

  if (Array.isArray(raw)) {
    for (const gid of raw) {
      if (typeof gid === 'string') {
        out[gid] = [];
      }
    }

    return out;
  }

  if (raw && typeof raw === 'object') {
    for (const [gid, members] of Object.entries(raw)) {
      out[gid] = Array.isArray(members) ? members.filter(x => typeof x === 'string') : [];
    }
  }

  return out;
}

/**
 * 正規化 groupSettings:無原型 map(原型污染防護),每群只取 requireMention 布林(非布林則忽略,留空物件 → 走預設)。
 *
 * @param {unknown} raw - 原始 groupSettings
 *
 * @returns {Record<string, { requireMention?: boolean }>} groupId → 行為設定
 */
function normalizeGroupSettings(raw: unknown): Record<string, { requireMention?: boolean }> {
  const out = Object.create(null) as Record<string, { requireMention?: boolean }>;

  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    for (const [gid, settings] of Object.entries(raw)) {
      const rm = (settings as { requireMention?: unknown } | null)?.requireMention;
      out[gid] = typeof rm === 'boolean' ? { requireMention: rm } : {};
    }
  }

  return out;
}

/**
 * 該事件所屬群組是否需 @ 才投遞:查 access.groupSettings[gid].requireMention,未設則預設 true。
 * 非群組(1:1)事件回 true(requireMention 對 1:1 無作用,1:1 照常投遞)。
 *
 * @param {LineEvent} event - 進來的事件
 * @param {Access} access - 存取設定
 *
 * @returns {boolean} 該群是否需 @ 才投遞
 */
export function resolveRequireMention(event: LineEvent, access: Access): boolean {
  const src = event.source;
  const gid = src?.type === 'group' ? src.groupId : src?.type === 'room' ? src.roomId : undefined;

  if (!gid) {
    return true;
  }

  return access.groupSettings[gid]?.requireMention ?? true;
}

/** 讀取 access.json;不存在或壞檔退回預設(只開放配對)。 */
function loadAccess(): Access {
  try {
    return normalizeAccess(JSON.parse(readFileSync(ACCESS_FILE, 'utf8')));
  } catch {
    return { ...DEFAULT_ACCESS };
  }
}

/** 原子寫入 access.json(0600)。 */
function saveAccess(access: Access): void {
  mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${ACCESS_FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify(access, null, 2), { mode: 0o600 });
  renameSync(tmp, ACCESS_FILE);
}

/** 移除過期的配對碼。 */
function prunePending(pending: Access['pending'], now: number): Access['pending'] {
  const kept: Access['pending'] = {};

  for (const [code, p] of Object.entries(pending)) {
    if (p.expiresAt > now) {
      kept[code] = p;
    }
  }

  return kept;
}

/** 產生配對碼(8 hex,32 bit)。 */
function genPairCode(): string {
  return randomBytes(4).toString('hex');
}

/** gate 的決策:投遞 / 丟棄 / 要求配對(pair 會帶回更新後的 access 供持久化)。 */
type GateDecision =
  | { action: 'deliver' }
  | { action: 'drop' }
  | { action: 'pair'; code: string; access: Access }
  | { action: 'group_pair'; groupId: string }
  | { action: 'member_pair'; groupId: string; userId: string };

/**
 * 依 access 設定決定一則事件該投遞 / 丟棄 / 要求配對。只處理 message 事件;群組 /
 * 多人聊天室只在白名單群組投遞;1:1 依 dmPolicy:disabled 全丟、allowlist 僅白名單、
 * pairing 對未配對者發配對碼。
 *
 * @param {LineEvent} event - LINE 事件
 * @param {Access} access - 存取設定
 * @param {number} now - 現在時間(ms)
 * @param {() => string} genCode - 配對碼產生器(可注入)
 *
 * @returns {GateDecision} 決策
 */
export function gate(event: LineEvent, access: Access, now: number, genCode: () => string = genPairCode): GateDecision {
  if (event.type !== 'message') {
    return { action: 'drop' };
  }

  const source = event.source;

  if (source?.type === 'group' || source?.type === 'room') {
    const gid = source.type === 'group' ? source.groupId : source.roomId;

    if (!gid) {
      return { action: 'drop' };
    }

    const members = access.allowGroups[gid];

    // 群組未授權:被 @ 時回 groupId + 授權指示(自助授權),否則靜默丟棄不洗版。
    if (members === undefined) {
      return isMentioned(event) ? { action: 'group_pair', groupId: gid } : { action: 'drop' };
    }

    const memberId = source.userId;

    // 群組已授權:僅清單內成員可驅動 bot。
    if (memberId && members.includes(memberId)) {
      return { action: 'deliver' };
    }

    // 已授權群組但發話者不在清單:被 @ 時回其 userId + 授權指示(成員自助),否則靜默丟棄。
    return isMentioned(event) && memberId ? { action: 'member_pair', groupId: gid, userId: memberId } : { action: 'drop' };
  }

  const userId = source?.userId;

  if (access.dmPolicy === 'disabled') {
    return { action: 'drop' };
  }

  if (userId && access.allowFrom.includes(userId)) {
    return { action: 'deliver' };
  }

  if (access.dmPolicy === 'allowlist' || !userId) {
    return { action: 'drop' };
  }

  // pairing:重用此 user 未過期的碼,否則產生新碼並帶回更新後的 access。
  const existing = Object.entries(access.pending).find(([, p]) => p.userId === userId && p.expiresAt > now);

  if (existing) {
    return { action: 'pair', code: existing[0], access };
  }

  // 避免新碼撞到既有未過期碼而靜默覆寫他人 pending。
  const pruned = prunePending(access.pending, now);
  let code = genCode();

  while (pruned[code]) {
    code = genCode();
  }

  const next: Access = { ...access, pending: { ...pruned, [code]: { userId, expiresAt: now + PAIR_TTL_MS } } };

  return { action: 'pair', code, access: next };
}

// ===== 群組訊息歷史(SQLite,供 get_history 摘要)=====

const HISTORY_DB = join(STATE_DIR, 'history.db');

/** 一筆歷史訊息(查詢回傳)。 */
type HistoryRow = { ts: number; user_id: string | null; user_name: string | null; type: string; text: string | null };

/** 被引用訊息查詢結果。 */
type QuotedRow = { user_id: string | null; user_name: string | null; text: string | null; file_path: string | null };

/**
 * 建立 / 連到群組訊息歷史庫,回傳 record / query / lookupMessage 介面(可注入 in-memory DB 供測試)。
 *
 * @param {Database} db - bun:sqlite 連線
 *
 * @returns {object} 歷史庫介面
 */
export function createHistoryStore(db: Database) {
  db.run(
    'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
      'group_id TEXT NOT NULL, ts INTEGER NOT NULL, user_id TEXT, user_name TEXT, type TEXT NOT NULL, text TEXT)',
  );

  // 既有 DB 補欄(已存在則忽略):message_id 供引用對照、file_path 供引用媒體取檔。
  for (const col of ['message_id TEXT', 'file_path TEXT']) {
    try {
      db.run(`ALTER TABLE messages ADD COLUMN ${col}`);
    } catch (err) {
      // 已存在(duplicate column)是預期路徑;其他錯誤記錄供排查,不靜默吞。
      if (!String(err).toLowerCase().includes('duplicate column')) {
        process.stderr.write(`line channel: ${col} 遷移非預期錯誤:${String(err)}\n`);
      }
    }
  }

  db.run('CREATE INDEX IF NOT EXISTS idx_messages_group_ts ON messages(group_id, ts)');
  db.run('CREATE INDEX IF NOT EXISTS idx_messages_mid ON messages(message_id)');

  const insert = db.query(
    'INSERT INTO messages (group_id, ts, user_id, user_name, type, text, message_id, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  );
  const select = db.query(
    'SELECT ts, user_id, user_name, type, text FROM messages WHERE group_id = ? AND ts >= ? AND ts <= ? ORDER BY ts ASC LIMIT ?',
  );
  const byMessageId = db.query(
    'SELECT user_id, user_name, text, file_path FROM messages WHERE message_id = ? ORDER BY id DESC LIMIT 1',
  );
  const purge = db.query('DELETE FROM messages WHERE ts < ?');

  return {
    record(groupId: string, ts: number, userId: string | undefined, userName: string | undefined, type: string, text: string, messageId?: string, filePath?: string): void {
      insert.run(groupId, ts, userId ?? null, userName ?? null, type, text, messageId ?? null, filePath ?? null);
    },

    query(groupId: string, sinceMs: number, untilMs: number, limit: number): HistoryRow[] {
      return select.all(groupId, sinceMs, untilMs, limit) as HistoryRow[];
    },

    lookupMessage(messageId: string): QuotedRow | null {
      return (byMessageId.get(messageId) as QuotedRow | undefined) ?? null;
    },

    /** 刪掉 ts 早於 cutoffMs 的歷史列,回傳刪除筆數。 */
    purgeOlderThan(cutoffMs: number): number {
      return purge.run(cutoffMs).changes;
    },
  };
}

type HistoryStore = ReturnType<typeof createHistoryStore>;

// 真實歷史庫延遲建立(被測試 import 時不建檔)。
let historyDb: HistoryStore | null = null;

function history(): HistoryStore {
  if (!historyDb) {
    mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    historyDb = createHistoryStore(new Database(HISTORY_DB, { create: true }));
  }

  return historyDb;
}

// 群組成員名字快取(避免每則訊息都打 profile API);key = `${groupId}:${userId}`,FIFO 上限淘汰。
const NAME_CACHE_MAX = 5000;
const nameCache = new Map<string, string>();

/**
 * 取群組成員顯示名(快取;失敗或拿不到回 undefined,退回只記 userId)。getGroupMemberProfile
 * 屬讀取類 API,不計入訊息額度。
 *
 * @param {string} groupId - 群組 ID
 * @param {string} userId - 成員 userId
 *
 * @returns {Promise<string | undefined>} 顯示名
 */
export async function resolveMemberName(groupId: string, userId: string): Promise<string | undefined> {
  const key = `${groupId}:${userId}`;
  const cached = nameCache.get(key);

  if (cached !== undefined) {
    return cached;
  }

  try {
    const res = await fetch(
      `https://api.line.me/v2/bot/group/${encodeURIComponent(groupId)}/member/${encodeURIComponent(userId)}`,
      { headers: { authorization: `Bearer ${accessToken()}` } },
    );

    if (!res.ok) {
      return undefined;
    }

    const name = ((await res.json()) as { displayName?: string }).displayName;

    if (name) {
      nameCache.set(key, name);

      if (nameCache.size > NAME_CACHE_MAX) {
        const oldest = nameCache.keys().next().value;

        if (oldest !== undefined) {
          nameCache.delete(oldest);
        }
      }
    }

    return name;
  } catch {
    return undefined;
  }
}

/**
 * 從群組事件取出要記錄的欄位;非群組 / 非訊息回 null。媒體記成 `(type)` 佔位。
 *
 * @param {LineEvent} event - LINE 事件
 *
 * @returns {object | null} 待記錄欄位
 */
export function groupMessageRow(event: LineEvent): { groupId: string; ts: number; userId?: string; type: string; text: string; messageId?: string } | null {
  const source = event.source;

  if (source?.type !== 'group' && source?.type !== 'room') {
    return null;
  }

  const groupId = source.type === 'group' ? source.groupId : source.roomId;

  if (!groupId || !event.message) {
    return null;
  }

  const m = event.message;
  const text = m.type === 'text' ? m.text ?? '' : `(${m.type})`;

  return { groupId, ts: event.timestamp ?? 0, userId: source.userId, type: m.type, text, messageId: m.id };
}

/** 預設:把已授權群組的訊息記進 SQLite(補發話者名字;媒體即時抓存以利日後引用取用)。 */
export async function defaultLogGroup(
  event: LineEvent,
  deps: { mediaDeps?: MediaDeps; store?: HistoryStore; resolveName?: (groupId: string, userId: string) => Promise<string | undefined> } = {},
): Promise<void> {
  const row = groupMessageRow(event);

  if (!row) {
    return;
  }

  const mediaDeps = deps.mediaDeps ?? lineMediaDeps;
  const store = deps.store ?? history();
  const resolveName = deps.resolveName ?? resolveMemberName;

  const name = row.userId ? await resolveName(row.groupId, row.userId) : undefined;
  const filePath = row.type === 'text' ? undefined : ((await fetchAndSaveMedia(event, mediaDeps)) ?? undefined);
  store.record(row.groupId, row.ts || Date.now(), row.userId, name, row.type, row.text, row.messageId, filePath);
}

/**
 * 記錄一則授權 1:1 訊息到歷史(chat_id = userId,存進 group_id 欄;不解析名字,user_name 留空)。
 * 用於投遞路徑:filePath 取自已建好的訊息 meta(1:1 媒體在 buildMediaMessage 已存檔),不重抓。store 可注入供測試。
 *
 * @param {LineEvent} event - 1:1 訊息事件
 * @param {string | undefined} filePath - 媒體本機路徑(文字則無)
 * @param {HistoryStore} store - 歷史庫(預設真實庫)
 *
 * @returns {void}
 */
export function defaultLogDirect(event: LineEvent, filePath: string | undefined, store: HistoryStore = history()): void {
  const userId = event.source?.type === 'user' ? event.source.userId : undefined;

  if (!userId || !event.message) {
    return;
  }

  const m = event.message;
  const text = m.type === 'text' ? m.text ?? '' : `(${m.type})`;
  store.record(userId, event.timestamp ?? Date.now(), userId, undefined, m.type, text, m.id, filePath);
}

/**
 * 刪掉 inbox 內 mtime 早於 cutoffMs 的檔,回傳刪除數。fs 操作可注入供測試。
 *
 * @param {string} dir - inbox 目錄
 * @param {number} cutoffMs - 早於此 mtime(毫秒)的檔刪除
 * @param {object} fs - readdir / stat / unlink(預設真實 fs)
 *
 * @returns {number} 刪除的檔數
 */
export function purgeInboxFiles(
  dir: string,
  cutoffMs: number,
  fs: { readdir: (d: string) => string[]; stat: (p: string) => { mtimeMs: number }; unlink: (p: string) => void } = {
    readdir: d => readdirSync(d),
    stat: p => statSync(p),
    unlink: p => unlinkSync(p),
  },
): number {
  let files: string[];

  try {
    files = fs.readdir(dir);
  } catch {
    return 0; // inbox 尚未建立 → 無事可清
  }

  let removed = 0;

  for (const name of files) {
    const path = join(dir, name);

    try {
      if (fs.stat(path).mtimeMs < cutoffMs) {
        fs.unlink(path);
        removed += 1;
      }
    } catch (err) {
      process.stderr.write(`line channel: 清理 inbox 檔失敗 ${path}:${String(err)}\n`);
    }
  }

  return removed;
}

/**
 * 清理超過 retentionDays 天的歷史列與 inbox 檔(retentionDays <= 0 則不清)。可注入供測試。
 *
 * @param {number} retentionDays - 保留天數(<= 0 不清)
 * @param {number} nowMs - 現在時間(毫秒)
 * @param {object} deps - 可注入的 store / inboxDir / purgeInbox
 *
 * @returns {object} 清理筆數
 */
export function runCleanup(
  retentionDays: number,
  nowMs: number,
  deps: { store?: HistoryStore; inboxDir?: string; purgeInbox?: typeof purgeInboxFiles } = {},
): { rows: number; files: number } {
  if (retentionDays <= 0) {
    return { rows: 0, files: 0 };
  }

  const cutoff = nowMs - retentionDays * 86_400_000;
  const store = deps.store ?? history();
  const inboxDir = deps.inboxDir ?? INBOX_DIR;
  const purgeInbox = deps.purgeInbox ?? purgeInboxFiles;

  const rows = store.purgeOlderThan(cutoff);
  const files = purgeInbox(inboxDir, cutoff);

  if (rows > 0 || files > 0) {
    process.stderr.write(`line channel: 清理 ${rows} 筆歷史 + ${files} 個 inbox 檔(逾 ${retentionDays} 天)\n`);
  }

  return { rows, files };
}

/**
 * 執行 get_history tool:解析時間段 → 查詢 → 回格式化訊息給 Claude 摘要。
 *
 * @param {object} args - chat_id 必填;minutes 取最近 N 分鐘,或 since/until(ISO 或毫秒)
 * @param {HistoryStore} store - 歷史庫
 * @param {number} nowMs - 現在時間(ms)
 * @param {Function} isKnownChat - 選填;限制只能查本 session 已互動的對話(防讀別群歷史)
 *
 * @returns {object} CallTool 回應
 */
export function runGetHistory(
  args: { chat_id?: string; minutes?: number; since?: string; until?: string; limit?: number },
  store: HistoryStore,
  nowMs: number,
  isKnownChat?: (chatId: string) => boolean,
): { content: { type: 'text'; text: string }[]; isError?: boolean } {
  if (!args.chat_id) {
    return { content: [{ type: 'text', text: 'get_history 需要 chat_id' }], isError: true };
  }

  if (isKnownChat && !isKnownChat(args.chat_id)) {
    return { content: [{ type: 'text', text: 'get_history 拒絕:此對話不在本 session 已互動來源' }], isError: true };
  }

  const parseTime = (v: string | undefined): number | undefined => {
    if (v === undefined || v.trim() === '') {
      return undefined;
    }

    const ms = Number(v);

    if (Number.isFinite(ms)) {
      return ms;
    }

    const parsed = Date.parse(v);

    return Number.isNaN(parsed) ? undefined : parsed;
  };

  const until = parseTime(args.until) ?? nowMs;
  const since = parseTime(args.since) ?? nowMs - (args.minutes ?? 60) * 60_000;

  if (since > until) {
    return { content: [{ type: 'text', text: 'get_history: since 晚於 until,請檢查時間範圍' }], isError: true };
  }

  const limit = Math.min(Math.max(args.limit ?? 1000, 1), 5000);
  const rows = store.query(args.chat_id, since, until, limit);

  if (rows.length === 0) {
    return { content: [{ type: 'text', text: '(此時間段無紀錄)' }] };
  }

  const lines = rows.map(r => `[${new Date(r.ts).toISOString()}] ${r.user_name || r.user_id || '(unknown)'}: ${r.text ?? ''}`);

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

/**
 * 執行 reply tool:驗參數 → 跑 outbound 級聯 → 回 Claude 看得懂的結果。
 *
 * @param {object} args - reply tool 參數(chat_id / text / reply_to)
 * @param {ReturnType<typeof createReplyStore>} store - replyToken 暫存器
 * @param {SendDeps} deps - Reply / Push 相依
 *
 * @returns {Promise<object>} CallTool 回應
 */
export async function runReplyTool(
  args: { chat_id?: string; text?: string; reply_to?: string },
  store: ReturnType<typeof createReplyStore>,
  deps: SendDeps,
  deferInsteadOfPush = DEFER_LONG_REPLIES,
): Promise<{ content: { type: 'text'; text: string }[]; isError?: boolean }> {
  if (!args.chat_id || !args.text || !args.text.trim()) {
    return { content: [{ type: 'text', text: 'reply 需要非空的 chat_id 與 text' }], isError: true };
  }

  try {
    const result = await sendOutbound(store, args.chat_id, args.text, args.reply_to, deps, deferInsteadOfPush);

    if (result.delivered) {
      return { content: [{ type: 'text', text: `sent (${result.via})` }] };
    }

    // 延後不是失敗:token 逾時無法現在送,系統已回覆使用者「處理中」;請保留答案待重送。
    if (result.reason === 'deferred') {
      return {
        content: [{ type: 'text', text: '已延後:任務太久、token 逾時,目前無法送出(系統已回覆使用者「處理中」)。請保留此答案,等使用者下次傳訊息時再 reply 一次同樣內容即可免費送達。' }],
      };
    }

    return { content: [{ type: 'text', text: `未送達:${result.reason}` }], isError: true };
  } catch (err) {
    process.stderr.write(`line channel: reply tool 例外 ${String(err)}\n`);

    return { content: [{ type: 'text', text: 'reply 失敗:內部錯誤' }], isError: true };
  }
}

// 授權者用文字「y/n <request_id>」核可 / 拒絕;request_id 為 5 個 a-z(不含 l)字母。
const PERMISSION_REPLY_RE = /^\s*(y|yes|n|no)\s+([a-km-z]{5})\s*$/i;

/** Claude Code 送來的工具授權請求 notification schema。 */
const PermissionRequestSchema = z.object({
  method: z.literal('notifications/claude/channel/permission_request'),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
});

/**
 * 解析授權回覆文字;非授權回覆回 null。
 *
 * @param {string} text - 使用者訊息文字
 *
 * @returns {{ request_id: string; behavior: 'allow' | 'deny' } | null} 裁決
 */
export function parsePermissionReply(text: string): { request_id: string; behavior: 'allow' | 'deny' } | null {
  const m = text.match(PERMISSION_REPLY_RE);

  if (!m) {
    return null;
  }

  return { request_id: m[2].toLowerCase(), behavior: m[1].toLowerCase().startsWith('y') ? 'allow' : 'deny' };
}

/**
 * 組推給授權者的工具授權提示文字。
 *
 * @param {object} req - 授權請求參數
 *
 * @returns {string} 提示文字
 */
export function permissionPromptText(req: { request_id: string; tool_name: string; description: string; input_preview: string }): string {
  return (
    `Claude 要使用工具 ${req.tool_name}:${req.description}\n${req.input_preview}\n` +
    `核可回「y ${req.request_id}」,拒絕回「n ${req.request_id}」。`
  );
}

/**
 * 組 channel instructions(注入 session 的行為指引)。teammateRouting 開啟時於最前面前置
 * 路由協議(細節見 README「多對話隔離」)。
 *
 * @param {boolean} teammateRouting - 是否啟用多對話路由模式
 *
 * @returns {string} instructions 字串
 */
export function buildInstructions(teammateRouting: boolean): string {
  const base =
    'LINE 訊息會以 <channel source="line" chat_id="..." message_id="..." user="..."> 進入此 session。' +
    'chat_id 以 C / R 開頭為群組 / 多人聊天室,以 U 開頭為 1:1。' +
    '若標籤帶 file_path 屬性,代表使用者傳了媒體,可 Read 該檔;帶 url 屬性則為外部媒體連結;' +
    '帶 media_status="unavailable" 代表媒體取得失敗,請告知使用者重傳。' +
    '帶 quoted_file_path 屬性代表使用者引用了一則媒體,Read 它即是被引用的圖 / 檔。' +
    '你的終端輸出不會傳到 LINE;要回覆使用者一律呼叫 reply tool,並帶上 inbound 標籤的 chat_id。' +
    '多個對話(不同 chat_id)會混在同一 session,請把每個 chat_id 當成獨立對話 —— 回覆某對話只依該對話脈絡,' +
    '不可把別的 chat_id 的內容混進來。為避免回錯對象,**每次 reply 都務必帶 reply_to=你正在回覆的那則 inbound message_id**' +
    '(系統會以該訊息的真實來源為準送達,並擋掉送往未互動對話的回覆)。' +
    '群組規則(chat_id 以 C / R 開頭):只有 @ 到你的文字訊息會進來;群組裡的媒體 / 檔案不會主動進來' +
    '(已在背景記錄+存檔)。使用者想針對某張圖 / 某個檔提問時,會「引用」那則媒體並 @ 你,此時標籤帶 quoted_file_path,Read 它即可。' +
    '1:1(chat_id 以 U 開頭)的媒體照常進來、可 Read 並回覆。' +
    '使用者在群組要求摘要某時間段聊天時,呼叫 get_history(chat_id 用該群 ID,minutes 取最近 N 分鐘或 since/until 指定範圍)' +
    '取得訊息後再摘要,並用 reply 回覆。' +
    '若 reply 回報「已延後」,代表任務太久、replyToken 已逾時(系統已自動回覆使用者「處理中」);' +
    '請保留你的答案,在該使用者下次傳訊息時把同樣答案再 reply 一次即可免費送達。';

  if (!teammateRouting) {
    return base;
  }

  const routing =
    '【最高優先・多對話路由模式】你運作在多對話 channel 上,務必逐則路由、絕不自己回答使用者:' +
    '每收到一則 <channel chat_id="X" message_id="M" ...> 訊息 → ' +
    '(1) 若尚無名為 chat-X 的 teammate,spawn 一個 background 具名 agent(name=chat-X),指示它' +
    '「你只負責 LINE 對話 X;處理訊息後先用 ToolSearch 載入 select:reply,再呼叫 reply(chat_id=\'X\', text=回覆, reply_to=你正在回覆的那則 inbound message_id);' +
    '保留此對話脈絡;媒體 / 引用 / 摘要 / 延後等規則同下列通則」;' +
    '(2) 若已有 chat-X,用 SendMessage 把訊息內容 + 該則 message_id 轉給它(teammate 回覆時 reply_to 用這個新的 message_id,勿沿用第一則)。你本人只路由、不產生任何給使用者的答案。' +
    '(以下通則同時適用於各 teammate 的回覆行為:)';

  return routing + base;
}

/**
 * 宣告 claude/channel capability 後,Claude Code 才會把此 MCP server 當成
 * channel;宣告 tools 才能提供 reply tool;宣告 claude/channel/permission 才會
 * 把工具授權提示轉送過來(需 Claude Code v2.1.81+,且因本 channel 有驗證寄件者
 * 才宣告)。
 */
const mcp = new Server(
  { name: 'line', version: '0.0.1' },
  {
    capabilities: { tools: {}, experimental: { 'claude/channel': {}, 'claude/channel/permission': {} } },
    instructions: buildInstructions(TEAMMATE_ROUTING),
  },
);

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'reply',
      description: '回覆訊息到 LINE。帶 inbound 標籤的 chat_id;reply_to 可指定要回覆的 message_id。',
      inputSchema: {
        type: 'object',
        properties: {
          chat_id: { type: 'string', description: '要回覆的對話(LINE userId / groupId / roomId)' },
          text: { type: 'string', description: '訊息內容' },
          reply_to: { type: 'string', description: '要回覆的 inbound message_id(可省略)' },
        },
        required: ['chat_id', 'text'],
      },
    },
    {
      name: 'get_history',
      description:
        '取得某群組在指定時間段的訊息(供摘要;涵蓋群組內所有訊息,不限有無 @ bot)。' +
        'chat_id 用群組 ID;minutes 取最近 N 分鐘,或用 since/until 指定範圍。',
      inputSchema: {
        type: 'object',
        properties: {
          chat_id: { type: 'string', description: '群組 ID(groupId / roomId)' },
          minutes: { type: 'number', description: '取最近 N 分鐘(預設 60)' },
          since: { type: 'string', description: '起點(ISO 8601 或毫秒);與 minutes 擇一' },
          until: { type: 'string', description: '終點(ISO 8601 或毫秒;預設現在)' },
          limit: { type: 'number', description: '最多筆數(預設 1000,上限 5000)' },
        },
        required: ['chat_id'],
      },
    },
  ],
}));

mcp.setRequestHandler(CallToolRequestSchema, async req => {
  if (req.params.name === 'reply') {
    const args = (req.params.arguments ?? {}) as { chat_id?: string; text?: string; reply_to?: string };

    // Claude 回覆了 → 取消該 chat 的「處理中」計時器(不再需要 interim 提示)。
    if (args.chat_id) {
      interimTimers.disarm(args.chat_id);
    }

    return runReplyTool(args, replyStore, lineDeps);
  }

  if (req.params.name === 'get_history') {
    return runGetHistory(
      (req.params.arguments ?? {}) as { chat_id?: string; minutes?: number; since?: string; until?: string; limit?: number },
      history(),
      Date.now(),
      replyStore.isKnownChat,
    );
  }

  return { content: [{ type: 'text', text: `unknown: ${req.params.name}` }], isError: true };
});

/**
 * 收到工具授權請求時,把 Allow/Deny 提示 Push 給授權者(allowFrom)。授權者用
 * 文字「y/n <request_id>」回覆,由 handleCallback 攔截送出裁決。
 */
mcp.setNotificationHandler(PermissionRequestSchema, async notification => {
  const access = loadAccess();
  const text = permissionPromptText(notification.params);

  await Promise.all(
    access.allowFrom.map(async userId => {
      const res = await lineDeps.push(userId, [{ type: 'text', text }]);

      if (!res.ok) {
        process.stderr.write(`line channel: 授權提示 push 失敗 to ${userId} status=${res.status}\n`);
      }
    }),
  );
});

/** 送出工具授權裁決給 Claude Code。 */
function sendVerdict(verdict: { request_id: string; behavior: 'allow' | 'deny' }): Promise<void> {
  return mcp.notification({ method: 'notifications/claude/channel/permission', params: verdict });
}

/**
 * 預設的訊息投遞:暫存 replyToken,並以 notification 把訊息推進 session。
 *
 * @param {ChannelMessage} msg - 要推進 session 的訊息
 * @param {LineEvent} event - 原始 LINE 事件
 *
 * @returns {Promise<void>}
 */
async function emitToSession(msg: ChannelMessage, event: LineEvent): Promise<void> {
  if (event.message) {
    replyStore.stash(event.message.id, msg.meta.chat_id, event.replyToken);

    // 啟用延後模式時,起一個計時器:Claude 逾時未回則送「處理中」提示(把答案延後、零 Push)。
    if (shouldArmInterim(DEFER_LONG_REPLIES, event.replyToken, INTERIM_MS)) {
      interimTimers.arm(msg.meta.chat_id, INTERIM_MS, () => sendInterim(msg.meta.chat_id));
    }
  }

  await mcp.notification({
    method: 'notifications/claude/channel',
    params: { content: msg.content, meta: msg.meta },
  });
}

/**
 * 處理本機收到的 HTTP 請求(LINE webhook)。驗章 → 解析 → 去重 → 投遞
 * (文字與媒體)。
 *
 * @param {Request} req - 進來的 HTTP 請求
 * @param {OnMessage} [onMessage] - 每則可投遞訊息的處理函式(預設推進 session)
 * @param {HandleOptions} [options] - 群組設定與媒體相依(測試可注入)
 *
 * @returns {Promise<Response>} 給 LINE 平台的回應
 */
export async function handleCallback(req: Request, onMessage: OnMessage = emitToSession, options: HandleOptions = {}): Promise<Response> {
  const mediaDeps = options.mediaDeps ?? lineMediaDeps;
  const markSeen = options.markSeen ?? markEventSeen;
  const access = options.access ?? loadAccess();
  const sendDeps = options.sendDeps ?? lineDeps;
  const onVerdict = options.onVerdict ?? sendVerdict;
  const persistAccess = options.persistAccess ?? saveAccess;
  const logGroup = options.logGroup ?? defaultLogGroup;
  const logDirect = options.logDirect ?? defaultLogDirect;
  const lookupQuote = options.lookupQuote ?? (id => history().lookupMessage(id));
  const url = new URL(req.url);

  if (url.pathname !== '/callback' || req.method !== 'POST') {
    return new Response('not found', { status: 404 });
  }

  // 必須讀「原始 bytes」來驗章,不可先 JSON parse 再 re-serialize。
  const raw = await req.text();
  const signature = req.headers.get('x-line-signature');

  if (!verifySignature(raw, signature, channelSecret())) {
    process.stderr.write('line channel: 簽章驗證失敗,拒絕此 webhook\n');

    return new Response('bad signature', { status: 400 });
  }

  let body: LineWebhookBody;
  try {
    body = JSON.parse(raw) as LineWebhookBody;
  } catch {
    return new Response('bad json', { status: 400 });
  }

  for (const event of body.events ?? []) {
    // 有 webhookEventId 才去重;缺 ID 的非標準事件照常處理,不誤殺。
    if (event.webhookEventId && !markSeen(event.webhookEventId)) {
      continue;
    }

    // 已授權群組:記錄每則訊息(供摘要 / 引用),涵蓋全群所有成員 —— 與「誰能驅動 bot」的成員清單、
    // 與 gate 的投遞決策無關(非成員、未 @ 的訊息也要進歷史)。失敗不影響後續。
    const src = event.source;
    const logGid = src?.type === 'group' ? src.groupId : src?.type === 'room' ? src.roomId : undefined;

    if (logGid && access.allowGroups[logGid] !== undefined) {
      try {
        await logGroup(event);
      } catch (err) {
        process.stderr.write(`line channel: 記錄群組訊息失敗:${String(err)}\n`);
      }
    }

    // 存取控制:未授權者丟棄;未配對的 1:1 用免費 Reply 回配對碼後丟棄。
    // gate 任何未預期例外一律 fail-closed(drop),不讓單一事件搞掛整批 webhook。
    let decision: GateDecision;

    try {
      decision = gate(event, access, Date.now());
    } catch (err) {
      process.stderr.write(`line channel: gate 例外,fail-closed drop:${String(err)}\n`);

      continue;
    }

    if (decision.action === 'drop') {
      continue;
    }

    if (decision.action === 'pair') {
      if (decision.access !== access) {
        persistAccess(decision.access);
      }

      if (event.replyToken) {
        try {
          await sendDeps.reply(event.replyToken, [
            { type: 'text', text: `配對碼:${decision.code}。請在 Claude Code 執行 /line:access pair ${decision.code} 完成配對。` },
          ]);
        } catch (err) {
          process.stderr.write(`line channel: 配對碼 reply 失敗:${String(err)}\n`);
        }
      }

      continue;
    }

    if (decision.action === 'group_pair') {
      if (event.replyToken) {
        try {
          await sendDeps.reply(event.replyToken, [
            {
              type: 'text',
              text:
                `群組 ID:${decision.groupId}。請在 Claude Code 執行 ` +
                `/line:access group-allow ${decision.groupId} 授權此群組(或把此 ID 加進 access.json 的 allowGroups)。`,
            },
          ]);
        } catch (err) {
          process.stderr.write(`line channel: 群組授權提示 reply 失敗 (${decision.groupId}):${String(err)}\n`);
        }
      }

      continue;
    }

    // 已授權群組但發話者不在成員清單:被 @ 時回其 userId + 授權指示(成員自助),不投遞進 session。
    if (decision.action === 'member_pair') {
      if (event.replyToken) {
        try {
          await sendDeps.reply(event.replyToken, [
            {
              type: 'text',
              text:
                `你的 userId:${decision.userId}。請管理員執行 ` +
                `/line:access group-member-allow ${decision.groupId} ${decision.userId} 授權你在此群使用 bot` +
                `(或把此 userId 加進 access.json 該群清單)。`,
            },
          ]);
        } catch (err) {
          process.stderr.write(`line channel: 成員授權提示 reply 失敗 (${decision.groupId}):${String(err)}\n`);
        }
      }

      continue;
    }

    // 授權者(1:1)的「y/n <code>」文字是工具授權裁決,攔截送出、不進 session。
    if (event.source?.type === 'user' && event.message?.type === 'text') {
      const verdict = parsePermissionReply(event.message.text ?? '');

      if (verdict) {
        await onVerdict(verdict);
        continue;
      }
    }

    // 是否需 @ 才投遞:逐事件依該群 groupSettings 決定(預設 true);options.requireMention 可全域覆寫(測試用)。
    const requireMention = options.requireMention ?? resolveRequireMention(event, access);

    // 群組媒體一律不投遞進 session(硬控制:由 logGroup 記錄+存檔,使用者引用該媒體 + @ 才取用),
    // 與 requireMention 解耦 —— 即使設 false 也不投遞、不重複抓;1:1 媒體照常投遞;文字由 eventToChannelMessage 把關。
    const inGroup = event.source?.type === 'group' || event.source?.type === 'room';
    const built = inGroup && parseMedia(event)
      ? null
      : eventToChannelMessage(event, requireMention) ?? (await buildMediaMessage(event, requireMention, mediaDeps));

    if (!built) {
      continue;
    }

    // 1:1 訊息記進歷史(chat_id = userId),供日後引用解析 / get_history;媒體 file_path 取自已建好的 meta(1:1 媒體已存檔,不重抓)。
    if (event.source?.type === 'user') {
      try {
        logDirect(event, built.meta.file_path);
      } catch (err) {
        process.stderr.write(`line channel: 記錄 1:1 訊息失敗:${String(err)}\n`);
      }
    }

    // 引用回覆:補上被引用訊息的發話者 + 內容;被引用的是媒體時,帶出 quoted_file_path 讓 Claude 能 Read 那張圖/檔。
    // 僅查得到已記錄(有 message_id)的訊息;bot 加入 / 開始記錄前的訊息查無 → graceful 照常投遞不加前綴。
    const quotedId = event.message?.quotedMessageId;
    const quoted = quotedId ? lookupQuote(quotedId) : null;
    let msg = built;

    if (quoted) {
      const quotedText = quoted.file_path ? `${quoted.text ?? '媒體'}(見 quoted_file_path)` : quoted.text ?? '';
      const meta = quoted.file_path ? { ...built.meta, quoted_file_path: quoted.file_path } : built.meta;
      msg = { content: `(引用 ${quoted.user_name || '某人'}:「${quotedText}」)\n${built.content}`, meta };
    }

    // 單一事件投遞失敗不可中斷整批(否則 LINE 會重送已成功的事件)。
    try {
      await onMessage(msg, event);
    } catch (err) {
      process.stderr.write(`line channel: 投遞事件失敗:${String(err)}\n`);
    }
  }

  return new Response('OK', { status: 200 });
}

/** 啟動時載入 ~/.claude/channels/line/.env(已存在的環境變數優先,不覆蓋)。 */
function loadDotEnv(): void {
  try {
    for (const line of readFileSync(join(STATE_DIR, '.env'), 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);

      if (m && process.env[m[1]] === undefined) {
        process.env[m[1]] = m[2];
      }
    }
  } catch {
    // 無 .env 就略過。
  }
}

// 僅在以進入點執行時啟動副作用(被測試 import 時不啟動 server)。.env 已在檔頭載入。
if (import.meta.main) {
  if (!channelSecret() || !accessToken()) {
    process.stderr.write('line channel: 缺少 LINE_CHANNEL_SECRET 或 LINE_CHANNEL_ACCESS_TOKEN,無法運作。\n');
    process.exit(1);
  }

  await mcp.connect(new StdioServerTransport());

  // stdout 已保留給 MCP JSON-RPC,所有 log 一律走 stderr。
  const tlsOpt = TLS_CERT && TLS_KEY ? { tls: { cert: Bun.file(TLS_CERT), key: Bun.file(TLS_KEY) } } : {};
  Bun.serve({ port: PORT, hostname: HOST, ...tlsOpt, fetch: req => handleCallback(req) });

  const scheme = TLS_CERT && TLS_KEY ? 'https' : 'http';
  process.stderr.write(`line channel: listening on ${scheme}://${HOST}:${PORT}/callback\n`);
  process.stderr.write('將你的公開 HTTPS 端點轉發到上面的 /callback,並設為 LINE webhook URL。\n');

  // 保留天數 > 0 才自動清理:啟動跑一次,之後每 24h 一次。
  if (RETENTION_DAYS > 0) {
    runCleanup(RETENTION_DAYS, Date.now());
    setInterval(() => runCleanup(RETENTION_DAYS, Date.now()), 86_400_000);
  }
}
