/**
 * Phase 1 測試:簽章驗證、事件去重、webhook 處理(驗章 / 解析 / 去重)。
 */

import { test, expect, beforeAll, describe } from 'bun:test';
import { createHmac } from 'crypto';
import { Database } from 'bun:sqlite';
import {
  verifySignature,
  createDedupe,
  handleCallback,
  chatIdOf,
  eventToChannelMessage,
  createReplyStore,
  chunkMessages,
  sendOutbound,
  runReplyTool,
  lineApiPost,
  isMentioned,
  deliverableChatId,
  parseMedia,
  buildMediaMessage,
  safeId,
  fetchLineContent,
  gate,
  normalizeAccess,
  resolveRequireMention,
  parsePermissionReply,
  permissionPromptText,
  createHistoryStore,
  groupMessageRow,
  runGetHistory,
  runGetGroupSummary,
  resolveGroupSummary,
  sanitizeGroupName,
  resolveMemberName,
  fetchAndSaveMedia,
  createInterimTimers,
  buildInstructions,
  shouldArmInterim,
  sendInterim,
  defaultLogGroup,
  defaultLogDirect,
  purgeInboxFiles,
  runCleanup,
} from './server.ts';

/** 一組假的媒體相依:可控的 fetchContent 結果,記錄存檔。 */
function fakeMediaDeps(options: { fetched?: { ok: boolean; status: number; bytes?: Uint8Array } } = {}) {
  const saved: { messageId: string; ext: string }[] = [];

  return {
    saved,
    deps: {
      fetchContent: async () => options.fetched ?? { ok: true, status: 200, bytes: new Uint8Array([1, 2, 3]) },
      saveFile: (messageId: string, _bytes: Uint8Array, ext: string) => {
        saved.push({ messageId, ext });

        return `/tmp/inbox/${messageId}${ext}`;
      },
    },
  };
}

/** 群組文字訊息事件(可選擇是否 @ 到 bot;userId 預設 'U1' 為發話成員)。 */
function groupTextEvent(id: string, text: string, mentioned: boolean, userId = 'U1'): {
  type: string;
  webhookEventId: string;
  source: { type: 'group'; groupId: string; userId: string };
  message: { id: string; type: string; text: string; mention?: { mentionees: { isSelf: boolean }[] } };
} {
  return {
    type: 'message',
    webhookEventId: id,
    source: { type: 'group', groupId: 'G1', userId },
    message: {
      id,
      type: 'text',
      text,
      ...(mentioned ? { mention: { mentionees: [{ isSelf: true }] } } : {}),
    },
  };
}

/** 一組假的 outbound 相依:記錄呼叫的 reply / push。 */
function fakeDeps(options: {
  reply?: { ok: boolean; status: number; message?: string };
  push?: { ok: boolean; status: number; message?: string };
} = {}) {
  const calls = { reply: 0, push: 0, pushTo: '' as string };

  return {
    calls,
    deps: {
      reply: async () => {
        calls.reply += 1;

        return options.reply ?? { ok: true, status: 200 };
      },
      push: async (to: string) => {
        calls.push += 1;
        calls.pushTo = to;

        return options.push ?? { ok: true, status: 200 };
      },
    },
  };
}

// 測試用:放行所有測試會用到的 1:1 user 與群組(避免預設 pairing 擋下並觸發真實 reply)。
const OPEN_ACCESS = {
  dmPolicy: 'allowlist' as const,
  allowFrom: ['U1', 'U0', 'Uabc', 'U9'],
  allowGroups: { G1: ['U1', 'U0', 'Uabc', 'U9'], R1: ['U1', 'U0', 'Uabc', 'U9'] },
  groupSettings: {} as Record<string, { requireMention?: boolean }>,
  pending: {},
};

const SECRET = 'test-channel-secret';

/** 用測試 secret 對 body 產生 LINE 風格簽章。 */
function sign(body: string, secret = SECRET): string {
  return createHmac('sha256', secret).update(body).digest('base64');
}

/** 組一個帶簽章 header 的 webhook 請求。 */
function webhookRequest(body: string, signature: string | null): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };

  if (signature !== null) {
    headers['x-line-signature'] = signature;
  }

  return new Request('http://127.0.0.1/callback', { method: 'POST', headers, body });
}

beforeAll(() => {
  process.env.LINE_CHANNEL_SECRET = SECRET;
});

test('verifySignature: 正確簽章回 true', () => {
  const body = '{"events":[]}';

  expect(verifySignature(body, sign(body), SECRET)).toBe(true);
});

test('verifySignature: 錯誤簽章回 false', () => {
  const body = '{"events":[]}';

  expect(verifySignature(body, sign(body, 'wrong-secret'), SECRET)).toBe(false);
});

test('verifySignature: body 被竄改回 false', () => {
  const signature = sign('{"events":[]}');

  expect(verifySignature('{"events":[{"x":1}]}', signature, SECRET)).toBe(false);
});

test('verifySignature: 缺 signature 或 secret 回 false', () => {
  const body = '{"events":[]}';

  expect(verifySignature(body, null, SECRET)).toBe(false);
  expect(verifySignature(body, sign(body), '')).toBe(false);
});

/**
 * 測試目標：verifySignature()
 * 情境：boundary — signature 長度與正確簽章不同
 * Mock：無需 mock
 * 預期：回 false 且不丟例外(timingSafeEqual 對不等長會 throw,函式需先擋掉)
 */
test('verifySignature: 簽章長度不符時回 false 而不丟例外', () => {
  const body = '{"events":[]}';
  const correct = sign(body);
  const tooShort = correct.slice(0, correct.length - 5);
  const tooLong = `${correct}AAAAA`;

  // Act + Assert：兩種長度都不等於正確簽章,且不可 throw
  // (空字串走 line 56 的 !signature 早退,不算長度不符路徑,故不放這裡)
  expect(verifySignature(body, tooShort, SECRET)).toBe(false);
  expect(verifySignature(body, tooLong, SECRET)).toBe(false);
});

test('createDedupe: 首見回 true、重複回 false', () => {
  const seen = createDedupe();

  expect(seen('evt-1')).toBe(true);
  expect(seen('evt-1')).toBe(false);
  expect(seen('evt-2')).toBe(true);
});

test('createDedupe: 超過上限以 FIFO 淘汰最舊', () => {
  const seen = createDedupe(2);

  expect(seen('a')).toBe(true); // {a}
  expect(seen('b')).toBe(true); // {a,b}
  expect(seen('c')).toBe(true); // 加入 c,淘汰最舊的 a → {b,c}
  expect(seen('a')).toBe(true); // a 已被淘汰,再次視為新事件,並淘汰 b → {c,a}
  expect(seen('c')).toBe(false); // c 仍在集合內
});

/**
 * 測試目標：createDedupe(1)
 * 情境：boundary — max=1 退化情形,每來一個新 ID 立刻淘汰前一個
 * Mock：無需 mock
 * 預期：同一 ID 連兩次仍可去重;但換 ID 後上一個立即被淘汰,再見視為新事件
 */
test('createDedupe: max=1 退化時只記得最後一個 ID', () => {
  const seen = createDedupe(1);

  // Act + Assert
  expect(seen('a')).toBe(true); // {a}
  expect(seen('a')).toBe(false); // a 仍在集合內 → 去重成立
  expect(seen('b')).toBe(true); // 加入 b 後 size>1,淘汰最舊的 a → {b}
  expect(seen('a')).toBe(true); // a 已被淘汰,再次視為新事件 → {a}
  expect(seen('b')).toBe(true); // b 也已被 a 擠掉,再次視為新事件
});

test('handleCallback: 正確簽章回 200', async () => {
  const body = JSON.stringify({
    destination: 'U0',
    events: [{ type: 'message', webhookEventId: 'w1', message: { id: 'm1', type: 'text', text: 'hi' } }],
  });
  const res = await handleCallback(webhookRequest(body, sign(body)));

  expect(res.status).toBe(200);
});

test('handleCallback: 簽章錯誤回 400', async () => {
  const body = JSON.stringify({ events: [] });
  const res = await handleCallback(webhookRequest(body, 'invalid-signature'));

  expect(res.status).toBe(400);
});

test('handleCallback: 缺簽章 header 回 400', async () => {
  const body = JSON.stringify({ events: [] });
  const res = await handleCallback(webhookRequest(body, null));

  expect(res.status).toBe(400);
});

test('handleCallback: 簽章對但 JSON 壞掉回 400', async () => {
  const body = 'not-json';
  const res = await handleCallback(webhookRequest(body, sign(body)));

  expect(res.status).toBe(400);
});

test('handleCallback: 非 /callback 或非 POST 回 404', async () => {
  const getReq = new Request('http://127.0.0.1/callback', { method: 'GET' });
  const otherPath = new Request('http://127.0.0.1/other', { method: 'POST' });

  expect((await handleCallback(getReq)).status).toBe(404);
  expect((await handleCallback(otherPath)).status).toBe(404);
});

test('handleCallback: 重送的事件仍回 200(去重不影響回應碼)', async () => {
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'dup-1', message: { id: 'm', type: 'text', text: 'x' } }],
  });

  expect((await handleCallback(webhookRequest(body, sign(body)))).status).toBe(200);
  expect((await handleCallback(webhookRequest(body, sign(body)))).status).toBe(200);
});

/**
 * 測試目標：handleCallback()
 * 情境：boundary — events 為空陣列,for 迴圈零次,不應出錯
 * Mock：無需 mock(用真實簽章驗章)
 * 預期：回 200
 */
test('handleCallback: events 為空陣列回 200', async () => {
  const body = JSON.stringify({ destination: 'U0', events: [] });

  // Act
  const res = await handleCallback(webhookRequest(body, sign(body)));

  // Assert
  expect(res.status).toBe(200);
});

/**
 * 測試目標：handleCallback()
 * 情境：boundary — body 完全沒有 events 欄位,靠 `body.events ?? []` 的 nullish 退回
 * Mock：無需 mock
 * 預期：回 200(不因 undefined 迭代而丟例外)
 */
test('handleCallback: body 缺 events 欄位回 200', async () => {
  const body = JSON.stringify({ destination: 'U0' });

  // Act
  const res = await handleCallback(webhookRequest(body, sign(body)));

  // Assert
  expect(res.status).toBe(200);
});

/**
 * 測試目標：handleCallback()
 * 情境：happy — 單一 request 含多個 events,迴圈需逐一處理皆不出錯
 * Mock：無需 mock(webhookEventId 用獨特值避開模組層級共用去重器的污染)
 * 預期：回 200
 */
test('handleCallback: 單一請求含多個 events 回 200', async () => {
  const body = JSON.stringify({
    events: [
      { type: 'message', webhookEventId: 'multi-1', message: { id: 'm1', type: 'text', text: 'a' } },
      { type: 'follow', webhookEventId: 'multi-2' },
      { type: 'message', webhookEventId: 'multi-3', message: { id: 'm3', type: 'sticker' } },
    ],
  });

  // Act
  const res = await handleCallback(webhookRequest(body, sign(body)));

  // Assert
  expect(res.status).toBe(200);
});

// ===== Phase 2:chatIdOf / eventToChannelMessage / 投遞(注入 onMessage)=====

test('chatIdOf: 依來源型別取對話 ID', () => {
  expect(chatIdOf({ type: 'user', userId: 'U1' })).toBe('U1');
  expect(chatIdOf({ type: 'group', groupId: 'G1', userId: 'U1' })).toBe('G1');
  expect(chatIdOf({ type: 'room', roomId: 'R1' })).toBe('R1');
  expect(chatIdOf(undefined)).toBeUndefined();
});

test('eventToChannelMessage: 1:1 文字訊息轉成 content + meta', () => {
  const msg = eventToChannelMessage({
    type: 'message',
    webhookEventId: 'e',
    timestamp: 1700000000000,
    source: { type: 'user', userId: 'U1' },
    message: { id: 'm1', type: 'text', text: 'hello' },
  });

  expect(msg?.content).toBe('hello');
  expect(msg?.meta.chat_id).toBe('U1');
  expect(msg?.meta.message_id).toBe('m1');
  expect(msg?.meta.user).toBe('U1');
});

test('eventToChannelMessage: 群組文字訊息 chat_id 用 groupId', () => {
  const msg = eventToChannelMessage({
    type: 'message',
    webhookEventId: 'e',
    source: { type: 'group', groupId: 'G1', userId: 'U9' },
    message: { id: 'm2', type: 'text', text: 'hi group' },
  });

  expect(msg?.meta.chat_id).toBe('G1');
  expect(msg?.meta.user).toBe('U9');
});

test('eventToChannelMessage: 非文字 / 非訊息事件回 null', () => {
  const follow = eventToChannelMessage({ type: 'follow', webhookEventId: 'e', source: { type: 'user', userId: 'U1' } });
  const sticker = eventToChannelMessage({
    type: 'message',
    webhookEventId: 'e',
    source: { type: 'user', userId: 'U1' },
    message: { id: 'm', type: 'sticker' },
  });

  expect(follow).toBeNull();
  expect(sticker).toBeNull();
});

test('eventToChannelMessage: 無法取得 chat_id 回 null', () => {
  const msg = eventToChannelMessage({ type: 'message', webhookEventId: 'e', message: { id: 'm', type: 'text', text: 'x' } });

  expect(msg).toBeNull();
});

test('handleCallback: 文字事件呼叫 onMessage 一次,帶正確 content/meta', async () => {
  const contents: string[] = [];
  const chatIds: string[] = [];
  const body = JSON.stringify({
    events: [
      {
        type: 'message',
        webhookEventId: 'p2-text',
        source: { type: 'user', userId: 'U1' },
        message: { id: 'm1', type: 'text', text: 'hey' },
      },
    ],
  });

  const res = await handleCallback(webhookRequest(body, sign(body)), msg => {
    contents.push(msg.content);
    chatIds.push(msg.meta.chat_id);
  }, { access: OPEN_ACCESS });

  expect(res.status).toBe(200);
  expect(contents).toEqual(['hey']);
  expect(chatIds).toEqual(['U1']);
});

test('handleCallback: 非文字事件不呼叫 onMessage', async () => {
  let count = 0;
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p2-sticker', source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'sticker' } }],
  });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    count += 1;
  }, { access: OPEN_ACCESS });

  expect(count).toBe(0);
});

test('handleCallback: 簽章錯誤時不呼叫 onMessage', async () => {
  let count = 0;
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p2-badsig', source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } }],
  });

  const res = await handleCallback(webhookRequest(body, 'bad'), () => {
    count += 1;
  });

  expect(res.status).toBe(400);
  expect(count).toBe(0);
});

test('handleCallback: 多事件只對文字事件呼叫 onMessage', async () => {
  const seen: string[] = [];
  const body = JSON.stringify({
    events: [
      { type: 'message', webhookEventId: 'p2-m1', source: { type: 'user', userId: 'U1' }, message: { id: 'a', type: 'text', text: '1' } },
      { type: 'follow', webhookEventId: 'p2-f1', source: { type: 'user', userId: 'U1' } },
      { type: 'message', webhookEventId: 'p2-m2', source: { type: 'user', userId: 'U1' }, message: { id: 'b', type: 'text', text: '2' } },
    ],
  });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    seen.push(msg.content);
  }, { access: OPEN_ACCESS });

  expect(seen).toEqual(['1', '2']);
});

test('handleCallback: 重送的文字事件只投遞一次', async () => {
  let count = 0;
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p2-dup', source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } }],
  });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    count += 1;
  }, { access: OPEN_ACCESS });
  await handleCallback(webhookRequest(body, sign(body)), () => {
    count += 1;
  }, { access: OPEN_ACCESS });

  expect(count).toBe(1);
});

// ===== Phase 2 補強:eventToChannelMessage 邊界 / onMessage 拋例外不中斷 / createReplyStore =====

/**
 * 測試目標：eventToChannelMessage()
 * 情境：boundary — room 來源(無 userId),chat_id 用 roomId 且 meta 不應帶 user
 * Mock：無需 mock
 * 預期：chat_id=roomId、content 正確、meta.user 不存在(room 無個別發話者 ID)
 */
test('eventToChannelMessage: room 來源 chat_id 用 roomId 且不帶 user', () => {
  // Arrange + Act
  const msg = eventToChannelMessage({
    type: 'message',
    webhookEventId: 'e',
    timestamp: 1700000000000,
    source: { type: 'room', roomId: 'R1' },
    message: { id: 'm5', type: 'text', text: 'hi room' },
  });

  // Assert
  expect(msg?.content).toBe('hi room');
  expect(msg?.meta.chat_id).toBe('R1');
  expect(msg?.meta.message_id).toBe('m5');
  expect(msg?.meta.user).toBeUndefined();
});

/**
 * 測試目標：eventToChannelMessage()
 * 情境：boundary — text 為空字串,須原樣保留(空字串是合法 LINE 輸入,不可被當缺值丟掉)
 * Mock：無需 mock
 * 預期：回傳非 null,content 為 ''(text ?? '' 只對 undefined 退回,空字串維持原值)
 */
test('eventToChannelMessage: 空字串 text 仍回非 null 且 content 為空字串', () => {
  // Arrange + Act
  const msg = eventToChannelMessage({
    type: 'message',
    webhookEventId: 'e',
    source: { type: 'user', userId: 'U1' },
    message: { id: 'm6', type: 'text', text: '' },
  });

  // Assert
  expect(msg).not.toBeNull();
  expect(msg?.content).toBe('');
  expect(msg?.meta.chat_id).toBe('U1');
});

/**
 * 測試目標：eventToChannelMessage()
 * 情境：boundary — timestamp 缺漏時不放 ts(避免送出誤導性的 1970 時間戳)
 * Mock：無需 mock
 * 預期：meta 不含 ts key,其餘欄位正常
 */
test('eventToChannelMessage: 缺 timestamp 時 meta 不含 ts', () => {
  // Arrange + Act
  const msg = eventToChannelMessage({
    type: 'message',
    webhookEventId: 'e',
    source: { type: 'user', userId: 'U1' },
    message: { id: 'm7', type: 'text', text: 'no ts' },
  });

  // Assert
  expect(msg?.meta.ts).toBeUndefined();
  expect(msg?.meta.chat_id).toBe('U1');
});

/**
 * 測試目標：handleCallback()
 * 情境：exception — 某事件的 onMessage 拋例外,不可中斷整批;其餘事件仍投遞且仍回 200
 * Mock：注入會對特定訊息拋例外的 onMessage(webhookEventId 用獨特值避開模組共用去重器)
 * 預期：三則文字事件中第一則拋例外,後兩則仍被呼叫,回應仍為 200
 */
test('handleCallback: onMessage 拋例外不中斷整批,其餘事件仍投遞且回 200', async () => {
  // Arrange
  const delivered: string[] = [];
  const body = JSON.stringify({
    events: [
      { type: 'message', webhookEventId: 'p2-throw-1', source: { type: 'user', userId: 'U1' }, message: { id: 'a', type: 'text', text: 'boom' } },
      { type: 'message', webhookEventId: 'p2-throw-2', source: { type: 'user', userId: 'U1' }, message: { id: 'b', type: 'text', text: 'ok-2' } },
      { type: 'message', webhookEventId: 'p2-throw-3', source: { type: 'user', userId: 'U1' }, message: { id: 'c', type: 'text', text: 'ok-3' } },
    ],
  });

  // Act
  const res = await handleCallback(webhookRequest(body, sign(body)), msg => {
    if (msg.content === 'boom') {
      throw new Error('deliver failed');
    }

    delivered.push(msg.content);
  }, { access: OPEN_ACCESS });

  // Assert
  expect(res.status).toBe(200);
  expect(delivered).toEqual(['ok-2', 'ok-3']);
});

/**
 * 測試目標：handleCallback()
 * 情境：exception — onMessage 回傳的 Promise reject(async 拋例外),同樣不中斷整批
 * Mock：注入 async onMessage,對特定訊息 reject(獨特 webhookEventId)
 * 預期：reject 的事件被吞掉,後續事件仍投遞,回 200
 */
test('handleCallback: onMessage async reject 不中斷整批且回 200', async () => {
  // Arrange
  const delivered: string[] = [];
  const body = JSON.stringify({
    events: [
      { type: 'message', webhookEventId: 'p2-reject-1', source: { type: 'user', userId: 'U1' }, message: { id: 'a', type: 'text', text: 'reject-me' } },
      { type: 'message', webhookEventId: 'p2-reject-2', source: { type: 'user', userId: 'U1' }, message: { id: 'b', type: 'text', text: 'after' } },
    ],
  });

  // Act
  const res = await handleCallback(webhookRequest(body, sign(body)), async msg => {
    if (msg.content === 'reject-me') {
      throw new Error('async deliver failed');
    }

    delivered.push(msg.content);
  }, { access: OPEN_ACCESS });

  // Assert
  expect(res.status).toBe(200);
  expect(delivered).toEqual(['after']);
});

// ===== Phase 3:replyStore readers / chunkMessages / sendOutbound 級聯 / runReplyTool =====

test('createReplyStore: resolve 用 reply_to 取得指定訊息的 token', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  store.stash('m2', 'U1', 'tok-2');

  const byId = store.resolve('U1', 'm1');

  expect(byId?.replyToken).toBe('tok-1');
});

test('createReplyStore: resolve 未指定 reply_to 時取該對話最近一則', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  store.stash('m2', 'U1', 'tok-2');

  expect(store.resolve('U1')?.replyToken).toBe('tok-2');
});

test('createReplyStore: 無 replyToken 不暫存,resolve 回 undefined', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', undefined);

  expect(store.resolve('U1')).toBeUndefined();
});

test('createReplyStore: markUsed 後 resolve 的 used 為 true', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  store.markUsed('m1');

  expect(store.resolve('U1', 'm1')?.used).toBe(true);
});

test('createReplyStore: 超過上限以 FIFO 淘汰最舊 token', () => {
  const store = createReplyStore(1);
  store.stash('m1', 'U1', 'tok-1');
  store.stash('m2', 'U2', 'tok-2'); // 淘汰 m1

  expect(store.resolve('U1', 'm1')).toBeUndefined();
  expect(store.resolve('U2', 'm2')?.replyToken).toBe('tok-2');
});

test('chunkMessages: 短文字回單則', () => {
  expect(chunkMessages('hello')).toEqual([{ type: 'text', text: 'hello' }]);
});

test('chunkMessages: 剛好 5000 字回單則', () => {
  const msgs = chunkMessages('a'.repeat(5000));

  expect(msgs.length).toBe(1);
  expect(msgs[0].text.length).toBe(5000);
});

test('chunkMessages: 5001 字切成兩則', () => {
  const msgs = chunkMessages('a'.repeat(5001));

  expect(msgs.length).toBe(2);
  expect(msgs[0].text.length).toBe(5000);
  expect(msgs[1].text).toBe('a');
});

test('chunkMessages: 超過 5 則容量時截斷在第 5 則', () => {
  const msgs = chunkMessages('a'.repeat(5000 * 6));

  expect(msgs.length).toBe(5);
  expect(msgs[4].text.includes('截斷')).toBe(true);
  expect(msgs[4].text.length).toBeLessThanOrEqual(5000);
});

test('chunkMessages: 空字串退回單則單空白(LINE 拒收空訊息)', () => {
  expect(chunkMessages('')).toEqual([{ type: 'text', text: ' ' }]);
});

test('sendOutbound: token 新鮮 → 用 Reply,不打 Push', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps, calls } = fakeDeps();

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result).toEqual({ delivered: true, via: 'reply' });
  expect(calls.reply).toBe(1);
  expect(calls.push).toBe(0);
});

test('sendOutbound: Reply 失敗 → 退回 Push', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps, calls } = fakeDeps({ reply: { ok: false, status: 400, message: 'Invalid reply token' } });

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result.delivered).toBe(true);
  expect(result.via).toBe('push');
  expect(calls.reply).toBe(1);
  expect(calls.push).toBe(1);
});

test('sendOutbound: 無 token → 直接 Push,目標為 chatId', async () => {
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined); // U1 為已知對話(白名單),但無 token → 走 push
  const { deps, calls } = fakeDeps();

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result.via).toBe('push');
  expect(calls.reply).toBe(0);
  expect(calls.push).toBe(1);
  expect(calls.pushTo).toBe('U1');
});

test('sendOutbound: token 已用過 → 改用 Push', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  store.markUsed('m1');
  const { deps, calls } = fakeDeps();

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result.via).toBe('push');
  expect(calls.reply).toBe(0);
});

test('sendOutbound: Push 超過每月額度 → 放棄不送', async () => {
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);
  const { deps } = fakeDeps({ push: { ok: false, status: 429, message: 'You have reached your monthly limit.' } });

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result).toEqual({ delivered: false, reason: 'monthly-quota' });
});

test('sendOutbound: Push 其他錯誤 → 未送達帶狀態', async () => {
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);
  const { deps } = fakeDeps({ push: { ok: false, status: 500 } });

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result.delivered).toBe(false);
  expect(result.reason).toBe('push-500');
});

test('sendOutbound: reply_to 指定特定訊息的 token', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  store.stash('m2', 'U1', 'tok-2');
  let usedToken = '';
  const deps = {
    reply: async (token: string) => {
      usedToken = token;

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  await sendOutbound(store, 'U1', 'hi', 'm1', deps);

  expect(usedToken).toBe('tok-1');
});

test('runReplyTool: 缺 chat_id 回 isError', async () => {
  const { deps } = fakeDeps();

  const res = await runReplyTool({ text: 'hi' }, createReplyStore(), deps);

  expect(res.isError).toBe(true);
});

test('runReplyTool: 空白 text 回 isError', async () => {
  const { deps } = fakeDeps();

  const res = await runReplyTool({ chat_id: 'U1', text: '   ' }, createReplyStore(), deps);

  expect(res.isError).toBe(true);
});

test('runReplyTool: 送達回 sent (via)', async () => {
  const { deps } = fakeDeps();
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);

  const res = await runReplyTool({ chat_id: 'U1', text: 'hi' }, store, deps);

  expect(res.isError).toBeUndefined();
  expect(res.content[0].text).toBe('sent (push)');
});

test('runReplyTool: 超額未送達回 isError 帶原因', async () => {
  const { deps } = fakeDeps({ push: { ok: false, status: 429, message: 'You have reached your monthly limit.' } });
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);

  const res = await runReplyTool({ chat_id: 'U1', text: 'hi' }, store, deps);

  expect(res.isError).toBe(true);
  expect(res.content[0].text).toContain('monthly-quota');
});

// ===== Phase 3 補強:Reply 成功/失敗的 markUsed、sent (reply) 路徑、中文切塊、reply_to 失效、catch =====

/**
 * 測試目標：sendOutbound()
 * 情境：happy — token 新鮮走 Reply 成功;不僅不打 Push,且該 token 須被 markUsed
 * Mock：fakeDeps（reply 預設成功）
 * 預期：via=reply、push 0 次、resolve 後 used=true(同一 token 不會被二次 Reply)
 */
test('sendOutbound: Reply 成功後 token 被 markUsed 且不打 Push', async () => {
  // Arrange
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps, calls } = fakeDeps();

  // Act
  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  // Assert
  expect(result).toEqual({ delivered: true, via: 'reply' });
  expect(calls.push).toBe(0);
  expect(store.resolve('U1', 'm1')?.used).toBe(true);
});

/**
 * 測試目標：sendOutbound()
 * 情境：boundary — Reply 失敗退回 Push;失效的 token 仍須被 markUsed
 *       (避免下次再拿同一張死 token 重試 Reply)
 * Mock：fakeDeps（reply 回 400 Invalid reply token）
 * 預期：退回 Push 送達,且 resolve 後 used=true
 */
test('sendOutbound: Reply 失敗後 token 仍被 markUsed（不重試死 token）', async () => {
  // Arrange
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps } = fakeDeps({ reply: { ok: false, status: 400, message: 'Invalid reply token' } });

  // Act
  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  // Assert
  expect(result.via).toBe('push');
  expect(store.resolve('U1', 'm1')?.used).toBe(true);
});

/**
 * 測試目標：runReplyTool()
 * 情境：happy — token 新鮮走 Reply 成功,回應字串須標明管道為 reply
 * Mock：fakeDeps（reply 預設成功）
 * 預期：非 isError,content 文字為 'sent (reply)'
 */
test('runReplyTool: 走 Reply 成功路徑回 sent (reply)', async () => {
  // Arrange
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps } = fakeDeps();

  // Act
  const res = await runReplyTool({ chat_id: 'U1', text: 'hi' }, store, deps);

  // Assert
  expect(res.isError).toBeUndefined();
  expect(res.content[0].text).toBe('sent (reply)');
});

/**
 * 測試目標：chunkMessages()
 * 情境：boundary — 含多位元組字元(中文)的切塊;切點按 code unit 計,中文皆 BMP
 *       (每字 1 code unit),故 5000 中文為單則、5001 切兩則,且字元不得被破壞
 * Mock：無需 mock
 * 預期：5000 中文回單則且首字尾字完整;5001 切兩則,第二則為剩下的 1 個中文字
 */
test('chunkMessages: 中文(多位元組)依 code unit 切塊且不破壞字元', () => {
  // Arrange + Act
  const exact = chunkMessages('中'.repeat(5000));
  const over = chunkMessages('中'.repeat(5001));

  // Assert：5000 中文 = 5000 code units = 單則,內容完整無亂碼
  expect(exact.length).toBe(1);
  expect(exact[0].text.length).toBe(5000);
  expect(exact[0].text).toBe('中'.repeat(5000));

  // Assert：5001 切兩則,第一則滿 5000、第二則剩 1 個完整中文字
  expect(over.length).toBe(2);
  expect(over[0].text.length).toBe(5000);
  expect(over[1].text).toBe('中');
});

/**
 * 測試目標：sendOutbound()
 * 情境：boundary — reply_to 指到不存在的 message_id,resolve 取不到 token → 走 Push
 * Mock：fakeDeps（reply / push 預設成功）
 * 預期：不打 Reply、改打 Push,且 Push 目標為 chatId
 */
test('sendOutbound: reply_to 指到不存在的訊息 → 改走 Push', async () => {
  // Arrange
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps, calls } = fakeDeps();

  // Act：reply_to 指向未暫存的 'nope'
  const result = await sendOutbound(store, 'U1', 'hi', 'nope', deps);

  // Assert
  expect(result.via).toBe('push');
  expect(calls.reply).toBe(0);
  expect(calls.push).toBe(1);
  expect(calls.pushTo).toBe('U1');
});

/**
 * 測試目標：runReplyTool()
 * 情境：exception — 底層 deps 丟例外,須被 try/catch 接住回 isError 而非整個 reject
 * Mock：自製 deps,push 直接 throw(token 不新鮮會落到 Push 路徑)
 * 預期：回 isError，content 文字含「reply 失敗」
 */
test('runReplyTool: 底層送出丟例外時回 isError 而不向外拋', async () => {
  // Arrange：U1 已知但無 token → 走 Push;push 丟例外
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);
  const deps = {
    reply: async () => ({ ok: true, status: 200 }),
    push: async () => {
      throw new Error('network down');
    },
  };

  // Act
  const res = await runReplyTool({ chat_id: 'U1', text: 'hi' }, store, deps);

  // Assert
  expect(res.isError).toBe(true);
  expect(res.content[0].text).toContain('reply 失敗');
});

// ===== Phase 3 修正:lineApiPost 網路錯誤收斂(REV-001)/ monthly-limit 變體(REV-002)=====

test('lineApiPost: fetch 網路錯誤收斂成 {ok:false,status:0} 不丟例外', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.reject(new Error('ECONNRESET'))) as typeof fetch;

  try {
    const result = await lineApiPost('https://api.line.me/v2/bot/message/push', { to: 'U1', messages: [] });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(0);
    expect(result.message).toBe('network-error');
  } finally {
    globalThis.fetch = orig;
  }
});

test('lineApiPost: 2xx 回 ok', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.resolve(new Response('{}', { status: 200 }))) as typeof fetch;

  try {
    const result = await lineApiPost('https://api.line.me/v2/bot/message/reply', {});

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
  } finally {
    globalThis.fetch = orig;
  }
});

test('lineApiPost: 非 2xx 帶回 LINE 的 message', async () => {
  const orig = globalThis.fetch;
  const body = JSON.stringify({ message: 'You have reached your monthly limit.' });
  globalThis.fetch = (() => Promise.resolve(new Response(body, { status: 429 }))) as typeof fetch;

  try {
    const result = await lineApiPost('https://api.line.me/v2/bot/message/push', {});

    expect(result.ok).toBe(false);
    expect(result.status).toBe(429);
    expect(result.message).toBe('You have reached your monthly limit.');
  } finally {
    globalThis.fetch = orig;
  }
});

test('sendOutbound: monthly-limit 大小寫/措辭變體仍判為 monthly-quota', async () => {
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);
  const { deps } = fakeDeps({ push: { ok: false, status: 429, message: 'You have reached your MONTHLY LIMIT for this month.' } });

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

  expect(result.reason).toBe('monthly-quota');
});

/**
 * 整合測試:用真實 lineApiPost 組 deps,Reply 的 fetch 網路 reject 時須端到端
 * 落到 Push 成功(鎖 REV-001 的關鍵級聯路徑,而非僅單元組合)。
 */
test('整合:Reply 端 fetch reject → 端到端落到 Push 送達', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = ((url: string | URL | Request) => {
    if (String(url).includes('/message/reply')) {
      return Promise.reject(new Error('ECONNRESET'));
    }

    return Promise.resolve(new Response('{}', { status: 200 }));
  }) as typeof fetch;

  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const deps = {
    reply: (replyToken: string, messages: { type: 'text'; text: string }[]) =>
      lineApiPost('https://api.line.me/v2/bot/message/reply', { replyToken, messages }),
    push: (to: string, messages: { type: 'text'; text: string }[]) =>
      lineApiPost('https://api.line.me/v2/bot/message/push', { to, messages }),
  };

  try {
    const result = await sendOutbound(store, 'U1', 'hi', undefined, deps);

    expect(result).toEqual({ delivered: true, via: 'push' });
    expect(store.resolve('U1', 'm1')?.used).toBe(true);
  } finally {
    globalThis.fetch = orig;
  }
});

// ===== Phase 4:群組 mention 過濾 / 媒體 =====

test('isMentioned: mentionees 含 isSelf 為 true 才算 @ 到 bot', () => {
  expect(isMentioned(groupTextEvent('e', 'hi', true))).toBe(true);
  expect(isMentioned(groupTextEvent('e', 'hi', false))).toBe(false);
  expect(isMentioned({ type: 'message', webhookEventId: 'e', message: { id: 'm', type: 'text', mention: { mentionees: [{ isSelf: false }] } } })).toBe(false);
});

test('deliverableChatId: 1:1 不受 requireMention 影響', () => {
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } };

  expect(deliverableChatId(event, true)).toBe('U1');
});

test('deliverableChatId: 群組未 @ 且 requireMention 時回 null', () => {
  expect(deliverableChatId(groupTextEvent('e', 'hi', false), true)).toBeNull();
  expect(deliverableChatId(groupTextEvent('e', 'hi', true), true)).toBe('G1');
  expect(deliverableChatId(groupTextEvent('e', 'hi', false), false)).toBe('G1');
});

test('deliverableChatId: 非 message 事件或無 chat_id 回 null', () => {
  expect(deliverableChatId({ type: 'follow', webhookEventId: 'e', source: { type: 'user', userId: 'U1' } }, false)).toBeNull();
  expect(deliverableChatId({ type: 'message', webhookEventId: 'e', message: { id: 'm', type: 'text', text: 'x' } }, false)).toBeNull();
});

test('eventToChannelMessage: 群組未 @ 且 requireMention 時回 null', () => {
  expect(eventToChannelMessage(groupTextEvent('e', 'hi', false), true)).toBeNull();
  expect(eventToChannelMessage(groupTextEvent('e', 'hi', true), true)?.content).toBe('hi');
});

test('parseMedia: 各媒體型別解析,文字 / sticker 回 null', () => {
  const image = parseMedia({ type: 'message', webhookEventId: 'e', message: { id: 'mi', type: 'image', contentProvider: { type: 'line' } } });
  const file = parseMedia({ type: 'message', webhookEventId: 'e', message: { id: 'mf', type: 'file', fileName: 'a.pdf' } });
  const ext = parseMedia({ type: 'message', webhookEventId: 'e', message: { id: 'mx', type: 'image', contentProvider: { type: 'external', originalContentUrl: 'https://x/y.jpg' } } });

  expect(image?.kind).toBe('image');
  expect(image?.provider).toBe('line');
  expect(file?.kind).toBe('file');
  expect(file?.fileName).toBe('a.pdf');
  expect(ext?.provider).toBe('external');
  expect(ext?.externalUrl).toBe('https://x/y.jpg');
  expect(parseMedia({ type: 'message', webhookEventId: 'e', message: { id: 'm', type: 'text', text: 'x' } })).toBeNull();
  expect(parseMedia({ type: 'message', webhookEventId: 'e', message: { id: 'm', type: 'sticker' } })).toBeNull();
});

test('buildMediaMessage: line provider 抓內容存檔並把路徑放 meta.file_path', async () => {
  const { deps, saved } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'mimg', type: 'image', contentProvider: { type: 'line' } } };

  const msg = await buildMediaMessage(event, false, deps);

  expect(msg?.meta.file_path).toBe('/tmp/inbox/mimg.jpg');
  expect(msg?.meta.media_type).toBe('image');
  expect(saved).toEqual([{ messageId: 'mimg', ext: '.jpg' }]);
});

test('buildMediaMessage: external provider 用 url 不抓內容', async () => {
  const { deps, saved } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'mx', type: 'image', contentProvider: { type: 'external', originalContentUrl: 'https://x/y.jpg' } } };

  const msg = await buildMediaMessage(event, false, deps);

  expect(msg?.meta.url).toBe('https://x/y.jpg');
  expect(msg?.meta.file_path).toBeUndefined();
  expect(saved.length).toBe(0);
});

test('buildMediaMessage: 取內容失敗時標 media_status=unavailable', async () => {
  const { deps } = fakeMediaDeps({ fetched: { ok: false, status: 404 } });
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'mf', type: 'image', contentProvider: { type: 'line' } } };

  const msg = await buildMediaMessage(event, false, deps);

  expect(msg?.meta.media_status).toBe('unavailable');
  expect(msg?.meta.file_path).toBeUndefined();
});

test('buildMediaMessage: 群組未 @ 且 requireMention 時回 null 且不抓內容', async () => {
  const { deps, saved } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'group' as const, groupId: 'G1' }, message: { id: 'mg', type: 'image', contentProvider: { type: 'line' } } };

  const msg = await buildMediaMessage(event, true, deps);

  expect(msg).toBeNull();
  expect(saved.length).toBe(0);
});

test('buildMediaMessage: 非媒體事件回 null', async () => {
  const { deps } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } };

  expect(await buildMediaMessage(event, false, deps)).toBeNull();
});

test('handleCallback: 群組未 @ bot(requireMention)不投遞', async () => {
  let count = 0;
  const body = JSON.stringify({ events: [groupTextEvent('p4-g1', 'hi', false)] });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    count += 1;
  }, { requireMention: true, access: OPEN_ACCESS, logGroup: () => {} });

  expect(count).toBe(0);
});

test('handleCallback: 群組 @ 到 bot 時投遞', async () => {
  const seen: string[] = [];
  const body = JSON.stringify({ events: [groupTextEvent('p4-g2', 'hey bot', true)] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    seen.push(msg.content);
  }, { requireMention: true, access: OPEN_ACCESS, logGroup: () => {} });

  expect(seen).toEqual(['hey bot']);
});

test('handleCallback: 媒體事件抓內容並以 file_path 投遞', async () => {
  const metas: Record<string, string>[] = [];
  const { deps, saved } = fakeMediaDeps();
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p4-img', source: { type: 'user', userId: 'U1' }, message: { id: 'mimg2', type: 'image', contentProvider: { type: 'line' } } }],
  });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    metas.push(msg.meta);
  }, { mediaDeps: deps, access: OPEN_ACCESS });

  expect(metas.length).toBe(1);
  expect(metas[0].file_path).toContain('mimg2');
  expect(saved.length).toBe(1);
});

// ===== Phase 4 補強:parseMedia 型別 / provider 預設、buildMediaMessage file / room / 退化、isMentioned 多 mentionee、room deliverable =====

/**
 * 測試目標：parseMedia()
 * 情境：boundary — video / audio 兩種型別也須被識別(現有測試只覆蓋 image / file)
 * Mock：無需 mock
 * 預期：kind 各為 video / audio,messageId 帶回;contentProvider type=line 時 provider=line
 */
test('parseMedia: video / audio 型別也被識別', () => {
  // Arrange + Act
  const video = parseMedia({ type: 'message', webhookEventId: 'pm-vid', message: { id: 'mv', type: 'video', contentProvider: { type: 'line' } } });
  const audio = parseMedia({ type: 'message', webhookEventId: 'pm-aud', message: { id: 'ma', type: 'audio', contentProvider: { type: 'line' } } });

  // Assert
  expect(video?.kind).toBe('video');
  expect(video?.messageId).toBe('mv');
  expect(video?.provider).toBe('line');
  expect(audio?.kind).toBe('audio');
  expect(audio?.messageId).toBe('ma');
  expect(audio?.provider).toBe('line');
});

/**
 * 測試目標：parseMedia()
 * 情境：boundary — 完全沒有 contentProvider 欄位時,provider 須預設為 line
 *       (server.ts:305 `contentProvider?.type === 'external' ? 'external' : 'line'`,
 *        缺欄位時 optional chaining 回 undefined → 落到 line)
 * Mock：無需 mock
 * 預期：provider=line、externalUrl 為 undefined
 */
test('parseMedia: 無 contentProvider 時 provider 預設為 line', () => {
  // Arrange + Act
  const media = parseMedia({ type: 'message', webhookEventId: 'pm-noprov', message: { id: 'mnp', type: 'image' } });

  // Assert
  expect(media?.provider).toBe('line');
  expect(media?.externalUrl).toBeUndefined();
});

/**
 * 測試目標：buildMediaMessage() + extForMedia()
 * 情境：boundary — file 型別且 fileName 帶副檔名,存檔副檔名須取自 fileName(而非 kind 預設 .bin),
 *       且 content 須帶出檔名(server.ts:373-377)
 * Mock：fakeMediaDeps（line provider 抓內容成功 → 走存檔路徑）
 * 預期：saved 的 ext 為 '.pdf'、file_path 以 .pdf 結尾、content 含檔名、media_type=file
 */
test('buildMediaMessage: file 型別存檔副檔名取自 fileName 且 content 帶檔名', async () => {
  // Arrange
  const { deps, saved } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'bm-file', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'mfile', type: 'file', fileName: 'report.pdf', contentProvider: { type: 'line' } } };

  // Act
  const msg = await buildMediaMessage(event, false, deps);

  // Assert
  expect(saved).toEqual([{ messageId: 'mfile', ext: '.pdf' }]);
  expect(msg?.meta.file_path).toBe('/tmp/inbox/mfile.pdf');
  expect(msg?.meta.media_type).toBe('file');
  expect(msg?.content).toContain('report.pdf');
});

/**
 * 測試目標：buildMediaMessage()
 * 情境：boundary — room 來源,deliverableChatId 須以 roomId 當 chat_id;requireMention 開啟但未 @
 *       時須回 null 不抓內容(room 與 group 同走「群組需 @」分支,server.ts:234)
 * Mock：fakeMediaDeps
 * 預期：未 @ 回 null 且不存檔;@ 到 bot 時 chat_id=R1 並走存檔
 */
test('buildMediaMessage: room 來源未 @ 回 null,@ 到 bot 時 chat_id 用 roomId', async () => {
  // Arrange:room 未 @ + requireMention
  const noMention = fakeMediaDeps();
  const roomNoAt = { type: 'message', webhookEventId: 'bm-room-1', source: { type: 'room' as const, roomId: 'R1' }, message: { id: 'mr1', type: 'image', contentProvider: { type: 'line' } } };

  // Act
  const blocked = await buildMediaMessage(roomNoAt, true, noMention.deps);

  // Assert:未 @ → null 且不抓內容
  expect(blocked).toBeNull();
  expect(noMention.saved.length).toBe(0);

  // Arrange:room @ 到 bot + requireMention
  const mentioned = fakeMediaDeps();
  const roomAt = { type: 'message', webhookEventId: 'bm-room-2', source: { type: 'room' as const, roomId: 'R1' }, message: { id: 'mr2', type: 'image', contentProvider: { type: 'line' }, mention: { mentionees: [{ isSelf: true }] } } };

  // Act
  const passed = await buildMediaMessage(roomAt, true, mentioned.deps);

  // Assert:@ 到 → chat_id=roomId 且走存檔
  expect(passed?.meta.chat_id).toBe('R1');
  expect(mentioned.saved).toEqual([{ messageId: 'mr2', ext: '.jpg' }]);
});

/**
 * 測試目標：buildMediaMessage()
 * 情境：boundary — provider 為 external 但缺 originalContentUrl;REV-002 後直接標
 *       unavailable,不去打對 external 注定失敗的 content API
 * Mock：fakeMediaDeps
 * 預期：meta.media_status=unavailable、無 url、無存檔
 */
test('buildMediaMessage: external 但缺 originalContentUrl 標 unavailable 不抓內容', async () => {
  // Arrange:external 型別但沒有 URL
  const { deps, saved } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'bm-ext-nourl', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'mext', type: 'image', contentProvider: { type: 'external' } } };

  // Act
  const msg = await buildMediaMessage(event, false, deps);

  // Assert:不抓內容,直接標無法取得
  expect(msg?.meta.media_status).toBe('unavailable');
  expect(msg?.meta.url).toBeUndefined();
  expect(saved.length).toBe(0);
});

/**
 * 測試目標：isMentioned()
 * 情境：boundary — mentionees 多筆,其中之一 isSelf=true 即算 @ 到 bot(server.ts:211 .some)
 * Mock：無需 mock
 * 預期：多筆中只要有一筆 isSelf=true 回 true;全為 false 回 false
 */
test('isMentioned: 多個 mentionees 其中一個 isSelf=true 即算 @ 到 bot', () => {
  // Arrange:三個 mentionee,只有中間那個是 bot
  const oneSelf = { type: 'message', webhookEventId: 'im-multi-1', message: { id: 'm', type: 'text', mention: { mentionees: [{ isSelf: false }, { isSelf: true }, { isSelf: false }] } } };
  const noneSelf = { type: 'message', webhookEventId: 'im-multi-2', message: { id: 'm', type: 'text', mention: { mentionees: [{ isSelf: false }, { isSelf: false }] } } };

  // Act + Assert
  expect(isMentioned(oneSelf)).toBe(true);
  expect(isMentioned(noneSelf)).toBe(false);
});

/**
 * 測試目標：deliverableChatId()
 * 情境：boundary — room 來源與 group 同走「群組需 @」分支:未 @ + requireMention 回 null,
 *       @ 到回 roomId,requireMention 關閉時不論有無 @ 都回 roomId
 * Mock：無需 mock
 * 預期：如上三種組合
 */
test('deliverableChatId: room 來源套用群組 mention 規則', () => {
  // Arrange:room 未 @ / 已 @
  const roomNoAt = { type: 'message', webhookEventId: 'dc-room-1', source: { type: 'room' as const, roomId: 'R1' }, message: { id: 'mr', type: 'text', text: 'x' } };
  const roomAt = { type: 'message', webhookEventId: 'dc-room-2', source: { type: 'room' as const, roomId: 'R1' }, message: { id: 'mr', type: 'text', text: 'x', mention: { mentionees: [{ isSelf: true }] } } };

  // Act + Assert
  expect(deliverableChatId(roomNoAt, true)).toBeNull();
  expect(deliverableChatId(roomAt, true)).toBe('R1');
  expect(deliverableChatId(roomNoAt, false)).toBe('R1');
});

// ===== Phase 4 修正:safeId 收斂(REV-001)/ external 缺 url(REV-002)/ markSeen 注入(REV-003)=====

test('safeId: 剔除 path traversal 與非白名單字元,空則 unknown', () => {
  expect(safeId('../../../../tmp/evil')).toBe('tmpevil');
  expect(safeId('466789577898262530')).toBe('466789577898262530');
  expect(safeId('a/b\\c?d#e')).toBe('abcde');
  expect(safeId('../')).toBe('unknown');
  expect(safeId('')).toBe('unknown');
});

test('buildMediaMessage: fileName 副檔名含路徑字元時白名單去除(.b/c → .bc)', async () => {
  const { deps, saved } = fakeMediaDeps();
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'mf', type: 'file', fileName: 'a.b/c', contentProvider: { type: 'line' } } };

  await buildMediaMessage(event, false, deps);

  expect(saved[0].ext).toBe('.bc');
  expect(saved[0].ext.includes('/')).toBe(false);
});

test('handleCallback: markSeen 可注入(回 false 視為重複,不投遞)', async () => {
  let count = 0;
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p4-inject', source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } }],
  });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    count += 1;
  }, { markSeen: () => false });

  expect(count).toBe(0);
});

// ===== Phase 4 安全加固:safeId 截長(M1)/ 畸形 timestamp(L2)/ 媒體大小上限(M2)=====

test('safeId: 超長 ID 截斷至 100 字', () => {
  expect(safeId('a'.repeat(5000)).length).toBe(100);
});

test('eventToChannelMessage: 畸形 timestamp 不放 ts 也不丟例外', () => {
  const nan = eventToChannelMessage({ type: 'message', webhookEventId: 'e', timestamp: NaN, source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } });
  const str = eventToChannelMessage({ type: 'message', webhookEventId: 'e', timestamp: 'abc' as unknown as number, source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } });

  expect(nan?.meta.ts).toBeUndefined();
  expect(str?.meta.ts).toBeUndefined();
});

test('fetchLineContent: content-length 超過上限回 413 不讀 body', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.resolve(new Response('x', { status: 200, headers: { 'content-length': String(999 * 1024 * 1024) } }))) as typeof fetch;

  try {
    const result = await fetchLineContent('m1');

    expect(result.ok).toBe(false);
    expect(result.status).toBe(413);
    expect(result.bytes).toBeUndefined();
  } finally {
    globalThis.fetch = orig;
  }
});

test('fetchLineContent: 正常大小回 ok 帶 bytes', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.resolve(new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { 'content-length': '3' } }))) as typeof fetch;

  try {
    const result = await fetchLineContent('m1');

    expect(result.ok).toBe(true);
    expect(result.bytes?.length).toBe(3);
  } finally {
    globalThis.fetch = orig;
  }
});

// ===== Phase 5:存取控制 gate + pairing 整合 =====

const pairingAccess = { dmPolicy: 'pairing' as const, allowFrom: [], allowGroups: {} as Record<string, string[]>, groupSettings: {} as Record<string, { requireMention?: boolean }>, pending: {} };

/** 組一個 1:1 文字事件。 */
function dmEvent(id: string, userId: string, replyToken = 'rt'): {
  type: string;
  webhookEventId: string;
  replyToken: string;
  source: { type: 'user'; userId: string };
  message: { id: string; type: string; text: string };
} {
  return { type: 'message', webhookEventId: id, replyToken, source: { type: 'user', userId }, message: { id, type: 'text', text: 'hi' } };
}

test('gate: 非 message 事件一律 drop', () => {
  expect(gate({ type: 'follow', webhookEventId: 'e', source: { type: 'user', userId: 'U1' } }, pairingAccess, 1000).action).toBe('drop');
});

test('gate: allowFrom 內的 user 直接 deliver', () => {
  const access = { ...pairingAccess, allowFrom: ['U1'] };

  expect(gate(dmEvent('e', 'U1'), access, 1000).action).toBe('deliver');
});

test('gate: disabled 政策一律 drop', () => {
  const access = { ...pairingAccess, dmPolicy: 'disabled' as const, allowFrom: ['U1'] };

  expect(gate(dmEvent('e', 'U1'), access, 1000).action).toBe('drop');
});

test('gate: allowlist 對未授權 user drop', () => {
  const access = { ...pairingAccess, dmPolicy: 'allowlist' as const };

  expect(gate(dmEvent('e', 'Ux'), access, 1000).action).toBe('drop');
});

test('gate: pairing 對未配對 user 產生配對碼並帶回更新後的 access', () => {
  const decision = gate(dmEvent('e', 'Unew'), pairingAccess, 1000, () => 'abc123');

  expect(decision.action).toBe('pair');

  if (decision.action === 'pair') {
    expect(decision.code).toBe('abc123');
    expect(decision.access.pending.abc123?.userId).toBe('Unew');
    expect(decision.access).not.toBe(pairingAccess);
  }
});

test('gate: pairing 重用此 user 未過期的碼', () => {
  const access = { ...pairingAccess, pending: { old: { userId: 'Unew', expiresAt: 5000 } } };
  const decision = gate(dmEvent('e', 'Unew'), access, 1000, () => 'should-not-use');

  expect(decision.action).toBe('pair');

  if (decision.action === 'pair') {
    expect(decision.code).toBe('old');
  }
});

test('gate: 群組已授權且發話者在成員清單內 deliver,否則 drop', () => {
  const allowed = { ...pairingAccess, allowGroups: { G1: ['U1'] } };

  expect(gate(groupTextEvent('e', 'hi', true), allowed, 1000).action).toBe('deliver');
  // 未授權群組 + 沒被 @ → 靜默 drop(被 @ 的未授權群組改走 group_pair,另有測試)
  expect(gate(groupTextEvent('e', 'hi', false), pairingAccess, 1000).action).toBe('drop');
});

test('gate: 已授權群組但發話者不在成員清單 → 被 @ 回 member_pair、未 @ drop', () => {
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };

  // 成員 U9 不在 G1 清單(只有 U1)
  const mentioned = gate(groupTextEvent('e', 'hi', true, 'U9'), access, 1000);
  expect(mentioned.action).toBe('member_pair');

  if (mentioned.action === 'member_pair') {
    expect(mentioned.groupId).toBe('G1');
    expect(mentioned.userId).toBe('U9');
  }

  expect(gate(groupTextEvent('e', 'hi', false, 'U9'), access, 1000).action).toBe('drop');
});

test('gate: 已授權群組成員清單空 → 無人可驅動(strict)', () => {
  const access = { ...pairingAccess, allowGroups: { G1: [] } };

  expect(gate(groupTextEvent('e', 'hi', true, 'U1'), access, 1000).action).toBe('member_pair');
  expect(gate(groupTextEvent('e', 'hi', false, 'U1'), access, 1000).action).toBe('drop');
});

test('handleCallback: 未配對的 1:1 回配對碼、不投遞,且新碼有寫入(persistAccess)', async () => {
  let delivered = 0;
  let persisted = 0;
  let saved: { pending: Record<string, { userId: string }> } | undefined;
  const replies: string[] = [];
  const body = JSON.stringify({ events: [dmEvent('p5-pair', 'Unew')] });
  const sendDeps = {
    reply: async (_token: string, messages: { type: 'text'; text: string }[]) => {
      replies.push(messages[0].text);

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, {
    access: { ...pairingAccess, allowFrom: [] },
    sendDeps,
    persistAccess: a => {
      persisted += 1;
      saved = a;
    },
  });

  expect(delivered).toBe(0);
  expect(replies[0]).toContain('配對碼');
  expect(replies[0]).toContain('/line:access pair');
  expect(persisted).toBe(1); // 新配對碼有實際寫入
  expect(Object.values(saved?.pending ?? {}).some(p => p.userId === 'Unew')).toBe(true);
});

test('handleCallback: 已授權的 1:1 正常投遞', async () => {
  const seen: string[] = [];
  const body = JSON.stringify({ events: [dmEvent('p5-ok', 'Uok')] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    seen.push(msg.content);
  }, { access: { ...pairingAccess, dmPolicy: 'allowlist', allowFrom: ['Uok'] } });

  expect(seen).toEqual(['hi']);
});

/**
 * 測試目標:gate() pairing 分支
 * 情境:boundary —— pending 已有「別的 user」的未過期碼
 * Mock:無需 mock(純函式,注入固定 genCode)
 * 預期:不重用他人的碼,產生新碼;他人未過期的碼仍保留在 access.pending
 */
test('gate: pairing 不重用他人的碼,產新碼且保留他人未過期碼', () => {
  const access = { ...pairingAccess, pending: { other: { userId: 'Uother', expiresAt: 9000 } } };
  const decision = gate(dmEvent('e', 'Umine'), access, 1000, () => 'mineCode');

  expect(decision.action).toBe('pair');

  if (decision.action === 'pair') {
    expect(decision.code).toBe('mineCode');
    expect(decision.access.pending.mineCode?.userId).toBe('Umine');
    expect(decision.access.pending.other?.userId).toBe('Uother');
  }
});

/**
 * 測試目標:gate() pairing 分支
 * 情境:boundary —— 該 user 的碼已過期
 * Mock:無需 mock(純函式,注入固定 genCode)
 * 預期:過期碼被 prune(不重用),產生新碼,且過期碼不留在 access.pending
 */
test('gate: pairing 不重用該 user 的過期碼,prune 後產新碼', () => {
  const access = { ...pairingAccess, pending: { stale: { userId: 'Umine', expiresAt: 500 } } };
  const decision = gate(dmEvent('e', 'Umine'), access, 1000, () => 'freshCode');

  expect(decision.action).toBe('pair');

  if (decision.action === 'pair') {
    expect(decision.code).toBe('freshCode');
    expect(decision.access.pending.stale).toBeUndefined();
    expect(decision.access.pending.freshCode?.userId).toBe('Umine');
  }
});

/**
 * 測試目標:gate() 群組分支
 * 情境:boundary —— 群組事件缺 groupId
 * Mock:無需 mock(純函式)
 * 預期:無法比對 allowGroups,fail-closed 一律 drop
 */
test('gate: 群組缺 groupId 一律 drop', () => {
  const event = { type: 'message', webhookEventId: 'e', source: { type: 'group' as const }, message: { id: 'e', type: 'text', text: 'hi', mention: { mentionees: [{ isSelf: true }] } } };

  expect(gate(event, { ...pairingAccess, allowGroups: { G1: ['U1'] } }, 1000).action).toBe('drop');
});

/**
 * 測試目標:gate() 1:1 分支
 * 情境:boundary —— allowlist 政策但 user 在 allowFrom
 * Mock:無需 mock(純函式)
 * 預期:allowFrom 優先於 allowlist 的 drop,直接 deliver
 */
test('gate: allowlist 政策下 allowFrom 內的 user 仍 deliver', () => {
  const access = { ...pairingAccess, dmPolicy: 'allowlist' as const, allowFrom: ['Umine'] };

  expect(gate(dmEvent('e', 'Umine'), access, 1000).action).toBe('deliver');
});

/**
 * 測試目標:gate() pairing 分支
 * 情境:boundary —— 1:1 事件來源缺 userId
 * Mock:無需 mock(純函式)
 * 預期:匿名來源不發配對碼,fail-closed drop
 */
test('gate: pairing 對缺 userId 的 1:1 來源 drop', () => {
  const event = { type: 'message', webhookEventId: 'e', replyToken: 'rt', source: { type: 'user' as const }, message: { id: 'e', type: 'text', text: 'hi' } };

  expect(gate(event, pairingAccess, 1000).action).toBe('drop');
});

/**
 * 測試目標:handleCallback 群組投遞整合
 * 情境:happy —— 授權群組(allowGroups)且 @ 到 bot
 * Mock:onMessage spy(注入 access + requireMention)
 * 預期:訊息被投遞,content 與 chat_id(groupId)正確
 */
test('handleCallback: 授權群組(allowGroups)經 gate 後正常投遞', async () => {
  const seen: { content: string; chatId?: string }[] = [];
  const body = JSON.stringify({ events: [groupTextEvent('p5-grp', 'group hi', true)] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    seen.push({ content: msg.content, chatId: msg.meta.chat_id });
  }, { access: { ...pairingAccess, allowGroups: { G1: ['U1'] } }, requireMention: true, logGroup: () => {} });

  expect(seen).toEqual([{ content: 'group hi', chatId: 'G1' }]);
});

/**
 * 測試目標:handleCallback pairing 重用碼整合
 * 情境:boundary —— pairing 未配對者已有未過期碼(expiresAt 須大於真實 Date.now,
 *   因 handleCallback 內 gate 以 Date.now() 判定碼是否過期)
 * Mock:sendDeps.reply 記錄回覆文字、onMessage spy
 * 預期:回覆送出既有碼、不投遞;access 物件未被替換(pending 不變,不觸發 saveAccess 寫檔)
 */
test('handleCallback: pairing 重用既有未過期碼,回該碼且不寫檔', async () => {
  const access = { ...pairingAccess, pending: { reuseCode: { userId: 'Ureuse', expiresAt: Date.now() + 3_600_000 } } };
  let delivered = 0;
  const replies: string[] = [];
  const body = JSON.stringify({ events: [dmEvent('p5-reuse', 'Ureuse')] });
  const sendDeps = {
    reply: async (_token: string, messages: { type: 'text'; text: string }[]) => {
      replies.push(messages[0].text);

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  let persisted = 0;

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, sendDeps, persistAccess: () => { persisted += 1; } });

  expect(delivered).toBe(0);
  expect(replies[0]).toContain('reuseCode');
  expect(Object.keys(access.pending)).toEqual(['reuseCode']);
  expect(persisted).toBe(0); // 重用既有碼不應寫檔
});

// ===== Phase 5 修正:normalizeAccess(REV-004)/ 配對碼碰撞避免(REV-001)=====

test('normalizeAccess: 壞型別欄位退回安全值', () => {
  const a = normalizeAccess({ dmPolicy: 'weird', allowFrom: 'U1', allowGroups: null, pending: null });

  expect(a.dmPolicy).toBe('pairing');
  expect(a.allowFrom).toEqual([]);
  expect(a.allowGroups).toEqual({});
  expect(a.pending).toEqual({});
});

test('normalizeAccess: 合法欄位原樣保留,allowFrom 內非字串過濾掉', () => {
  const a = normalizeAccess({ dmPolicy: 'allowlist', allowFrom: ['U1', 123, 'U2'], allowGroups: { G1: ['U1', 7, 'U2'] }, pending: { c: { userId: 'U1', expiresAt: 9 } } });

  expect(a.dmPolicy).toBe('allowlist');
  expect(a.allowFrom).toEqual(['U1', 'U2']);
  expect(a.allowGroups).toEqual({ G1: ['U1', 'U2'] }); // 成員清單內非字串過濾掉
  expect(a.pending.c?.userId).toBe('U1');
});

test('normalizeAccess: 舊格式 allowGroups 字串陣列 → 遷移成成員空的 map(strict)', () => {
  const a = normalizeAccess({ dmPolicy: 'allowlist', allowFrom: [], allowGroups: ['G1', 'R1'], pending: {} });

  expect(a.allowGroups).toEqual({ G1: [], R1: [] });
});

test('normalizeAccess: null / 非物件退回全預設', () => {
  expect(normalizeAccess(null).dmPolicy).toBe('pairing');
  expect(normalizeAccess(undefined).allowFrom).toEqual([]);
});

test('gate: 產碼撞到既有未過期碼時改用新碼,不覆寫他人 pending', () => {
  const access = { ...pairingAccess, pending: { dup: { userId: 'Uother', expiresAt: 5000 } } };
  let i = 0;
  const codes = ['dup', 'fresh'];
  const decision = gate(dmEvent('e', 'Unew'), access, 1000, () => codes[i++]);

  expect(decision.action).toBe('pair');

  if (decision.action === 'pair') {
    expect(decision.code).toBe('fresh');
    expect(decision.access.pending.dup?.userId).toBe('Uother');
    expect(decision.access.pending.fresh?.userId).toBe('Unew');
  }
});

// ===== Phase 6:permission relay =====

test('parsePermissionReply: y/yes → allow、n/no → deny,大小寫不拘', () => {
  expect(parsePermissionReply('y abcde')).toEqual({ request_id: 'abcde', behavior: 'allow' });
  expect(parsePermissionReply('yes xyzab')).toEqual({ request_id: 'xyzab', behavior: 'allow' });
  expect(parsePermissionReply('n abcde')).toEqual({ request_id: 'abcde', behavior: 'deny' });
  expect(parsePermissionReply('NO ABCDE')).toEqual({ request_id: 'abcde', behavior: 'deny' });
});

test('parsePermissionReply: 非授權回覆格式回 null', () => {
  expect(parsePermissionReply('hello there')).toBeNull();
  expect(parsePermissionReply('y abcdef')).toBeNull(); // 6 字母
  expect(parsePermissionReply('y abcdl')).toBeNull(); // request_id 不含 l 且須 5 碼
  expect(parsePermissionReply('yabcde')).toBeNull(); // 缺空白
});

test('permissionPromptText: 含工具名與 y/n 指示', () => {
  const text = permissionPromptText({ request_id: 'abcde', tool_name: 'Bash', description: 'run ls', input_preview: 'ls -la' });

  expect(text).toContain('Bash');
  expect(text).toContain('y abcde');
  expect(text).toContain('n abcde');
});

test('handleCallback: 授權 1:1 的「y <code>」攔截成裁決,不投遞', async () => {
  const verdicts: { request_id: string; behavior: string }[] = [];
  let delivered = 0;
  const verdictBody = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p6-v', replyToken: 'rt', source: { type: 'user', userId: 'Uok' }, message: { id: 'm', type: 'text', text: 'y abcde' } }],
  });

  await handleCallback(webhookRequest(verdictBody, sign(verdictBody)), () => {
    delivered += 1;
  }, {
    access: { ...pairingAccess, dmPolicy: 'allowlist', allowFrom: ['Uok'] },
    onVerdict: v => {
      verdicts.push(v);
    },
  });

  expect(delivered).toBe(0);
  expect(verdicts).toEqual([{ request_id: 'abcde', behavior: 'allow' }]);
});

test('handleCallback: 授權 1:1 的一般訊息不被當裁決,照常投遞', async () => {
  const verdicts: unknown[] = [];
  const seen: string[] = [];
  const body = JSON.stringify({ events: [dmEvent('p6-normal', 'Uok')] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    seen.push(msg.content);
  }, {
    access: { ...pairingAccess, dmPolicy: 'allowlist', allowFrom: ['Uok'] },
    onVerdict: v => {
      verdicts.push(v);
    },
  });

  expect(seen).toEqual(['hi']);
  expect(verdicts).toEqual([]);
});

// ===== Phase 6 補強:parsePermissionReply 邊界 / permissionPromptText 呈現 / 未授權與群組裁決防護 =====

/**
 * 測試目標:parsePermissionReply()
 * 情境:boundary —— 全形 yes / no 不可被當成裁決(正規表示式只認 ASCII y/yes/n/no)
 * Mock:無需 mock(純函式)
 * 預期:全形「ｙ」「ｎ」「ｙｅｓ」「ｎｏ」一律回 null,避免非預期字元被誤判為核可/拒絕
 */
test('parsePermissionReply: 全形 yes/no 不被當裁決,回 null', () => {
  // Arrange + Act + Assert
  expect(parsePermissionReply('ｙ abcde')).toBeNull();
  expect(parsePermissionReply('ｎ abcde')).toBeNull();
  expect(parsePermissionReply('ｙｅｓ abcde')).toBeNull();
  expect(parsePermissionReply('ｎｏ abcde')).toBeNull();
});

/**
 * 測試目標:parsePermissionReply()
 * 情境:boundary —— 合法裁決前後帶空白(含全形空白 U+3000,JS \s 也涵蓋)仍須解析成功
 * Mock:無需 mock(純函式)
 * 預期:前後 ASCII 空白、tab、換行、全形空白都被 \s* 吃掉,request_id 正確解析
 */
test('parsePermissionReply: 前後空白(含全形空白)仍正確解析', () => {
  // Arrange + Act + Assert
  expect(parsePermissionReply('   y abcde   ')).toEqual({ request_id: 'abcde', behavior: 'allow' });
  expect(parsePermissionReply('\ty abcde\n')).toEqual({ request_id: 'abcde', behavior: 'allow' });
  expect(parsePermissionReply('　n xyzab　')).toEqual({ request_id: 'xyzab', behavior: 'deny' });
});

/**
 * 測試目標:parsePermissionReply()
 * 情境:boundary —— request_id 長度不符(4 碼 / 6 碼)一律回 null(須恰好 5 碼)
 * Mock:無需 mock(純函式)
 * 預期:4 碼與 6 碼皆 null(現有測試已覆蓋 6 碼,此處補 4 碼下界並一併鎖住兩端)
 */
test('parsePermissionReply: request_id 4 碼 / 6 碼皆回 null', () => {
  // Arrange + Act + Assert
  expect(parsePermissionReply('y abcd')).toBeNull(); // 4 碼
  expect(parsePermissionReply('y abcdef')).toBeNull(); // 6 碼
});

/**
 * 測試目標:parsePermissionReply()
 * 情境:boundary —— request_id 含字母 l(大小寫皆是;正規以 [a-km-z] 排除 l)回 null,
 *   但 5 碼數字非法、含 l 以外字母合法(behavior 仍轉小寫)
 * Mock:無需 mock(純函式)
 * 預期:大寫 L 與小寫 l 都被排除回 null;含其他字母的合法碼正常解析且轉小寫
 */
test('parsePermissionReply: request_id 含 l/L 回 null,合法碼轉小寫', () => {
  // Arrange + Act + Assert
  expect(parsePermissionReply('y abcdl')).toBeNull(); // 末位小寫 l
  expect(parsePermissionReply('y abcdL')).toBeNull(); // 末位大寫 L(忽略大小寫後即 l)
  expect(parsePermissionReply('Y ABKZM')).toEqual({ request_id: 'abkzm', behavior: 'allow' });
});

/**
 * 測試目標:permissionPromptText()
 * 情境:happy —— 提示須完整帶出 description 與 input_preview(讓授權者看得到工具實際輸入),
 *   且把 request_id 嵌進 y/n 指示
 * Mock:無需 mock(純函式)
 * 預期:輸出含 tool_name、description、input_preview 原文,以及「y <id>」「n <id>」
 */
test('permissionPromptText: 呈現 description 與 input_preview 原文', () => {
  // Arrange
  const req = { request_id: 'xyzab', tool_name: 'Bash', description: '執行清單', input_preview: 'rm -rf /tmp/foo' };

  // Act
  const text = permissionPromptText(req);

  // Assert
  expect(text).toContain('執行清單');
  expect(text).toContain('rm -rf /tmp/foo');
  expect(text).toContain('y xyzab');
  expect(text).toContain('n xyzab');
});

/**
 * 測試目標:handleCallback() 裁決攔截 + gate 防護
 * 情境:exception(安全) —— 未授權的 1:1(allowlist 但不在 allowFrom)送出「y abcde」,
 *   gate 先判 drop,裁決路徑根本到不了 → onVerdict 不可被呼叫、也不投遞。
 *   鎖住「未授權者能下裁決」這條攻擊面。
 * Mock:onVerdict spy、onMessage spy、sendDeps(避免打真 API)
 * 預期:onVerdict 0 次、delivered 0 次
 */
test('handleCallback: 未授權 1:1(gate=drop)的裁決文字不觸發 onVerdict 也不投遞', async () => {
  // Arrange
  const verdicts: unknown[] = [];
  let delivered = 0;
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p6-unauth', replyToken: 'rt', source: { type: 'user', userId: 'Uevil' }, message: { id: 'm', type: 'text', text: 'y abcde' } }],
  });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, {
    access: { ...pairingAccess, dmPolicy: 'allowlist', allowFrom: [] },
    onVerdict: v => {
      verdicts.push(v);
    },
  });

  // Assert
  expect(verdicts).toEqual([]);
  expect(delivered).toBe(0);
});

/**
 * 測試目標:handleCallback() 裁決攔截 + gate 防護
 * 情境:exception(安全) —— 未配對的 pairing 1:1 送出「y abcde」,gate 判 pair(回配對碼)
 *   而非 deliver,裁決路徑到不了 → onVerdict 不可被呼叫;回的是配對碼提示。
 * Mock:onVerdict spy、onMessage spy、sendDeps 記錄回覆文字
 * 預期:onVerdict 0 次、delivered 0 次、回覆含「配對碼」
 */
test('handleCallback: 未配對 pairing 1:1(gate=pair)的裁決文字不觸發 onVerdict', async () => {
  // Arrange
  const verdicts: unknown[] = [];
  let delivered = 0;
  const replies: string[] = [];
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p6-pair-verdict', replyToken: 'rt', source: { type: 'user', userId: 'Unew' }, message: { id: 'm', type: 'text', text: 'y abcde' } }],
  });
  const sendDeps = {
    reply: async (_token: string, messages: { type: 'text'; text: string }[]) => {
      replies.push(messages[0].text);

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, {
    access: { ...pairingAccess, allowFrom: [] },
    onVerdict: v => {
      verdicts.push(v);
    },
    sendDeps,
    persistAccess: () => {},
  });

  // Assert
  expect(verdicts).toEqual([]);
  expect(delivered).toBe(0);
  expect(replies[0]).toContain('配對碼');
});

/**
 * 測試目標:handleCallback() 裁決攔截來源限定
 * 情境:exception(安全) —— 授權群組(allowGroups)內、@ 到 bot 的「y abcde」不可被當裁決
 *   (裁決攔截限 source.type === 'user');群組訊息應照常投遞為一般內容。
 * Mock:onVerdict spy、onMessage spy
 * 預期:onVerdict 0 次;訊息以原文「y abcde」投遞(chat_id=groupId)
 */
test('handleCallback: 群組來源的「y abcde」不被當裁決,照常投遞', async () => {
  // Arrange
  const verdicts: unknown[] = [];
  const seen: { content: string; chatId?: string }[] = [];
  const body = JSON.stringify({ events: [groupTextEvent('p6-grp-verdict', 'y abcde', true)] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), msg => {
    seen.push({ content: msg.content, chatId: msg.meta.chat_id });
  }, {
    access: { ...pairingAccess, allowGroups: { G1: ['U1'] } },
    logGroup: () => {},
    requireMention: true,
    onVerdict: v => {
      verdicts.push(v);
    },
  });

  // Assert
  expect(verdicts).toEqual([]);
  expect(seen).toEqual([{ content: 'y abcde', chatId: 'G1' }]);
});

/**
 * 測試目標:handleCallback() 裁決攔截 + requireMention
 * 情境:exception(安全) —— 授權群組內但「未 @ bot」的「y abcde」:既非裁決(來源非 user)、
 *   又被 requireMention 擋下不投遞 → onVerdict 與 onMessage 都不應被呼叫。
 * Mock:onVerdict spy、onMessage spy
 * 預期:onVerdict 0 次、delivered 0 次
 */
test('handleCallback: 群組未 @ 的「y abcde」既不被當裁決也被 requireMention 擋下', async () => {
  // Arrange
  const verdicts: unknown[] = [];
  let delivered = 0;
  const body = JSON.stringify({ events: [groupTextEvent('p6-grp-nomention', 'y abcde', false)] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, {
    access: { ...pairingAccess, allowGroups: { G1: ['U1'] } },
    logGroup: () => {},
    requireMention: true,
    onVerdict: v => {
      verdicts.push(v);
    },
  });

  // Assert
  expect(verdicts).toEqual([]);
  expect(delivered).toBe(0);
});

/**
 * 測試目標:handleCallback() 裁決攔截行為(deny 路徑)
 * 情境:happy —— 授權 1:1 送出「n abcde」須攔截成 deny 裁決,不投遞
 *   (現有測試只覆蓋 allow 路徑,此處補 deny)
 * Mock:onVerdict spy、onMessage spy
 * 預期:onVerdict 收到 { request_id: 'abcde', behavior: 'deny' };delivered 0 次
 */
test('handleCallback: 授權 1:1 的「n <code>」攔截成 deny 裁決,不投遞', async () => {
  // Arrange
  const verdicts: { request_id: string; behavior: string }[] = [];
  let delivered = 0;
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'p6-deny', replyToken: 'rt', source: { type: 'user', userId: 'Uok' }, message: { id: 'm', type: 'text', text: 'n abcde' } }],
  });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, {
    access: { ...pairingAccess, dmPolicy: 'allowlist', allowFrom: ['Uok'] },
    onVerdict: v => {
      verdicts.push(v);
    },
  });

  // Assert
  expect(delivered).toBe(0);
  expect(verdicts).toEqual([{ request_id: 'abcde', behavior: 'deny' }]);
});

// ===== 群組自助授權:未授權群組被 @ 時回 group_pair(groupId)=====

test('gate: 未授權群組被 @ 時回 group_pair 帶 groupId', () => {
  const decision = gate(groupTextEvent('g', 'hi bot', true), pairingAccess, 1000);

  expect(decision.action).toBe('group_pair');

  if (decision.action === 'group_pair') {
    expect(decision.groupId).toBe('G1');
  }
});

test('gate: 未授權群組「沒被 @」仍靜默 drop(不洗版)', () => {
  expect(gate(groupTextEvent('g', 'hi', false), pairingAccess, 1000).action).toBe('drop');
});

test('gate: 已授權群組且成員在清單內照常 deliver(不走 group_pair / member_pair)', () => {
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };

  expect(gate(groupTextEvent('g', 'hi bot', true), access, 1000).action).toBe('deliver');
});

test('handleCallback: 未授權群組被 @ → 回 groupId 提示且不投遞', async () => {
  let delivered = 0;
  const replies: string[] = [];
  const body = JSON.stringify({ events: [{ ...groupTextEvent('g-pair', 'hi bot', true), replyToken: 'rt' }] });
  const sendDeps = {
    reply: async (_token: string, messages: { type: 'text'; text: string }[]) => {
      replies.push(messages[0].text);

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access: pairingAccess, sendDeps });

  expect(delivered).toBe(0);
  expect(replies[0]).toContain('群組 ID:G1');
  expect(replies[0]).toContain('group-allow G1');
});

test('handleCallback: 未授權群組同事件重送 → dedup 擋下,只回一次提示', async () => {
  const replies: string[] = [];
  const body = JSON.stringify({ events: [{ ...groupTextEvent('g-dup', 'hi bot', true), replyToken: 'rt' }] });
  const sendDeps = {
    reply: async (_token: string, messages: { type: 'text'; text: string }[]) => {
      replies.push(messages[0].text);

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  await handleCallback(webhookRequest(body, sign(body)), () => {}, { access: pairingAccess, sendDeps });
  await handleCallback(webhookRequest(body, sign(body)), () => {}, { access: pairingAccess, sendDeps });

  expect(replies.length).toBe(1); // 第二次同 webhookEventId 被 markSeen 擋下
});

test('handleCallback: 未授權群組被 @ 但缺 replyToken → 不投遞不丟例外回 200', async () => {
  let delivered = 0;
  const body = JSON.stringify({ events: [groupTextEvent('g-noreply', 'hi bot', true)] });

  const res = await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access: pairingAccess });

  expect(res.status).toBe(200);
  expect(delivered).toBe(0);
});

// ===== 群組訊息歷史(SQLite)/ get_history =====

function memStore() {
  return createHistoryStore(new Database(':memory:'));
}

test('createHistoryStore: record + query 依時間段過濾、依時間排序', () => {
  const store = memStore();
  store.record('G1', 1000, 'U1', 'Alice', 'text', 'a');
  store.record('G1', 2000, 'U2', 'Bob', 'text', 'b');
  store.record('G1', 3000, 'U1', 'Alice', 'text', 'c');
  store.record('G2', 2000, 'U9', 'Zoe', 'text', 'other-group');

  const rows = store.query('G1', 1500, 3000, 100);

  expect(rows.map(r => r.text)).toEqual(['b', 'c']); // ts=1000 排除、G2 不混入
  expect(rows[0].user_name).toBe('Bob');
});

test('createHistoryStore: limit 限制筆數', () => {
  const store = memStore();

  for (let i = 0; i < 5; i += 1) {
    store.record('G1', 1000 + i, 'U1', null, 'text', String(i));
  }

  expect(store.query('G1', 0, 9999, 2).length).toBe(2);
});

test('groupMessageRow: 群組文字→row、room→roomId、媒體→佔位、非群組/無訊息→null', () => {
  const g = groupMessageRow({
    type: 'message',
    webhookEventId: 'e',
    timestamp: 1700000000000,
    source: { type: 'group', groupId: 'G1', userId: 'U1' },
    message: { id: 'm', type: 'text', text: 'hi' },
  });

  expect(g).toEqual({ groupId: 'G1', ts: 1700000000000, userId: 'U1', type: 'text', text: 'hi', messageId: 'm' });

  const room = groupMessageRow({ type: 'message', webhookEventId: 'e', source: { type: 'room', roomId: 'R1' }, message: { id: 'm', type: 'text', text: 'x' } });
  expect(room?.groupId).toBe('R1');

  const media = groupMessageRow({ type: 'message', webhookEventId: 'e', source: { type: 'group', groupId: 'G1' }, message: { id: 'm', type: 'image' } });
  expect(media?.text).toBe('(image)');

  expect(groupMessageRow({ type: 'message', webhookEventId: 'e', source: { type: 'user', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'x' } })).toBeNull();
  expect(groupMessageRow({ type: 'message', webhookEventId: 'e', source: { type: 'group', groupId: 'G1' } })).toBeNull();
});

test('runGetHistory: 缺 chat_id → isError', () => {
  expect(runGetHistory({}, memStore(), 10000).isError).toBe(true);
});

test('runGetHistory: minutes 取最近 N 分鐘', () => {
  const store = memStore();
  const now = 10_000_000;
  store.record('G1', now - 30 * 60_000, 'U1', 'Alice', 'text', 'in-window');
  store.record('G1', now - 90 * 60_000, 'U1', 'Alice', 'text', 'too-old');
  store.record('G1', now - 1000, 'U2', 'Bob', 'text', 'recent');

  const res = runGetHistory({ chat_id: 'G1', minutes: 60 }, store, now);

  expect(res.content[0].text).toContain('in-window');
  expect(res.content[0].text).toContain('recent');
  expect(res.content[0].text).not.toContain('too-old');
  expect(res.content[0].text).toContain('Alice'); // 用名字
});

test('runGetHistory: since/until 指定範圍(毫秒)', () => {
  const store = memStore();
  store.record('G1', 1000, 'U1', 'A', 'text', 'a');
  store.record('G1', 5000, 'U1', 'A', 'text', 'b');
  store.record('G1', 9000, 'U1', 'A', 'text', 'c');

  const res = runGetHistory({ chat_id: 'G1', since: '2000', until: '8000' }, store, 99999);

  expect(res.content[0].text).toContain('b');
  expect(res.content[0].text).not.toContain('a');
  expect(res.content[0].text).not.toContain('c');
});

test('runGetHistory: 無紀錄回提示', () => {
  expect(runGetHistory({ chat_id: 'Gx', minutes: 60 }, memStore(), 10000).content[0].text).toContain('無紀錄');
});

test('handleCallback: 已授權群組訊息呼叫 logGroup;1:1 不呼叫', async () => {
  const logged: string[] = [];
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] }, allowFrom: ['U1'] };
  const logGroup = (e: { source?: { groupId?: string } }) => {
    logged.push(e.source?.groupId ?? '?');
  };

  const groupBody = JSON.stringify({ events: [{ ...groupTextEvent('lg-1', 'hi bot', true), replyToken: 'rt' }] });
  await handleCallback(webhookRequest(groupBody, sign(groupBody)), () => {}, { access, logGroup });

  const dmBody = JSON.stringify({ events: [dmEvent('lg-dm', 'U1')] });
  await handleCallback(webhookRequest(dmBody, sign(dmBody)), () => {}, { access, logGroup });

  expect(logged).toEqual(['G1']); // 只有群組那則被記錄
});

test('runGetHistory: minutes 0 視為 0 分鐘(不誤落預設 60 分)', () => {
  const store = memStore();
  const now = 10_000_000;
  store.record('G1', now - 5 * 60_000, 'U1', 'A', 'text', 'five-min-ago');

  // minutes:0 → since=until=now,5 分鐘前的訊息不該被涵蓋
  const res = runGetHistory({ chat_id: 'G1', minutes: 0 }, store, now);
  expect(res.content[0].text).not.toContain('five-min-ago');
});

test('runGetHistory: since 晚於 until → isError', () => {
  const res = runGetHistory({ chat_id: 'G1', since: '9000', until: '1000' }, memStore(), 99999);
  expect(res.isError).toBe(true);
  expect(res.content[0].text).toContain('since 晚於 until');
});

test('resolveMemberName: 200 回 displayName 並快取(第二次不再 fetch)', async () => {
  const orig = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (() => {
    calls += 1;

    return Promise.resolve(new Response(JSON.stringify({ displayName: 'Alice' }), { status: 200 }));
  }) as typeof fetch;

  try {
    expect(await resolveMemberName('Gr1', 'Ur1')).toBe('Alice');
    expect(await resolveMemberName('Gr1', 'Ur1')).toBe('Alice'); // 快取命中
    expect(calls).toBe(1);
  } finally {
    globalThis.fetch = orig;
  }
});

test('resolveMemberName: 非 200 回 undefined(退回只記 userId)', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.resolve(new Response('{}', { status: 404 }))) as typeof fetch;

  try {
    expect(await resolveMemberName('Gr2', 'Ur2')).toBeUndefined();
  } finally {
    globalThis.fetch = orig;
  }
});

test('resolveMemberName: fetch reject 回 undefined 不丟例外', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.reject(new Error('net'))) as typeof fetch;

  try {
    expect(await resolveMemberName('Gr3', 'Ur3')).toBeUndefined();
  } finally {
    globalThis.fetch = orig;
  }
});

test('handleCallback: 群組媒體「不」主動投遞進 session(硬控制,改由記錄+引用取用)', async () => {
  let delivered = 0;
  const { deps } = fakeMediaDeps();
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  // 群組圖片,發話者 U1 為成員(證明即使成員的媒體也不投遞 → 硬控制),無 mention
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'grp-media', source: { type: 'group', groupId: 'G1', userId: 'U1' }, message: { id: 'gm', type: 'image', contentProvider: { type: 'line' } } }],
  });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, mediaDeps: deps, logGroup: () => {} });

  expect(delivered).toBe(0); // 群組媒體不主動進 session
});

test('handleCallback: 已授權群組的文字「沒 @」仍不投遞(媒體放行不影響文字規則)', async () => {
  let delivered = 0;
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  const body = JSON.stringify({ events: [groupTextEvent('grp-text-noat', 'just chatting', false)] });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, requireMention: true, logGroup: () => {} });

  expect(delivered).toBe(0);
});

// ===== 引用回覆(quotedMessageId)=====

test('createHistoryStore: lookupMessage 依 message_id 取回被引用訊息;查無回 null', () => {
  const store = memStore();
  store.record('G1', 1000, 'U1', 'Alice', 'text', 'hello there', 'MID-1');
  store.record('G1', 2000, 'U2', 'Bob', 'text', 'no id'); // 無 message_id

  const found = store.lookupMessage('MID-1');
  expect(found?.text).toBe('hello there');
  expect(found?.user_name).toBe('Alice');
  expect(store.lookupMessage('NOPE')).toBeNull();
});

test('handleCallback: 引用回覆時補上被引用訊息的發話者 + 內容', async () => {
  const delivered: string[] = [];
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  const ev = {
    type: 'message',
    webhookEventId: 'q-1',
    replyToken: 'rt',
    source: { type: 'group', groupId: 'G1', userId: 'U1' },
    message: { id: 'm-q', type: 'text', text: '這句什麼意思?', mention: { mentionees: [{ isSelf: true }] }, quotedMessageId: 'MID-1' },
  };
  const body = JSON.stringify({ events: [ev] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    delivered.push(msg.content);
  }, {
    access,
    logGroup: () => {},
    lookupQuote: id => (id === 'MID-1' ? { user_name: 'Alice', text: 'the quoted line' } : null),
  });

  expect(delivered.length).toBe(1);
  expect(delivered[0]).toContain('引用 Alice');
  expect(delivered[0]).toContain('the quoted line');
  expect(delivered[0]).toContain('這句什麼意思?');
});

test('handleCallback: 引用但查無被引用訊息 → 照常投遞不加前綴', async () => {
  const delivered: string[] = [];
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  const ev = {
    type: 'message',
    webhookEventId: 'q-2',
    replyToken: 'rt',
    source: { type: 'group', groupId: 'G1', userId: 'U1' },
    message: { id: 'm-q2', type: 'text', text: 'orphan quote', mention: { mentionees: [{ isSelf: true }] }, quotedMessageId: 'GONE' },
  };
  const body = JSON.stringify({ events: [ev] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    delivered.push(msg.content);
  }, { access, logGroup: () => {}, lookupQuote: () => null });

  expect(delivered[0]).toBe('orphan quote'); // 無前綴
});

test('createHistoryStore: 舊 schema 有資料 → 自動補 message_id 欄且舊資料保留', () => {
  const db = new Database(':memory:');
  db.run('CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL, ts INTEGER NOT NULL, user_id TEXT, user_name TEXT, type TEXT NOT NULL, text TEXT)');
  db.run("INSERT INTO messages (group_id, ts, user_id, user_name, type, text) VALUES ('G1', 1000, 'U1', 'Alice', 'text', 'old')");

  const store = createHistoryStore(db);

  expect(store.query('G1', 0, 9999, 100).map(r => r.text)).toEqual(['old']);
  expect(store.lookupMessage('old')).toBeNull(); // 舊列 message_id 為 NULL,不被誤中
});

test('createHistoryStore: 已遷移 DB 二次建立不丟例外、資料不變', () => {
  const db = new Database(':memory:');
  const s1 = createHistoryStore(db);
  s1.record('G1', 1000, 'U1', 'Alice', 'text', 'hi', 'MID-1');

  const s2 = createHistoryStore(db); // ALTER 應被 catch

  expect(s2.lookupMessage('MID-1')?.text).toBe('hi');
});

// ===== 硬控制 + 引用媒體 =====

test('fetchAndSaveMedia: line 媒體抓取存檔回路徑;external / 非媒體回 null', async () => {
  const { deps, saved } = fakeMediaDeps();
  const img = { type: 'message', webhookEventId: 'fs', source: { type: 'group', groupId: 'G1' }, message: { id: 'fm', type: 'image', contentProvider: { type: 'line' } } };

  const path = await fetchAndSaveMedia(img, deps);

  expect(path).toContain('fm');
  expect(saved.length).toBe(1);

  const ext = { type: 'message', webhookEventId: 'fs2', source: { type: 'group', groupId: 'G1' }, message: { id: 'fm2', type: 'image', contentProvider: { type: 'external', originalContentUrl: 'http://x' } } };
  expect(await fetchAndSaveMedia(ext, deps)).toBeNull();

  const txt = { type: 'message', webhookEventId: 'fs3', source: { type: 'group', groupId: 'G1' }, message: { id: 'fm3', type: 'text', text: 'hi' } };
  expect(await fetchAndSaveMedia(txt, deps)).toBeNull();
});

test('createHistoryStore: record 帶 file_path → lookupMessage 取得得回', () => {
  const store = memStore();
  store.record('G1', 1000, 'U1', 'Alice', 'image', '(image)', 'IMG-1', '/inbox/IMG-1.jpg');

  expect(store.lookupMessage('IMG-1')?.file_path).toBe('/inbox/IMG-1.jpg');
});

test('handleCallback: 引用媒體 → 帶出 quoted_file_path 供 Read', async () => {
  const out: { content: string; meta: Record<string, string> }[] = [];
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  const ev = {
    type: 'message',
    webhookEventId: 'qm-1',
    replyToken: 'rt',
    source: { type: 'group', groupId: 'G1', userId: 'U1' },
    message: { id: 'm-qm', type: 'text', text: '這張圖是什麼?', mention: { mentionees: [{ isSelf: true }] }, quotedMessageId: 'IMG-1' },
  };
  const body = JSON.stringify({ events: [ev] });

  await handleCallback(webhookRequest(body, sign(body)), msg => {
    out.push(msg);
  }, {
    access,
    logGroup: () => {},
    lookupQuote: id => (id === 'IMG-1' ? { user_id: 'U1', user_name: 'Alice', text: '(image)', file_path: '/inbox/IMG-1.jpg' } : null),
  });

  expect(out.length).toBe(1);
  expect(out[0].meta.quoted_file_path).toBe('/inbox/IMG-1.jpg');
  expect(out[0].content).toContain('引用 Alice');
  expect(out[0].content).toContain('quoted_file_path');
});

test('handleCallback: 群組媒體即使 requireMention=false 也不投遞(硬控制與 mention 解耦)', async () => {
  let delivered = 0;
  const { deps } = fakeMediaDeps();
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  const body = JSON.stringify({
    events: [{ type: 'message', webhookEventId: 'g-rmf', source: { type: 'group', groupId: 'G1', userId: 'U1' }, message: { id: 'gm2', type: 'image', contentProvider: { type: 'line' } } }],
  });

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, mediaDeps: deps, requireMention: false, logGroup: () => {} });

  expect(delivered).toBe(0); // 即使關閉 mention,群組媒體仍不進 session
});

// ===== 群組成員級授權(每群獨立成員白名單) =====

test('handleCallback: 已授權群組非成員被 @ → 回其 userId(member_pair)且不投遞', async () => {
  let delivered = 0;
  const replies: string[] = [];
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } }; // 只有 U1 是成員
  const body = JSON.stringify({ events: [{ ...groupTextEvent('mp-1', 'hi bot', true, 'U9'), replyToken: 'rt' }] }); // U9 非成員
  const sendDeps = {
    reply: async (_t: string, m: { type: 'text'; text: string }[]) => {
      replies.push(m[0].text);

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, sendDeps, logGroup: () => {} });

  expect(delivered).toBe(0);
  expect(replies[0]).toContain('你的 userId:U9');
  expect(replies[0]).toContain('group-member-allow G1 U9');
});

test('handleCallback: 已授權群組「非成員」訊息仍被記錄(摘要涵蓋全群,與成員清單無關)', async () => {
  const logged: string[] = [];
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } }; // U9 非成員
  const body = JSON.stringify({ events: [groupTextEvent('lognm', 'random chat', false, 'U9')] });

  await handleCallback(webhookRequest(body, sign(body)), () => {}, {
    access,
    logGroup: (e: { source?: { userId?: string } }) => {
      logged.push(e.source?.userId ?? '?');
    },
  });

  expect(logged).toEqual(['U9']); // 非成員、未投遞,但仍記錄供摘要
});

test('handleCallback: member_pair 缺 replyToken → 不投遞不丟例外回 200', async () => {
  let delivered = 0;
  const access = { ...pairingAccess, allowGroups: { G1: ['U1'] } };
  const body = JSON.stringify({ events: [groupTextEvent('mp-noreply', 'hi bot', true, 'U9')] }); // 非成員、無 replyToken

  const res = await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, logGroup: () => {} });

  expect(res.status).toBe(200);
  expect(delivered).toBe(0);
});

// ===== 原型鏈污染防護(security P1) =====

test('gate: 原型鏈鍵名(toString)經 normalizeAccess 後不被誤判為已授權群組', () => {
  // production 路徑:normalizeAccess → allowGroups 為無原型 map
  const access = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: { G1: ['U1'] }, pending: {} });
  const ev = {
    type: 'message',
    webhookEventId: 'proto',
    source: { type: 'group' as const, groupId: 'toString', userId: 'U1' },
    message: { id: 'm', type: 'text', text: 'hi', mention: { mentionees: [{ isSelf: true }] } },
  };

  // 'toString' 非真實授權群組 → 應走 group_pair(未授權),而非 member_pair / deliver
  expect(gate(ev, access, 1000).action).toBe('group_pair');
});

test('handleCallback: gate 例外時 fail-closed(不投遞、回 200)', async () => {
  let delivered = 0;
  // 未經 normalizeAccess 的 plain-object access:allowGroups['hasOwnProperty'] 命中原型 function → gate 內 includes 丟例外
  const access = { dmPolicy: 'pairing' as const, allowFrom: [], allowGroups: {} as Record<string, string[]>, pending: {} };
  const ev = {
    type: 'message',
    webhookEventId: 'thr',
    source: { type: 'group', groupId: 'hasOwnProperty', userId: 'U1' },
    message: { id: 'm', type: 'text', text: 'hi', mention: { mentionees: [{ isSelf: true }] } },
  };
  const body = JSON.stringify({ events: [ev] });

  const res = await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, logGroup: () => {} });

  expect(res.status).toBe(200);
  expect(delivered).toBe(0);
});

// ===== single-harden:回錯對象止血(reply_to 反查覆寫 + 出口白名單) =====

test('createReplyStore: sourceChatOf 取訊息來源、isKnownChat 認已互動對話', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');

  expect(store.sourceChatOf('m1')).toBe('U1');
  expect(store.sourceChatOf('nope')).toBeUndefined();
  expect(store.isKnownChat('U1')).toBe(true);
  expect(store.isKnownChat('U999')).toBe(false);
});

test('sendOutbound: reply_to 反查覆寫目的地(Claude 填錯 chat_id 也送對對話)', async () => {
  const store = createReplyStore();
  store.stash('m-a', 'Ua', 'tok-a'); // 訊息 m-a 來自 Ua
  let pushedTo = '';
  const deps = {
    reply: async () => ({ ok: false, status: 400 }), // reply 失敗 → 退回 push,方便驗目的地
    push: async (to: string) => {
      pushedTo = to;

      return { ok: true, status: 200 };
    },
  };

  // Claude 填錯 chat_id='Ub',但 reply_to='m-a'(來自 Ua)→ 應送到 Ua
  await sendOutbound(store, 'Ub', 'hi', 'm-a', deps);

  expect(pushedTo).toBe('Ua');
});

test('sendOutbound: 目的地不在已互動來源 → 擋下不送(回錯對象止血)', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1'); // 只互動過 U1
  const { deps, calls } = fakeDeps();

  // 嘗試送往從沒互動過的 U999 → 擋下,reply / push 都不打
  const result = await sendOutbound(store, 'U999', 'hi', undefined, deps);

  expect(result.delivered).toBe(false);
  expect(result.reason).toContain('目的地不在已知對話');
  expect(calls.reply).toBe(0);
  expect(calls.push).toBe(0);
});

test('runGetHistory: isKnownChat 擋下未互動對話(防讀別群歷史)', () => {
  const store = memStore();
  store.record('G1', 1000, 'U1', 'Alice', 'text', 'hi', 'M1');
  const known = (c: string) => c === 'G1'; // 此 session 只互動過 G1

  expect(runGetHistory({ chat_id: 'G2', minutes: 60 }, store, 99999, known).isError).toBe(true);
  expect(runGetHistory({ chat_id: 'G1', minutes: 60 }, store, 99999, known).isError).toBeUndefined();
});

// ===== 長任務延後(interim 計時器 + defer 取代 Push,零 Push 額度) =====

function fakeScheduler() {
  const cbs = new Map<number, () => void>();
  let nextId = 1;

  return {
    cbs,
    sched: {
      set: (cb: () => void) => {
        const id = nextId;
        nextId += 1;
        cbs.set(id, cb);

        return id;
      },
      clear: (id: number) => {
        cbs.delete(id);
      },
    },
    fireAll() {
      for (const cb of cbs.values()) {
        cb();
      }
    },
  };
}

test('createInterimTimers: arm 逾時觸發 onTimeout', () => {
  let fired = 0;
  const f = fakeScheduler();
  const timers = createInterimTimers(f.sched);

  timers.arm('U1', 50000, () => {
    fired += 1;
  });
  f.fireAll();

  expect(fired).toBe(1);
});

test('createInterimTimers: disarm 後逾時不觸發', () => {
  let fired = 0;
  const f = fakeScheduler();
  const timers = createInterimTimers(f.sched);

  timers.arm('U1', 50000, () => {
    fired += 1;
  });
  timers.disarm('U1');
  f.fireAll();

  expect(fired).toBe(0);
});

test('createInterimTimers: 同 chat 重 arm 取消舊計時器', () => {
  let firstFired = 0;
  let secondFired = 0;
  const f = fakeScheduler();
  const timers = createInterimTimers(f.sched);

  timers.arm('U1', 50000, () => {
    firstFired += 1;
  });
  timers.arm('U1', 50000, () => {
    secondFired += 1;
  });
  f.fireAll();

  expect(firstFired).toBe(0); // 舊計時器被取消
  expect(secondFired).toBe(1);
});

test('sendOutbound: deferInsteadOfPush=true 時 token 不可用 → 延後不 Push', async () => {
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined); // 已知對話、無 token
  const { deps, calls } = fakeDeps();

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps, true);

  expect(result).toEqual({ delivered: false, reason: 'deferred' });
  expect(calls.push).toBe(0); // 不耗 Push 額度
});

test('sendOutbound: token 新鮮時即使開 defer 仍正常 Reply', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps, calls } = fakeDeps();

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps, true);

  expect(result).toEqual({ delivered: true, via: 'reply' });
  expect(calls.reply).toBe(1);
});

test('sendOutbound: defer=true + token 存在但 reply 失敗 → 仍 defer 不 Push', async () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'tok-1');
  const { deps, calls } = fakeDeps({ reply: { ok: false, status: 400, message: 'Invalid reply token' } });

  const result = await sendOutbound(store, 'U1', 'hi', undefined, deps, true);

  expect(result).toEqual({ delivered: false, reason: 'deferred' });
  expect(calls.push).toBe(0); // reply 失敗也不耗 Push
  expect(store.resolve('U1', 'm1')?.used).toBe(true); // 死 token 已標記
});

test('runReplyTool: deferred 回非錯誤的延後引導', async () => {
  const store = createReplyStore();
  store.stash('m0', 'U1', undefined);
  const { deps } = fakeDeps();

  const res = await runReplyTool({ chat_id: 'U1', text: 'hi' }, store, deps, true);

  expect(res.isError).toBeUndefined(); // 延後不是錯誤
  expect(res.content[0].text).toContain('已延後');
});

// ===== 多對話路由模式(LINE_TEAMMATE_ROUTING) =====

test('buildInstructions: 預設不含路由協議;開啟時把路由協議前置(最顯著)', () => {
  const off = buildInstructions(false);
  const on = buildInstructions(true);

  expect(off).not.toContain('多對話路由模式');
  expect(off).toContain('LINE 訊息會以'); // 仍含基礎指引

  expect(on.startsWith('【最高優先')).toBe(true); // 路由協議在最前面
  expect(on).toContain('spawn 一個 background 具名 agent');
  expect(on).toContain('LINE 訊息會以'); // 基礎指引也在(teammate 通則)
});

test('buildInstructions: on = 路由前綴 + 一字不差的 base(鎖住抽取不漂移)', () => {
  const off = buildInstructions(false);
  const on = buildInstructions(true);

  expect(on.endsWith(off)).toBe(true); // on 結尾必須是完整 base → base 不被路由前綴牽連改動
  // base 關鍵不變式(任一被誤刪都該紅)
  expect(off).toContain('每次 reply 都務必帶 reply_to');
  expect(off).toContain('U 開頭為 1:1');
  expect(off).toContain('quoted_file_path');
});

// ===== P2 媒體 byteLength backstop(A:content-length 缺失時的硬上限)=====

test('fetchLineContent: content-length 缺失但實際超過上限 → byteLength backstop 回 413', async () => {
  const orig = globalThis.fetch;
  // 模擬無 content-length 標頭、實際 20 bytes 的回應(declared=0 會通過預檢,須由 backstop 擋下)
  globalThis.fetch = (() => Promise.resolve({
    ok: true,
    status: 200,
    headers: { get: () => null },
    arrayBuffer: async () => new ArrayBuffer(20),
  })) as unknown as typeof fetch;

  try {
    const result = await fetchLineContent('m1', 10);

    expect(result.ok).toBe(false);
    expect(result.status).toBe(413);
  } finally {
    globalThis.fetch = orig;
  }
});

test('fetchLineContent: content-length 缺失但實際在上限內 → 正常回 bytes', async () => {
  const orig = globalThis.fetch;
  globalThis.fetch = (() => Promise.resolve({
    ok: true,
    status: 200,
    headers: { get: () => null },
    arrayBuffer: async () => new ArrayBuffer(5),
  })) as unknown as typeof fetch;

  try {
    const result = await fetchLineContent('m1', 10);

    expect(result.ok).toBe(true);
    expect(result.bytes?.byteLength).toBe(5);
  } finally {
    globalThis.fetch = orig;
  }
});

// ===== P2 interim arm 決策(B3)=====

test('shouldArmInterim: 延後開 + 有 replyToken + interim>0 → true;任一不滿足 → false', () => {
  expect(shouldArmInterim(true, 'rt', 50000)).toBe(true);
  expect(shouldArmInterim(false, 'rt', 50000)).toBe(false); // 延後關
  expect(shouldArmInterim(true, undefined, 50000)).toBe(false); // 無 replyToken
  expect(shouldArmInterim(true, 'rt', 0)).toBe(false); // interim 停用
});

// ===== P2 sendInterim 直測(B2)=====

test('sendInterim: token 新鮮未用 → 送 INTERIM_TEXT 並標記 token 已用', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'rt-1');
  const sent: { token: string; text: string }[] = [];
  const deps = {
    reply: async (token: string, messages: { type: 'text'; text: string }[]) => {
      sent.push({ token, text: messages[0].text });

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  sendInterim('U1', store, deps);

  expect(sent.length).toBe(1);
  expect(sent[0].token).toBe('rt-1');
  expect(sent[0].text).toContain('處理中'); // 預設 INTERIM_TEXT
  expect(store.resolve('U1')?.used).toBe(true);
});

test('sendInterim: token 已用 → 不再送', () => {
  const store = createReplyStore();
  store.stash('m1', 'U1', 'rt-1');
  store.markUsed('m1');
  let calls = 0;
  const deps = {
    reply: async () => {
      calls += 1;

      return { ok: true, status: 200 };
    },
    push: async () => ({ ok: true, status: 200 }),
  };

  sendInterim('U1', store, deps);

  expect(calls).toBe(0);
});

// ===== P2 defaultLogGroup 媒體分支(B4)=====

test('defaultLogGroup: 群組圖片 → 取存媒體、record 帶 file_path 與補到的 user_name', async () => {
  const store = createHistoryStore(new Database(':memory:'));
  const media = fakeMediaDeps();
  const event = {
    type: 'message',
    source: { type: 'group' as const, groupId: 'G1', userId: 'U1' },
    timestamp: 1000,
    message: { id: 'mi1', type: 'image', contentProvider: { type: 'line' } },
  };

  await defaultLogGroup(event as never, { mediaDeps: media.deps, store, resolveName: async () => 'Alice' });

  expect(media.saved.length).toBe(1); // 有實際取存媒體
  const row = store.lookupMessage('mi1');
  expect(row?.file_path).toBeTruthy(); // file_path 有寫入
  expect(row?.user_name).toBe('Alice'); // 補到的名字
});

test('defaultLogGroup: 群組文字 → 不取媒體、file_path 為空', async () => {
  const store = createHistoryStore(new Database(':memory:'));
  const media = fakeMediaDeps();

  await defaultLogGroup(groupTextEvent('mt1', 'hello', false, 'U1') as never, {
    mediaDeps: media.deps,
    store,
    resolveName: async () => 'Bob',
  });

  expect(media.saved.length).toBe(0); // 文字不抓媒體
  const row = store.lookupMessage('mt1');
  expect(row?.file_path == null).toBe(true); // 無 file_path
  expect(row?.user_name).toBe('Bob');
});

// ===== Feature 1:授權 1:1 訊息寫入歷史 =====

/** 1:1 媒體事件(source.type='user';預設 image,line provider)。 */
function directMediaEvent(id: string, userId: string, type = 'image'): {
  type: string;
  webhookEventId: string;
  replyToken: string;
  timestamp: number;
  source: { type: 'user'; userId: string };
  message: { id: string; type: string; contentProvider: { type: string } };
} {
  return {
    type: 'message',
    webhookEventId: id,
    replyToken: 'rt',
    timestamp: 1000,
    source: { type: 'user', userId },
    message: { id, type, contentProvider: { type: 'line' } },
  };
}

/**
 * 測試目標:defaultLogDirect()
 * 情境:happy path — 1:1 文字訊息記進歷史,chat_id=userId 存進 group_id 欄
 * Mock:in-memory HistoryStore(:memory: SQLite,非外部依賴不算 mock)
 * 預期:lookupMessage 取回 user_id=userId、user_name=null、text 吻合、file_path=null;query(userId) 撈得到該列
 */
test('defaultLogDirect: 1:1 文字 → 存進 group_id=userId 欄、user_name 留空、get_history 撈得到', () => {
  // Arrange
  const store = createHistoryStore(new Database(':memory:'));
  const event = dmEvent('D-text-1', 'Uabc');

  // Act
  defaultLogDirect(event as never, undefined, store);

  // Assert
  const looked = store.lookupMessage('D-text-1');
  expect(looked).toEqual({ user_id: 'Uabc', user_name: null, text: 'hi', file_path: null });

  const rows = store.query('Uabc', 0, Number.MAX_SAFE_INTEGER, 10);
  expect(rows.map(r => r.text)).toEqual(['hi']); // chat_id=userId 存進 group_id 欄 → get_history(U…) 可用
});

/**
 * 測試目標:defaultLogDirect()
 * 情境:happy path — 1:1 媒體訊息帶 filePath,text 存成 `(type)` 佔位
 * Mock:in-memory HistoryStore
 * 預期:lookupMessage 的 file_path 為傳入路徑、text 為 '(image)'
 */
test('defaultLogDirect: 1:1 媒體 → file_path 寫入、text 為 (image)', () => {
  // Arrange
  const store = createHistoryStore(new Database(':memory:'));
  const event = directMediaEvent('D-img-1', 'Uabc', 'image');

  // Act
  defaultLogDirect(event as never, '/inbox/x.jpg', store);

  // Assert
  const looked = store.lookupMessage('D-img-1');
  expect(looked?.file_path).toBe('/inbox/x.jpg');
  expect(looked?.text).toBe('(image)');
});

/**
 * 測試目標:defaultLogDirect()
 * 情境:boundary — 群組事件(source.type='group')不屬 1:1,不記
 * Mock:in-memory HistoryStore
 * 預期:lookupMessage 回 null(store 無變化)
 */
test('defaultLogDirect: 群組事件 → 不記(非 user 來源直接 return)', () => {
  // Arrange
  const store = createHistoryStore(new Database(':memory:'));
  const event = groupTextEvent('D-grp-1', 'hi', false, 'U1');

  // Act
  defaultLogDirect(event as never, undefined, store);

  // Assert
  expect(store.lookupMessage('D-grp-1')).toBeNull();
});

/**
 * 測試目標:handleCallback() 對 logDirect 的接線
 * 情境:happy path — 授權 1:1 文字投遞時呼叫 logDirect、filePath 為 undefined;群組訊息不呼叫 logDirect
 * Mock:logDirect spy(計數 + 記錄 args)、OPEN_ACCESS、logGroup 空殼
 * 預期:1:1 呼叫 1 次且 filePath===undefined;群組訊息 logDirect 不被呼叫
 */
test('handleCallback: 授權 1:1 文字 → 呼叫 logDirect(filePath undefined);群組 → 不呼叫 logDirect', async () => {
  // Arrange
  const directCalls: { userId?: string; filePath: string | undefined }[] = [];
  const logDirect = (e: { source?: { userId?: string } }, filePath: string | undefined) => {
    directCalls.push({ userId: e.source?.userId, filePath });
  };

  // Act:授權 1:1 文字
  const dmBody = JSON.stringify({ events: [dmEvent('wire-dm', 'U1')] });
  await handleCallback(webhookRequest(dmBody, sign(dmBody)), () => {}, { access: OPEN_ACCESS, logDirect });

  // Act:群組訊息(走 logGroup,不該碰 logDirect)
  const groupBody = JSON.stringify({ events: [{ ...groupTextEvent('wire-grp', 'hi bot', true), replyToken: 'rt' }] });
  await handleCallback(webhookRequest(groupBody, sign(groupBody)), () => {}, { access: OPEN_ACCESS, logDirect, logGroup: () => {} });

  // Assert
  expect(directCalls).toEqual([{ userId: 'U1', filePath: undefined }]); // 只 1:1 那則、無媒體路徑
});

/**
 * 測試目標:handleCallback() 對 logDirect 的接線
 * 情境:boundary — 授權 1:1 傳「y <code>」是工具裁決,被 onVerdict 攔截,投遞前 continue
 * Mock:logDirect spy、onVerdict spy、OPEN_ACCESS
 * 預期:onVerdict 被呼叫、logDirect 不被呼叫(裁決訊息不進歷史)
 */
test('handleCallback: 授權 1:1 裁決訊息 → onVerdict 攔截、logDirect 不被呼叫', async () => {
  // Arrange
  let directCount = 0;
  const verdicts: { request_id: string; behavior: string }[] = [];
  const logDirect = () => {
    directCount += 1;
  };
  const onVerdict = (v: { request_id: string; behavior: 'allow' | 'deny' }) => {
    verdicts.push(v);
  };
  // parsePermissionReply 認得的裁決格式為「y/n <5 碼 [a-km-z]>」(見其既有測試),非 'y 12345'
  const event = { ...dmEvent('wire-verdict', 'U1'), message: { id: 'wire-verdict', type: 'text', text: 'y abcde' } };
  const body = JSON.stringify({ events: [event] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {}, { access: OPEN_ACCESS, logDirect, onVerdict });

  // Assert
  expect(verdicts).toEqual([{ request_id: 'abcde', behavior: 'allow' }]); // 被當裁決攔下
  expect(directCount).toBe(0); // 投遞前就 continue,不記歷史
});

/**
 * 測試目標:handleCallback() 對 logDirect 的接線(隱私不變式)
 * 情境:boundary — 未授權 1:1(gate=drop)在投遞前 continue,不入歷史
 * Mock:logDirect spy(計數)、allowlist + 空 allowFrom(任何 user 皆 drop)
 * 預期:logDirect 完全不被呼叫(未授權者訊息不留痕)
 */
test('handleCallback: 未授權 1:1(gate=drop)→ logDirect 不被呼叫(不入歷史)', async () => {
  // Arrange
  let directCount = 0;
  const logDirect = () => {
    directCount += 1;
  };
  const body = JSON.stringify({ events: [dmEvent('unauth-nolog', 'Uevil')] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {}, {
    access: { ...pairingAccess, dmPolicy: 'allowlist' as const, allowFrom: [] },
    logDirect,
  });

  // Assert
  expect(directCount).toBe(0); // gate=drop → 投遞前 continue → 不記歷史
});

/**
 * 測試目標:handleCallback() 對 logDirect 的接線(媒體整合)
 * 情境:happy path — 授權 1:1 媒體,logDirect 收到的 filePath 即 buildMediaMessage 經注入 mediaDeps 存的路徑
 * Mock:fakeMediaDeps(saveFile 回傳路徑)、logDirect spy(記錄 args)、OPEN_ACCESS
 * 預期:logDirect 收到 1 次,filePath === mediaDeps.saveFile 回傳值(非 undefined、不重抓)
 */
test('handleCallback: 授權 1:1 媒體 → logDirect 收到 mediaDeps 存的 file_path', async () => {
  // Arrange
  const media = fakeMediaDeps();
  const directPaths: (string | undefined)[] = [];
  const logDirect = (_e: unknown, filePath: string | undefined) => {
    directPaths.push(filePath);
  };
  const body = JSON.stringify({ events: [directMediaEvent('wire-img', 'U1', 'image')] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {}, { access: OPEN_ACCESS, mediaDeps: media.deps, logDirect });

  // Assert
  expect(media.saved).toEqual([{ messageId: 'wire-img', ext: '.jpg' }]); // 確實經 mediaDeps 存檔一次
  const savedPath = `/tmp/inbox/${media.saved[0].messageId}${media.saved[0].ext}`; // fakeMediaDeps.saveFile 的回傳格式
  expect(directPaths).toEqual([savedPath]); // logDirect 拿到的就是該路徑,非 undefined、不重抓
});

// ===== Feature 2:歷史 / inbox 自動清理 =====

/**
 * 測試目標:HistoryStore.purgeOlderThan()
 * 情境:happy path — 刪除 ts < cutoff 的列,回傳刪除筆數
 * Mock:in-memory HistoryStore
 * 預期:purgeOlderThan(5000) 回 1、剩 ts=5000 / 9000
 */
test('purgeOlderThan: 刪 ts < cutoff 的列、回傳刪除數', () => {
  // Arrange
  const store = createHistoryStore(new Database(':memory:'));
  store.record('G1', 1000, 'U1', 'A', 'text', 'a');
  store.record('G1', 5000, 'U1', 'A', 'text', 'b');
  store.record('G1', 9000, 'U1', 'A', 'text', 'c');

  // Act
  const removed = store.purgeOlderThan(5000);

  // Assert
  expect(removed).toBe(1); // 只 ts=1000 那列被刪
  expect(store.query('G1', 0, Number.MAX_SAFE_INTEGER, 10).map(r => r.ts)).toEqual([5000, 9000]);
});

/**
 * 測試目標:purgeInboxFiles()
 * 情境:happy path — 刪 mtime < cutoff 的檔、保留較新檔、回傳刪除數
 * Mock:注入 fakeFs(readdir / stat / unlink)
 * 預期:回 1、unlink 被呼叫於 join 後的 old 路徑、new 保留
 */
test('purgeInboxFiles: 刪 mtime < cutoff 的檔、回傳刪除數、保留較新檔', () => {
  // Arrange
  const unlinked: string[] = [];
  const mtimes: Record<string, number> = { '/inbox/old': 100, '/inbox/new': 9000 };
  const fakeFs = {
    readdir: () => ['old', 'new'],
    stat: (p: string) => ({ mtimeMs: mtimes[p] }),
    unlink: (p: string) => {
      unlinked.push(p);
    },
  };

  // Act
  const removed = purgeInboxFiles('/inbox', 5000, fakeFs);

  // Assert
  expect(removed).toBe(1);
  expect(unlinked).toEqual(['/inbox/old']); // 只刪舊檔,用 join 後路徑;new 保留
});

/**
 * 測試目標:purgeInboxFiles()
 * 情境:boundary — readdir 丟例外(目錄不存在)
 * Mock:注入會 throw 的 readdir
 * 預期:回 0、unlink 完全未被呼叫
 */
test('purgeInboxFiles: readdir 丟例外(目錄不存在) → 回 0、不刪檔', () => {
  // Arrange
  const unlinked: string[] = [];
  const fakeFs = {
    readdir: () => {
      throw new Error('ENOENT');
    },
    stat: () => ({ mtimeMs: 0 }),
    unlink: (p: string) => {
      unlinked.push(p);
    },
  };

  // Act
  const removed = purgeInboxFiles('/inbox', 5000, fakeFs);

  // Assert
  expect(removed).toBe(0);
  expect(unlinked).toEqual([]); // 目錄不存在 → 無事可清
});

/**
 * 測試目標:runCleanup()
 * 情境:boundary — retentionDays <= 0 不清,且不呼叫任何 purge
 * Mock:注入 store(purgeOlderThan spy)+ purgeInbox spy
 * 預期:回 {rows:0,files:0}、兩個 purge 皆未被呼叫
 */
test('runCleanup: retentionDays <= 0 → 不清、不呼叫 purge', () => {
  // Arrange
  let storeCalls = 0;
  let inboxCalls = 0;
  const store = { purgeOlderThan: () => (storeCalls += 1, 0) } as never;
  const purgeInbox = (() => (inboxCalls += 1, 0)) as never;

  // Act
  const result = runCleanup(0, 1_700_000_000_000, { store, purgeInbox });

  // Assert
  expect(result).toEqual({ rows: 0, files: 0 });
  expect(storeCalls).toBe(0); // 未碰 store
  expect(inboxCalls).toBe(0); // 未碰 inbox
});

/**
 * 測試目標:runCleanup()
 * 情境:happy path — retentionDays > 0,cutoff = now - days*86400000,呼叫兩個 purge 各一次
 * Mock:注入 store(purgeOlderThan 記 cutoff 回 3)+ purgeInbox(記 cutoff 回 2)
 * 預期:cutoff === now - 30*86400000、兩 purge 各 1 次、回傳 {rows:3,files:2}
 */
test('runCleanup: retentionDays > 0 → 以正確 cutoff 呼叫兩個 purge 並組合回傳值', () => {
  // Arrange
  const now = 1_000_000_000_000;
  const storeCutoffs: number[] = [];
  const inboxArgs: { dir: string; cutoff: number }[] = [];
  const store = {
    purgeOlderThan: (cutoff: number) => {
      storeCutoffs.push(cutoff);

      return 3;
    },
  } as never;
  const purgeInbox = ((dir: string, cutoff: number) => {
    inboxArgs.push({ dir, cutoff });

    return 2;
  }) as never;

  // Act
  const result = runCleanup(30, now, { store, inboxDir: '/inbox', purgeInbox });

  // Assert
  const expectedCutoff = now - 30 * 86_400_000;
  expect(storeCutoffs).toEqual([expectedCutoff]); // store 收到正確 cutoff、僅一次
  expect(inboxArgs).toEqual([{ dir: '/inbox', cutoff: expectedCutoff }]); // inbox 收到正確 dir + cutoff、僅一次
  expect(result).toEqual({ rows: 3, files: 2 });
});

// ===== per-group requireMention(群組是否需 @ 才投遞)=====

/**
 * 測試目標：resolveRequireMention()
 * 情境：happy — 群組設 requireMention:false → 回 false
 * Mock：無需 mock(access 用 normalizeAccess 建以確保 groupSettings 正規化)
 * 預期：該群回 false(不需 @ 即可投遞)
 */
test('resolveRequireMention: 群組設 requireMention:false → 回 false', () => {
  // Arrange
  const access = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { C1: { requireMention: false } }, pending: {} });
  const event = { type: 'message', webhookEventId: 'rrm-1', source: { type: 'group' as const, groupId: 'C1', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'hi' } };

  // Act
  const result = resolveRequireMention(event, access);

  // Assert
  expect(result).toBe(false);
});

/**
 * 測試目標：resolveRequireMention()
 * 情境：boundary — 群組有列出但設定為空物件 → 走預設 true
 * Mock：無需 mock
 * 預期：該群回 true(空設定視同未設,預設需 @)
 */
test('resolveRequireMention: 群組空設定 {} → 回 true(預設)', () => {
  // Arrange
  const access = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { C2: {} }, pending: {} });
  const event = { type: 'message', webhookEventId: 'rrm-2', source: { type: 'group' as const, groupId: 'C2', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'hi' } };

  // Act
  const result = resolveRequireMention(event, access);

  // Assert
  expect(result).toBe(true);
});

/**
 * 測試目標：resolveRequireMention()
 * 情境：boundary — 群組未列於 groupSettings → 走預設 true
 * Mock：無需 mock
 * 預期：未列群組回 true
 */
test('resolveRequireMention: 群組未列於 groupSettings → 回 true(預設)', () => {
  // Arrange
  const access = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { C1: { requireMention: false } }, pending: {} });
  const event = { type: 'message', webhookEventId: 'rrm-3', source: { type: 'group' as const, groupId: 'C3', userId: 'U1' }, message: { id: 'm', type: 'text', text: 'hi' } };

  // Act
  const result = resolveRequireMention(event, access);

  // Assert
  expect(result).toBe(true);
});

/**
 * 測試目標：resolveRequireMention()
 * 情境：boundary — 1:1(user)事件 → 永遠回 true(requireMention 對 1:1 無作用)
 * Mock：無需 mock
 * 預期：回 true(即使 groupSettings 設了別的群組也不影響 1:1)
 */
test('resolveRequireMention: 1:1 事件 → 回 true', () => {
  // Arrange
  const access = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { C1: { requireMention: false } }, pending: {} });
  const event = { type: 'message', webhookEventId: 'rrm-4', source: { type: 'user' as const, userId: 'U1' }, message: { id: 'm', type: 'text', text: 'hi' } };

  // Act
  const result = resolveRequireMention(event, access);

  // Assert
  expect(result).toBe(true);
});

/**
 * 測試目標：normalizeGroupSettings()(經 normalizeAccess)
 * 情境：happy — 合法 requireMention:false 原樣保留
 * Mock：無需 mock
 * 預期：normalized.groupSettings.C1.requireMention === false
 */
test('normalizeAccess: groupSettings 合法 requireMention:false 保留', () => {
  // Arrange / Act
  const a = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { C1: { requireMention: false } }, pending: {} });

  // Assert
  expect(a.groupSettings.C1).toEqual({ requireMention: false });
});

/**
 * 測試目標：normalizeGroupSettings()(經 normalizeAccess)
 * 情境：boundary — 非布林 requireMention 被忽略 → 變空物件(走預設 true)
 * Mock：無需 mock
 * 預期：normalized.groupSettings.C1 === {}(非布林值丟棄)
 */
test('normalizeAccess: groupSettings 非布林 requireMention → 變 {}(走預設)', () => {
  // Arrange / Act
  const a = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { C1: { requireMention: 'x' } }, pending: {} });

  // Assert
  expect(a.groupSettings.C1).toEqual({});
});

/**
 * 測試目標：normalizeGroupSettings()(經 normalizeAccess)
 * 情境：exception — 原型鏈鍵名(toString)不污染、map 為無原型物件(security P1)
 * Mock：無需 mock
 * 預期：groupSettings 原型為 null;讀 toString 拿到自有設定而非原型函式
 */
test('normalizeAccess: groupSettings 原型污染防護(無原型 map)', () => {
  // Arrange / Act
  const a = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: { toString: { requireMention: false } }, pending: {} });

  // Assert
  expect(Object.getPrototypeOf(a.groupSettings)).toBeNull(); // 無原型,toString 等鍵名不命中 Object.prototype
  expect(a.groupSettings.toString).toEqual({ requireMention: false }); // 自有鍵正常取用
});

/**
 * 測試目標：normalizeGroupSettings()(經 normalizeAccess)
 * 情境：boundary — 陣列輸入非合法 map → 退回空 {}
 * Mock：無需 mock
 * 預期：normalized.groupSettings 為空物件
 */
test('normalizeAccess: groupSettings 陣列輸入 → 退回 {}', () => {
  // Arrange / Act
  const a = normalizeAccess({ dmPolicy: 'pairing', allowFrom: [], allowGroups: {}, groupSettings: ['C1', 'C2'], pending: {} });

  // Assert
  expect(a.groupSettings).toEqual({});
});

/**
 * 測試目標：handleCallback()(per-group requireMention wiring)
 * 情境：happy(核心新行為)— 群組 G1 設 requireMention:false + 非 @ 文字 → 投遞
 * Mock：onMessage spy、OPEN_ACCESS(含 G1 授權)覆寫 groupSettings、logGroup 空殼
 * 預期：onMessage 被呼叫一次(非 @ 仍投遞,因該群關閉 requireMention)
 */
test('handleCallback: 群組 requireMention:false + 非 @ 文字 → 有投遞', async () => {
  // Arrange
  let delivered = 0;
  const access = { ...OPEN_ACCESS, groupSettings: { G1: { requireMention: false } } };
  const body = JSON.stringify({ events: [groupTextEvent('rm-deliver', 'just chatting', false)] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, logGroup: () => {} });

  // Assert
  expect(delivered).toBe(1);
});

/**
 * 測試目標：handleCallback()(per-group requireMention wiring)
 * 情境：boundary — 群組 G1 預設(無 groupSettings 設定)+ 非 @ 文字 → 不投遞(維持原行為)
 * Mock：onMessage spy、OPEN_ACCESS(groupSettings:{})、logGroup 空殼
 * 預期：onMessage 不被呼叫(預設需 @)
 */
test('handleCallback: 群組預設 + 非 @ 文字 → 不投遞(維持原行為)', async () => {
  // Arrange
  let delivered = 0;
  const body = JSON.stringify({ events: [groupTextEvent('rm-default', 'just chatting', false)] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access: OPEN_ACCESS, logGroup: () => {} });

  // Assert
  expect(delivered).toBe(0);
});

/**
 * 測試目標：handleCallback()(per-group requireMention wiring)
 * 情境：boundary — 群組 G1 設 requireMention:false + 有 @ 文字 → 仍投遞(不破壞 @ 情況)
 * Mock：onMessage spy、OPEN_ACCESS 覆寫 groupSettings、logGroup 空殼
 * 預期：onMessage 被呼叫一次(有 @ 一向投遞)
 */
test('handleCallback: 群組 requireMention:false + 有 @ 文字 → 仍投遞', async () => {
  // Arrange
  let delivered = 0;
  const access = { ...OPEN_ACCESS, groupSettings: { G1: { requireMention: false } } };
  const body = JSON.stringify({ events: [groupTextEvent('rm-at', 'hey bot', true)] });

  // Act
  await handleCallback(webhookRequest(body, sign(body)), () => {
    delivered += 1;
  }, { access, logGroup: () => {} });

  // Assert
  expect(delivered).toBe(1);
});

// ===== 獲取群組名稱:resolveGroupSummary / sanitizeGroupName / runGetGroupSummary / 表頭 / 整合 =====
// 注意:resolveGroupSummary 內含模組層級 FIFO 快取(無對外重置),故每個會實際 fetch 的測試
// 都用「獨一無二的 C 開頭 groupId」避免跨測試快取污染(test smell:互相依賴 / 未清理狀態)。

describe('resolveGroupSummary', () => {
  /**
   * 情境:happy —— 非 C 開頭(room R / 1:1 U)直接回 undefined,連 fetch 都不打
   * Mock:globalThis.fetch(計數器,驗證完全沒被呼叫)
   * 預期:回 undefined 且 calls 為 0(不浪費 API 額度)
   */
  test('非 C 開頭直接回 undefined 且不打 API', async () => {
    // Arrange
    const orig = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (() => {
      calls += 1;

      return Promise.resolve(new Response('{}', { status: 200 }));
    }) as typeof fetch;

    try {
      // Act + Assert:R / U 前綴都不該觸發 summary API
      expect(await resolveGroupSummary('R999notC')).toBeUndefined();
      expect(await resolveGroupSummary('U999notC')).toBeUndefined();
      expect(calls).toBe(0);
    } finally {
      globalThis.fetch = orig;
    }
  });

  /**
   * 情境:happy —— C 開頭且 res.ok,回 {groupName, pictureUrl} 並快取
   * Mock:globalThis.fetch(計數器 + 記錄 URL)
   * 預期:回正確摘要、打到 /summary endpoint、同 groupId 第二次走快取(calls 仍為 1)
   */
  test('C 開頭 ok 回 {groupName,pictureUrl} 並快取(第二次不重打)', async () => {
    // Arrange
    const orig = globalThis.fetch;
    let calls = 0;
    let calledUrl = '';
    globalThis.fetch = ((url: string | URL | Request) => {
      calls += 1;
      calledUrl = String(url);

      return Promise.resolve(new Response(JSON.stringify({ groupName: '行銷部', pictureUrl: 'https://p/x.jpg' }), { status: 200 }));
    }) as typeof fetch;

    try {
      // Act:同一 groupId 連續解析兩次
      const first = await resolveGroupSummary('Ccache001');
      const second = await resolveGroupSummary('Ccache001');

      // Assert
      expect(first).toEqual({ groupName: '行銷部', pictureUrl: 'https://p/x.jpg' });
      expect(second).toEqual({ groupName: '行銷部', pictureUrl: 'https://p/x.jpg' });
      expect(calledUrl).toContain('/group/Ccache001/summary');
      expect(calls).toBe(1); // 第二次走快取
    } finally {
      globalThis.fetch = orig;
    }
  });

  /**
   * 測試目標:resolveGroupSummary()
   * 情境:regression —— C 開頭 200 但 body 缺 groupName(如 {pictureUrl} 無群名)時不快取,保留下次重試
   * Mock:globalThis.fetch(計數器;每次回 200 但僅含 pictureUrl、無 groupName)
   * 預期:回物件但 groupName 為 undefined;同 groupId 第二次仍重打(calls 為 2,證明沒被快取)
   * 對應修正:REV-001(比照 resolveMemberName,200 缺群名不快取)
   */
  test('200 但缺 groupName 不快取(第二次仍重打)', async () => {
    // Arrange
    const orig = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (() => {
      calls += 1;

      return Promise.resolve(new Response(JSON.stringify({ pictureUrl: 'https://p/noname.jpg' }), { status: 200 }));
    }) as typeof fetch;

    try {
      // Act:同一 groupId 連續解析兩次
      const first = await resolveGroupSummary('Cnoname1');
      const second = await resolveGroupSummary('Cnoname1');

      // Assert:沒拿到群名 → 不快取 → 第二次仍打 API(對比上方「有 groupName → 第二次走快取」)
      expect(first?.groupName).toBeUndefined();
      expect(second?.groupName).toBeUndefined();
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = orig;
    }
  });

  /**
   * 情境:exception —— C 開頭但 res 非 2xx(bot 不在該群 / LINE 暫時無法提供)
   * Mock:globalThis.fetch 回 404
   * 預期:回 undefined(不快取、不丟例外)
   */
  test('C 開頭但非 2xx 回 undefined', async () => {
    const orig = globalThis.fetch;
    globalThis.fetch = (() => Promise.resolve(new Response('{}', { status: 404 }))) as typeof fetch;

    try {
      expect(await resolveGroupSummary('C404bad')).toBeUndefined();
    } finally {
      globalThis.fetch = orig;
    }
  });

  /**
   * 情境:exception —— fetch 直接 reject(網路錯誤)
   * Mock:globalThis.fetch reject
   * 預期:被 try/catch 收斂回 undefined,不向外丟例外
   */
  test('fetch reject 回 undefined 不丟例外', async () => {
    const orig = globalThis.fetch;
    globalThis.fetch = (() => Promise.reject(new Error('ECONNRESET'))) as typeof fetch;

    try {
      expect(await resolveGroupSummary('Cthrow01')).toBeUndefined();
    } finally {
      globalThis.fetch = orig;
    }
  });
});

describe('sanitizeGroupName', () => {
  /**
   * 情境:exception —— 含引號 / 角括號的注入字串(模擬可破壞標籤屬性的群名)
   * Mock:無需 mock(純函式)
   * 預期:" < > 等危險字元全數移除,無法破壞屬性
   */
  test('含引號/角括號的注入字串被清乾淨', () => {
    // Arrange
    const malicious = 'a"><script>x</script>';

    // Act
    const result = sanitizeGroupName(malicious);

    // Assert
    expect(result).not.toContain('"');
    expect(result).not.toContain('<');
    expect(result).not.toContain('>');
    expect(result).toBe('ascriptxscript');
  });

  /**
   * 情境:happy —— 全為白名單字元(中文 / 英數 / 空白 / 底線 / 連字號)
   * Mock:無需 mock(純函式)
   * 預期:原樣保留
   */
  test('中文/英數/空白/底線/連字號保留', () => {
    expect(sanitizeGroupName('行銷部 group_1-A')).toBe('行銷部 group_1-A');
  });

  /**
   * 情境:boundary —— 超過 40 字
   * Mock:無需 mock(純函式)
   * 預期:截斷到 40 字
   */
  test('超過 40 字被截斷到 40 字', () => {
    // Arrange + Act
    const result = sanitizeGroupName('a'.repeat(50));

    // Assert
    expect(result.length).toBe(40);
    expect(result).toBe('a'.repeat(40));
  });

  /**
   * 情境:boundary —— 全為非白名單符號
   * Mock:無需 mock(純函式)
   * 預期:回空字串
   */
  test('全符號 → 回空字串', () => {
    expect(sanitizeGroupName('!@#$%^&*()<>"\'')).toBe('');
  });

  /**
   * 測試目標:sanitizeGroupName()
   * 情境:regression —— 含 astral 平面字(CJK 擴充 B,屬 \p{L} 會通過白名單)的群名截斷
   * Mock:無需 mock(純函式)
   * 預期:(a) 41 個 astral 字 → 恰 40 個完整 code point、無落單 surrogate;(b) 41 個 BMP 中文字 → 40 字行為不變
   * 對應修正:REV-002(截斷改以 code point 計,避免切斷 astral 字代理對)
   */
  test('astral 字以 code point 截斷(不切斷代理對)', () => {
    // Arrange:astral = CJK 擴充 B 𠀀(U+20000),1 個 code point = 2 個 UTF-16 code unit
    const astral = '\u{20000}';
    // 落單 surrogate:高位後無低位,或低位前無高位(舊 code unit 截法在奇數邊界會切出落單位)
    const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

    // Act (a):41 個 astral 字
    const astralResult = sanitizeGroupName(astral.repeat(41));

    // Assert (a):恰 40 個完整 code point(舊 code unit 截法只會剩 20 個)、結果完整且無落單 surrogate
    expect([...astralResult].length).toBe(40);
    expect(astralResult).toBe(astral.repeat(40));
    expect(loneSurrogate.test(astralResult)).toBe(false);

    // Act + Assert (b):純 BMP 對照組 —— 41 個中文字截到 40,行為不變
    const bmpResult = sanitizeGroupName('中'.repeat(41));
    expect([...bmpResult].length).toBe(40);
    expect(bmpResult).toBe('中'.repeat(40));
  });
});

describe('runGetGroupSummary', () => {
  /**
   * 情境:exception —— 缺 chat_id
   * Mock:注入永遠回有名的 resolve stub(驗證 stub 不應被呼叫到)
   * 預期:isError,訊息提示需要 chat_id
   */
  test('缺 chat_id → isError', async () => {
    const resolve = async () => ({ groupName: 'X' });
    const res = await runGetGroupSummary({}, resolve);

    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('需要 chat_id');
  });

  /**
   * 情境:exception —— isKnownChat 回 false(非本 session 已互動來源)
   * Mock:注入 resolve stub(計數器,驗證被 gate 擋下、不解析)
   * 預期:isError 拒絕,且 resolve 未被呼叫
   */
  test('isKnownChat 回 false → 拒絕(isError),不解析', async () => {
    // Arrange
    let resolveCalled = 0;
    const resolve = async () => {
      resolveCalled += 1;

      return { groupName: 'X' };
    };

    // Act
    const res = await runGetGroupSummary({ chat_id: 'C1' }, resolve, () => false);

    // Assert
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('不在本 session 已互動來源');
    expect(resolveCalled).toBe(0);
  });

  /**
   * 情境:happy —— resolve 回有 groupName 但無頭像
   * Mock:注入 resolve stub
   * 預期:單行「群組名稱:X」,不含頭像行
   */
  test('resolve 回有 groupName(無頭像)→ 回「群組名稱:X」', async () => {
    const resolve = async () => ({ groupName: '行銷部' });
    const res = await runGetGroupSummary({ chat_id: 'C1' }, resolve);

    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toBe('群組名稱:行銷部');
  });

  /**
   * 情境:happy —— resolve 回 groupName + pictureUrl
   * Mock:注入 resolve stub
   * 預期:「群組名稱:X」後接「頭像:URL」
   */
  test('resolve 回 groupName + pictureUrl → 加「頭像:URL」', async () => {
    const resolve = async () => ({ groupName: '行銷部', pictureUrl: 'https://p/x.jpg' });
    const res = await runGetGroupSummary({ chat_id: 'C1' }, resolve);

    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toBe('群組名稱:行銷部\n頭像:https://p/x.jpg');
  });

  /**
   * 情境:exception —— resolve 回 undefined(取不到摘要)
   * Mock:注入回 undefined 的 resolve stub
   * 預期:isError「取不到群組名稱」
   */
  test('resolve 回 undefined → isError 取不到群組名稱', async () => {
    const resolve = async () => undefined;
    const res = await runGetGroupSummary({ chat_id: 'C1' }, resolve);

    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('取不到群組名稱');
  });

  /**
   * 情境:exception —— resolve 回物件但缺 groupName(只有頭像)
   * Mock:注入回 {pictureUrl} 的 resolve stub
   * 預期:isError「取不到群組名稱」(無名一律視為取不到)
   */
  test('resolve 回物件但無 groupName → isError', async () => {
    const resolve = async () => ({ pictureUrl: 'https://p/x.jpg' });
    const res = await runGetGroupSummary({ chat_id: 'C1' }, resolve);

    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('取不到群組名稱');
  });

  /**
   * 情境:happy —— isKnownChat 回 true(已互動來源)應放行
   * Mock:注入 resolve stub
   * 預期:正常解析,回「群組名稱:X」(驗證 isKnownChat 不誤擋)
   */
  test('isKnownChat 回 true → 放行並正常解析', async () => {
    const resolve = async () => ({ groupName: '客服群' });
    const res = await runGetGroupSummary({ chat_id: 'C1' }, resolve, () => true);

    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toBe('群組名稱:客服群');
  });
});

describe('runGetHistory: groupName 表頭(第 5 參數)', () => {
  /**
   * 情境:happy —— 傳 groupName 時輸出最前面多一行「群組:X (chat_id)」
   * Mock:無需 mock(注入 in-memory store)
   * 預期:首行為群組表頭,後接紀錄
   */
  test('傳 groupName → 最前面多一行「群組:X (chat_id)」', () => {
    // Arrange
    const store = memStore();
    store.record('G1', 5000, 'U1', 'Alice', 'text', 'hello');

    // Act
    const res = runGetHistory({ chat_id: 'G1', since: '1000', until: '9000' }, store, 99999, undefined, '行銷部');

    // Assert
    expect(res.content[0].text.startsWith('群組:行銷部 (G1)\n')).toBe(true);
    expect(res.content[0].text).toContain('hello');
  });

  /**
   * 情境:happy —— 不傳 groupName 維持原樣(回歸既有行為,不破壞既有測試)
   * Mock:無需 mock(注入 in-memory store)
   * 預期:無群組表頭,直接從第一筆紀錄起
   */
  test('不傳 groupName → 無群組表頭(維持原樣)', () => {
    // Arrange
    const store = memStore();
    store.record('G1', 5000, 'U1', 'Alice', 'text', 'hello');

    // Act
    const res = runGetHistory({ chat_id: 'G1', since: '1000', until: '9000' }, store, 99999);

    // Assert
    expect(res.content[0].text).not.toContain('群組:');
    expect(res.content[0].text.startsWith('[')).toBe(true);
  });

  /**
   * 情境:boundary —— 空紀錄 + 傳 groupName(表頭應與無紀錄提示並存)
   * Mock:無需 mock(空 in-memory store)
   * 預期:「群組:X (chat_id)」換行接「(此時間段無紀錄)」
   */
  test('空紀錄 + groupName → 表頭仍帶,接無紀錄提示', () => {
    const res = runGetHistory({ chat_id: 'Cempty1', minutes: 60 }, memStore(), 10000, undefined, '客服群');

    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toBe('群組:客服群 (Cempty1)\n(此時間段無紀錄)');
  });
});

describe('handleCallback: 群組名稱整合(Surface B / C)', () => {
  /**
   * 測試目標:handleCallback 群組投遞 meta.group_name(Surface B)
   * 情境:happy —— 授權 C 群組 + @ → 投遞訊息的 meta 帶消毒後群名
   * Mock:globalThis.fetch 回含危險字元的群名(驗證投遞前經 sanitizeGroupName)
   * 預期:onMessage 收到 1 則,meta.group_name 為消毒後字串
   */
  test('群組訊息投遞時 meta.group_name 帶入(經消毒)', async () => {
    // Arrange:summary 回一個含 < > " 的群名,驗證消毒
    const orig = globalThis.fetch;
    globalThis.fetch = (() => Promise.resolve(new Response(JSON.stringify({ groupName: '行銷<部>"x"' }), { status: 200 }))) as typeof fetch;
    const metas: Record<string, string>[] = [];
    const access = { ...pairingAccess, allowGroups: { Cdeliver1: ['U1'] } };
    const event = { type: 'message', webhookEventId: 'sb-deliver', source: { type: 'group', groupId: 'Cdeliver1', userId: 'U1' }, message: { id: 'm-sb', type: 'text', text: 'hi bot', mention: { mentionees: [{ isSelf: true }] } } };
    const body = JSON.stringify({ events: [event] });

    try {
      // Act
      await handleCallback(webhookRequest(body, sign(body)), msg => {
        metas.push(msg.meta);
      }, { access, requireMention: true, logGroup: () => {} });

      // Assert
      expect(metas.length).toBe(1);
      expect(metas[0].group_name).toBe('行銷部x'); // < > " 全被消毒
    } finally {
      globalThis.fetch = orig;
    }
  });

  /**
   * 測試目標:handleCallback 1:1 投遞 meta(Surface B 對照)
   * 情境:boundary —— 1:1 訊息不走群組路徑,meta 不應帶 group_name
   * Mock:logDirect 空殼(避免寫真實歷史庫);1:1 路徑不會打 summary,故無需 mock fetch
   * 預期:onMessage 收到 1 則,meta.group_name 為 undefined
   */
  test('1:1 訊息不帶 group_name', async () => {
    // Arrange
    const metas: Record<string, string>[] = [];
    const access = { ...pairingAccess, dmPolicy: 'allowlist' as const, allowFrom: ['U1'] };
    const body = JSON.stringify({ events: [dmEvent('sb-dm', 'U1')] });

    // Act
    await handleCallback(webhookRequest(body, sign(body)), msg => {
      metas.push(msg.meta);
    }, { access, logDirect: () => {} });

    // Assert
    expect(metas.length).toBe(1);
    expect(metas[0].group_name).toBeUndefined();
  });

  /**
   * 測試目標:handleCallback group_pair reply 文字(Surface C)
   * 情境:happy —— 未授權 C 群組被 @ → group_pair,reply 夾入(群組名:X)
   * Mock:globalThis.fetch 回 summary;sendDeps 記錄 reply 文字
   * 預期:reply 同時含群組 ID 與(群組名:X)
   */
  test('未授權 C 群組被 @ → group_pair reply 夾入(群組名:X)', async () => {
    // Arrange
    const orig = globalThis.fetch;
    globalThis.fetch = (() => Promise.resolve(new Response(JSON.stringify({ groupName: '行銷部' }), { status: 200 }))) as typeof fetch;
    const replies: string[] = [];
    const event = { type: 'message', webhookEventId: 'sc-grouppair', replyToken: 'rt', source: { type: 'group', groupId: 'Cgrouppair1', userId: 'U1' }, message: { id: 'm-gp', type: 'text', text: 'hi bot', mention: { mentionees: [{ isSelf: true }] } } };
    const body = JSON.stringify({ events: [event] });
    const sendDeps = {
      reply: async (_t: string, m: { type: 'text'; text: string }[]) => {
        replies.push(m[0].text);

        return { ok: true, status: 200 };
      },
      push: async () => ({ ok: true, status: 200 }),
    };

    try {
      // Act:pairingAccess 的 allowGroups 為空 → Cgrouppair1 未授權
      await handleCallback(webhookRequest(body, sign(body)), () => {}, { access: pairingAccess, sendDeps });

      // Assert
      expect(replies[0]).toContain('群組 ID:Cgrouppair1');
      expect(replies[0]).toContain('(群組名:行銷部)');
    } finally {
      globalThis.fetch = orig;
    }
  });

  /**
   * 測試目標:handleCallback member_pair reply 文字(Surface C)
   * 情境:happy —— 已授權 C 群組、非成員被 @ → member_pair,reply 夾入(群組名:X)
   * Mock:globalThis.fetch 回 summary;sendDeps 記錄 reply;logGroup 空殼(群組已授權會記錄)
   * 預期:reply 同時含「你的 userId」與「此群(群組名:X)」
   */
  test('已授權 C 群組非成員被 @ → member_pair reply 夾入(群組名:X)', async () => {
    // Arrange:Cmemberpair1 授權但只 U1 是成員,發話者 U9 非成員
    const orig = globalThis.fetch;
    globalThis.fetch = (() => Promise.resolve(new Response(JSON.stringify({ groupName: '客服群' }), { status: 200 }))) as typeof fetch;
    const replies: string[] = [];
    const access = { ...pairingAccess, allowGroups: { Cmemberpair1: ['U1'] } };
    const event = { type: 'message', webhookEventId: 'sc-memberpair', replyToken: 'rt', source: { type: 'group', groupId: 'Cmemberpair1', userId: 'U9' }, message: { id: 'm-mp', type: 'text', text: 'hi bot', mention: { mentionees: [{ isSelf: true }] } } };
    const body = JSON.stringify({ events: [event] });
    const sendDeps = {
      reply: async (_t: string, m: { type: 'text'; text: string }[]) => {
        replies.push(m[0].text);

        return { ok: true, status: 200 };
      },
      push: async () => ({ ok: true, status: 200 }),
    };

    try {
      // Act
      await handleCallback(webhookRequest(body, sign(body)), () => {}, { access, sendDeps, logGroup: () => {} });

      // Assert
      expect(replies[0]).toContain('你的 userId:U9');
      expect(replies[0]).toContain('此群(群組名:客服群)');
    } finally {
      globalThis.fetch = orig;
    }
  });
});
