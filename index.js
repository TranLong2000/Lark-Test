require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// ===================== ENV =====================
const LARK_DOMAIN = process.env.Lark_Domain || 'https://open.larksuite.com';
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.Encrypt_Key?.trim();
const AI_KEY = process.env.AI_Key?.trim();

// ===================== VERIFY SIGNATURE =====================
function verifySignature(timestamp, nonce, body, signature) {
  try {
    const raw = `${timestamp}${nonce}${ENCRYPT_KEY}${body}`;
    const hash = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
    return hash === signature;
  } catch {
    return false;
  }
}

// ===================== DECRYPT =====================
function decryptMessage(encrypt) {
  const key = Buffer.from(ENCRYPT_KEY, 'utf8');
  const aesKey = crypto.createHash('sha256').update(key).digest();
  const data = Buffer.from(encrypt, 'base64');

  const iv = data.slice(0, 16);
  const encryptedText = data.slice(16);

  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return JSON.parse(decrypted.toString());
}

// ===================== GET APP TOKEN =====================
async function getAppAccessToken() {
  const res = await axios.post(
    `${LARK_DOMAIN}/open-apis/auth/v3/app_access_token/internal`,
    {
      app_id: APP_ID,
      app_secret: APP_SECRET
    }
  );
  return res.data.app_access_token;
}

// ===================== REPLY TO LARK =====================
async function replyToLark(messageId, text) {
  const token = await getAppAccessToken();

  await axios.post(
    `${LARK_DOMAIN}/open-apis/im/v1/messages/${messageId}/reply`,
    {
      msg_type: 'text',
      content: JSON.stringify({ text })
    },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    }
  );
}

// ===================== WEBHOOK =====================
app.post('/lark-webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    console.log('🔥 WEBHOOK HIT');

    const rawBody = req.body.toString('utf8');

    const signature = req.headers['x-lark-signature'];
    const timestamp = req.headers['x-lark-request-timestamp'];
    const nonce = req.headers['x-lark-request-nonce'];

    // ---------- VERIFY ----------
    if (
      rawBody.includes('"encrypt"') &&
      signature &&
      timestamp &&
      nonce &&
      !verifySignature(timestamp, nonce, rawBody, signature)
    ) {
      console.warn('[Webhook] ⚠️ Signature mismatch (ignored)');
    }

    // ---------- PARSE ----------
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return res.sendStatus(400);
    }

    // ---------- DECRYPT ----------
    let decrypted = payload;
    if (payload.encrypt) {
      decrypted = decryptMessage(payload.encrypt);
    }

    // ---------- CHALLENGE ----------
    if (decrypted?.challenge) {
      return res.json({ challenge: decrypted.challenge });
    }

    // ---------- TOKEN ----------
    if (decrypted.token && decrypted.token !== VERIFICATION_TOKEN) {
      return res.json({ code: 0 });
    }

    // ---------- MESSAGE ----------
    if (decrypted.header?.event_type === 'im.message.receive_v1') {
      const event = decrypted.event;
      const message = event.message;

      const messageId = message.message_id;
      const chatType = message.chat_type; // group | p2p
      const mentions = message.mentions || [];

      let text = '';
      try {
        text = JSON.parse(message.content || '{}')?.text || '';
      } catch {}

      console.log('🧩 chatType:', chatType);
      console.log('🧩 raw text:', text);
      console.log('🧩 mentions:', JSON.stringify(mentions, null, 2));

      // ===== DETECT BOT MENTION (SAFE MODE) =====
      let botMentioned = false;

      // case 1: mentions array
      for (const m of mentions) {
        if (m.id?.app_id === APP_ID || m.id?.open_id) {
          botMentioned = true;
          if (m.key) {
            text = text.replace(new RegExp(m.key, 'gi'), '');
          }
        }
      }

      // case 2: any <at> tag
      if (!botMentioned && /<at .*?>/i.test(text)) {
        botMentioned = true;
      }

      // cleanup
      text = text.replace(/<at.*?<\/at>/g, '').trim();

      console.log('🤖 botMentioned:', botMentioned);
      console.log('[User]', text);

      // ✅ ACK NGAY
      res.json({ code: 0 });

      // ❌ group mà KHÔNG detect mention → vẫn cho trả lời (fallback)
      // 👉 tránh mất tín hiệu tag do Lark bug

      // ---------- CALL OPENROUTER ----------
      try {
        const aiResp = await axios.post(
          'https://openrouter.ai/api/v1/chat/completions',
          {
            model: 'allenai/olmo-3.1-32b-think:free',
            messages: [{ role: 'user', content: text }]
          },
          {
            headers: {
              Authorization: `Bearer ${AI_KEY}`,
              'Content-Type': 'application/json'
            }
          }
        );

        const aiReply =
          aiResp.data?.choices?.[0]?.message?.content ||
          '⚠️ AI không phản hồi';

        await replyToLark(messageId, aiReply);
      } catch (err) {
        console.error('[AI Error]', err.response?.data || err.message);
      }

      return;
    }

    return res.json({ code: 0 });

  } catch (err) {
    console.error('[Webhook] ❌ Global error:', err.message);
    return res.json({ code: 0 });
  }
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
