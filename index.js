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

    if (hash !== signature) {
      console.warn('[verifySignature] ❌ Signature mismatch');
      console.warn('  ↳ Calculated:', hash);
      console.warn('  ↳ Received:  ', signature);
      return false;
    }
    return true;
  } catch (err) {
    console.error('[verifySignature] Error:', err.message);
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
    },
    { timeout: 30000 }
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
  let payload;

  try {
    const rawBody = req.body.toString('utf8');

    const signature = req.headers['x-lark-signature'];
    const timestamp = req.headers['x-lark-request-timestamp'];
    const nonce = req.headers['x-lark-request-nonce'];

    // ---------- STEP 1: VERIFY SIGNATURE (GIỐNG ĐOẠN 1) ----------
    let isVerified = true;

    if (
      rawBody.includes('"encrypt"') &&
      signature &&
      timestamp &&
      nonce
    ) {
      isVerified = verifySignature(timestamp, nonce, rawBody, signature);
    }

    if (!isVerified) {
      console.warn(
        '[Webhook] ⚠️ Signature verification failed – fallback allowed'
      );
      // ❌ KHÔNG return → cho card / reaction / challenge chạy
    }

    // ---------- STEP 2: PARSE JSON ----------
    try {
      payload = JSON.parse(rawBody);
    } catch (err) {
      console.warn('[Webhook] ❌ JSON parse error:', err.message);
      return res.sendStatus(400);
    }

    // ---------- STEP 3: DECRYPT ----------
    let decrypted = payload;
    if (payload.encrypt) {
      try {
        decrypted = decryptMessage(payload.encrypt);
      } catch (err) {
        console.error('[Webhook] ❌ Decrypt error:', err.message);
        return res.json({ code: 0 });
      }
    }

    console.log('[Webhook] Decrypted:', decrypted);

    // ---------- STEP 4: CHALLENGE ----------
    if (decrypted?.challenge) {
      console.log('[Webhook] 🔑 Challenge received');
      return res.json({ challenge: decrypted.challenge });
    }

    // ---------- STEP 5: TOKEN VERIFY ----------
    if (decrypted.token && decrypted.token !== VERIFICATION_TOKEN) {
      console.warn('[Webhook] ❌ Invalid verification token');
      return res.json({ code: 0 });
    }

    // ---------- STEP 6: CHAT MESSAGE ----------
    if (decrypted.header?.event_type === 'im.message.receive_v1') {
      const messageId = decrypted.event?.message?.message_id;
      let userMessage = '';

      try {
        userMessage =
          JSON.parse(decrypted.event?.message?.content || '{}')?.text || '';
      } catch {}

      console.log('[User]', userMessage);

      // ✅ ACK NGAY cho Lark
      res.json({ code: 0 });

      // ---------- CALL AI ----------
      try {
        const aiResp = await axios.post(
          'https://openrouter.ai/api/v1/chat/completions',
          {
            model: 'bytedance-seed/seedream-4.5',
            messages: [{ role: 'user', content: userMessage }]
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

        console.log('[AI]', aiReply);

        // ---------- REPLY TO LARK ----------
        await replyToLark(messageId, aiReply);

      } catch (err) {
        console.error('[AI Error]', err.response?.data || err.message);
      }

      return;
    }

    // ---------- DEFAULT ACK ----------
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
