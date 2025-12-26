require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// Thông tin từ .env
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.LARK_ENCRYPT_KEY.trim();
const AI_KEY = process.env.AI_Key.trim();
const LARK_DOMAIN = process.env.LARK_DOMAIN || 'https://open.larksuite.com/';

// Hàm xác thực chữ ký Lark bằng SHA256
function verifySignature(timestamp, nonce, body, signature) {
  const raw = `${timestamp}${nonce}${ENCRYPT_KEY}${body}`;
  const hash = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  const isValid = hash === signature;
  
  if (!isValid) {
    console.warn("[verifySignature] ❌ Signature mismatch");
    console.warn("  ↳ Calculated:", hash);
    console.warn("  ↳ Received:  ", signature);
  }

  return isValid;
}

// Hàm giải mã message (AES-256-CBC)
function decryptMessage(encrypt) {
  const key = Buffer.from(ENCRYPT_KEY, 'utf-8');
  const aesKey = crypto.createHash('sha256').update(key).digest();
  const data = Buffer.from(encrypt, 'base64');
  const iv = data.slice(0, 16);
  const encryptedText = data.slice(16);

  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return JSON.parse(decrypted.toString());
}

// -------------------- WEBHOOK --------------------
app.post('/lark-webhook', express.raw({ type: '*/*' }), async (req, res) => {
  const rawBody = req.body.toString('utf8');
  const signature = req.headers['x-lark-signature'];
  const timestamp = req.headers['x-lark-request-timestamp'];
  const nonce = req.headers['x-lark-request-nonce'];

  console.log("All headers:", req.headers);
  console.log("Raw body:", rawBody);

  // Kiểm tra các headers cần thiết
  if (!timestamp || !nonce || !signature) {
    console.log("Missing required headers for signature verification");
    return res.status(400).send('Missing headers');
  }

  let isVerified = true;
  if (rawBody.includes('"encrypt"')) {
    isVerified = verifySignature(timestamp, nonce, rawBody, signature);
  }

  if (!isVerified) {
    console.error("[Webhook] ❌ Signature verification failed.");
    return res.status(401).send('Invalid signature');
  }

  // ---------- Step 1: Parse JSON ----------
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    console.warn("[Webhook] ❌ Cannot parse JSON payload:", err.message);
    return res.sendStatus(400);
  }

  // ---------- Step 2: Decrypt if needed ----------
  let decrypted = payload;
  if (payload?.encrypt) {
    try {
      decrypted = decryptMessage(payload.encrypt);  // Giải mã payload nếu có trường "encrypt"
    } catch (err) {
      console.error("[Webhook] ❌ decryptMessage error:", err.message);
      return res.json({ code: 0 });
    }
  }

  console.log("Decrypted payload:", decrypted);

  // ---------- Step 3: Verification challenge ----------
  if (decrypted?.challenge) {
    console.log("[Webhook] 🔑 Verification challenge received");
    return res.json({ challenge: decrypted.challenge });
  }

  // ---------- Step 4: Card / Approve / Reaction ----------
  if (decrypted?.action || decrypted.header?.event_type === "card.action.trigger") {
    const messageId = decrypted.open_message_id || decrypted?.action?.value?.message_id;
    const userId = decrypted.open_id || decrypted?.action?.value?.user_id;
    const actionType = decrypted?.action?.value?.action || decrypted.header?.event_type;

    console.log(`[Webhook] 🧩 Card Action: ${actionType} | messageId=${messageId} | userId=${userId}`);

    if (actionType === "got_it" && messageId) await addReaction(messageId);

    if (actionType === "approve" && messageId && userId) {
      const userName =
        decrypted?.operator?.user_name ||
        decrypted?.action?.user?.name ||
        "Unknown User";

      console.log(`[Webhook] ✅ Approved by ${userName} (${userId})`);
      return res.json({ code: 0 });
    }

    return res.json({ code: 0 });
  }

  // ---------- Step 5: Chat AI ----------
  if (decrypted.header?.event_type === "im.message.receive_v1") {
    return await handleChatAIWebhook(decrypted, res);
  }

  // ---------- Step 6: Unhandled event ----------
  console.log("[Webhook] ⚙️ Unhandled event type:", decrypted.header?.event_type);
  return res.json({ code: 0 });
});

// Dummy function to handle AI Webhook
async function handleChatAIWebhook(decrypted, res) {
  const userMessage = decrypted.event?.text?.content || '';
  console.log("[AI Webhook] User message:", userMessage);

  try {
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: userMessage }],
      },
      { headers: { 'Authorization': `Bearer ${AI_KEY}` } }
    );

    const aiReply = response.data.choices[0].message.content;
    console.log('AI reply:', aiReply);

    return res.json({
      status: "success",
      msg_type: "text",
      content: { text: aiReply }
    });
  } catch (err) {
    console.error('[AI Webhook] Error:', err.message);
    return res.status(500).json({ status: "error", message: "Error in AI response" });
  }
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
