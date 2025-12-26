require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// Thông tin từ .env
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.Encrypt_Key.trim();
const AI_KEY = process.env.AI_Key.trim();
const LARK_DOMAIN = process.env.Lark_Domain?.trim() || 'https://open.larksuite.com/';

// Hàm xác thực signature Lark bằng HMAC SHA256
function verifySignature(timestamp, nonce, body, signature) {
  try {
    const key = Buffer.from(ENCRYPT_KEY, 'base64');
    const text = `${timestamp}\n${nonce}\n${body}\n`;
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(text);
    const hash = hmac.digest('base64');
    return hash === signature;
  } catch (err) {
    console.error("Signature verify error:", err);
    return false;
  }
}

// Hàm giải mã message (AES-128-ECB)
function decryptMessage(encrypt) {
  try {
    const key = Buffer.from(ENCRYPT_KEY, 'base64').slice(0, 16);
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(encrypt, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (err) {
    console.error("Decrypt error:", err.message);
    return null;
  }
}

// -------------------- WEBHOOK --------------------
app.post('/lark-webhook', express.raw({ type: '*/*' }), async (req, res) => {
  let payload;
  const rawBody = req.body.toString('utf8');
  const signature = req.headers['x-lark-signature'];
  const timestamp = req.headers['x-lark-request-timestamp'];
  const nonce = req.headers['x-lark-request-nonce'];

  console.log('All headers:', req.headers); // In tất cả các headers để kiểm tra
  console.log("Raw body:", rawBody);

  // Kiểm tra xem có đủ các headers cần thiết không
  if (!timestamp || !nonce || !signature) {
    console.log("Missing required headers for signature verification");
    return res.status(400).send('Missing headers');
  }

  // Nếu có trường encrypt, thực hiện xác thực chữ ký
  let isVerified = true;
  if (rawBody.includes('"encrypt"')) {
    isVerified = verifySignature(timestamp, nonce, rawBody, signature);
  }

  if (!isVerified) {
    console.error("[Webhook] ❌ Signature verification failed.");
  }

  // ---------- Step 1: Parse JSON ----------
  try {
    payload = JSON.parse(rawBody);  // Parse raw body thành JSON
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
      return res.json({ code: 0 });  // Nếu lỗi giải mã, trả về mã lỗi
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

    if (actionType === "got_it" && messageId) await addReaction(messageId);  // Thêm reaction nếu có action

    if (actionType === "approve" && messageId && userId) {
      const userName =
        decrypted?.operator?.user_name ||
        decrypted?.action?.user?.name ||
        "Unknown User";
    
      console.log(`[Webhook] ✅ Approved by ${userName} (${userId})`);
      return res.json({ code: 0 });  // Trả về mã thành công
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

// Dummy function to handle AI Webhook (you can implement this accordingly)
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
