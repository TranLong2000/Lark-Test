require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// ======= Thông tin từ .env =======
const APP_ID = process.env.App_ID.trim();
const APP_SECRET = process.env.App_Secret.trim();
const VERIFICATION_TOKEN = process.env.Verification_Token.trim();
const ENCRYPT_KEY = process.env.Encrypt_Key.trim();
const AI_KEY = process.env.AI_Key.trim();
const LARK_DOMAIN = process.env.Lark_Domain?.trim() || 'https://open.larksuite.com/';

// ======= Middleware nhận raw body =======
app.use('/lark-webhook', express.raw({ type: '*/*' }));

// ======= Hàm verify signature =======
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

// ======= Hàm giải mã message (AES-128-ECB) =======
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

// ======= Webhook xử lý sự kiện Lark =======
app.post('/lark-webhook', async (req, res) => {
  const timestamp = req.headers['x-lark-request-timestamp'];
  const nonce = req.headers['x-lark-request-nonce'];
  const signature = req.headers['x-lark-signature'];

  const rawBody = req.body.toString('utf8');
  console.log("Headers received:", { timestamp, nonce, signature });
  console.log("Raw body:", rawBody);

  // Nếu headers không đủ → không verify
  if (!timestamp || !nonce || !signature) {
    console.log("Missing required headers for signature verification");
    return res.status(400).send('Missing headers');
  }

  // Verify chữ ký nếu payload có encrypt
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    console.warn("Cannot parse JSON payload:", err.message);
    return res.status(400).send('Invalid JSON');
  }

  if (payload?.encrypt) {
    if (!verifySignature(timestamp, nonce, rawBody, signature)) {
      console.log("Invalid signature!");
      return res.status(401).send('Invalid signature');
    }
  }

  // Giải mã nếu cần
  let decrypted = payload;
  if (payload?.encrypt) {
    decrypted = decryptMessage(payload.encrypt);
    if (!decrypted) return res.status(400).send('Decrypt failed');
  }

  console.log("Decrypted payload:", decrypted);

  // URL verification
  if (decrypted.type === 'url_verification' && decrypted.challenge) {
    console.log("URL verification challenge received");
    return res.json({ challenge: decrypted.challenge });
  }

  // Token verification (nếu có encrypt)
  if (decrypted.encrypt && decrypted.token !== VERIFICATION_TOKEN) {
    console.log("Invalid token:", decrypted.token);
    return res.status(401).send('Invalid token');
  }

  // Chat AI
  if (decrypted.header?.event_type === 'im.message.receive_v1') {
    const userMessage = decrypted.event?.text?.content || '';
    console.log("User message:", userMessage);

    try {
      const response = await axios.post(
        'https://openrouter.ai/api/v1/chat/completions',
        {
          model: "gpt-4o-mini",
          messages: [{ role: "user", content: userMessage }]
        },
        { headers: { 'Authorization': `Bearer ${AI_KEY}` } }
      );

      const aiReply = response.data.choices[0].message.content;
      console.log("AI reply:", aiReply);

      return res.json({
        status: "success",
        msg_type: "text",
        content: { text: aiReply }
      });
    } catch (err) {
      console.error("OpenRouter API error:", err.message);
      return res.status(500).json({ status: "error", message: "OpenRouter API error" });
    }
  }

  // Card / Reaction / Other events
  console.log("Unhandled or non-encrypt event, return code 0");
  return res.json({ code: 0 });
});

// ======= Start server =======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
