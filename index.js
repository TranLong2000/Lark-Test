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
  const rawBody = req.body.toString('utf8');
  const signature = req.headers['x-lark-signature'];
  const timestamp = req.headers['x-lark-request-timestamp'];
  const nonce = req.headers['x-lark-request-nonce'];

  console.log("Headers received:", { timestamp, nonce, signature });
  console.log("=== Incoming raw body ===");
  console.log(rawBody);

  if (!timestamp || !nonce || !signature) {
    return res.status(400).send('Missing required headers');
  }

  if (!verifySignature(timestamp, nonce, rawBody, signature)) {
    return res.status(401).send('Invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    console.error("Cannot parse JSON:", err.message);
    return res.status(400).send('Invalid JSON');
  }

  const decrypted = payload.encrypt ? decryptMessage(payload.encrypt) : payload;
  if (!decrypted) return res.status(400).send('Decrypt failed');

  console.log("=== Decrypted payload ===");
  console.log(decrypted);

  // Xác thực challenge khi verify url
  if (decrypted.challenge) {
    return res.json({ challenge: decrypted.challenge });
  }

  if (decrypted.token && decrypted.token !== VERIFICATION_TOKEN) {
    return res.status(401).send('Invalid token');
  }

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
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
