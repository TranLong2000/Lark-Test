require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// Giữ raw body để debug
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Thông tin từ .env
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.Encrypt_Key;
const AI_KEY = process.env.AI_Key;

// Hàm xác thực signature Lark bằng SHA256
function verifySignature(timestamp, nonce, body, signature) {
  const str = `${timestamp}${nonce}${ENCRYPT_KEY}${body}`;
  const hash = crypto.createHash('sha256').update(str).digest('hex');
  return hash === signature;
}

// Hàm giải mã message (AES-ECB, Base64)
function decryptMessage(encrypt) {
  try {
    const key = Buffer.from(ENCRYPT_KEY + '=', 'base64'); // Lark EncodingAESKey Base64 + '='
    const decipher = crypto.createDecipheriv('aes-128-ecb', key.slice(0, 16), '');
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(encrypt, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (err) {
    console.error("Decrypt error:", err.message);
    return null;
  }
}

// Webhook Lark Bot
app.post('/lark-webhook', async (req, res) => {
  const timestamp = req.headers['x-lark-request-timestamp'];
  const nonce = req.headers['x-lark-request-nonce'];
  const signature = req.headers['x-lark-signature'];

  console.log("=== Incoming raw body ===");
  console.log(req.rawBody);

  // Xác thực signature
  if (!verifySignature(timestamp, nonce, req.rawBody, signature)) {
    console.log("Invalid signature!");
    return res.status(401).send('Invalid signature');
  }

  const encrypt = req.body.encrypt;
  if (!encrypt) {
    console.log("No encrypt field found");
    return res.status(400).send('No encrypt field');
  }

  const decrypted = decryptMessage(encrypt);
  if (!decrypted) {
    return res.status(400).send('Decrypt failed');
  }

  console.log("=== Decrypted payload ===");
  console.log(decrypted);

  // Xử lý URL verification
  if (decrypted.type === 'url_verification') {
    return res.json({ challenge: decrypted.challenge });
  }

  // Xác thực token
  if (decrypted.token !== VERIFICATION_TOKEN) {
    console.log("Invalid token:", decrypted.token);
    return res.status(401).send('Invalid token');
  }

  const userMessage = decrypted.event?.text?.content || '';
  console.log("User message:", userMessage);

  try {
    // Gửi request tới OpenRouter
    const response = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: userMessage }]
      },
      {
        headers: { 'Authorization': `Bearer ${AI_KEY}` }
      }
    );

    const aiReply = response.data.choices[0].message.content;
    console.log("AI reply:", aiReply);

    // Trả về Lark
    res.json({
      status: "success",
      msg_type: "text",
      content: { text: aiReply }
    });

  } catch (err) {
    console.error("OpenRouter API error:", err.message);
    res.status(500).json({ status: "error", message: "OpenRouter API error" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
