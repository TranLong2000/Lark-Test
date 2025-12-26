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

// Hàm giải mã Lark payload
function decryptMessage(encrypt) {
  try {
    const key = Buffer.from(ENCRYPT_KEY, 'base64');
    const iv = key.slice(0, 16); // IV lấy 16 byte đầu
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
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
  console.log("=== Incoming encrypted payload ===");
  console.log(req.rawBody);

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
    console.log("URL verification request received");
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

    // Trả về Lark theo chuẩn JSON
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
