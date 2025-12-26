require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();

// Giữ nguyên raw body để debug
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

// Webhook Lark Bot
app.post('/lark-webhook', async (req, res) => {
  console.log("=== Incoming Lark payload ===");
  console.log(req.rawBody);  // In payload thô
  console.log("=== Parsed JSON body ===");
  console.log(req.body);     // In payload đã parse

  const body = req.body;

  // URL verification
  if (body.type === 'url_verification') {
    console.log("URL verification request received");
    return res.json({ challenge: body.challenge });
  }

  // Xác thực token
  if (body.token !== VERIFICATION_TOKEN) {
    console.log("Invalid token:", body.token);
    return res.status(401).send('Invalid token');
  }

  const userMessage = body.event?.text?.content || '';

  try {
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
