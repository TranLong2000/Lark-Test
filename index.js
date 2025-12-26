require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());

// Thông tin từ .env
const APP_ID = process.env.App_ID;
const APP_SECRET = process.env.App_Secret;
const VERIFICATION_TOKEN = process.env.Verification_Token;
const ENCRYPT_KEY = process.env.Encrypt_Key;
const AI_KEY = process.env.AI_Key;

// Webhook Lark Bot
app.post('/lark-webhook', async (req, res) => {
  const body = req.body;

  // Xử lý URL verification
  if (body.type === 'url_verification') {
    return res.json({ challenge: body.challenge });
  }

  // Xác thực token nếu là event bình thường
  if (body.token !== VERIFICATION_TOKEN) {
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

    // Trả về theo chuẩn Lark
    res.json({
      status: "success",
      msg_type: "text",
      content: { text: aiReply }
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ status: "error", message: "OpenRouter API error" });
  }
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
