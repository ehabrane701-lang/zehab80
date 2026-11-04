/**
 * 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 - نظام استضافة متطور مع لوحة تحكم وإدارة وبوت تيليجرام مدمج (Node.js)
 * طُوِّر بواسطة: 𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜 | @Y_20_20
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');
const http = require('http');
const net = require('net');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const AdmZip = require('adm-zip');
const axios = require('axios');
const { Telegraf, Markup } = require('telegraf');

const BASE_DIR = __dirname;
const USERS_DIR = path.join(BASE_DIR, "USERS");
if (!fs.existsSync(USERS_DIR)) fs.mkdirSync(USERS_DIR, { recursive: true });

const RUNNING_DIR = path.join(BASE_DIR, "active_bots");
const LOGS_DIR = path.join(BASE_DIR, "bot_logs");
const DB_DIR = path.join(BASE_DIR, "database");
const ASSETS_DIR = path.join(BASE_DIR, "assets");
const STORE_DIR = path.join(BASE_DIR, "store_files");
const THUMBS_DIR = path.join(ASSETS_DIR, "thumbs");
const MARKET_DIR = path.join(BASE_DIR, "market");
const ENV_DIR = path.join(BASE_DIR, "bot_environments");
const ENCRYPTED_DIR = path.join(BASE_DIR, "encrypted_files");

[RUNNING_DIR, LOGS_DIR, DB_DIR, ASSETS_DIR, STORE_DIR, THUMBS_DIR, MARKET_DIR, ENV_DIR, ENCRYPTED_DIR].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const USERS_DB = path.join(DB_DIR, "users.json");
const FILES_DB = path.join(DB_DIR, "files.json");
const SETTINGS_DB = path.join(DB_DIR, "settings.json");
const STORE_DB = path.join(DB_DIR, "store.json");
const ADMINS_DB = path.join(DB_DIR, "admins.json");
const MARKET_DB = path.join(DB_DIR, "market.json");
const SECURITY_DB = path.join(DB_DIR, "security.json");

let activeProcesses = {};
let processHours = {};

function readJson(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, "utf-8");
            return JSON.parse(data);
        }
    } catch (e) {
        console.error(`JSON read error (${filePath}):`, e);
    }
    return {};
}

function writeJson(filePath, data) {
    try {
        const tempPath = filePath + ".tmp";
        fs.writeFileSync(tempPath, JSON.stringify(data, null, 4), "utf-8");
        fs.renameSync(tempPath, filePath);
    } catch (e) {
        console.error(`JSON write error (${filePath}):`, e);
    }
}

// نظام الحماية المتقدم للأكواد ضد الاختراق والتخريب
function scanCodeSecurity(content) {
    const dangerousPatterns = [
        /\bos\.system\s*\(/i,
        /\bos\.popen\s*\(/i,
        /\bshutil\.rmtree\s*\(\s*["']\//i,
        /\bctypes\b/i,
        /open\s*\(\s*["'].*\/etc\/passwd/i,
        /open\s*\(\s*["'].*\/root\//i,
        /rm\s+-rf\s+\//i,
        /\bsubprocess\.Popen\s*\(\s*\[\s*["']rm/i,
        /\beval\s*\(/i,
        /\bexec\s*\(/i,
        /child_process.*execSync\s*\(\s*["']rm\s+-rf\s+\//i
    ];
    for (const pattern of dangerousPatterns) {
        if (pattern.test(content)) {
            return { safe: false, message: "⚠️ تم رفض الملف حظراً أمنياً لاحتوائه على أكواد خطيرة أو محاولات اختراق." };
        }
    }
    return { safe: true, message: "الكود آمن" };
}

function initSecurity() {
    let security = readJson(SECURITY_DB);
    if (!security.master_key) {
        security.master_key = crypto.randomBytes(32).toString("base64");
        security.file_keys = {};
        writeJson(SECURITY_DB, security);
    }
}
initSecurity();

function getMasterKey() {
    let security = readJson(SECURITY_DB);
    let masterKey = security.master_key;
    if (!masterKey) {
        masterKey = crypto.randomBytes(32).toString("base64");
        security.master_key = masterKey;
        writeJson(SECURITY_DB, security);
    }
    return Buffer.from(masterKey, "base64");
}

function generateFileKey(fid, userId, adminId, token) {
    let security = readJson(SECURITY_DB);
    let fileKeys = security.file_keys || {};
    if (!fileKeys[fid]) {
        let combined = `${fid}:${userId}:${adminId}:${token}`;
        let salt = crypto.createHash("sha256").update(combined).digest().slice(0, 16);
        let masterKey = getMasterKey();
        let kdf = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, "sha256");
        fileKeys[fid] = {
            key: kdf.toString("base64"),
            salt: salt.toString("base64"),
            user_id: userId
        };
        security.file_keys = fileKeys;
        writeJson(SECURITY_DB, security);
    }
    return fileKeys[fid];
}

function encryptFileContent(content, fid, userId, adminId, token) {
    try {
        let fileKeyInfo = generateFileKey(fid, userId, adminId, token);
        let key = Buffer.from(fileKeyInfo.key, "base64");
        let salt = Buffer.from(fileKeyInfo.salt, "base64");
        let iv = crypto.randomBytes(16);
        let cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
        let encrypted = Buffer.concat([cipher.update(content, "utf-8"), cipher.final()]);
        let encryptedData = {
            iv: iv.toString("base64"),
            ciphertext: encrypted.toString("base64"),
            salt: salt.toString("base64"),
            fid: fid,
            user_id: userId,
            timestamp: new Date().toISOString()
        };
        return JSON.stringify(encryptedData);
    } catch (e) {
        console.error("Encryption error:", e);
        return null;
    }
}

function decryptFileContent(encryptedJson, fid) {
    try {
        let data = JSON.parse(encryptedJson);
        let security = readJson(SECURITY_DB);
        let fileKeys = security.file_keys || {};
        let fileKeyInfo = fileKeys[fid];
        if (!fileKeyInfo) return null;
        let key = Buffer.from(fileKeyInfo.key, "base64");
        let iv = Buffer.from(data.iv, "base64");
        let ciphertext = Buffer.from(data.ciphertext, "base64");
        let decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
        let decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString("utf-8");
    } catch (e) {
        console.error("Decryption error:", e);
        return null;
    }
}

const BOT_TOKEN = "9294301891:AAG4oWwRlxxnyCIe3yIutxr_NSELsgBic68";
const ADMIN_TELEGRAM_IDS = [1002670694];
const ADMIN_ID = 1002670694;
const API_BASE_URL = process.env.API_BASE_URL || "https://zehab80.onrender.com";
const DEVELOPER_INFO = "🛠 طُوِّر بواسطة: *𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜*\n📬 تواصل: @Y_20_20";

function notifyAdmin(message) {
    try {
        for (const adminId of ADMIN_TELEGRAM_IDS) {
            axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
                chat_id: adminId,
                text: message,
                parse_mode: "Markdown"
            }).catch(() => {});
        }
    } catch (e) {}
}

// قوالب الـ HTML
const LANDING_HTML_CONTENT = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 | استضافة احترافية</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: #0a0a0a; color: #ffffff; overflow-x: hidden; }
        .hero-bg { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #0a0a0a 100%); }
        .glow-orb { position: fixed; width: 600px; height: 600px; background: radial-gradient(circle, rgba(255, 215, 0, 0.15), transparent 70%); border-radius: 50%; top: -200px; right: -200px; z-index: -1; animation: floatGlow 20s ease-in-out infinite; }
        .glow-orb-2 { position: fixed; width: 500px; height: 500px; background: radial-gradient(circle, rgba(255, 100, 0, 0.1), transparent 70%); border-radius: 50%; bottom: -150px; left: -150px; z-index: -1; animation: floatGlow 25s ease-in-out infinite reverse; }
        @keyframes floatGlow { 0%, 100% { transform: translate(0, 0) scale(1); opacity: 0.5; } 50% { transform: translate(50px, 30px) scale(1.1); opacity: 0.8; } }
        .grid-pattern { position: fixed; inset: 0; background-image: linear-gradient(rgba(255, 215, 0, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 215, 0, 0.03) 1px, transparent 1px); background-size: 60px 60px; z-index: -1; }
        .navbar { position: fixed; top: 0; width: 100%; padding: 20px 40px; background: rgba(10, 10, 10, 0.95); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(255, 215, 0, 0.2); display: flex; justify-content: space-between; align-items: center; z-index: 100; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 45px; height: 45px; background: linear-gradient(145deg, #1a1a2e, #0a0a0a); border: 1.5px solid #FFD700; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; color: #FFD700; box-shadow: 0 0 20px rgba(255, 215, 0, 0.3); }
        .logo-text { font-size: 1.6rem; font-weight: 800; background: linear-gradient(135deg, #FFD700, #FFA500); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .nav-buttons { display: flex; gap: 16px; }
        .nav-btn { padding: 10px 28px; border-radius: 50px; font-weight: 600; font-size: 0.9rem; cursor: pointer; transition: all 0.3s; border: none; font-family: 'Tajawal', sans-serif; }
        .nav-btn.login { background: transparent; border: 1.5px solid rgba(255, 215, 0, 0.5); color: #FFD700; }
        .nav-btn.login:hover { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
        .nav-btn.register { background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; box-shadow: 0 4px 15px rgba(255, 215, 0, 0.3); }
        .nav-btn.register:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(255, 215, 0, 0.4); }
        .hero { min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; padding: 100px 20px 60px; }
        .hero-content { max-width: 900px; }
        .hero-badge { display: inline-block; background: rgba(255, 215, 0, 0.15); border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 50px; padding: 8px 20px; font-size: 0.8rem; color: #FFD700; margin-bottom: 30px; }
        .hero-title { font-size: 3.5rem; font-weight: 800; margin-bottom: 20px; line-height: 1.3; }
        .hero-title .highlight { background: linear-gradient(135deg, #FFD700, #FFA500); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .hero-subtitle { font-size: 1.2rem; color: #9ca3cf; margin-bottom: 40px; line-height: 1.8; }
        .hero-buttons { display: flex; gap: 20px; justify-content: center; flex-wrap: wrap; }
        .btn-primary { padding: 14px 40px; font-size: 1rem; font-weight: 700; border-radius: 50px; border: none; cursor: pointer; transition: all 0.3s; font-family: 'Tajawal', sans-serif; background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; box-shadow: 0 4px 20px rgba(255, 215, 0, 0.3); }
        .btn-primary:hover { transform: translateY(-3px); box-shadow: 0 8px 30px rgba(255, 215, 0, 0.5); }
        .btn-secondary { padding: 14px 40px; font-size: 1rem; font-weight: 700; border-radius: 50px; border: 1.5px solid rgba(255, 215, 0, 0.5); background: transparent; color: #FFD700; cursor: pointer; transition: all 0.3s; font-family: 'Tajawal', sans-serif; }
        .btn-secondary:hover { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
        .features { padding: 80px 40px; background: rgba(0, 0, 0, 0.6); }
        .section-title { text-align: center; font-size: 2.2rem; font-weight: 700; margin-bottom: 50px; }
        .section-title span { color: #FFD700; }
        .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .feature-card { background: rgba(20, 20, 40, 0.8); backdrop-filter: blur(10px); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 28px; padding: 35px 25px; text-align: center; transition: all 0.3s; }
        .feature-card:hover { border-color: rgba(255, 215, 0, 0.5); transform: translateY(-8px); }
        .feature-icon { width: 70px; height: 70px; background: linear-gradient(145deg, #FFD70020, #FFA50010); border-radius: 20px; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; font-size: 2rem; color: #FFD700; }
        .feature-card h3 { font-size: 1.3rem; margin-bottom: 12px; }
        .feature-card p { color: #9ca3cf; font-size: 0.85rem; line-height: 1.6; }
        .pricing { padding: 80px 40px; }
        .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; max-width: 1200px; margin: 0 auto; }
        .pricing-card { background: rgba(15, 15, 30, 0.9); backdrop-filter: blur(10px); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 32px; padding: 35px; text-align: center; transition: all 0.3s; position: relative; }
        .pricing-card.popular { border-color: #FFD700; transform: scale(1.02); box-shadow: 0 10px 40px rgba(255, 215, 0, 0.2); }
        .popular-badge { position: absolute; top: -12px; right: 50%; transform: translateX(50%); background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; padding: 5px 20px; border-radius: 50px; font-size: 0.7rem; font-weight: 700; }
        .plan-name { font-size: 1.5rem; font-weight: 700; margin-bottom: 15px; }
        .plan-price { font-size: 2.5rem; font-weight: 800; color: #FFD700; margin-bottom: 20px; }
        .plan-price small { font-size: 0.9rem; color: #9ca3cf; }
        .plan-features { list-style: none; margin: 25px 0; }
        .plan-features li { padding: 8px 0; color: #b9c3e0; font-size: 0.85rem; }
        .plan-features i { color: #FFD700; margin-left: 8px; }
        .stats-section { padding: 60px 40px; background: linear-gradient(135deg, #0a0a0a, #0f0f1a); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 30px; max-width: 1000px; margin: 0 auto; text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: 800; color: #FFD700; }
        .stat-label { color: #9ca3cf; margin-top: 8px; }
        .footer { padding: 40px; text-align: center; border-top: 1px solid rgba(255, 215, 0, 0.1); color: #6b7aaa; font-size: 0.8rem; }
        @media (max-width: 768px) { .navbar { padding: 15px 20px; } .logo-text { font-size: 1.2rem; } .hero-title { font-size: 2rem; } .hero-subtitle { font-size: 1rem; } .features, .pricing, .stats-section { padding: 50px 20px; } .nav-buttons { gap: 8px; } .nav-btn { padding: 6px 16px; font-size: 0.8rem; } }
    </style>
</head>
<body>
<div class="hero-bg"></div>
<div class="glow-orb"></div>
<div class="glow-orb-2"></div>
<div class="grid-pattern"></div>
<nav class="navbar">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <span class="logo-text">𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓</span>
    </div>
    <div class="nav-buttons">
        <button class="nav-btn login" onclick="window.location.href='/login'">تسجيل الدخول</button>
        <button class="nav-btn register" onclick="window.location.href='/login'">إنشاء حساب</button>
    </div>
</nav>
<section class="hero">
    <div class="hero-content">
        <div class="hero-badge"><i class="fas fa-bolt"></i> أقوى منصة استضافة في الشرق الأوسط</div>
        <h1 class="hero-title">استضف مشاريعك<br>بأعلى <span class="highlight">أداء وأمان</span></h1>
        <p class="hero-subtitle">منصة 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 توفر لك بيئة استضافة متكاملة لبوتات تيليجرام ومواقع Node.js<br>مع دعم فني 24/7 وأسعار تنافسية</p>
        <div class="hero-buttons">
            <button class="btn-primary" onclick="window.location.href='/login'"><i class="fas fa-rocket"></i> ابدأ الآن مجاناً</button>
            <button class="btn-secondary" onclick="scrollToFeatures()"><i class="fas fa-info-circle"></i> تعرف على المميزات</button>
        </div>
    </div>
</section>
<section class="features" id="features">
    <h2 class="section-title">لماذا <span>𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓</span>؟</h2>
    <div class="features-grid">
        <div class="feature-card">
            <div class="feature-icon"><i class="fab fa-python"></i></div>
            <h3>Python & Node.js</h3>
            <p>دعم كامل لجميع أنواع البوتات والتطبيقات مع أحدث الإصدارات</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><i class="fas fa-cloud-upload-alt"></i></div>
            <h3>رفع سهل وسريع</h3>
            <p>ارفع ملفاتك عبر السحب والإفلات أو من خلال مدير الملفات المتطور</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
            <h3>حماية متطورة</h3>
            <p>أنظمة أمان متعددة الطبقات لحماية مشاريعك وبياناتك</p>
        </div>
        <div class="feature-card">
            <div class="feature-icon"><i class="fas fa-headset"></i></div>
            <h3>دعم فني 24/7</h3>
            <p>فريق دعم متخصص يجيب على استفساراتك في أي وقت</p>
        </div>
    </div>
</section>
<section class="pricing">
    <h2 class="section-title">خطط <span>استضافة</span> تناسب الجميع</h2>
    <div class="pricing-grid">
        <div class="pricing-card">
            <div class="plan-name">🎁 مجاني</div>
            <div class="plan-price">0$ <small>/شهر</small></div>
            <ul class="plan-features">
                <li><i class="fas fa-check"></i> مساحة تخزين عالية</li>
                <li><i class="fas fa-check"></i> 256 MB رام</li>
                <li><i class="fas fa-check"></i> 0.5 CPU نواة</li>
                <li><i class="fas fa-check"></i> 2 سيرفر كحد أقصى</li>
                <li><i class="fas fa-check"></i> دعم Python و Node.js</li>
                <li><i class="fas fa-check"></i> SSL مجاني</li>
            </ul>
        </div>
        <div class="pricing-card popular">
            <div class="popular-badge"><i class="fas fa-star"></i> الأكثر طلباً</div>
            <div class="plan-name">💎 4 جيجا</div>
            <div class="plan-price">5$ <small>/شهر</small></div>
            <ul class="plan-features">
                <li><i class="fas fa-check"></i> 4 GB مساحة تخزين</li>
                <li><i class="fas fa-check"></i> 1024 MB رام</li>
                <li><i class="fas fa-check"></i> 1 CPU نواة</li>
                <li><i class="fas fa-check"></i> 5 سيرفر كحد أقصى</li>
                <li><i class="fas fa-check"></i> دعم Python و Node.js</li>
                <li><i class="fas fa-check"></i> SSL مجاني + دعم أولوية</li>
            </ul>
        </div>
        <div class="pricing-card">
            <div class="plan-name">💎 10 جيجا</div>
            <div class="plan-price">10$ <small>/شهر</small></div>
            <ul class="plan-features">
                <li><i class="fas fa-check"></i> 10 GB مساحة تخزين</li>
                <li><i class="fas fa-check"></i> 2048 MB رام</li>
                <li><i class="fas fa-check"></i> 2 CPU نواة</li>
                <li><i class="fas fa-check"></i> 10 سيرفر كحد أقصى</li>
                <li><i class="fas fa-check"></i> دعم Python و Node.js</li>
                <li><i class="fas fa-check"></i> SSL مجاني + دعم VIP</li>
            </ul>
        </div>
    </div>
</section>
<section class="stats-section">
    <div class="stats-grid">
        <div><div class="stat-number">500+</div><div class="stat-label">مستخدم نشط</div></div>
        <div><div class="stat-number">1000+</div><div class="stat-label">سيرفر مستضاف</div></div>
        <div><div class="stat-number">99.9%</div><div class="stat-label">وقت تشغيل</div></div>
        <div><div class="stat-number">24/7</div><div class="stat-label">دعم فني</div></div>
    </div>
</section>
<footer class="footer">
    <p><i class="fas fa-crown"></i> 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 - منصة الاستضافة الأقوى في الشرق الأوسط</p>
    <p style="margin-top: 12px;">© 2026 جميع الحقوق محفوظة | تصميم وتطوير ZIAD</p>
</footer>
<script>
    function scrollToFeatures() {
        document.getElementById('features').scrollIntoView({ behavior: 'smooth' });
    }
</script>
</body>
</html>`;

const LOGIN_HTML_CONTENT = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 | تسجيل الدخول</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: #000000; min-height: 100vh; display: flex; align-items: center; justify-content: center; position: relative; }
        .bg-gold { position: fixed; inset: 0; background: radial-gradient(ellipse at 30% 40%, rgba(255,215,0,0.1), transparent 70%); z-index: -2; }
        .login-card { background: rgba(5,5,5,0.95); backdrop-filter: blur(20px); border: 1px solid rgba(255,215,0,0.3); border-radius: 32px; padding: 40px; width: 90%; max-width: 450px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo-icon { width: 70px; height: 70px; background: linear-gradient(145deg, #000, #0a0a0a); border: 1.5px solid #FFD700; border-radius: 20px; display: flex; align-items: center; justify-content: center; margin: 0 auto 15px; font-size: 2rem; color: #FFD700; }
        .logo-text { font-size: 1.5rem; font-weight: 800; background: linear-gradient(135deg, #FFD700, #FFA500); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .tabs { display: flex; gap: 8px; margin-bottom: 25px; background: rgba(0,0,0,0.5); border-radius: 60px; padding: 4px; }
        .tab-btn { flex: 1; padding: 10px; border-radius: 50px; border: none; background: none; color: #9ca3cf; font-weight: 600; cursor: pointer; transition: 0.2s; }
        .tab-btn.active { background: linear-gradient(135deg, #FFD700, #FFA500); color: #000; }
        .form-group { margin-bottom: 20px; }
        .form-group input { width: 100%; padding: 14px 18px; background: #000; border: 1px solid rgba(255,215,0,0.3); border-radius: 16px; color: white; font-family: 'Tajawal', sans-serif; font-size: 0.9rem; outline: none; }
        .form-group input:focus { border-color: #FFD700; }
        .submit-btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #FFD700, #FFA500); border: none; border-radius: 16px; color: #000; font-weight: 700; font-size: 1rem; cursor: pointer; transition: 0.2s; }
        .submit-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(255,215,0,0.4); }
        .alert { background: rgba(255,61,90,0.15); border: 1px solid rgba(255,61,90,0.4); border-radius: 12px; padding: 12px; margin-bottom: 20px; color: #ff7a94; font-size: 0.8rem; display: none; }
        .footer-note { text-align: center; margin-top: 20px; font-size: 0.7rem; color: #6b7aaa; }
        .footer-note a { color: #FFD700; text-decoration: none; }
        @media (max-width: 500px) { .login-card { padding: 30px 20px; } }
    </style>
</head>
<body>
<div class="bg-gold"></div>
<div class="login-card">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <div class="logo-text">𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓</div>
    </div>
    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('login')">تسجيل الدخول</button>
        <button class="tab-btn" onclick="switchTab('register')">حساب جديد</button>
    </div>
    <div id="alertBox" class="alert"></div>
    <div id="loginForm">
        <div class="form-group"><input type="email" id="loginEmail" placeholder="البريد الإلكتروني"></div>
        <div class="form-group"><input type="password" id="loginPassword" placeholder="كلمة المرور"></div>
        <button class="submit-btn" onclick="doLogin()"><i class="fas fa-sign-in-alt"></i> دخول</button>
    </div>
    <div id="registerForm" style="display:none;">
        <div class="form-group"><input type="email" id="regEmail" placeholder="البريد الإلكتروني"></div>
        <div class="form-group"><input type="password" id="regPassword" placeholder="كلمة المرور (4 أحرف على الأقل)"></div>
        <button class="submit-btn" onclick="doRegister()"><i class="fas fa-user-plus"></i> إنشاء حساب</button>
    </div>
    <div class="footer-note"><i class="fas fa-shield-alt"></i> 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 | استضافة آمنة</div>
</div>
<script>
    function showAlert(msg, isError=true) {
        const alert = document.getElementById('alertBox');
        alert.innerHTML = `<i class="fas \${isError ? 'fa-exclamation-circle' : 'fa-check-circle'}"></i> \${msg}`;
        alert.style.display = 'block';
        setTimeout(() => alert.style.display = 'none', 4000);
    }
    function switchTab(tab) {
        document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
        document.getElementById('registerForm').style.display = tab === 'register' ? 'block' : 'none';
        document.querySelectorAll('.tab-btn').forEach((btn, i) => {
            btn.classList.toggle('active', (tab === 'login' && i === 0) || (tab === 'register' && i === 1));
        });
    }
    async function doLogin() {
        const email = document.getElementById('loginEmail').value.trim().toLowerCase();
        const password = document.getElementById('loginPassword').value.trim();
        if(!email || !password) { showAlert('الرجاء إدخال جميع البيانات'); return; }
        try {
            const res = await fetch('/api/login', { method: 'POST', headers:{ 'Content-Type': 'application/json' }, body:JSON.stringify({email, password}) });
            const data = await res.json();
            if(data.success) { window.location.href = data.redirect; }
            else { showAlert(data.message || 'بيانات غير صحيحة'); }
        } catch(e) { showAlert('خطأ في الاتصال'); }
    }
    async function doRegister() {
        const email = document.getElementById('regEmail').value.trim().toLowerCase();
        const password = document.getElementById('regPassword').value.trim();
        if(!email || !password) { showAlert('الرجاء إدخال جميع البيانات'); return; }
        if(password.length < 4) { showAlert('كلمة المرور يجب أن تكون 4 أحرف على الأقل'); return; }
        try {
            const res = await fetch('/api/register', { method: 'POST', headers:{ 'Content-Type': 'application/json' }, body:JSON.stringify({email, password}) });
            const data = await res.json();
            if(data.success) {
                showAlert('✅ تم إنشاء الحساب! يمكنك تسجيل الدخول', false);
                switchTab('login');
                document.getElementById('loginEmail').value = email;
            } else { showAlert(data.message || 'فشل إنشاء الحساب'); }
        } catch(e) { showAlert('خطأ في الاتصال'); }
    }
    fetch('/api/current_user').then(r=>r.json()).then(d=>{ if(d.success) window.location.href = d.is_admin ? '/admin' : '/dashboard'; }).catch(()=>{});
</script>
</body>
</html>`;

const INDEX_HTML_CONTENT = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 | لوحة التحكم</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: #0a0a0a; color: #ffffff; overflow-x: hidden; }
        .bg-gradient { position: fixed; inset: 0; background: radial-gradient(ellipse at 20% 30%, rgba(255, 215, 0, 0.06), transparent 60%), radial-gradient(ellipse at 80% 70%, rgba(255, 255, 255, 0.02), transparent 70%); z-index: -2; }
        .bg-grid { position: fixed; inset: 0; background-image: linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px); background-size: 50px 50px; z-index: -1; }
        .navbar { background: rgba(10, 10, 10, 0.98); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(255, 215, 0, 0.2); padding: 12px 28px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 38px; height: 38px; background: linear-gradient(145deg, #1a1a1a, #0a0a0a); border: 1px solid #FFD700; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1rem; color: #FFD700; }
        .logo-text { font-size: 1.2rem; font-weight: 700; color: #ffffff; }
        .logo-text span { color: #FFD700; }
        .user-section { display: flex; align-items: center; gap: 18px; }
        .user-greeting { font-size: 0.8rem; color: #888888; }
        .user-greeting strong { color: #FFD700; }
        .logout-btn { background: rgba(255, 70, 85, 0.1); border: 1px solid rgba(255, 70, 85, 0.3); color: #ff5e7c; padding: 6px 16px; border-radius: 40px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
        .logout-btn:hover { background: rgba(255, 70, 85, 0.2); }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 32px; }
        .stat-card { background: rgba(15, 15, 15, 0.9); backdrop-filter: blur(12px); border: 1px solid rgba(255, 215, 0, 0.15); border-radius: 20px; padding: 20px; transition: all 0.3s; }
        .stat-card:hover { border-color: rgba(255, 215, 0, 0.4); transform: translateY(-3px); }
        .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .stat-title { font-size: 0.7rem; text-transform: uppercase; color: #888888; }
        .stat-icon { width: 40px; height: 40px; background: rgba(255, 215, 0, 0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1rem; color: #FFD700; }
        .stat-value { font-size: 1.6rem; font-weight: 700; margin-top: 8px; }
        .stat-progress { height: 4px; background: rgba(255, 255, 255, 0.1); border-radius: 10px; overflow: hidden; margin-top: 8px; }
        .stat-progress-bar { height: 100%; background: linear-gradient(90deg, #FFD700, #FFA500); width: 0%; }
        .servers-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 16px; }
        .servers-title { font-size: 1rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }
        .servers-title i { color: #FFD700; }
        .create-server-btn { background: #FFD700; border: none; border-radius: 40px; padding: 10px 24px; font-weight: 700; font-size: 0.8rem; color: #000000; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: 0.2s; }
        .create-server-btn:hover { background: #FFC107; transform: translateY(-2px); }
        .servers-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 24px; }
        .server-card { background: rgba(15, 15, 15, 0.9); backdrop-filter: blur(12px); border: 1px solid rgba(255, 215, 0, 0.15); border-radius: 24px; overflow: hidden; transition: all 0.3s; cursor: pointer; }
        .server-card:hover { border-color: rgba(255, 215, 0, 0.4); transform: translateY(-5px); }
        .server-card-header { padding: 18px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255, 215, 0, 0.1); }
        .server-icon { width: 45px; height: 45px; background: rgba(255, 215, 0, 0.1); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; }
        .server-icon.python { color: #3776AB; }
        .server-icon.nodejs { color: #68A063; }
        .server-status { display: flex; align-items: center; gap: 6px; font-size: 0.7rem; background: rgba(0, 0, 0, 0.5); padding: 5px 12px; border-radius: 30px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; }
        .dot-online { background: #00ff88; box-shadow: 0 0 5px #00ff88; }
        .dot-offline { background: #666666; }
        .status-online { color: #00ff88; }
        .status-offline { color: #888888; }
        .server-name { font-size: 1rem; font-weight: 700; padding: 16px 20px 0 20px; }
        .server-meta { display: flex; gap: 12px; padding: 8px 20px; font-size: 0.7rem; color: #888888; flex-wrap: wrap; }
        .server-meta span { background: rgba(255, 255, 255, 0.05); padding: 4px 12px; border-radius: 30px; }
        .server-stats { display: flex; gap: 16px; padding: 12px 20px; font-size: 0.7rem; color: #aaaaaa; border-top: 1px solid rgba(255, 215, 0, 0.08); border-bottom: 1px solid rgba(255, 215, 0, 0.08); }
        .server-actions { display: flex; gap: 8px; padding: 16px 20px; justify-content: space-between; flex-wrap: wrap; }
        .action-group { display: flex; gap: 6px; flex-wrap: wrap; }
        .action-btn { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 30px; padding: 6px 14px; font-size: 0.7rem; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; transition: 0.2s; color: #cccccc; }
        .action-btn i { font-size: 0.7rem; }
        .action-btn.start:hover { background: rgba(0, 255, 136, 0.15); border-color: #00ff88; color: #00ff88; }
        .action-btn.stop:hover { background: rgba(255, 61, 90, 0.15); border-color: #ff3d5a; color: #ff3d5a; }
        .action-btn.restart:hover { background: rgba(255, 215, 0, 0.15); border-color: #FFD700; color: #FFD700; }
        .action-btn.delete:hover { background: rgba(255, 61, 90, 0.15); border-color: #ff3d5a; color: #ff3d5a; }
        .action-btn.detail:hover { background: rgba(255, 215, 0, 0.15); border-color: #FFD700; color: #FFD700; }
        .server-detail { display: none; animation: fadeIn 0.3s ease; }
        .server-detail.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .detail-header { background: rgba(15, 15, 15, 0.95); border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 50px; padding: 12px 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
        .back-btn { background: rgba(255, 215, 0, 0.1); border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 40px; padding: 8px 20px; font-size: 0.8rem; color: #FFD700; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; }
        .server-type { background: rgba(255, 215, 0, 0.1); border-radius: 40px; padding: 8px 20px; font-size: 0.8rem; color: #FFD700; }
        .detail-actions { display: flex; gap: 12px; flex-wrap: wrap; }
        .glow-btn { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 40px; padding: 8px 20px; font-size: 0.75rem; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; cursor: pointer; transition: 0.2s; }
        .glow-btn.start { color: #00ff88; border-color: #00ff88; }
        .glow-btn.stop { color: #ff5e7c; border-color: #ff5e7c; }
        .glow-btn.restart { color: #FFD700; border-color: #FFD700; }
        .glow-btn.delete { color: #ff8a5c; border-color: #ff8a5c; }
        .glow-btn:hover { transform: translateY(-2px); background: rgba(255, 215, 0, 0.1); }
        .tabs-nav { display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 1px solid rgba(255, 215, 0, 0.15); padding-bottom: 12px; flex-wrap: wrap; }
        .tab-nav-btn { background: none; border: none; padding: 10px 24px; font-size: 0.85rem; font-weight: 600; color: #888888; cursor: pointer; transition: 0.2s; border-radius: 40px; }
        .tab-nav-btn.active { background: rgba(255, 215, 0, 0.15); color: #FFD700; }
        .tab-pane { display: none; animation: fadeIn 0.2s; }
        .tab-pane.active { display: block; }
        .console-box { background: #050505; border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 16px; padding: 20px; height: 500px; overflow-y: auto; font-family: monospace; font-size: 0.75rem; color: #00ff88; white-space: pre-wrap; }
        .files-table { width: 100%; border-collapse: collapse; }
        .files-table th, .files-table td { padding: 12px 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); text-align: right; }
        .files-table th { color: #888888; font-weight: 500; font-size: 0.75rem; }
        .upload-zone { border: 1px dashed rgba(255, 215, 0, 0.4); border-radius: 16px; padding: 30px; text-align: center; margin-bottom: 20px; cursor: pointer; transition: 0.2s; }
        .upload-zone:hover { border-color: #FFD700; background: rgba(255, 215, 0, 0.03); }
        .modal { display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.95); backdrop-filter: blur(12px); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: #111111; border: 1px solid rgba(255, 215, 0, 0.3); border-radius: 24px; width: 90%; max-width: 500px; padding: 30px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-size: 0.8rem; color: #888888; }
        .form-group input, .form-group select, textarea { width: 100%; padding: 12px 16px; background: #0a0a0a; border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 12px; color: white; font-family: 'Tajawal', sans-serif; outline: none; }
        .form-group input:focus, .form-group select:focus, textarea:focus { border-color: #FFD700; }
        .server-type-selector { display: flex; gap: 15px; margin: 20px 0; }
        .type-option { flex: 1; padding: 15px; border: 1px solid rgba(255, 215, 0, 0.2); border-radius: 16px; text-align: center; cursor: pointer; transition: 0.2s; }
        .type-option.selected { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
        .type-option i { font-size: 1.5rem; display: block; margin-bottom: 8px; }
        .toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: #1a1a1a; border: 1px solid #FFD700; border-radius: 50px; padding: 10px 24px; z-index: 1100; display: none; font-size: 0.8rem; }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 12px; } .servers-grid { grid-template-columns: 1fr; } .container { padding: 16px; } .detail-header { flex-direction: column; align-items: stretch; border-radius: 20px; } .detail-actions { justify-content: center; } }
    </style>
</head>
<body>
<div class="bg-gradient"></div>
<div class="bg-grid"></div>
<div class="navbar">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <div class="logo-text">ZIAD<span>HOST</span></div>
    </div>
    <div class="user-section">
        <div class="user-greeting"><i class="far fa-user-circle"></i> مرحباً، <strong id="userEmail">...</strong></div>
        <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> خروج</button>
    </div>
</div>
<div class="container">
    <div id="homeView">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">الخوادم المستخدمة</span><div class="stat-icon"><i class="fas fa-server"></i></div></div>
                <div class="stat-value" id="usedServers">0/0</div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">الصلاحية المتبقية</span><div class="stat-icon"><i class="fas fa-calendar-alt"></i></div></div>
                <div class="stat-value" id="expiryDays">-- يوم</div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">المساحة المستخدمة</span><div class="stat-icon"><i class="fas fa-hdd"></i></div></div>
                <div class="stat-value" id="diskUsed">0 MB</div>
                <div class="stat-progress"><div class="stat-progress-bar" id="diskProgress"></div></div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-title">استخدام الرام</span><div class="stat-icon"><i class="fas fa-microchip"></i></div></div>
                <div class="stat-value" id="ramUsage">0%</div>
                <div class="stat-progress"><div class="stat-progress-bar" id="ramProgress"></div></div>
            </div>
        </div>
        <div class="servers-header">
            <div class="servers-title"><i class="fas fa-cubes"></i> الخوادم النشطة</div>
            <button class="create-server-btn" id="openCreateModalBtn"><i class="fas fa-plus-circle"></i> خادم جديد</button>
        </div>
        <div class="servers-grid" id="serversGrid"><div style="text-align:center; padding:60px; color:#666;">جاري التحميل...</div></div>
    </div>
    <div id="detailView" class="server-detail">
        <div class="detail-header">
            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <button class="back-btn" onclick="goHome()"><i class="fas fa-arrow-right"></i> رجوع</button>
                <div class="server-type" id="serverTypeBadge">🐍 Python</div>
            </div>
            <div class="detail-actions">
                <button class="glow-btn start" onclick="serverAction('start')"><i class="fas fa-play"></i> تشغيل</button>
                <button class="glow-btn restart" onclick="serverAction('restart')"><i class="fas fa-sync-alt"></i> إعادة</button>
                <button class="glow-btn stop" onclick="serverAction('stop')"><i class="fas fa-stop"></i> إيقاف</button>
                <button class="glow-btn delete" onclick="confirmDelete()"><i class="fas fa-trash"></i> حذف</button>
            </div>
        </div>
        <div class="tabs-nav">
            <button class="tab-nav-btn active" data-tab="console">🖥 كونسول</button>
            <button class="tab-nav-btn" data-tab="files">📁 ملفات</button>
            <button class="tab-nav-btn" data-tab="stats">📊 إحصائيات</button>
            <button class="tab-nav-btn" data-tab="settings">⚙ إعدادات</button>
            <button class="tab-nav-btn" data-tab="api">🔑 API</button>
        </div>
        <div id="consoleTab" class="tab-pane active"><div class="console-box" id="consoleOut"></div></div>
        <div id="filesTab" class="tab-pane">
            <div class="upload-zone" onclick="document.getElementById('fileUpload').click()" ondragover="event.preventDefault()" ondrop="handleDrop(event)">
                <i class="fas fa-cloud-upload-alt" style="font-size: 1.8rem; color: #FFD700; margin-bottom: 10px; display: block;"></i>
                <span>اسحب الملفات هنا (أو ملفات .zip مفكوكة) أو انقر للرفع</span>
            </div>
            <input type="file" id="fileUpload" multiple style="display:none" onchange="uploadFiles(this.files)">
            <div style="display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;">
                <button class="glow-btn" onclick="showCreateFileModal()" style="background:#FFD700; color:#000;"><i class="fas fa-file"></i> ملف جديد</button>
                <button class="glow-btn" onclick="installPackages()" style="background:#FFD700; color:#000;"><i class="fas fa-cube"></i> تثبيت المكتبات</button>
                <button class="glow-btn" onclick="showCreateFolderModal()" style="background:#FFD700; color:#000;"><i class="fas fa-folder-plus"></i> مجلد جديد</button>
            </div>
            <table class="files-table">
                <thead><tr><th></th><th>الاسم</th><th>الحجم</th><th>الإجراءات</th></tr></thead>
                <tbody id="filesList"></tbody>
            </table>
        </div>
        <div id="statsTab" class="tab-pane">
            <div style="display: grid; grid-template-columns: repeat(2,1fr); gap: 16px;">
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-microchip"></i> CPU</div>
                    <div class="stat-value" id="cpuStat">0%</div>
                    <div class="stat-progress"><div class="stat-progress-bar" id="cpuProgress"></div></div>
                </div>
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-memory"></i> RAM</div>
                    <div class="stat-value" id="ramStat">0 MB</div>
                    <div class="stat-progress"><div class="stat-progress-bar" id="ramDetailProgress"></div></div>
                </div>
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-hdd"></i> التخزين</div>
                    <div class="stat-value" id="storageStat">0 MB</div>
                    <div class="stat-progress"><div class="stat-progress-bar" id="storageProgress"></div></div>
                </div>
                <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:20px;">
                    <div><i class="fas fa-clock"></i> وقت التشغيل</div>
                    <div class="stat-value" id="uptimeStat">0</div>
                </div>
            </div>
        </div>
        <div id="settingsTab" class="tab-pane">
            <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:24px; margin-bottom:20px;">
                <div><i class="fas fa-rocket"></i> ملف بدء التشغيل</div>
                <div style="display: flex; gap: 12px; margin-top: 15px; flex-wrap: wrap;">
                    <select id="startupFileSelect" style="flex:1; background:#0a0a0a; border:1px solid #FFD700; border-radius:40px; padding:10px 16px; color:white;"></select>
                    <button class="glow-btn" onclick="setStartupFile()">حفظ</button>
                </div>
            </div>
            <div style="background:rgba(15,15,15,0.8); border-radius:20px; padding:24px;">
                <div>الخطة: <span id="planDetails"></span></div>
                <div style="margin-top: 12px;">الرام الأقصى: <span id="ramLimit"></span> MB</div>
                <div>المساحة القصوى: <span id="storageLimit"></span> MB</div>
            </div>
        </div>
        <div id="apiTab" class="tab-pane">
            <div style="background:rgba(15,15,15,0.8); border-radius:24px; padding:28px;">
                <h3 style="margin-bottom:16px;"><i class="fas fa-key"></i> مفتاح API</h3>
                <div id="apiKeyDisplay" style="background:#050505; border-radius:50px; padding:14px 20px; font-family:monospace; word-break:break-all; border:1px solid #FFD700;">لا يوجد مفتاح</div>
                <button class="glow-btn" onclick="generateApiKey()" style="margin-top:20px; background:#FFD700; color:#000;"><i class="fas fa-sync-alt"></i> إنشاء مفتاح جديد</button>
            </div>
        </div>
    </div>
</div>
<div id="createServerModal" class="modal">
    <div class="modal-content">
        <h3 style="color:#FFD700; margin-bottom:20px;"><i class="fas fa-rocket"></i> إنشاء خادم جديد</h3>
        <div class="form-group"><label>اسم السيرفر</label><input type="text" id="serverName" placeholder="أدخل اسم السيرفر"></div>
        <div class="server-type-selector">
            <div class="type-option" data-type="Python" onclick="selectType('Python')"><i class="fab fa-python"></i><div>Python</div></div>
            <div class="type-option" data-type="Node.js" onclick="selectType('Node.js')"><i class="fab fa-node-js"></i><div>Node.js</div></div>
        </div>
        <button class="glow-btn" onclick="createServer()" style="width:100%; margin-top:20px; background:#FFD700; color:#000;"><i class="fas fa-check"></i> إنشاء</button>
        <button class="glow-btn" onclick="closeCreateModal()" style="width:100%; margin-top:10px;">إلغاء</button>
    </div>
</div>
<div id="editorModal" class="modal">
    <div class="modal-content">
        <textarea id="editorContent" rows="12" style="width:100%; background:#0a0a0a; border:1px solid #FFD700; border-radius:12px; padding:12px; color:white;"></textarea>
        <button class="glow-btn" onclick="saveFile()" style="width:100%; margin-top:16px; background:#FFD700; color:#000;">حفظ</button>
        <button class="glow-btn" onclick="closeEditorModal()" style="width:100%; margin-top:10px;">إلغاء</button>
    </div>
</div>
<div id="createFileModal" class="modal">
    <div class="modal-content">
        <h3 style="color:#FFD700;"><i class="fas fa-file"></i> ملف جديد</h3>
        <div class="form-group"><input type="text" id="newFileName" placeholder="اسم الملف"></div>
        <div class="form-group"><textarea id="newFileContent" rows="5" placeholder="محتوى الملف"></textarea></div>
        <button class="glow-btn" onclick="createNewFile()" style="background:#FFD700; color:#000;">إنشاء</button>
    </div>
</div>
<div id="createFolderModal" class="modal">
    <div class="modal-content">
        <h3 style="color:#FFD700;"><i class="fas fa-folder-plus"></i> مجلد جديد</h3>
        <div class="form-group"><input type="text" id="newFolderName" placeholder="اسم المجلد"></div>
        <button class="glow-btn" onclick="createNewFolder()" style="background:#FFD700; color:#000;">إنشاء</button>
    </div>
</div>
<div id="confirmModal" class="modal">
    <div class="modal-content">
        <p id="confirmMessage"></p>
        <div style="display:flex; gap:12px; margin-top:20px;">
            <button class="glow-btn" id="confirmYesBtn" style="background:#ff3d5a;">تأكيد</button>
            <button class="glow-btn" onclick="closeConfirmModal()">إلغاء</button>
        </div>
    </div>
</div>
<div id="toast" class="toast"></div>
<script>
    let currentServer = null;
    let currentEditFile = null;
    let confirmCallback = null;
    let pollingInterval = null;
    let selectedType = "Python";
    function selectType(type) {
        selectedType = type;
        document.querySelectorAll('.type-option').forEach(opt => {
            if(opt.dataset.type === type) opt.classList.add('selected');
            else opt.classList.remove('selected');
        });
    }
    function showToast(msg, isSuccess = false) {
        const toast = document.getElementById('toast');
        toast.innerHTML = \`<i class="fas \${isSuccess ? 'fa-check-circle' : 'fa-info-circle'}"></i> \${msg}\`;
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 3000);
    }
    function showConfirm(msg, callback) {
        document.getElementById('confirmMessage').innerText = msg;
        confirmCallback = callback;
        document.getElementById('confirmModal').classList.add('active');
    }
    function closeConfirmModal() {
        document.getElementById('confirmModal').classList.remove('active');
        confirmCallback = null;
    }
    document.getElementById('confirmYesBtn').onclick = () => {
        if(confirmCallback) confirmCallback();
        closeConfirmModal();
    };
    async function logout() {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login';
    }
    async function checkAuth() {
        try {
            const res = await fetch('/api/current_user');
            const data = await res.json();
            if(!data.success) window.location.href = '/login';
            else {
                document.getElementById('userEmail').innerText = data.email;
                loadServers();
                loadSystemStats();
                setInterval(loadSystemStats, 10000);
            }
        } catch(e) { console.error(e); }
    }
    async function loadSystemStats() {
        try {
            const res = await fetch('/api/system/metrics');
            const data = await res.json();
            document.getElementById('ramUsage').innerText = data.memory + '%';
            document.getElementById('ramProgress').style.width = data.memory + '%';
            if(document.getElementById('cpuStat')) {
                document.getElementById('cpuStat').innerText = data.cpu + '%';
                document.getElementById('cpuProgress').style.width = data.cpu + '%';
            }
        } catch(e) {}
    }
    async function loadServers() {
        try {
            const res = await fetch('/api/servers');
            const data = await res.json();
            if(!data.success) return;
            document.getElementById('usedServers').innerHTML = \`\${data.stats.used}/\${data.stats.total || 2}\`;
            document.getElementById('expiryDays').innerHTML = \`\${data.stats.expiry || '--'} يوم\`;
            const diskTotal = data.stats.disk_total || 512000;
            const diskUsed = data.stats.disk_used || 0;
            document.getElementById('diskUsed').innerHTML = \`\${Math.round(diskUsed)}/\${Math.round(diskTotal/1024)} MB\`;
            document.getElementById('diskProgress').style.width = Math.min((diskUsed/diskTotal)*100, 100) + '%';
            const grid = document.getElementById('serversGrid');
            if(!data.servers || data.servers.length === 0) {
                grid.innerHTML = '<div style="text-align:center; padding:60px; color:#666;">لا توجد خوادم، أنشئ واحداً</div>';
                return;
            }
            grid.innerHTML = '';
            data.servers.forEach(s => {
                const typeIcon = s.server_type === 'Node.js' ? '<i class="fab fa-node-js"></i>' : '<i class="fab fa-python"></i>';
                const typeClass = s.server_type === 'Node.js' ? 'nodejs' : 'python';
                const card = document.createElement('div');
                card.className = 'server-card';
                card.innerHTML = \`
                    <div class="server-card-header">
                        <div class="server-icon \${typeClass}">\${typeIcon}</div>
                        <div class="server-status \${s.status==='Running'?'status-online':'status-offline'}">
                            <span class="status-dot \${s.status==='Running'?'dot-online':'dot-offline'}"></span>\${s.status==='Running'?'يعمل':'متوقف'}
                        </div>
                    </div>
                    <div class="server-name">\${escapeHtml(s.title)}</div>
                    <div class="server-meta">
                        <span><i class="fas fa-plug"></i> المنفذ: \${s.port||'N/A'}</span>
                        <span><i class="fas fa-tag"></i> \${s.plan==='free'?'مجاني':s.plan}</span>
                    </div>
                    <div class="server-stats">
                        <span><i class="fas fa-hdd"></i> \${Math.round((s.storage_limit||512000)/1024)} MB</span>
                        <span><i class="fas fa-microchip"></i> \${s.cpu_limit||0.5}</span>
                        <span><i class="fas fa-clock"></i> \${s.uptime || '0'}</span>
                    </div>
                    <div class="server-actions">
                        <div class="action-group">
                            <button class="action-btn start" data-action="start" data-folder="\${s.folder}"><i class="fas fa-play"></i> تشغيل</button>
                            <button class="action-btn restart" data-action="restart" data-folder="\${s.folder}"><i class="fas fa-sync-alt"></i> إعادة</button>
                            <button class="action-btn stop" data-action="stop" data-folder="\${s.folder}"><i class="fas fa-stop"></i> إيقاف</button>
                        </div>
                        <div class="action-group">
                            <button class="action-btn delete" data-action="delete" data-folder="\${s.folder}"><i class="fas fa-trash"></i> حذف</button>
                            <button class="action-btn detail" data-action="detail" data-folder="\${s.folder}"><i class="fas fa-chevron-left"></i> تفاصيل</button>
                        </div>
                    </div>
                \`;
                card.onclick = (e) => { if(!e.target.closest('.action-btn')) openServer(s); };
                card.querySelectorAll('.action-btn').forEach(btn => {
                    btn.onclick = (e) => {
                        e.stopPropagation();
                        const action = btn.dataset.action;
                        const folder = btn.dataset.folder;
                        if(action === 'detail') openServer(s);
                        else performAction(folder, action);
                    };
                });
                grid.appendChild(card);
            });
        } catch(e) { console.error(e); }
    }
    async function performAction(folder, action) {
        if(action === 'delete' && !confirm('⚠️ حذف الخادم نهائياً؟')) return;
        showToast(\`جاري \${action}...\`);
        try {
            const res = await fetch(\`/api/server/action/\${folder}/\${action}\`, { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                showToast(data.message || 'تم بنجاح', true);
                if(action !== 'delete') loadServers();
                else location.reload();
            } else showToast(data.message || 'فشل', false);
        } catch(e) { showToast('خطأ في الاتصال', false); }
    }
    function openServer(server) {
        currentServer = server;
        document.getElementById('homeView').style.display = 'none';
        document.getElementById('detailView').classList.add('active');
        const typeIcon = server.server_type === 'Node.js' ? '<i class="fab fa-node-js"></i>' : '<i class="fab fa-python"></i>';
        document.getElementById('serverTypeBadge').innerHTML = \`\${typeIcon} \${server.server_type || 'Python'} | \${escapeHtml(server.title)}\`;
        document.getElementById('ramLimit').innerHTML = (server.ram_limit || 256) + ' MB';
        document.getElementById('storageLimit').innerHTML = Math.round((server.storage_limit || 512000)/1024) + ' MB';
        document.getElementById('planDetails').innerHTML = server.plan === 'free' ? 'مجاني' : server.plan;
        if(pollingInterval) clearInterval(pollingInterval);
        loadServerStats();
        pollingInterval = setInterval(loadServerStats, 4000);
        loadFiles();
        loadStartupFiles();
        loadApiKey();
        document.querySelectorAll('.tab-nav-btn').forEach((btn, idx) => btn.classList.toggle('active', idx === 0));
        document.querySelectorAll('.tab-pane').forEach((pane, idx) => pane.classList.toggle('active', idx === 0));
    }
    async function loadServerStats() {
        if(!currentServer) return;
        try {
            const res = await fetch(\`/api/server/stats/\${currentServer.folder}\`);
            const data = await res.json();
            if(!data.success) return;
            const consoleOut = document.getElementById('consoleOut');
            consoleOut.innerHTML = (data.logs || 'لا توجد مخرجات').split('\\n').map(l => \`<div>\${escapeHtml(l)}</div>\`).join('');
            consoleOut.scrollTop = consoleOut.scrollHeight;
            const ramLimit = currentServer.ram_limit || 256;
            const mem = parseFloat(data.mem) || 0;
            document.getElementById('ramStat').innerHTML = \`\${mem} / \${ramLimit} MB\`;
            document.getElementById('ramDetailProgress').style.width = Math.min((mem/ramLimit)*100, 100) + '%';
            document.getElementById('uptimeStat').innerHTML = data.uptime || '0';
        } catch(e) {}
    }
    async function serverAction(action) {
        if(action === 'delete') { confirmDelete(); return; }
        showToast(\`جاري \${action}...\`);
        try {
            const res = await fetch(\`/api/server/action/\${currentServer.folder}/\${action}\`, { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                showToast(data.message, true);
                setTimeout(loadServerStats, 1000);
                loadServers();
            } else showToast(data.message, false);
        } catch(e) { showToast('خطأ', false); }
    }
    function confirmDelete() {
        showConfirm('⚠️ حذف الخادم نهائياً؟ لا يمكن التراجع', async () => {
            const res = await fetch(\`/api/server/action/\${currentServer.folder}/delete\`, { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                showToast('تم الحذف', true);
                if(pollingInterval) clearInterval(pollingInterval);
                goHome();
            } else showToast(data.message, false);
        });
    }
    function goHome() {
        document.getElementById('homeView').style.display = 'block';
        document.getElementById('detailView').classList.remove('active');
        if(pollingInterval) clearInterval(pollingInterval);
        currentServer = null;
        loadServers();
    }
    document.querySelectorAll('.tab-nav-btn').forEach(btn => {
        btn.onclick = () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.getElementById(\`\${tab}Tab\`).classList.add('active');
            if(tab === 'files') loadFiles();
            if(tab === 'settings') loadStartupFiles();
            if(tab === 'api') loadApiKey();
        };
    });
    async function loadFiles() {
        if(!currentServer) return;
        const tbody = document.getElementById('filesList');
        tbody.innerHTML = '<tr><td colspan="4">جاري...</td></tr>';
        try {
            const res = await fetch(\`/api/files/list/\${currentServer.folder}\`);
            const files = await res.json();
            if(files.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">لا توجد ملفات</td></tr>';
                return;
            }
            tbody.innerHTML = files.map(f => \`
                <tr>
                    <td><i class="fas \${f.is_dir ? 'fa-folder' : 'fa-file'}"></i></td>
                    <td>\${escapeHtml(f.name)}</td>
                    <td>\${f.size}</td>
                    <td>
                        \${!f.is_dir ? \`<button class="action-btn" onclick="editFile('\${escapeHtml(f.name)}')"><i class="fas fa-edit"></i></button>\` : ''}
                        <button class="action-btn" onclick="renameFile('\${escapeHtml(f.name)}')"><i class="fas fa-i-cursor"></i></button>
                        \${f.name.toLowerCase().endsWith('.zip') ? \`<button class="action-btn" onclick="unzipFile('\${escapeHtml(f.name)}')"><i class="fas fa-file-archive"></i></button>\` : ''}
                        <button class="action-btn" onclick="deleteFile('\${escapeHtml(f.name)}')" style="color:#ff5e7c;"><i class="fas fa-trash"></i></button>
                    </td>
                </tr>
            \`).join('');
        } catch(e) { tbody.innerHTML = '<tr><td colspan="4">خطأ</td></tr>'; }
    }
    function editFile(name) {
        currentEditFile = name;
        fetch(\`/api/files/content/\${currentServer.folder}/\${name}\`)
            .then(res => res.json())
            .then(data => {
                document.getElementById('editorContent').value = data.content || '';
                document.getElementById('editorModal').classList.add('active');
            });
    }
    function saveFile() {
        const content = document.getElementById('editorContent').value;
        fetch(\`/api/files/save/\${currentServer.folder}/\${currentEditFile}\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        }).then(() => {
            showToast('تم الحفظ', true);
            document.getElementById('editorModal').classList.remove('active');
            loadFiles();
        });
    }
    function closeEditorModal() { document.getElementById('editorModal').classList.remove('active'); }
    function deleteFile(name) {
        showConfirm(\`حذف \${name}؟\`, async () => {
            await fetch(\`/api/files/delete/\${currentServer.folder}\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ names: [name] })
            });
            loadFiles();
        });
    }
    function renameFile(name) {
        const newName = prompt('أدخل الاسم الجديد:', name);
        if(newName && newName !== name) {
            fetch(\`/api/files/rename/\${currentServer.folder}\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_name: name, new_name: newName })
            }).then(() => loadFiles());
        }
    }
    function uploadFiles(files) {
        if(!files.length) return;
        const fd = new FormData();
        for(let f of files) fd.append('files[]', f);
        fetch(\`/api/files/upload/\${currentServer.folder}\`, { method: 'POST', body: fd })
            .then(() => { loadFiles(); showToast('تم رفع الملفات وفك ضغطها بنجاح', true); });
    }
    function handleDrop(e) {
        e.preventDefault();
        uploadFiles(e.dataTransfer.files);
    }
    function unzipFile(name) {
        showToast('جاري فك الضغط...');
        fetch(\`/api/files/unzip/\${currentServer.folder}/\${name}\`, { method: 'POST' })
            .then(() => { loadFiles(); showToast('تم فك الضغط', true); });
    }
    function installPackages() {
        fetch(\`/api/server/install/\${currentServer.folder}\`, { method: 'POST' })
            .then(res => res.json())
            .then(data => showToast(data.message, data.success));
    }
    function showCreateFileModal() {
        document.getElementById('newFileName').value = '';
        document.getElementById('newFileContent').value = '';
        document.getElementById('createFileModal').classList.add('active');
    }
    function createNewFile() {
        const name = document.getElementById('newFileName').value.trim();
        const content = document.getElementById('newFileContent').value;
        if(!name) return;
        fetch(\`/api/files/create/\${currentServer.folder}\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: name, content })
        }).then(() => {
            document.getElementById('createFileModal').classList.remove('active');
            loadFiles();
            loadStartupFiles();
        });
    }
    function showCreateFolderModal() {
        document.getElementById('newFolderName').value = '';
        document.getElementById('createFolderModal').classList.add('active');
    }
    function createNewFolder() {
        const name = document.getElementById('newFolderName').value.trim();
        if(!name) return;
        fetch(\`/api/files/create/\${currentServer.folder}\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: name, content: '' })
        }).then(() => {
            document.getElementById('createFolderModal').classList.remove('active');
            loadFiles();
        });
    }
    async function loadStartupFiles() {
        if(!currentServer) return;
        const res = await fetch(\`/api/files/list/\${currentServer.folder}\`);
        const files = await res.json();
        const ext = currentServer.server_type === 'Node.js' ? '.js' : '.py';
        const codeFiles = files.filter(f => f.name.endsWith(ext) && !f.is_dir);
        const select = document.getElementById('startupFileSelect');
        select.innerHTML = '<option value="">-- اختر ملف التشغيل --</option>' +
            codeFiles.map(f => \`<option value="\${f.name}" \${currentServer.startup_file === f.name ? 'selected' : ''}>\${f.name}</option>\`).join('');
    }
    function setStartupFile() {
        const filename = document.getElementById('startupFileSelect').value;
        if(!filename) return;
        fetch(\`/api/server/set-startup/\${currentServer.folder}\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        }).then(() => showToast('تم تعيين ملف التشغيل', true));
    }
    async function loadApiKey() {
        try {
            const res = await fetch('/api/current_user');
            const data = await res.json();
            if(data.api_key) document.getElementById('apiKeyDisplay').innerHTML = data.api_key;
            else document.getElementById('apiKeyDisplay').innerHTML = 'لا يوجد مفتاح - اضغط إنشاء';
        } catch(e) {}
    }
    async function generateApiKey() {
        try {
            const res = await fetch('/api/create_api_key', { method: 'POST' });
            const data = await res.json();
            if(data.success) {
                document.getElementById('apiKeyDisplay').innerHTML = data.api_key;
                showToast('تم إنشاء مفتاح API', true);
            } else showToast('فشل الإنشاء', false);
        } catch(e) { showToast('خطأ', false); }
    }
    function showCreateModal() {
        document.getElementById('serverName').value = '';
        selectType('Python');
        document.getElementById('createServerModal').classList.add('active');
    }
    function closeCreateModal() { document.getElementById('createServerModal').classList.remove('active'); }
    async function createServer() {
        const name = document.getElementById('serverName').value.trim();
        if(!name) { showToast('الرجاء إدخال اسم السيرفر', false); return; }
        closeCreateModal();
        showToast('جاري إنشاء السيرفر...');
        try {
            const res = await fetch('/api/server/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, server_type: selectedType })
            });
            const data = await res.json();
            if(data.success) {
                showToast(data.message, true);
                loadServers();
            } else showToast(data.message, false);
        } catch(e) { showToast('خطأ في الاتصال', false); }
    }
    function escapeHtml(str) {
        return String(str).replace(/[&<>]/g, m => m === '&' ? '&amp;' : m === '<' ? '&lt;' : '&gt;');
    }
    document.getElementById('openCreateModalBtn').onclick = showCreateModal;
    checkAuth();
</script>
</body>
</html>`;

const ADMIN_HTML_CONTENT = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>لوحة المسؤول | 𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@300;400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', 'Tajawal', sans-serif; background: #0a0c10; color: #eef2ff; overflow-x: hidden; }
        .bg-cyber { position: fixed; inset: 0; background: radial-gradient(ellipse at 20% 40%, rgba(45, 122, 255, 0.12), transparent 70%), radial-gradient(ellipse at 80% 60%, rgba(0, 229, 255, 0.08), transparent 60%); z-index: -2; }
        .bg-grid { position: fixed; inset: 0; background-image: linear-gradient(rgba(45, 122, 255, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(45, 122, 255, 0.04) 1px, transparent 1px); background-size: 50px 50px; z-index: -1; }
        .navbar { background: rgba(8, 12, 28, 0.85); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(45, 122, 255, 0.3); padding: 12px 28px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 38px; height: 38px; background: linear-gradient(145deg, #0f172a, #0a0f1c); border: 1px solid #00e5ff; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 18px; color: #00e5ff; box-shadow: 0 0 12px rgba(0, 229, 255, 0.3); }
        .logo-text { font-size: 16px; font-weight: 900; letter-spacing: 2px; background: linear-gradient(135deg, #2d7aff, #00e5ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .user-section { display: flex; align-items: center; gap: 18px; }
        .admin-badge { background: rgba(45, 122, 255, 0.2); padding: 4px 12px; border-radius: 30px; font-size: 0.7rem; color: #2d7aff; }
        .logout-btn { background: rgba(255, 70, 85, 0.15); border: 1px solid rgba(255, 70, 85, 0.4); color: #ff5e7c; padding: 6px 16px; border-radius: 40px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
        .logout-btn:hover { background: rgba(255, 70, 85, 0.25); transform: translateY(-1px); }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 28px; }
        .stat-card { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(45, 122, 255, 0.2); border-radius: 24px; padding: 20px; transition: all 0.3s; }
        .stat-card:hover { border-color: rgba(45, 122, 255, 0.5); transform: translateY(-3px); }
        .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .stat-title { font-size: 0.7rem; text-transform: uppercase; color: #9ca3cf; }
        .stat-icon { width: 42px; height: 42px; background: rgba(45, 122, 255, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #2d7aff; }
        .stat-value { font-size: 2rem; font-weight: 700; color: white; }
        .stat-change { font-size: 0.7rem; margin-top: 8px; color: #00ff88; }
        .tabs-container { background: rgba(15, 23, 42, 0.5); border-radius: 20px; padding: 6px; display: flex; gap: 8px; margin-bottom: 28px; flex-wrap: wrap; }
        .tab-btn { background: transparent; border: none; padding: 12px 28px; border-radius: 16px; font-family: 'Tajawal', sans-serif; font-weight: 600; font-size: 0.85rem; color: #9ca3cf; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; gap: 8px; }
        .tab-btn i { font-size: 1rem; }
        .tab-btn.active { background: rgba(45, 122, 255, 0.2); color: #2d7aff; }
        .tab-btn:not(.active):hover { background: rgba(255, 255, 255, 0.05); color: #eef2ff; }
        .tab-content { display: none; animation: fadeSlide 0.3s ease; }
        .tab-content.active { display: block; }
        @keyframes fadeSlide { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .card { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(45, 122, 255, 0.15); border-radius: 28px; padding: 24px; margin-bottom: 24px; }
        .card-title { font-size: 1rem; font-weight: 700; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; color: #2d7aff; }
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; margin-bottom: 8px; font-size: 0.75rem; color: #9ca3cf; }
        .form-group input, .form-group select { width: 100%; padding: 12px 16px; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(45, 122, 255, 0.3); border-radius: 50px; color: white; font-family: 'Tajawal', sans-serif; outline: none; transition: 0.2s; }
        .form-group input:focus { border-color: #2d7aff; background: rgba(45, 122, 255, 0.05); }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .btn-primary { background: linear-gradient(135deg, #2d7aff, #1a5cd8); border: none; border-radius: 50px; padding: 12px 24px; color: white; font-weight: 700; font-size: 0.85rem; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 4px 14px rgba(45, 122, 255, 0.3); }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(45, 122, 255, 0.4); }
        .data-table { width: 100%; border-collapse: collapse; }
        .data-table th { text-align: right; padding: 14px 12px; color: #9ca3cf; font-weight: 500; font-size: 0.7rem; border-bottom: 1px solid rgba(45, 122, 255, 0.15); }
        .data-table td { padding: 14px 12px; border-bottom: 1px solid rgba(45, 122, 255, 0.08); font-size: 0.8rem; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 30px; font-size: 0.7rem; font-weight: 600; }
        .badge-admin { background: rgba(45, 122, 255, 0.2); color: #2d7aff; }
        .badge-user { background: rgba(0, 229, 255, 0.15); color: #00e5ff; }
        .action-btn { background: none; border: none; color: #ff5e7c; cursor: pointer; font-size: 1rem; margin: 0 4px; }
        .action-btn.edit { color: #2d7aff; }
        .search-box { position: relative; margin-bottom: 20px; }
        .search-box i { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); color: #9ca3cf; }
        .search-box input { width: 100%; padding: 12px 45px 12px 16px; background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(45, 122, 255, 0.3); border-radius: 50px; color: white; }
        .chart-container { background: rgba(15, 23, 42, 0.5); border-radius: 24px; padding: 20px; margin-top: 20px; }
        canvas { max-height: 300px; }
        .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #1e293b; border: 1px solid #2d7aff; border-radius: 60px; padding: 10px 24px; font-size: 0.75rem; z-index: 1100; display: none; }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 12px; } .form-row { grid-template-columns: 1fr; } .tabs-container { flex-direction: column; } .tab-btn { justify-content: center; } }
    </style>
</head>
<body>
<div class="bg-cyber"></div>
<div class="bg-grid"></div>
<div class="navbar">
    <div class="logo">
        <div class="logo-icon"><i class="fas fa-crown"></i></div>
        <span class="logo-text">𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 | ADMIN</span>
    </div>
    <div class="user-section">
        <span class="admin-badge"><i class="fas fa-shield-alt"></i> مسؤول</span>
        <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> خروج</button>
    </div>
</div>
<div class="container">
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">إجمالي المستخدمين</span><div class="stat-icon"><i class="fas fa-users"></i></div></div>
            <div class="stat-value" id="totalUsers">0</div>
            <div class="stat-change"><i class="fas fa-chart-line"></i> نشط</div>
        </div>
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">إجمالي السيرفرات</span><div class="stat-icon"><i class="fas fa-server"></i></div></div>
            <div class="stat-value" id="totalServers">0</div>
            <div class="stat-change"><i class="fas fa-chart-line"></i> قيد التشغيل</div>
        </div>
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">السيرفرات النشطة</span><div class="stat-icon"><i class="fas fa-play-circle"></i></div></div>
            <div class="stat-value" id="activeServers">0</div>
            <div class="stat-change"><i class="fas fa-check-circle"></i> نشطة</div>
        </div>
        <div class="stat-card">
            <div class="stat-header"><span class="stat-title">المساحة المستخدمة</span><div class="stat-icon"><i class="fas fa-hdd"></i></div></div>
            <div class="stat-value" id="totalDisk">0 GB</div>
            <div class="stat-change"><i class="fas fa-chart-line"></i> إجمالي</div>
        </div>
    </div>
    <div class="tabs-container">
        <button class="tab-btn active" data-tab="dashboard"><i class="fas fa-chart-pie"></i> لوحة التحكم</button>
        <button class="tab-btn" data-tab="users"><i class="fas fa-users-gear"></i> إدارة المستخدمين</button>
        <button class="tab-btn" data-tab="servers"><i class="fas fa-globe"></i> السيرفرات</button>
        <button class="tab-btn" data-tab="settings"><i class="fas fa-sliders-h"></i> الإعدادات</button>
        <button class="tab-btn" data-tab="analytics"><i class="fas fa-chart-line"></i> التحليلات</button>
        <button class="tab-btn" data-tab="plans"><i class="fas fa-gem"></i> الخطط</button>
    </div>
    <div id="dashboardTab" class="tab-content active">
        <div class="card">
            <div class="card-title"><i class="fas fa-chart-simple"></i> نظرة عامة</div>
            <p style="color:#9ca3cf; margin-bottom: 16px;">مرحباً في لوحة التحكم المركزية. يمكنك مراقبة وإدارة جميع جوانب المنصة.</p>
            <div class="chart-container"><canvas id="userGrowthChart"></canvas></div>
        </div>
        <div class="card">
            <div class="card-title"><i class="fas fa-clock"></i> آخر النشاطات</div>
            <p style="color:#9ca3cf;">آخر تحديث: <span id="lastUpdate" style="color:#2d7aff;">الآن</span></p>
        </div>
    </div>
    <div id="usersTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-user-plus"></i> إضافة مستخدم جديد</div>
            <div id="userAlert"></div>
            <div class="form-row">
                <div class="form-group"><label>اسم المستخدم (البريد الإلكتروني)</label><input type="text" id="newUsername" placeholder="admin@ziadhost.com"></div>
                <div class="form-group"><label>كلمة المرور</label><input type="password" id="newPassword" placeholder="أدخل كلمة المرور"></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label>عدد السيرفرات المسموح بها</label><input type="number" id="maxServers" placeholder="2" value="2" min="1" max="100"></div>
                <div class="form-group"><label>عدد الأيام (الصلاحية)</label><input type="number" id="expiryDays" placeholder="365" value="365" min="1" max="3650"></div>
            </div>
            <button class="btn-primary" onclick="createNewUser()"><i class="fas fa-sparkles"></i> إنشاء الحساب</button>
        </div>
        <div class="card">
            <div class="card-title"><i class="fas fa-list"></i> قائمة المستخدمين</div>
            <div class="search-box"><i class="fas fa-search"></i><input type="text" id="userSearch" placeholder="ابحث عن مستخدم..."></div>
            <table class="data-table">
                <thead><tr><th>اسم المستخدم</th><th>النوع</th><th>الخطة</th><th>السيرفرات</th><th>الصلاحية</th><th>تاريخ الإنشاء</th><th>الإجراءات</th></tr></thead>
                <tbody id="usersList"></tbody>
            </table>
        </div>
    </div>
    <div id="serversTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-server"></i> جميع السيرفرات</div>
            <div class="search-box"><i class="fas fa-search"></i><input type="text" id="serverSearch" placeholder="ابحث عن سيرفر..."></div>
            <table class="data-table">
                <thead><tr><th>اسم السيرفر</th><th>المالك</th><th>النوع</th><th>الحالة</th><th>تاريخ الإنشاء</th><th>الإجراءات</th></tr></thead>
                <tbody id="serversList"><tr><td colspan="6" style="text-align:center;">جاري التحميل...</td></tr></tbody>
            </table>
        </div>
    </div>
    <div id="settingsTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-cog"></i> إعدادات النظام</div>
            <div class="form-row">
                <div class="form-group"><label>اسم المنصة</label><input type="text" id="siteName" value="𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓"></div>
                <div class="form-group"><label>الحد الأقصى للسيرفرات لكل مستخدم (افتراضي)</label><input type="number" id="globalMaxServers" value="2" min="1" max="100"></div>
            </div>
            <button class="btn-primary" onclick="saveSettings()"><i class="fas fa-save"></i> حفظ الإعدادات</button>
        </div>
    </div>
    <div id="analyticsTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-chart-line"></i> إحصائيات الاستخدام</div>
            <div class="chart-container"><canvas id="serversGrowthChart"></canvas></div>
        </div>
    </div>
    <div id="plansTab" class="tab-content">
        <div class="card">
            <div class="card-title"><i class="fas fa-gem"></i> خطط الاستضافة</div>
            <div class="form-row" id="plansList"></div>
            <div class="form-row" style="margin-top: 20px;">
                <div class="form-group"><label>معرف الخطة</label><input type="text" id="newPlanId" placeholder="gold"></div>
                <div class="form-group"><label>اسم الخطة</label><input type="text" id="newPlanName" placeholder="خطة ذهبية"></div>
            </div>
            <button class="btn-primary" onclick="addPlan()"><i class="fas fa-plus"></i> إضافة خطة جديدة</button>
        </div>
    </div>
</div>
<div id="toast" class="toast"></div>
<script>
    let usersChart = null;
    let serversChart = null;
    const showToast = (msg, type = 'info') => {
        const t = document.getElementById('toast');
        t.innerHTML = \`<i class="fas \${type === 'success' ? 'fa-check-circle' : 'fa-info-circle'}"></i> \${msg}\`;
        t.style.display = 'block';
        setTimeout(() => t.style.display = 'none', 3000);
    };
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab + 'Tab').classList.add('active');
            if (tab === 'users') loadUsers();
            if (tab === 'servers') loadAllServers();
            if (tab === 'analytics') loadAnalytics();
            if (tab === 'plans') loadPlans();
        });
    });
    async function loadDashboard() {
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            if (data.success) {
                document.getElementById('totalUsers').innerText = data.users.length;
                let totalServers = 0, activeServers = 0, totalDisk = 0;
                for (const user of data.users) {
                    const userServers = await fetch(\`/api/servers?user=\${encodeURIComponent(user.username)}\`).then(r => r.json());
                    if (userServers.servers) {
                        totalServers += userServers.servers.length;
                        activeServers += userServers.servers.filter(s => s.status === 'Running').length;
                        totalDisk += userServers.stats?.disk_total || 0;
                    }
                }
                document.getElementById('totalServers').innerText = totalServers;
                document.getElementById('activeServers').innerText = activeServers;
                document.getElementById('totalDisk').innerText = (totalDisk / 1024).toFixed(1) + ' GB';
                document.getElementById('lastUpdate').innerText = new Date().toLocaleTimeString('ar-SA');
            }
        } catch (e) { console.log(e); }
    }
    async function loadUsers() {
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            const list = document.getElementById('usersList');
            list.innerHTML = data.users.map(u => \`
                <tr>
                    <td><strong>\${escapeHtml(u.username)}</strong></td>
                    <td><span class="badge \${u.is_admin ? 'badge-admin' : 'badge-user'}">\${u.is_admin ? '👑 مسؤول' : '👤 مستخدم'}</span></td>
                    <td>\${u.plan || 'free'}</td>
                    <td>\${u.max_servers}</td>
                    <td>\${u.expiry_days} يوم</td>
                    <td style="font-size:11px;">\${(u.created_at || '').substring(0,10)}</td>
                    <td>
                        \${!u.is_admin ? \`<button class="action-btn delete" onclick="deleteUser('\${escapeHtml(u.username)}')"><i class="fas fa-trash"></i></button>\` : '<span style="color:#9ca3cf;">محمي</span>'}
                    </td>
                </tr>
            \`).join('');
            document.getElementById('userSearch').oninput = function() {
                const q = this.value.toLowerCase();
                list.querySelectorAll('tr').forEach(r => {
                    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
            };
        } catch(e) { showToast('خطأ في تحميل المستخدمين', 'error'); }
    }
    async function loadAllServers() {
        const tbody = document.getElementById('serversList');
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">جاري التحميل...</td></tr>';
        try {
            const res = await fetch('/api/admin/users');
            const data = await res.json();
            let allServers = [];
            for (const user of data.users) {
                const serversRes = await fetch(\`/api/servers?user=\${encodeURIComponent(user.username)}\`);
                const serversData = await serversRes.json();
                if (serversData.servers) {
                    serversData.servers.forEach(s => {
                        allServers.push({ ...s, owner: user.username });
                    });
                }
            }
            if (allServers.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">لا توجد سيرفرات</td></tr>';
                return;
            }
            tbody.innerHTML = allServers.map(s => \`
                <tr>
                    <td>\${escapeHtml(s.title || s.name)}</td>
                    <td>\${escapeHtml(s.owner)}</td>
                    <td>\${s.server_type || 'Python'}</td>
                    <td><span class="badge \${s.status === 'Running' ? 'badge-admin' : ''}" style="\${s.status !== 'Running' ? 'background:#555;' : ''}">\${s.status === 'Running' ? '🟢 نشط' : '⚫ متوقف'}</span></td>
                    <td style="font-size:11px;">\${(s.created_at || '').substring(0,10)}</td>
                    <td><button class="action-btn delete" onclick="deleteServer('\${s.folder}')"><i class="fas fa-trash"></i></button></td>
                </tr>
            \`).join('');
            document.getElementById('serverSearch').oninput = function() {
                const q = this.value.toLowerCase();
                tbody.querySelectorAll('tr').forEach(r => {
                    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
            };
        } catch(e) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">خطأ في التحميل</td></tr>'; }
    }
    async function loadPlans() {
        try {
            const res = await fetch('/api/plans');
            const data = await res.json();
            if (data.success) {
                const container = document.getElementById('plansList');
                container.innerHTML = '';
                for (const [id, plan] of Object.entries(data.plans)) {
                    const planDiv = document.createElement('div');
                    planDiv.className = 'stat-card';
                    planDiv.style.cssText = 'background:rgba(15,23,42,0.5); border-radius:20px; padding:16px; flex:1; min-width:200px;';
                    planDiv.innerHTML = \`
                        <div style="font-weight:700; margin-bottom:8px; color:#2d7aff;">\${plan.name} (\${id})</div>
                        <div>💰 \${plan.price === 0 ? 'مجاني' : plan.price + '$'}</div>
                        <div>💾 \${(plan.storage / 1024).toFixed(0)} GB</div>
                        <div>🧠 \${plan.ram} MB</div>
                        <div>🖥 \${plan.cpu} نواة</div>
                        <div>📦 حد أقصى: \${plan.max_servers} سيرفر</div>
                    \`;
                    container.appendChild(planDiv);
                }
            }
        } catch(e) { console.error(e); }
    }
    async function createNewUser() {
        const username = document.getElementById('newUsername').value.trim();
        const password = document.getElementById('newPassword').value.trim();
        const max_servers = parseInt(document.getElementById('maxServers').value) || 2;
        const expiry_days = parseInt(document.getElementById('expiryDays').value) || 365;
        if (!username || !password) { showToast('⚠️ الرجاء إدخال جميع البيانات', 'error'); return; }
        try {
            const res = await fetch('/api/admin/create-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: username, password, max_servers, expiry_days })
            });
            const data = await res.json();
            if (data.success) {
                showToast('✅ تم إنشاء المستخدم بنجاح', 'success');
                document.getElementById('newUsername').value = '';
                document.getElementById('newPassword').value = '';
                loadUsers();
                loadDashboard();
            } else { showToast('❌ ' + (data.message || 'فشل الإنشاء'), 'error'); }
        } catch(e) { showToast('❌ خطأ في الاتصال', 'error'); }
    }
    async function deleteUser(username) {
        if (!confirm(\`حذف المستخدم "\${username}" نهائياً؟\`)) return;
        try {
            const res = await fetch('/api/admin/delete-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: username })
            });
            const data = await res.json();
            if (data.success) {
                showToast('🗑️ تم حذف المستخدم', 'success');
                loadUsers();
                loadDashboard();
            } else { showToast('❌ ' + (data.message || 'فشل الحذف'), 'error'); }
        } catch(e) { showToast('❌ خطأ', 'error'); }
    }
    async function deleteServer(folder) {
        if (!confirm(\`حذف السيرفر نهائياً؟\`)) return;
        try {
            const res = await fetch(\`/api/server/action/\${folder}/delete\`, { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast('🗑️ تم حذف السيرفر', 'success');
                loadAllServers();
                loadDashboard();
            } else { showToast('❌ فشل الحذف', 'error'); }
        } catch(e) { showToast('❌ خطأ', 'error'); }
    }
    function saveSettings() { showToast('✅ تم حفظ الإعدادات بنجاح', 'success'); }
    async function addPlan() {
        const plan_id = document.getElementById('newPlanId').value.trim().toLowerCase();
        const name = document.getElementById('newPlanName').value.trim();
        if (!plan_id || !name) { showToast('⚠️ الرجاء إدخال المعرف واسم الخطة', 'error'); return; }
        try {
            const res = await fetch('/api/admin/add-plan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plan_id, name, price: 0, storage: 512000, ram: 256, cpu: 0.5, max_servers: 2 })
            });
            const data = await res.json();
            if (data.success) {
                showToast('✅ تم إضافة الخطة بنجاح', 'success');
                loadPlans();
                document.getElementById('newPlanId').value = '';
                document.getElementById('newPlanName').value = '';
            } else { showToast('❌ ' + (data.message || 'فشل الإضافة'), 'error'); }
        } catch(e) { showToast('❌ خطأ', 'error'); }
    }
    async function loadAnalytics() {
        try {
            await fetch('/api/system/metrics').then(r => r.json());
        } catch(e) {}
        if (usersChart) usersChart.destroy();
        if (serversChart) serversChart.destroy();
        const ctx1 = document.getElementById('userGrowthChart').getContext('2d');
        const ctx2 = document.getElementById('serversGrowthChart').getContext('2d');
        usersChart = new Chart(ctx1, { type: 'line', data: { labels: ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو'], datasets: [{ label: 'المستخدمين', data: [2, 4, 7, 10, 15, 20], borderColor: '#2d7aff', backgroundColor: 'rgba(45,122,255,0.1)', fill: true }] }, options: { responsive: true, maintainAspectRatio: true } });
        serversChart = new Chart(ctx2, { type: 'bar', data: { labels: ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو'], datasets: [{ label: 'السيرفرات', data: [1, 3, 5, 8, 12, 18], backgroundColor: '#2d7aff' }] }, options: { responsive: true, maintainAspectRatio: true } });
    }
    function logout() { fetch('/api/logout', { method: 'POST' }).then(() => window.location.href = '/login'); }
    function escapeHtml(s) { return String(s).replace(/[&<>]/g, m => m === '&' ? '&amp;' : m === '<' ? '&lt;' : '&gt;'); }
    loadDashboard();
    loadUsers();
    loadAnalytics();
    setInterval(() => { loadDashboard(); loadAnalytics(); }, 30000);
</script>
</body>
</html>`;

fs.writeFileSync(path.join(BASE_DIR, "landing.html"), LANDING_HTML_CONTENT, "utf-8");
fs.writeFileSync(path.join(BASE_DIR, "login.html"), LOGIN_HTML_CONTENT, "utf-8");
fs.writeFileSync(path.join(BASE_DIR, "index.html"), INDEX_HTML_CONTENT, "utf-8");
fs.writeFileSync(path.join(BASE_DIR, "admin_panel.html"), ADMIN_HTML_CONTENT, "utf-8");

const DB_FILE = path.join(BASE_DIR, "db.json");

function loadDb() {
    if (fs.existsSync(DB_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
            if (!data.plans) data.plans = {};
            if (!data.server_types) data.server_types = ["Python", "Node.js"];
            if (!data.pending_users) data.pending_users = [];
            return data;
        } catch (e) {}
    }
    const adminEmail = process.env.ADMIN_EMAIL || "admin@ziadhost.com";
    const adminPassword = process.env.ADMIN_PASSWORD || "admin123";
    const adminHash = crypto.createHash("sha256").update(adminPassword).digest("hex");

    const defaultDb = {
        users: {
            [adminEmail]: {
                password: adminHash,
                is_admin: true,
                created_at: new Date().toISOString(),
                max_servers: 999999,
                expiry_days: 3650,
                last_login: null,
                telegram_id: ADMIN_TELEGRAM_IDS[0],
                api_key: null,
                storage_limit: 10240,
                plan: "admin"
            }
        },
        servers: {},
        logs: [],
        pending_users: [],
        plans: {
            free: { name: "🎁 مجاني", storage: 512000, ram: 256, cpu: 0.5, max_servers: 2, price: 0 },
            "4gb": { name: "💎 4 جيجا", storage: 4096000, ram: 1024, cpu: 1, max_servers: 5, price: 5 },
            "10gb": { name: "💎 10 جيجا", storage: 10240000, ram: 2048, cpu: 2, max_servers: 10, price: 10 }
        },
        server_types: ["Python", "Node.js"]
    };
    saveDb(defaultDb);
    return defaultDb;
}

function saveDb(dbData) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(dbData, null, 4), "utf-8");
        return true;
    } catch (e) {
        console.error("❌ خطأ في حفظ DB:", e);
        return false;
    }
}

let db = loadDb();

const PORT_RANGE_START = 8100;
const PORT_RANGE_END = 9100;

function getAssignedPort() {
    let used = new Set();
    for (const srv of Object.values(db.servers || {})) {
        if (srv.port) used.add(srv.port);
    }
    for (let port = PORT_RANGE_START; port < PORT_RANGE_END; port++) {
        if (!used.has(port)) return port;
    }
    return PORT_RANGE_START;
}

function getUserServersDir(email) {
    let safeEmail = email.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    let p = path.join(USERS_DIR, safeEmail, "SERVERS");
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
    return p;
}

function isAdmin(email) {
    let u = db.users[email];
    return u ? !!u.is_admin : false;
}

function generateApiKey() {
    return crypto.randomBytes(24).toString("hex");
}

function getUserByApiKey(apiKey) {
    for (const [email, udata] of Object.entries(db.users || {})) {
        if (udata.api_key === apiKey) return [email, udata];
    }
    return [null, null];
}

function uptimeStr(startTime) {
    if (!startTime) return "0 ثانية";
    let diff = (Date.now() - startTime) / 1000;
    let days = Math.floor(diff / 86400);
    let hours = Math.floor((diff % 86400) / 3600);
    let mins = Math.floor((diff % 3600) / 60);
    let parts = [];
    if (days > 0) parts.push(`${days} يوم`);
    if (hours > 0) parts.push(`${hours} ساعة`);
    if (mins > 0) parts.push(`${mins} دقيقة`);
    return parts.length > 0 ? parts.join(" و ") : "أقل من دقيقة";
}

function checkAdminAccess(req) {
    if (req.session && req.session.email && isAdmin(req.session.email)) return true;
    let apiKey = null;
    if (req.body && req.body.api_key) apiKey = req.body.api_key;
    if (!apiKey && req.query && req.query.api_key) apiKey = req.query.api_key;
    if (apiKey) {
        let [email] = getUserByApiKey(apiKey);
        if (email && isAdmin(email)) return true;
    }
    return false;
}

function detectMainFile(srvPath) {
    for (const candidate of ["main.py", "bot.py", "app.py", "index.py", "run.py", "start.py"]) {
        if (fs.existsSync(path.join(srvPath, candidate))) return candidate;
    }
    try {
        let files = fs.readdirSync(srvPath);
        let pyFiles = files.filter(f => f.endsWith(".py"));
        return pyFiles.length > 0 ? pyFiles[0] : "";
    } catch (e) {
        return "";
    }
}

function autoInstallDeps(srvPath, logStream) {
    try {
        let req = path.join(srvPath, "requirements.txt");
        if (fs.existsSync(req)) {
            logStream.write("\n📦 تثبيت requirements.txt...\n");
            let proc = spawn("pip", ["install", "-r", "requirements.txt"], { cwd: srvPath, shell: true });
            proc.stdout.on("data", d => logStream.write(d));
            proc.stderr.on("data", d => logStream.write(d));
            proc.on("close", () => logStream.write("✅ تم تثبيت المكتبات بنجاح\n"));
        }
    } catch (e) {
        logStream.write(`\n⚠️ تثبيت تلقائي: ${e}\n`);
    }
}

function detectNodeMainFile(srvPath) {
    for (const candidate of ["index.js", "server.js", "app.js", "main.js", "bot.js", "start.js"]) {
        if (fs.existsSync(path.join(srvPath, candidate))) return candidate;
    }
    try {
        let files = fs.readdirSync(srvPath);
        let jsFiles = files.filter(f => f.endsWith(".js"));
        return jsFiles.length > 0 ? jsFiles[0] : "";
    } catch (e) {
        return "";
    }
}

function autoInstallNodeDeps(srvPath, logStream) {
    try {
        let packageJson = path.join(srvPath, "package.json");
        if (fs.existsSync(packageJson)) {
            logStream.write("\n📦 تثبيت حزم Node.js...\n");
            let proc = spawn("npm", ["install"], { cwd: srvPath, shell: true });
            proc.stdout.on("data", d => logStream.write(d));
            proc.stderr.on("data", d => logStream.write(d));
            proc.on("close", () => logStream.write("✅ تم تثبيت حزم Node.js بنجاح\n"));
        }
    } catch (e) {
        logStream.write(`\n⚠️ تثبيت حزم Node.js فشل: ${e}\n`);
    }
}

function startServerProcess(folder) {
    let srv = db.servers[folder];
    if (!srv) return [false, "السيرفر غير موجود"];
    if (srv.server_type === "Node.js") {
        return startNodeServerProcess(folder);
    } else {
        return startPythonServerProcess(folder);
    }
}

function startPythonServerProcess(folder) {
    let srv = db.servers[folder];
    if (!srv) return [false, "السيرفر غير موجود"];

    let mainFile = srv.startup_file;
    if (!mainFile || !fs.existsSync(path.join(srv.path, mainFile))) {
        let detected = detectMainFile(srv.path);
        if (detected) {
            srv.startup_file = detected;
            mainFile = detected;
            saveDb(db);
        } else {
            return [false, "لا يوجد ملف تشغيل Python (.py)"];
        }
    }

    let filePath = path.join(srv.path, mainFile);
    if (!fs.existsSync(filePath)) return [false, `الملف ${mainFile} غير موجود`];

    let port = srv.port || getAssignedPort();
    srv.port = port;
    saveDb(db);

    let logPath = path.join(srv.path, "out.log");
    let errorPath = path.join(srv.path, "errors.log");
    let logStream = fs.createWriteStream(logPath, { flags: 'a', encoding: 'utf-8' });
    logStream.write(`\n${'='.repeat(50)}\n🚀 بدء التشغيل (Python) - ${new Date()}\n📁 ${mainFile}\n🔌 المنفذ: ${port}\n${'='.repeat(50)}\n\n`);

    try {
        let env = Object.assign({}, process.env, { PORT: String(port), SERVER_PORT: String(port) });
        let proc = spawn("python", ["-u", mainFile], { cwd: srv.path, env: env, detached: false });
        
        proc.stdout.on("data", d => logStream.write(d));
        proc.stderr.on("data", d => {
            logStream.write(d);
            fs.appendFileSync(errorPath, d);
        });

        srv.status = "Running";
        srv.pid = proc.pid;
        srv.start_time = Date.now();
        activeProcesses[folder] = proc;
        saveDb(db);
        return [true, "✅ تم التشغيل بنجاح"];
    } catch (e) {
        logStream.write(`\n❌ خطأ: ${e.message}\n`);
        return [false, e.message];
    }
}

function startNodeServerProcess(folder) {
    let srv = db.servers[folder];
    if (!srv) return [false, "السيرفر غير موجود"];

    let mainFile = srv.startup_file;
    if (!mainFile || !fs.existsSync(path.join(srv.path, mainFile))) {
        let detected = detectNodeMainFile(srv.path);
        if (detected) {
            srv.startup_file = detected;
            mainFile = detected;
            saveDb(db);
        } else {
            return [false, "لا يوجد ملف تشغيل JavaScript (.js)"];
        }
    }

    let filePath = path.join(srv.path, mainFile);
    if (!fs.existsSync(filePath)) return [false, `الملف ${mainFile} غير موجود`];

    let port = srv.port || getAssignedPort();
    srv.port = port;
    saveDb(db);

    let logPath = path.join(srv.path, "out.log");
    let errorPath = path.join(srv.path, "errors.log");
    let logStream = fs.createWriteStream(logPath, { flags: 'a', encoding: 'utf-8' });
    logStream.write(`\n${'='.repeat(50)}\n🚀 بدء التشغيل (Node.js) - ${new Date()}\n📁 ${mainFile}\n🔌 المنفذ: ${port}\n${'='.repeat(50)}\n\n`);

    try {
        let env = Object.assign({}, process.env, { PORT: String(port), SERVER_PORT: String(port) });
        let proc = spawn("node", [mainFile], { cwd: srv.path, env: env, detached: false });

        proc.stdout.on("data", d => logStream.write(d));
        proc.stderr.on("data", d => {
            logStream.write(d);
            fs.appendFileSync(errorPath, d);
        });

        srv.status = "Running";
        srv.pid = proc.pid;
        srv.start_time = Date.now();
        activeProcesses[folder] = proc;
        saveDb(db);
        return [true, "✅ تم التشغيل بنجاح"];
    } catch (e) {
        logStream.write(`\n❌ خطأ: ${e.message}\n`);
        return [false, e.message];
    }
}

function stopServerProcess(folder) {
    let srv = db.servers[folder];
    if (!srv) return;
    if (activeProcesses[folder]) {
        try {
            activeProcesses[folder].kill();
        } catch (e) {}
        delete activeProcesses[folder];
    } else if (srv.pid) {
        try {
            process.kill(srv.pid, 'SIGTERM');
        } catch (e) {}
    }
    srv.status = "Stopped";
    srv.pid = null;
    saveDb(db);
}

function restartServer(folder) {
    stopServerProcess(folder);
    setTimeout(() => {
        startServerProcess(folder);
    }, 2000);
}

// مراقب العمليات
setInterval(() => {
    try {
        for (const [folder, srv] of Object.entries(db.servers || {})) {
            if (srv.status === "Running" && srv.pid) {
                try {
                    process.kill(srv.pid, 0); // Check if process exists
                } catch (e) {
                    restartServer(folder);
                }
            }
        }
    } catch (e) {}
}, 15000);

const app = express();
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(session({
    secret: "ZIAD_HOST_GOLD_2026_SUPER_SECRET_KEY",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));
app.use(express.static(BASE_DIR));

app.get('/', (req, res) => {
    if (req.session && req.session.email) {
        if (isAdmin(req.session.email)) return res.redirect('/admin');
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(BASE_DIR, "landing.html"));
});

app.get('/login', (req, res) => {
    if (req.session && req.session.email) return res.redirect('/');
    res.sendFile(path.join(BASE_DIR, "login.html"));
});

app.get('/dashboard', (req, res) => {
    if (!req.session || !req.session.email) return res.redirect('/login');
    res.sendFile(path.join(BASE_DIR, "index.html"));
});

app.get('/admin', (req, res) => {
    if (!req.session || !req.session.email || !isAdmin(req.session.email)) return res.redirect('/login');
    res.sendFile(path.join(BASE_DIR, "admin_panel.html"));
});

app.post('/api/register', (req, res) => {
    const { email, password } = req.body || {};
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanPass = (password || "").trim();

    if (!cleanEmail || !cleanPass) return res.json({ success: false, message: "جميع الحقول مطلوبة" });
    if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) return res.json({ success: false, message: "البريد الإلكتروني غير صالح" });
    if (cleanPass.length < 4) return res.json({ success: false, message: "كلمة المرور 4 أحرف على الأقل" });
    if (db.users[cleanEmail]) return res.json({ success: false, message: "البريد الإلكتروني موجود بالفعل" });

    const passwordHash = crypto.createHash("sha256").update(cleanPass).digest("hex");
    db.users[cleanEmail] = {
        password: passwordHash,
        is_admin: false,
        created_at: new Date().toISOString(),
        max_servers: db.plans.free.max_servers,
        expiry_days: 365,
        last_login: null,
        telegram_id: null,
        api_key: null,
        storage_limit: db.plans.free.storage,
        plan: "free"
    };
    saveDb(db);

    const safeEmail = cleanEmail.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    const userDir = path.join(USERS_DIR, safeEmail);
    fs.mkdirSync(path.join(userDir, "SERVERS"), { recursive: true });

    notifyAdmin(`🔔 *مستخدم جديد!*\n📧 ${cleanEmail}`);
    res.json({ success: true, message: "✅ تم إنشاء حسابك بنجاح!" });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body || {};
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanPass = (password || "").trim();
    const passwordHash = crypto.createHash("sha256").update(cleanPass).digest("hex");

    let user = db.users[cleanEmail];
    if (user && user.password === passwordHash) {
        req.session.email = cleanEmail;
        user.last_login = new Date().toISOString();
        saveDb(db);
        let isAdm = !!user.is_admin;
        return res.json({ success: true, redirect: isAdm ? "/admin" : "/dashboard", is_admin: isAdm });
    }
    res.json({ success: false, message: "بيانات غير صحيحة" });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/api/current_user', (req, res) => {
    if (req.session && req.session.email) {
        let u = db.users[req.session.email];
        if (u) {
            return res.json({
                success: true,
                email: req.session.email,
                username: req.session.email,
                is_admin: !!u.is_admin,
                plan: u.plan || "free",
                api_key: u.api_key
            });
        }
    }
    res.json({ success: false });
});

app.post('/api/create_api_key', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false, message: "غير مصرح" });
    let email = req.session.email;
    let newKey = generateApiKey();
    db.users[email].api_key = newKey;
    saveDb(db);
    res.json({ success: true, api_key: newKey });
});

app.get('/api/plans', (req, res) => {
    res.json({ success: true, plans: db.plans || {} });
});

app.get('/api/admin/users', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    let usersList = [];
    for (const [uemail, udata] of Object.entries(db.users || {})) {
        usersList.push({
            email: uemail,
            username: uemail,
            is_admin: !!udata.is_admin,
            created_at: udata.created_at,
            max_servers: udata.max_servers || 1,
            expiry_days: udata.expiry_days || 365,
            plan: udata.plan || "free"
        });
    }
    res.json({ success: true, users: usersList });
});

app.post('/api/admin/create-user', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    const { email, password, max_servers, expiry_days } = req.body || {};
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanPass = (password || "").trim();

    if (!cleanEmail || !cleanPass) return res.json({ success: false, message: "البريد وكلمة المرور مطلوبة" });
    if (db.users[cleanEmail]) return res.json({ success: false, message: "المستخدم موجود بالفعل" });

    const passwordHash = crypto.createHash("sha256").update(cleanPass).digest("hex");
    db.users[cleanEmail] = {
        password: passwordHash,
        is_admin: false,
        created_at: new Date().toISOString(),
        max_servers: parseInt(max_servers) || 2,
        expiry_days: parseInt(expiry_days) || 365,
        last_login: null,
        telegram_id: null,
        api_key: null,
        storage_limit: db.plans.free.storage,
        plan: "free"
    };
    saveDb(db);

    const safeEmail = cleanEmail.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    const userDir = path.join(USERS_DIR, safeEmail);
    fs.mkdirSync(path.join(userDir, "SERVERS"), { recursive: true });

    res.json({ success: true, message: "✅ تم إنشاء الحساب بنجاح" });
});

app.post('/api/admin/delete-user', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    const { email } = req.body || {};
    let target = db.users[email];
    if (target && target.is_admin) return res.json({ success: false, message: "لا يمكن حذف الأدمن" });

    if (db.users[email]) {
        for (const [fid, srv] of Object.entries(db.servers || {})) {
            if (srv.owner === email) {
                stopServerProcess(fid);
                if (fs.existsSync(srv.path)) fs.rmSync(srv.path, { recursive: true, force: true });
                delete db.servers[fid];
            }
        }
        delete db.users[email];
        saveDb(db);
        return res.json({ success: true, message: "🗑 تم حذف المستخدم" });
    }
    res.json({ success: false, message: "المستخدم غير موجود" });
});

app.post('/api/admin/add-plan', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    const { plan_id, name, price, storage, ram, cpu, max_servers } = req.body || {};
    const pid = (plan_id || "").trim().toLowerCase();
    const pname = (name || "").trim();
    if (!pid || !pname) return res.json({ success: false, message: "معرف الخطة والاسم مطلوبان" });

    db.plans[pid] = {
        name: pname,
        price: parseFloat(price) || 0,
        storage: parseInt(storage) || 512000,
        ram: parseInt(ram) || 256,
        cpu: parseFloat(cpu) || 0.5,
        max_servers: parseInt(max_servers) || 2
    };
    saveDb(db);
    res.json({ success: true, message: "✅ تم إضافة الخطة بنجاح" });
});

app.get('/api/system/metrics', (req, res) => {
    const cpus = require('os').cpus();
    let cpuUsage = Math.floor(Math.random() * 20) + 10;
    const totalMem = require('os').totalmem();
    const freeMem = require('os').freemem();
    const usedMemPercent = Math.round(((totalMem - freeMem) / totalMem) * 100);
    res.json({
        cpu: cpuUsage,
        memory: usedMemPercent,
        disk: 25
    });
});

app.get('/api/servers', (req, res) => {
    if (!req.session || !req.session.email && !checkAdminAccess(req)) return res.status(401).json({ success: false });

    let targetUser = req.query.user;
    let ownerEmail = (targetUser && checkAdminAccess(req)) ? targetUser : req.session.email;

    let userServers = [];
    let totalDiskUsed = 0;
    for (const [folder, srv] of Object.entries(db.servers || {})) {
        if (srv.owner === ownerEmail) {
            let diskUsed = 0;
            if (fs.existsSync(srv.path)) {
                try {
                    const walkSync = (dir) => {
                        let files = fs.readdirSync(dir);
                        files.forEach(file => {
                            let filepath = path.join(dir, file);
                            let stat = fs.statSync(filepath);
                            if (stat.isDirectory()) walkSync(filepath);
                            else diskUsed += stat.size;
                        });
                    };
                    walkSync(srv.path);
                } catch (e) {}
            }
            let diskUsedMb = Math.round((diskUsed / (1024 * 1024)) * 100) / 100;
            totalDiskUsed += diskUsedMb;
            userServers.push({
                folder: folder,
                title: srv.name,
                name: srv.name,
                server_type: srv.server_type || "Python",
                status: srv.status || "Stopped",
                uptime: srv.status === "Running" ? uptimeStr(srv.start_time) : "0 ثانية",
                port: srv.port || "N/A",
                plan: srv.plan || "free",
                storage_limit: srv.storage_limit || 512000,
                ram_limit: srv.ram_limit || 256,
                cpu_limit: srv.cpu_limit || 0.5,
                disk_used: diskUsedMb,
                startup_file: srv.startup_file || ""
            });
        }
    }
    let user = db.users[ownerEmail] || {};
    res.json({
        success: true,
        servers: userServers,
        stats: {
            used: userServers.length,
            total: user.max_servers || 2,
            expiry: user.expiry_days || 365,
            disk_used: Math.round(totalDiskUsed * 100) / 100,
            disk_total: user.storage_limit || 512000
        }
    });
});

app.post('/api/server/add', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false, message: "غير مصرح" });
    let email = req.session.email;
    let user = db.users[email];
    if (!user) return res.json({ success: false, message: "مستخدم غير موجود" });

    let userSrvCount = Object.values(db.servers || {}).filter(s => s.owner === email).length;
    if (userSrvCount >= (user.max_servers || 2)) {
        return res.json({ success: false, message: `وصلت للحد الأقصى (${user.max_servers || 2}) سيرفر` });
    }

    const { name, server_type } = req.body || {};
    const sName = (name || "").trim();
    const sType = server_type || "Python";
    if (!sName) return res.json({ success: false, message: "الرجاء إدخال اسم للسيرفر" });

    let planId = user.plan || "free";
    let plan = db.plans[planId] || db.plans.free;

    let safeEmail = email.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    let folder = `${safeEmail}_${sName.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    let srvPath = path.join(getUserServersDir(email), folder);
    fs.mkdirSync(srvPath, { recursive: true });
    let assignedPort = getAssignedPort();

    db.servers[folder] = {
        name: sName,
        owner: email,
        path: srvPath,
        server_type: sType,
        status: "Stopped",
        created_at: new Date().toISOString(),
        startup_file: "",
        pid: null,
        port: assignedPort,
        plan: planId,
        storage_limit: plan.storage,
        ram_limit: plan.ram,
        cpu_limit: plan.cpu
    };
    saveDb(db);
    res.json({ success: true, message: `✅ تم إنشاء ${sType} سيرفر: ${sName}` });
});

app.post('/api/server/action/:folder/:action', (req, res) => {
    let email = req.session ? req.session.email : null;
    let { folder, action } = req.params;
    let srv = db.servers[folder];
    if (!srv) return res.json({ success: false, message: "السيرفر غير موجود" });
    if (!isAdmin(email) && srv.owner !== email) return res.json({ success: false, message: "غير مصرح" });

    if (action === "start") {
        if (srv.status === "Running") return res.json({ success: false, message: "الخادم يعمل بالفعل" });
        let [ok, msg] = startServerProcess(folder);
        return res.json({ success: ok, message: msg });
    } else if (action === "stop") {
        stopServerProcess(folder);
        return res.json({ success: true, message: "🛑 تم الإيقاف" });
    } else if (action === "restart") {
        restartServer(folder);
        return res.json({ success: true, message: "🔄 تم إعادة التشغيل" });
    } else if (action === "delete") {
        stopServerProcess(folder);
        if (fs.existsSync(srv.path)) fs.rmSync(srv.path, { recursive: true, force: true });
        delete db.servers[folder];
        saveDb(db);
        return res.json({ success: true, message: "🗑 تم الحذف" });
    }
    res.json({ success: false });
});

app.get('/api/server/stats/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let status = srv.status || "Stopped";
    let logs = "لا توجد مخرجات بعد";
    let logPath = path.join(srv.path, "out.log");
    if (fs.existsSync(logPath)) {
        try {
            let content = fs.readFileSync(logPath, "utf-8");
            let lines = content.split('\n');
            logs = lines.slice(-500).join('\n');
        } catch (e) {}
    }

    let memInfo = "0";
    if (srv.pid && status === "Running") {
        memInfo = "45.2";
    }

    res.json({
        success: true,
        status: status,
        logs: logs,
        mem: memInfo,
        uptime: status === "Running" ? uptimeStr(srv.start_time) : "0 ثانية",
        port: srv.port || "--"
    });
});

app.get('/api/files/list/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json([]);
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json([]);

    let srvPath = srv.path;
    let filesList = [];
    try {
        let items = fs.readdirSync(srvPath);
        items.forEach(item => {
            if (["out.log", "server.log", "meta.json", "errors.log"].includes(item)) return;
            let fpath = path.join(srvPath, item);
            let stat = fs.statSync(fpath);
            let sizeBytes = stat.size;
            let sizeStr = "";
            if (sizeBytes < 1024) sizeStr = `${sizeBytes} B`;
            else if (sizeBytes < 1024 * 1024) sizeStr = `${(sizeBytes/1024).toFixed(1)} KB`;
            else sizeStr = `${(sizeBytes/(1024*1024)).toFixed(1)} MB`;

            filesList.push({
                name: item,
                size: sizeStr,
                is_dir: stat.isDirectory(),
                modified: new Date(stat.mtime).toISOString().replace('T', ' ').substring(0, 16)
            });
        });
    } catch (e) {}
    filesList.sort((a, b) => (a.is_dir === b.is_dir ? a.name.localeCompare(b.name) : (a.is_dir ? -1 : 1)));
    res.json(filesList);
});

app.get('/api/files/content/:folder/:filename(*)', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ content: "" });
    let srv = db.servers[req.params.folder];
    let filename = req.params.filename;
    if (!srv || srv.owner !== req.session.email || filename.includes('..')) return res.json({ content: "" });

    let fpath = path.join(srv.path, filename);
    if (!fs.existsSync(fpath) || fs.statSync(fpath).isDirectory()) return res.json({ content: "" });
    try {
        let content = fs.readFileSync(fpath, "utf-8");
        res.json({ content: content });
    } catch (e) {
        res.json({ content: "[ملف ثنائي]" });
    }
});

app.post('/api/files/save/:folder/:filename(*)', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    let filename = req.params.filename;
    if (!srv || srv.owner !== req.session.email || filename.includes('..')) return res.json({ success: false });

    let content = (req.body || {}).content || "";
    let sec = scanCodeSecurity(content);
    if (!sec.safe) return res.json({ success: false, message: sec.message });

    let fpath = path.join(srv.path, filename);
    try {
        fs.writeFileSync(fpath, content, "utf-8");
        res.json({ success: true, message: "✅ تم الحفظ بنجاح" });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

const upload = multer({ limits: { fileSize: 500 * 1024 * 1024 } });
app.post('/api/files/upload/:folder', upload.array('files[]'), (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let files = req.files || [];
    let uploaded = 0;
    files.forEach(f => {
        if (f && f.originalname && !f.originalname.includes('..')) {
            let savePath = path.join(srv.path, f.originalname);
            fs.writeFileSync(savePath, f.buffer);
            uploaded++;

            if (f.originalname.toLowerCase().endsWith('.zip')) {
                try {
                    let zip = new AdmZip(savePath);
                    zip.extractAllTo(srv.path, true);
                } catch (e) {}
            }
        }
    });

    if (uploaded > 0) {
        if (srv.server_type === "Node.js") {
            let detected = detectNodeMainFile(srv.path);
            if (detected) {
                srv.startup_file = detected;
                saveDb(db);
            }
            let logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' });
            autoInstallNodeDeps(srv.path, logStream);
        } else {
            let detected = detectMainFile(srv.path);
            if (detected) {
                srv.startup_file = detected;
                saveDb(db);
            }
            let logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' });
            autoInstallDeps(srv.path, logStream);
        }
        return res.json({ success: true, message: "✅ تم رفع الملفات وفك ضغطها بنجاح" });
    }
    res.json({ success: false, message: "فشل الرفع" });
});

app.post('/api/files/delete/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let names = req.body.names || req.body.name || [];
    if (typeof names === 'string') names = [names];

    let deleted = 0;
    names.forEach(name => {
        if (name && !name.includes('..')) {
            let fpath = path.join(srv.path, name);
            try {
                if (fs.existsSync(fpath)) {
                    fs.rmSync(fpath, { recursive: true, force: true });
                    deleted++;
                }
            } catch (e) {}
        }
    });
    res.json({ success: true, message: `🗑 تم حذف ${deleted} ملف` });
});

app.post('/api/files/create/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const { filename, content } = req.body || {};
    if (!filename || filename.includes('..')) return res.json({ success: false });

    let sec = scanCodeSecurity(content || "");
    if (!sec.safe) return res.json({ success: false, message: sec.message });

    let fpath = path.join(srv.path, filename);
    try {
        if (filename.endsWith('/')) {
            fs.mkdirSync(fpath, { recursive: true });
        } else {
            fs.writeFileSync(fpath, content || "", "utf-8");
            if (!srv.startup_file && (filename.endsWith('.py') || filename.endsWith('.js'))) {
                srv.startup_file = filename;
                saveDb(db);
            }
        }
        res.json({ success: true, message: `✅ تم إنشاء ${filename}` });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.post('/api/files/rename/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const { old_name, new_name } = req.body || {};
    if (!old_name || !new_name || old_name.includes('..') || new_name.includes('..')) return res.json({ success: false });

    let oldPath = path.join(srv.path, old_name);
    let newPath = path.join(srv.path, new_name);
    if (!fs.existsSync(oldPath)) return res.json({ success: false });

    try {
        fs.renameSync(oldPath, newPath);
        if (srv.startup_file === old_name) {
            srv.startup_file = new_name;
            saveDb(db);
        }
        res.json({ success: true, message: "✅ تم تغيير الاسم" });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.post('/api/files/unzip/:folder/:filename(*)', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    let filename = req.params.filename;
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let zipPath = path.join(srv.path, filename);
    if (!fs.existsSync(zipPath)) return res.json({ success: false });

    try {
        let zip = new AdmZip(zipPath);
        zip.extractAllTo(srv.path, true);

        let detected = srv.server_type === "Node.js" ? detectNodeMainFile(srv.path) : detectMainFile(srv.path);
        if (detected) {
            srv.startup_file = detected;
            saveDb(db);
        }
        res.json({ success: true, message: "✅ تم فك الضغط واكتشاف ملف التشغيل" });
    } catch (e) {
        res.json({ success: false, message: "فشل فك الضغط" });
    }
});

app.post('/api/server/set-startup/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const { filename } = req.body || {};
    if (!filename || filename.includes('..')) return res.json({ success: false });

    srv.startup_file = filename;
    saveDb(db);
    res.json({ success: true, message: `✅ تم تعيين ${filename}` });
});

app.post('/api/server/install/:folder', (req, res) => {
    if (!req.session || !req.session.email) return res.status(401).json({ success: false });
    let srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' });
    if (srv.server_type === "Node.js") {
        autoInstallNodeDeps(srv.path, logStream);
    } else {
        autoInstallDeps(srv.path, logStream);
    }
    res.json({ success: true, message: "📦 بدأ تثبيت المكتبات" });
});

app.post('/api/bot/verify', (req, res) => {
    const { api_key } = req.body || {};
    if (!api_key) return res.json({ success: false });
    let [email, user] = getUserByApiKey(api_key);
    if (!email) return res.json({ success: false });
    res.json({
        success: true,
        email: email,
        username: email,
        is_admin: isAdmin(email),
        max_servers: user.max_servers || 2
    });
});

app.get('/api/bot/servers', (req, res) => {
    let apiKey = req.query.api_key;
    if (!apiKey) return res.status(401).json({ success: false });
    let [email] = getUserByApiKey(apiKey);
    if (!email) return res.status(401).json({ success: false });

    let userServers = [];
    for (const [folder, srv] of Object.entries(db.servers || {})) {
        if (srv.owner === email) {
            userServers.push({
                folder: folder,
                title: srv.name,
                name: srv.name,
                status: srv.status || "Stopped",
                port: srv.port || "N/A",
                type: srv.server_type || "Python",
                server_type: srv.server_type || "Python",
                uptime: srv.status === "Running" ? uptimeStr(srv.start_time) : "0 ثانية"
            });
        }
    }
    res.json({ success: true, servers: userServers });
});

app.post('/api/bot/server/action', (req, res) => {
    const { api_key, folder, action } = req.body || {};
    if (!api_key || !folder || !action) return res.status(400).json({ success: false });
    let [email] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false });
    let srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    if (action === "start") {
        let [ok, msg] = startServerProcess(folder);
        return res.json({ success: ok, message: msg });
    } else if (action === "stop") {
        stopServerProcess(folder);
        return res.json({ success: true, message: "🛑 تم الإيقاف" });
    } else if (action === "restart") {
        restartServer(folder);
        return res.json({ success: true, message: "🔄 تم إعادة التشغيل" });
    } else if (action === "delete") {
        stopServerProcess(folder);
        if (fs.existsSync(srv.path)) fs.rmSync(srv.path, { recursive: true, force: true });
        delete db.servers[folder];
        saveDb(db);
        return res.json({ success: true, message: "🗑 تم الحذف" });
    }
    res.json({ success: false });
});

app.get('/api/bot/console', (req, res) => {
    let apiKey = req.query.api_key;
    let folder = req.query.folder;
    if (!apiKey || !folder) return res.status(400).json({ success: false });
    let [email] = getUserByApiKey(apiKey);
    if (!email) return res.status(401).json({ success: false });
    let srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    let logPath = path.join(srv.path, "out.log");
    let logs = "لا توجد مخرجات بعد";
    if (fs.existsSync(logPath)) {
        try {
            logs = fs.readFileSync(logPath, "utf-8").slice(-3500);
        } catch (e) {}
    }
    res.json({ success: true, logs: logs });
});

app.get('/api/bot/errors', (req, res) => {
    let apiKey = req.query.api_key;
    let folder = req.query.folder;
    if (!apiKey || !folder) return res.status(400).json({ success: false });
    let [email] = getUserByApiKey(apiKey);
    if (!email) return res.status(401).json({ success: false });
    let srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    let errPath = path.join(srv.path, "errors.log");
    let errors = "✅ لا توجد أخطاء";
    if (fs.existsSync(errPath)) {
        try {
            errors = fs.readFileSync(errPath, "utf-8").slice(-3500);
        } catch (e) {}
    }
    res.json({ success: true, errors: errors });
});

app.post('/api/bot/install', (req, res) => {
    const { api_key, folder } = req.body || {};
    if (!api_key || !folder) return res.status(400).json({ success: false });
    let [email] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false });
    let srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    let logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' });
    if (srv.server_type === "Node.js") {
        autoInstallNodeDeps(srv.path, logStream);
    } else {
        autoInstallDeps(srv.path, logStream);
    }
    res.json({ success: true, message: "📦 بدأ تثبيت المكتبات" });
});

app.post('/api/bot/create_server', (req, res) => {
    const { api_key, name, server_type } = req.body || {};
    if (!api_key) return res.status(401).json({ success: false, message: "غير مصرح" });
    let [email, user] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false, message: "غير مصرح" });

    let userSrvCount = Object.values(db.servers || {}).filter(s => s.owner === email).length;
    if (userSrvCount >= (user.max_servers || 2)) {
        return res.json({ success: false, message: `وصلت للحد الأقصى (${user.max_servers || 2}) سيرفر` });
    }

    let sName = (name || "").trim();
    let sType = server_type || "Python";
    if (!sName) return res.json({ success: false, message: "الرجاء إدخال اسم للسيرفر" });

    let planId = user.plan || "free";
    let plan = db.plans[planId] || db.plans.free;

    let safeEmail = email.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    let folder = `${safeEmail}_${sName.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    let srvPath = path.join(getUserServersDir(email), folder);
    fs.mkdirSync(srvPath, { recursive: true });
    let assignedPort = getAssignedPort();

    db.servers[folder] = {
        name: sName,
        owner: email,
        path: srvPath,
        server_type: sType,
        status: "Stopped",
        created_at: new Date().toISOString(),
        startup_file: "",
        pid: null,
        port: assignedPort,
        plan: planId,
        storage_limit: plan.storage,
        ram_limit: plan.ram,
        cpu_limit: plan.cpu
    };
    saveDb(db);
    res.json({ success: true, message: `✅ تم إنشاء ${sType} سيرفر: ${sName}` });
});

// إعداد بوت التيليجرام باستخدام Telegraf
function runTelegramBot() {
    try {
        console.log("\n" + "=".repeat(60));
        console.log(" 🤖 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 - جاري تشغيل بوت التحكم المدمج (Node.js)");
        console.log(" 🚀 يتم الآن الاتصال بخوادم تليجرام...");
        console.log("=".repeat(60) + "\n");

        const bot = new Telegraf(BOT_TOKEN);

        function isAdminTg(ctx) {
            return ADMIN_TELEGRAM_IDS.includes(ctx.chat.id);
        }

        async function showMainMenu(ctx, edit = false) {
            let apiKey = ctx.session ? ctx.session.api_key : null;
            let username = ctx.session ? ctx.session.username : "";
            let isAdm = isAdminTg(ctx);

            let buttons = [];
            if (apiKey) {
                buttons.push([
                    Markup.button.callback("📁 سيرفراتي", "my_servers"),
                    Markup.button.callback("➕ إنشاء سيرفر", "create_server")
                ]);
                buttons.push([
                    Markup.button.callback("🔑 تغيير API Key", "change_api"),
                    Markup.button.callback("🚪 تسجيل خروج", "logout")
                ]);
            } else {
                buttons.push([Markup.button.callback("🔑 ربط API Key", "enter_api")]);
            }

            if (isAdm) {
                buttons.push([Markup.button.callback("👑 لوحة الإدارة", "admin_panel")]);
            }
            buttons.push([Markup.button.url("💬 تواصل مع المطور @Y_20_20", "https://t.me/Y_20_20")]);

            let text = "━━━━━━━━━━━━━━━━━━━━\n      𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 🚀\n━━━━━━━━━━━━━━━━━━━━\n";
            if (username) text += `👤 أهلاً، *${username}*!\n`;
            text += apiKey ? "✅ متصل بالنظام\n" : "⚠️ يجب ربط API Key أولاً\n";
            text += `\n${DEVELOPER_INFO}`;

            try {
                if (edit && ctx.callbackQuery) {
                    await ctx.editMessageText(text, { parse_mode: "Markdown", ...Markup.inlineKeyboard(buttons) });
                } else if (ctx.reply) {
                    await ctx.reply(text, { parse_mode: "Markdown", ...Markup.inlineKeyboard(buttons) });
                }
            } catch (e) {}
        }

        bot.start(async (ctx) => {
            if (!ctx.session) ctx.session = {};
            let apiKey = ctx.session.api_key;
            if (apiKey) {
                try {
                    let resp = await axios.post(`${API_BASE_URL}/api/bot/verify`, { api_key: apiKey });
                    if (resp.data && resp.data.success) {
                        ctx.session.username = resp.data.username;
                        await showMainMenu(ctx);
                        return;
                    }
                } catch (e) {}
                ctx.session.api_key = null;
            }
            await ctx.reply(
                "━━━━━━━━━━━━━━━━━━━━\n      𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 🚀\n━━━━━━━━━━━━━━━━━━━━\nللاشتراك والحصول على حساب:\n📬 تواصل مع المطور: @Y_20_20\n\n" + DEVELOPER_INFO,
                { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🔑 إدخال API Key", "enter_api")], [Markup.button.url("💬 تواصل مع المطور @Y_20_20", "https://t.me/Y_20_20")]]) }
            );
        });

        bot.help(async (ctx) => {
            await ctx.reply("📚 المساعدة:\n\nهذا البوت يعمل بشكل مستمر على خادم 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓\nللاشتراك أو الاستفسار: @Y_20_20");
        });

        bot.command("info", async (ctx) => {
            await ctx.reply("ℹ️ معلومات البوت:\n\n🤖 الخدمة: 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓\n✅ الحالة: نشط ومستمر\n🛠 المطور: @Y_20_20");
        });

        bot.action("enter_api", async (ctx) => {
            await ctx.answerCbQuery();
            ctx.session.waiting_api = true;
            await ctx.editMessageText("🔑 *أدخل API Key الخاص بك:*\n\nيمكنك الحصول عليه من لوحة التحكم في الموقع.", { parse_mode: "Markdown" });
        });

        bot.action("change_api", async (ctx) => {
            await ctx.answerCbQuery();
            ctx.session.api_key = null;
            ctx.session.waiting_api = true;
            await ctx.editMessageText("🔑 *أدخل API Key الجديد:*\n\nيمكنك الحصول عليه من لوحة التحكم في الموقع.", { parse_mode: "Markdown" });
        });

        bot.action("logout", async (ctx) => {
            await ctx.answerCbQuery();
            ctx.session.api_key = null;
            ctx.session.username = null;
            await ctx.editMessageText("🚪 تم تسجيل الخروج.\nاستخدم /start للدخول مجدداً.");
        });

        bot.action("main_menu", async (ctx) => {
            await ctx.answerCbQuery();
            await showMainMenu(ctx, true);
        });

        bot.action("my_servers", async (ctx) => {
            await ctx.answerCbQuery();
            let apiKey = ctx.session ? ctx.session.api_key : null;
            if (!apiKey) {
                await ctx.editMessageText("❌ يجب ربط API Key أولاً.");
                return;
            }
            try {
                let resp = await axios.get(`${API_BASE_URL}/api/bot/servers`, { params: { api_key: apiKey } });
                let data = resp.data;
                if (!data || !data.success) {
                    await ctx.editMessageText("❌ فشل جلب السيرفرات. تحقق من صحة API Key.", { ...Markup.inlineKeyboard([[Markup.button.callback("🔙 رجوع", "main_menu")]]) });
                    return;
                }
                let servers = data.servers || [];
                if (servers.length === 0) {
                    await ctx.editMessageText("📭 لا توجد سيرفرات. أنشئ سيرفرك الأول الآن!", {
                        ...Markup.inlineKeyboard([
                            [Markup.button.callback("➕ إنشاء سيرفر", "create_server")],
                            [Markup.button.callback("🔙 رجوع", "main_menu")]
                        ])
                    });
                    return;
                }
                await ctx.editMessageText(`📋 لديك *${servers.length}* سيرفر:`, { parse_mode: "Markdown" });
                for (const srv of servers) {
                    let statusEmoji = srv.status === "Running" ? "🟢" : "⚫";
                    let srvType = srv.type || "Python";
                    let typeIcon = srvType === "Python" ? "🐍" : "🟨";
                    let text = `━━━━━━━━━━━━━━━━━━━━\n${statusEmoji} *${srv.title}*\n━━━━━━━━━━━━━━━━━━━━\n${typeIcon} النوع: \`${srvType}\`\n📊 الحالة: \`${srv.status}\`\n🔌 المنفذ: \`${srv.port}\`\n⏱ وقت التشغيل: ${srv.uptime}`;
                    let folder = srv.folder;
                    let kb = [
                        [Markup.button.callback("▶️ تشغيل", `srv_start|${folder}`), Markup.button.callback("⏹ إيقاف", `srv_stop|${folder}`), Markup.button.callback("🔄 إعادة", `srv_restart|${folder}`)],
                        [Markup.button.callback("🖥 كونسول", `console|${folder}`), Markup.button.callback("⚠️ أخطاء", `errors|${folder}`), Markup.button.callback("🗑 حذف", `srv_delete|${folder}`)],
                        [Markup.button.callback("📦 تثبيت مكتبات تلقائياً", `install|${folder}`)]
                    ];
                    await ctx.reply(text, { parse_mode: "Markdown", ...Markup.inlineKeyboard(kb) });
                }
                await ctx.reply("━━━━━━━━━━━━━━━━━━━━", { ...Markup.inlineKeyboard([[Markup.button.callback("🔙 القائمة الرئيسية", "main_menu")]]) });
            } catch (e) {
                await ctx.editMessageText("❌ حدث خطأ أثناء جلب السيرفرات.");
            }
        });

        bot.action("create_server", async (ctx) => {
            await ctx.answerCbQuery();
            ctx.session.waiting_server_name = true;
            await ctx.editMessageText("➕ *إنشاء سيرفر جديد*\n\n📝 أرسل اسم السيرفر:", { parse_mode: "Markdown" });
        });

        bot.action(/^server_type_(python|nodejs)$/, async (ctx) => {
            await ctx.answerCbQuery();
            let srvType = ctx.match[1] === "python" ? "Python" : "Node.js";
            let name = ctx.session.pending_server_name || "Server";
            let apiKey = ctx.session.api_key;
            try {
                let resp = await axios.post(`${API_BASE_URL}/api/bot/create_server`, {
                    api_key: apiKey, name: name, server_type: srvType
                });
                let data = resp.data;
                let typeIcon = srvType === "Python" ? "🐍" : "🟨";
                if (data && data.success) {
                    await ctx.editMessageText(`✅ *تم إنشاء السيرفر بنجاح!*\n\n📛 الاسم: \`${name}\`\n${typeIcon} النوع: \`${srvType}\`\n\nارفع ملفاتك عبر لوحة التحكم الآن.`, { parse_mode: "Markdown" });
                } else {
                    await ctx.editMessageText(`❌ *فشل الإنشاء!*\n${data.message || 'خطأ'}`, { parse_mode: "Markdown" });
                }
            } catch (e) {
                await ctx.editMessageText("❌ خطأ في الاتصال بالخادم.");
            }
            await showMainMenu(ctx);
        });

        bot.action("admin_panel", async (ctx) => {
            await ctx.answerCbQuery();
            if (!isAdminTg(ctx)) {
                await ctx.editMessageText("❌ غير مصرح لك بالدخول.");
                return;
            }
            let apiKey = ctx.session.api_key;
            try {
                let resp = await axios.get(`${API_BASE_URL}/api/admin/users`, { params: { api_key: apiKey } });
                let users = resp.data && resp.data.success ? resp.data.users : [];
                let text = `━━━━━━━━━━━━━━━━━━━━\n  👑 لوحة إدارة 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓\n━━━━━━━━━━━━━━━━━━━━\n👥 المستخدمين: *${users.length}*\n━━━━━━━━━━━━━━━━━━━━\n`;
                for (const u of users.slice(0, 10)) {
                    text += `• \`${u.username}\` | ${u.max_servers || 1} سيرفر\n`;
                }
                await ctx.editMessageText(text, { parse_mode: "Markdown", ...Markup.inlineKeyboard([
                    [Markup.button.callback("📊 إحصائيات النظام", "admin_stats")],
                    [Markup.button.callback("🔙 رجوع", "main_menu")]
                ]) });
            } catch (e) {
                await ctx.editMessageText("❌ خطأ في جلب بيانات الإدارة.");
            }
        });

        bot.action("admin_stats", async (ctx) => {
            await ctx.answerCbQuery();
            let cpus = require('os').cpus();
            let cpu = Math.floor(Math.random() * 20) + 10;
            let totalMem = require('os').totalmem();
            let freeMem = require('os').freemem();
            let ram = Math.round(((totalMem - freeMem) / totalMem) * 100);
            await ctx.editMessageText(
                `━━━━━━━━━━━━━━━━━━━━\n  📊 إحصائيات النظام\n━━━━━━━━━━━━━━━━━━━━\n🖥 CPU:  *${cpu}%*\n💾 RAM:  *${ram}%*\n💿 Disk: *25%*`,
                { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🔙 رجوع", "admin_panel")]]) }
            );
        });

        bot.action(/^(srv_start|srv_stop|srv_restart|srv_delete)\|(.+)$/, async (ctx) => {
            let action = ctx.match[1].replace("srv_", "");
            let folder = ctx.match[2];
            let apiKey = ctx.session.api_key;
            try {
                let resp = await axios.post(`${API_BASE_URL}/api/bot/server/action`, {
                    api_key: apiKey, folder: folder, action: action
                });
                let data = resp.data;
                await ctx.answerCallQuery((data && data.success ? data.message : "فشل العملية").substring(0, 200));
            } catch (e) {
                await ctx.answerCallQuery("❌ خطأ في الاتصال");
            }
        });

        bot.action(/^console\|(.+)$/, async (ctx) => {
            await ctx.answerCbQuery();
            let folder = ctx.match[1];
            let apiKey = ctx.session.api_key;
            try {
                let resp = await axios.get(`${API_BASE_URL}/api/bot/console`, { params: { api_key: apiKey, folder: folder } });
                let logs = resp.data && resp.data.success ? resp.data.logs : "لا توجد مخرجات";
                if (logs.length > 3500) logs = "...\n" + logs.slice(-3500);
                await ctx.editMessageText(`🖥 *كونسول السيرفر*\n\`\`\`\n${logs}\n\`\`\``, { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🔄 تحديث", `console|${folder}`), Markup.button.callback("🔙 رجوع", "my_servers")]]) });
            } catch (e) {
                await ctx.editMessageText("❌ فشل جلب الكونسول");
            }
        });

        bot.action(/^errors\|(.+)$/, async (ctx) => {
            await ctx.answerCbQuery();
            let folder = ctx.match[1];
            let apiKey = ctx.session.api_key;
            try {
                let resp = await axios.get(`${API_BASE_URL}/api/bot/errors`, { params: { api_key: apiKey, folder: folder } });
                let errors = resp.data && resp.data.success ? resp.data.errors : "✅ لا توجد أخطاء";
                if (errors.length > 3500) errors = "...\n" + errors.slice(-3500);
                await ctx.editMessageText(`⚠️ *سجل الأخطاء*\n\`\`\`\n${errors}\n\`\`\``, { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🔙 رجوع", "my_servers")]]) });
            } catch (e) {
                await ctx.editMessageText("❌ فشل جلب سجل الأخطاء");
            }
        });

        bot.action(/^install\|(.+)$/, async (ctx) => {
            await ctx.answerCbQuery();
            let folder = ctx.match[1];
            let apiKey = ctx.session.api_key;
            try {
                let resp = await axios.post(`${API_BASE_URL}/api/bot/install`, { api_key: apiKey, folder: folder });
                let msg = resp.data && resp.data.success ? "📦 بدأ تثبيت المكتبات" : "❌ فشل التثبيت";
                await ctx.editMessageText(`📦 *تثبيت المكتبات*\n\n${msg}\n\nتابع الكونسول للتفاصيل.`, { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🖥 كونسول", `console|${folder}`), Markup.button.callback("🔙 رجوع", "my_servers")]]) });
            } catch (e) {
                await ctx.editMessageText("❌ خطأ في الاتصال");
            }
        });

        bot.on("text", async (ctx) => {
            if (!ctx.session) ctx.session = {};
            if (ctx.session.waiting_api) {
                let apiKey = ctx.text.trim();
                try {
                    let resp = await axios.post(`${API_BASE_URL}/api/bot/verify`, { api_key: apiKey });
                    let data = resp.data;
                    if (!data || !data.success) {
                        await ctx.reply("❌ *مفتاح API غير صالح!*\n\nتحقق من الكود وحاول مرة أخرى أو تواصل مع المطور: @Y_20_20", { parse_mode: "Markdown" });
                        return;
                    }
                    ctx.session.api_key = apiKey;
                    ctx.session.username = data.username;
                    ctx.session.waiting_api = false;
                    await ctx.reply(`✅ *تم الربط بنجاح!*\n👤 مرحباً *${data.username}*!`, { parse_mode: "Markdown" });
                    await showMainMenu(ctx);
                } catch (e) {
                    await ctx.reply("❌ خطأ في التحقق من المفتاح.");
                }
                return;
            }
            if (ctx.session.waiting_server_name) {
                let name = ctx.text.trim();
                ctx.session.pending_server_name = name;
                ctx.session.waiting_server_name = false;
                await ctx.reply(`📦 *اختر نوع السيرفر:*\n\nالاسم: \`${name}\``, { parse_mode: "Markdown", ...Markup.inlineKeyboard([
                    [Markup.button.callback("🐍 Python", "server_type_python"), Markup.button.callback("🟨 Node.js", "server_type_nodejs")]
                ]) });
                return;
            }
            await ctx.reply(`📨 تم استقبال رسالتك:\n\n${ctx.text}\n\nشكراً لاستخدامك 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓!\n🛠 @Y_20_20`);
        });

        bot.launch().then(() => {
            console.log(" ✅ بوت 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 جاهز الآن ويعمل بشكل مستمر (Node.js)!");
        });
    } catch (e) {
        console.error("❌ خطأ في تشغيل بوت تيليجرام:", e);
    }
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🌐 𝗘𝗛𝗔𝗕 𝐇𝐎𝐒𝐓 Server running on port ${PORT}`);
    runTelegramBot();
});
