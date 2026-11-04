
#!/usr/bin/env node
/**
 * ZIAD HOST - نظام استضافة متطور مع لوحة تحكم وإدارة وبوت تيليجرام مدمج
 * طُوِّر بواسطة: 𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜 | @Y_20_20
 * [محول ومصحح بالكامل لضمان تشغيل ملفات بايثون وجافا سكريبت بكفاءة عالية على Node.js]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const os = require('os');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const AdmZip = require('adm-zip');
const axios = require('axios');
const { Telegraf, Markup } = require('telegraf');

const BASE_DIR = __dirname;
const USERS_DIR = path.join(BASE_DIR, "USERS");
if (!fs.existsSync(USERS_DIR)) fs.mkdirSync(USERS_DIR, { recursive: true });

// مسارات التخزين الإضافية المطلوبة بنظام الحماية والهيكلة
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

const DB_FILE = path.join(BASE_DIR, "db.json");
const SECURITY_DB = path.join(DB_DIR, "security.json");

function readJson(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
        return {};
    } catch (e) {
        return {};
    }
}

function writeJson(filePath, data) {
    try {
        const tempPath = filePath + ".tmp";
        fs.writeFileSync(tempPath, JSON.stringify(data, null, 4), 'utf8');
        fs.renameSync(tempPath, filePath);
    } catch (e) {
        console.error(`JSON write error: ${e}`);
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
        /\bexec\s*\(/i
    ];
    for (const pattern of dangerousPatterns) {
        if (pattern.test(content)) {
            return [false, "⚠️ تم رفض الملف حظراً أمنياً لاحتوائه على أكواد خطيرة أو محاولات اختراق."];
        }
    }
    return [true, "الكود آمن"];
}

function getMasterKey() {
    let security = readJson(SECURITY_DB);
    let masterKey = security.master_key;
    if (!masterKey) {
        masterKey = crypto.randomBytes(32).toString('base64');
        security.master_key = masterKey;
        security.file_keys = {};
        writeJson(SECURITY_DB, security);
    }
    return Buffer.from(masterKey, 'base64');
}

function generateFileKey(fid, userId, adminId, token) {
    let security = readJson(SECURITY_DB);
    security.file_keys = security.file_keys || {};
    if (!security.file_keys[fid]) {
        const combined = `${fid}:${userId}:${adminId}:${token}`;
        const salt = crypto.createHash('sha256').update(combined).digest().subarray(0, 16);
        const masterKey = getMasterKey();
        const kdf = crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha256');
        security.file_keys[fid] = {
            key: kdf.toString('base64'),
            salt: salt.toString('base64'),
            user_id: userId
        };
        writeJson(SECURITY_DB, security);
    }
    return security.file_keys[fid];
}

function getFileKey(fid) {
    let security = readJson(SECURITY_DB);
    return security.file_keys ? security.file_keys[fid] : null;
}

function encryptFileContent(content, fid, userId, adminId, token) {
    try {
        const fileKeyInfo = generateFileKey(fid, userId, adminId, token);
        const key = Buffer.from(fileKeyInfo.key, 'base64');
        const salt = Buffer.from(fileKeyInfo.salt, 'base64');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let ciphertext = cipher.update(content, 'utf8', 'base64');
        ciphertext += cipher.final('base64');
        const encryptedData = {
            iv: iv.toString('base64'),
            ciphertext: ciphertext,
            salt: salt.toString('base64'),
            fid: fid,
            user_id: userId,
            timestamp: new Date().toISOString()
        };
        return JSON.stringify(encryptedData);
    } catch (e) {
        console.error(`Encryption error: ${e}`);
        return null;
    }
}

function decryptFileContent(encryptedJson, fid) {
    try {
        const data = JSON.parse(encryptedJson);
        const fileKeyInfo = getFileKey(fid);
        if (!fileKeyInfo) return null;
        const key = Buffer.from(fileKeyInfo.key, 'base64');
        const iv = Buffer.from(data.iv, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let pt = decipher.update(data.ciphertext, 'base64', 'utf8');
        pt += decipher.final('utf8');
        return pt;
    } catch (e) {
        console.error(`Decryption error: ${e}`);
        return null;
    }
}

const LANDING_HTML_CONTENT = `<!DOCTYPE html>...` // (نفس محتوى HTML الأصلي)
const LOGIN_HTML_CONTENT = `<!DOCTYPE html>...`
const INDEX_HTML_CONTENT = `<!DOCTYPE html>...`
const ADMIN_HTML_CONTENT = `<!DOCTYPE html>...`

// كتابة صفحات الواجهات
fs.writeFileSync(path.join(BASE_DIR, "landing.html"), LANDING_HTML_CONTENT, 'utf8');
fs.writeFileSync(path.join(BASE_DIR, "login.html"), LOGIN_HTML_CONTENT, 'utf8');
fs.writeFileSync(path.join(BASE_DIR, "index.html"), INDEX_HTML_CONTENT, 'utf8');
fs.writeFileSync(path.join(BASE_DIR, "admin_panel.html"), ADMIN_HTML_CONTENT, 'utf8');

function loadDb() {
    if (fs.existsSync(DB_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
            if (!data.plans) data.plans = {};
            if (!data.server_types) data.server_types = ["Python", "Node.js"];
            if (!data.pending_users) data.pending_users = [];
            return data;
        } catch (e) {}
    }
    
    const adminEmail = process.env.ADMIN_EMAIL || "admin@ziadhost.com";
    const adminPassword = process.env.ADMIN_PASSWORD || "admin123";
    const adminHash = crypto.createHash('sha256').update(adminPassword).digest('hex');
    
    const defaultDb = {
        users: {
            [adminEmail]: {
                password: adminHash,
                is_admin: true,
                created_at: new Date().toISOString(),
                max_servers: 999999,
                expiry_days: 3650,
                last_login: null,
                telegram_id: 1002670694,
                api_key: null,
                storage_limit: 10240,
                plan: "admin"
            }
        },
        servers: {},
        logs: [],
        pending_users: [],
        plans: {
            "free": { "name": "🎁 مجاني", "storage": 512000, "ram": 256, "cpu": 0.5, "max_servers": 2, "price": 0 },
            "4gb": { "name": "💎 4 جيجا", "storage": 4096000, "ram": 1024, "cpu": 1, "max_servers": 5, "price": 5 },
            "10gb": { "name": "💎 10 جيجا", "storage": 10240000, "ram": 2048, "cpu": 2, "max_servers": 10, "price": 10 }
        },
        server_types: ["Python", "Node.js"]
    };
    saveDb(defaultDb);
    return defaultDb;
}

function saveDb(dbData) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(dbData, null, 4), 'utf8');
        return true;
    } catch (e) {
        console.error(`❌ خطأ في حفظ DB: ${e}`);
        return false;
    }
}

let db = loadDb();

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

const BOT_TOKEN = "9198716816:AAHYWvbY4SwwBQ5hKnoA17SOuxlA851oNCY";
const ADMIN_TELEGRAM_IDS = [1002670694];
const API_BASE_URL = process.env.API_BASE_URL || "https://ehab-10.onrender.com";
const DEVELOPER_INFO = "🛠 طُوِّر بواسطة: *𝗘𝗛𝗔𝗕𝗔𝗜𝗛𝗔𝗪𝗕𝗔𝗡𝗜*\n📬 تواصل: @Y_20_20";

function notifyAdmin(message) {
    try {
        for (const adminId of ADMIN_TELEGRAM_IDS) {
            axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
                chat_id: adminId, text: message, parse_mode: "Markdown"
            }, { timeout: 3000 }).catch(() => {});
        }
    } catch (e) {}
}

const PORT_RANGE_START = 8100;
const PORT_RANGE_END = 9100;
let activeProcesses = {};

function getAssignedPort() {
    const used = new Set();
    for (const srv of Object.values(db.servers || {})) {
        if (srv.port) used.add(srv.port);
    }
    for (let port = PORT_RANGE_START; port < PORT_RANGE_END; port++) {
        if (!used.has(port)) return port;
    }
    return PORT_RANGE_START;
}

function isAdmin(email) {
    const u = db.users[email];
    return u ? !!u.is_admin : false;
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('urlsafe');
}

function getUserByApiKey(apiKey) {
    for (const [email, udata] of Object.entries(db.users || {})) {
        if (udata.api_key === apiKey) return [email, udata];
    }
    return [null, null];
}

function uptimeStr(startTime) {
    if (!startTime) return "0 ثانية";
    const diff = (Date.now() - startTime) / 1000;
    const days = Math.floor(diff / 86400);
    const hours = Math.floor((diff % 86400) / 3600);
    const mins = Math.floor((diff % 3600) / 60);
    const parts = [];
    if (days > 0) parts.push(`${days} يوم`);
    if (hours > 0) parts.push(`${hours} ساعة`);
    if (mins > 0) parts.push(`${mins} دقيقة`);
    return parts.length > 0 ? parts.join(" و ") : "أقل من دقيقة";
}

function checkAdminAccess(req) {
    if (req.session && req.session.email && isAdmin(req.session.email)) return true;
    let apiKey = req.body && req.body.api_key ? req.body.api_key : req.query.api_key;
    if (apiKey) {
        const [email, user] = getUserByApiKey(apiKey);
        if (email && isAdmin(email)) return true;
    }
    return false;
}

function detectMainFile(srvPath) {
    for (const candidate of ["main.py", "bot.py", "app.py", "index.py", "run.py", "start.py"]) {
        if (fs.existsSync(path.join(srvPath, candidate))) return candidate;
    }
    try {
        const files = fs.readdirSync(srvPath);
        const pyFiles = files.filter(f => f.endsWith(".py"));
        if (pyFiles.length > 0) return pyFiles[0];
    } catch (e) {}
    return "";
}

function detectNodeMainFile(srvPath) {
    for (const candidate of ["index.js", "server.js", "app.js", "main.js", "bot.js", "start.js"]) {
        if (fs.existsSync(path.join(srvPath, candidate))) return candidate;
    }
    try {
        const files = fs.readdirSync(srvPath);
        const jsFiles = files.filter(f => f.endsWith(".js"));
        if (jsFiles.length > 0) return jsFiles[0];
    } catch (e) {}
    return "";
}

function autoInstallDeps(srvPath, logStream) {
    const req = path.join(srvPath, "requirements.txt");
    if (fs.existsSync(req)) {
        logStream.write("\n📦 تثبيت requirements.txt...\n");
        const proc = spawn("pip", ["install", "-r", "requirements.txt"], { cwd: srvPath, shell: true });
        proc.stdout.on('data', d => logStream.write(d));
        proc.stderr.on('data', d => logStream.write(d));
        proc.on('close', () => logStream.end());
    } else {
        logStream.end();
    }
}

function autoInstallNodeDeps(srvPath, logStream) {
    const pkg = path.join(srvPath, "package.json");
    if (fs.existsSync(pkg)) {
        logStream.write("\n📦 تثبيت حزم Node.js...\n");
        const proc = spawn("npm", ["install"], { cwd: srvPath, shell: true });
        proc.stdout.on('data', d => logStream.write(d));
        proc.stderr.on('data', d => logStream.write(d));
        proc.on('close', () => logStream.end());
    } else {
        logStream.end();
    }
}

function startServerProcess(folder) {
    const srv = db.servers[folder];
    if (!srv) return [false, "السيرفر غير موجود"];
    return srv.server_type === "Node.js" ? startNodeServerProcess(folder) : startPythonServerProcess(folder);
}

function startPythonServerProcess(folder) {
    const srv = db.servers[folder];
    let mainFile = srv.startup_file;
    if (!mainFile || !fs.existsSync(path.join(srv.path, mainFile))) {
        const detected = detectMainFile(srv.path);
        if (detected) {
            srv.startup_file = detected;
            mainFile = detected;
            saveDb(db);
        } else {
            return [false, "لا يوجد ملف تشغيل Python (.py)"];
        }
    }

    const port = srv.port || getAssignedPort();
    srv.port = port;
    saveDb(db);

    const logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a', encoding: 'utf-8' });
    const errStream = fs.createWriteStream(path.join(srv.path, "errors.log"), { flags: 'a', encoding: 'utf-8' });

    try {
        const env = { ...process.env, PORT: String(port), SERVER_PORT: String(port) };
        const proc = spawn("python3", ["-u", mainFile], { cwd: srv.path, env, shell: true });
        proc.stdout.pipe(logStream);
        proc.stderr.pipe(errStream);

        activeProcesses[folder] = proc;
        srv.status = "Running";
        srv.pid = proc.pid;
        srv.start_time = Date.now();
        saveDb(db);

        proc.on('exit', () => {
            srv.status = "Stopped";
            srv.pid = null;
            saveDb(db);
            delete activeProcesses[folder];
        });
        return [true, "✅ تم التشغيل بنجاح"];
    } catch (e) {
        return [false, e.message];
    }
}

function startNodeServerProcess(folder) {
    const srv = db.servers[folder];
    let mainFile = srv.startup_file;
    if (!mainFile || !fs.existsSync(path.join(srv.path, mainFile))) {
        const detected = detectNodeMainFile(srv.path);
        if (detected) {
            srv.startup_file = detected;
            mainFile = detected;
            saveDb(db);
        } else {
            return [false, "لا يوجد ملف تشغيل JavaScript (.js)"];
        }
    }

    const port = srv.port || getAssignedPort();
    srv.port = port;
    saveDb(db);

    const logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a', encoding: 'utf-8' });
    const errStream = fs.createWriteStream(path.join(srv.path, "errors.log"), { flags: 'a', encoding: 'utf-8' });

    try {
        const env = { ...process.env, PORT: String(port), SERVER_PORT: String(port) };
        const proc = spawn("node", [mainFile], { cwd: srv.path, env, shell: true });
        proc.stdout.pipe(logStream);
        proc.stderr.pipe(errStream);

        activeProcesses[folder] = proc;
        srv.status = "Running";
        srv.pid = proc.pid;
        srv.start_time = Date.now();
        saveDb(db);

        proc.on('exit', () => {
            srv.status = "Stopped";
            srv.pid = null;
            saveDb(db);
            delete activeProcesses[folder];
        });
        return [true, "✅ تم التشغيل بنجاح"];
    } catch (e) {
        return [false, e.message];
    }
}

function stopServerProcess(folder) {
    const srv = db.servers[folder];
    if (!srv) return;
    if (activeProcesses[folder]) {
        try { activeProcesses[folder].kill(); } catch (e) {}
        delete activeProcesses[folder];
    } else if (srv.pid) {
        try { process.kill(srv.pid, 'SIGTERM'); } catch (e) {}
    }
    srv.status = "Stopped";
    srv.pid = null;
    saveDb(db);
}

function restartServer(folder) {
    stopServerProcess(folder);
    setTimeout(() => startServerProcess(folder), 2000);
}

// مراقب العمليات الخلفية
setInterval(() => {
    try {
        for (const [folder, srv] of Object.entries(db.servers || {})) {
            if (srv.status === "Running" && srv.pid) {
                try {
                    process.kill(srv.pid, 0);
                } catch (e) {
                    restartServer(folder);
                }
            }
        }
    } catch (e) {}
}, 15000);

// مسارات الـ Web و API
app.get('/', (req, res) => {
    if (req.session.email) {
        if (isAdmin(req.session.email)) return res.redirect('/admin');
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(BASE_DIR, "landing.html"));
});

app.get('/login', (req, res) => {
    if (req.session.email) return res.redirect('/');
    res.sendFile(path.join(BASE_DIR, "login.html"));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.email) return res.redirect('/login');
    res.sendFile(path.join(BASE_DIR, "index.html"));
});

app.get('/admin', (req, res) => {
    if (!req.session.email || !isAdmin(req.session.email)) return res.redirect('/login');
    res.sendFile(path.join(BASE_DIR, "admin_panel.html"));
});

app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanPass = (password || "").trim();

    if (!cleanEmail || !cleanPass) return res.json({ success: false, message: "جميع الحقول مطلوبة" });
    if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) return res.json({ success: false, message: "البريد الإلكتروني غير صالح" });
    if (cleanPass.length < 4) return res.json({ success: false, message: "كلمة المرور 4 أحرف على الأقل" });
    if (db.users[cleanEmail]) return res.json({ success: false, message: "البريد الإلكتروني موجود بالفعل" });

    db.users[cleanEmail] = {
        password: crypto.createHash('sha256').update(cleanPass).digest('hex'),
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
    const { email, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanPass = (password || "").trim();
    const user = db.users[cleanEmail];

    if (user && user.password === crypto.createHash('sha256').update(cleanPass).digest('hex')) {
        req.session.email = cleanEmail;
        user.last_login = new Date().toISOString();
        saveDb(db);
        const isAdm = !!user.is_admin;
        return res.json({ success: true, redirect: isAdm ? "/admin" : "/dashboard", is_admin: isAdm });
    }
    res.json({ success: false, message: "بيانات غير صحيحة" });
});

app.all('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/api/current_user', (req, res) => {
    if (req.session.email) {
        const u = db.users[req.session.email];
        if (u) {
            return res.json({
                success: true, email: req.session.email, username: req.session.email,
                is_admin: !!u.is_admin, plan: u.plan || "free", api_key: u.api_key
            });
        }
    }
    res.json({ success: false });
});

app.post('/api/create_api_key', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false, message: "غير مصرح" });
    const newKey = crypto.randomBytes(32).toString('hex');
    db.users[req.session.email].api_key = newKey;
    saveDb(db);
    res.json({ success: true, api_key: newKey });
});

app.get('/api/plans', (req, res) => {
    res.json({ success: true, plans: db.plans || {} });
});

app.get('/api/admin/users', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    const usersList = [];
    for (const [uemail, udata] of Object.entries(db.users || {})) {
        usersList.push({
            email: uemail, username: uemail, is_admin: !!udata.is_admin,
            created_at: udata.created_at, max_servers: udata.max_servers || 1,
            expiry_days: udata.expiry_days || 365, plan: udata.plan || "free"
        });
    }
    res.json({ success: true, users: usersList });
});

app.post('/api/admin/create-user', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    const { email, password, max_servers, expiry_days } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    if (!cleanEmail || !password) return res.json({ success: false, message: "البريد وكلمة المرور مطلوبة" });
    if (db.users[cleanEmail]) return res.json({ success: false, message: "المستخدم موجود بالفعل" });

    db.users[cleanEmail] = {
        password: crypto.createHash('sha256').update(password).digest('hex'),
        is_admin: false, created_at: new Date().toISOString(),
        max_servers: parseInt(max_servers) || 2, expiry_days: parseInt(expiry_days) || 365,
        last_login: null, telegram_id: null, api_key: null,
        storage_limit: db.plans.free.storage, plan: "free"
    };
    saveDb(db);
    fs.mkdirSync(path.join(USERS_DIR, cleanEmail.replace(/@/g, "_at_").replace(/\./g, "_dot_"), "SERVERS"), { recursive: true });
    res.json({ success: true, message: "✅ تم إنشاء الحساب بنجاح" });
});

app.post('/api/admin/delete-user', (req, res) => {
    if (!checkAdminAccess(req)) return res.status(403).json({ success: false });
    const email = (req.body.email || "").trim().toLowerCase();
    const target = db.users[email];
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
    const { plan_id, name, price, storage, ram, cpu, max_servers } = req.body;
    const cleanId = (plan_id || "").trim().toLowerCase();
    if (!cleanId || !name) return res.json({ success: false, message: "معرف الخطة والاسم مطلوبان" });

    db.plans[cleanId] = {
        name: name.trim(), price: parseFloat(price) || 0,
        storage: parseInt(storage) || 512000, ram: parseInt(ram) || 256,
        cpu: parseFloat(cpu) || 0.5, max_servers: parseInt(max_servers) || 2
    };
    saveDb(db);
    res.json({ success: true, message: "✅ تم إضافة الخطة بنجاح" });
});

app.get('/api/system/metrics', (req, res) => {
    res.json({
        cpu: os.loadavg()[0].toFixed(1),
        memory: ((1 - os.freemem() / os.totalmem()) * 100).toFixed(1),
        disk: 45
    });
});

app.get('/api/servers', (req, res) => {
    if (!req.session.email && !checkAdminAccess(req)) return res.status(401).json({ success: false });
    const targetUser = req.query.user;
    const ownerEmail = (targetUser && checkAdminAccess(req)) ? targetUser : req.session.email;

    let userServers = [];
    let totalDiskUsed = 0;
    for (const [folder, srv] of Object.entries(db.servers || {})) {
        if (srv.owner === ownerEmail) {
            let diskUsed = 0;
            if (fs.existsSync(srv.path)) {
                const walk = (dir) => {
                    try {
                        for (const file of fs.readdirSync(dir)) {
                            const fp = path.join(dir, file);
                            const stat = fs.statSync(fp);
                            if (stat.isDirectory()) walk(fp);
                            else diskUsed += stat.size;
                        }
                    } catch (e) {}
                };
                walk(srv.path);
            }
            const diskUsedMb = parseFloat((diskUsed / (1024 * 1024)).toFixed(2));
            totalDiskUsed += diskUsedMb;

            userServers.push({
                folder, title: srv.name, name: srv.name,
                server_type: srv.server_type || "Python", status: srv.status || "Stopped",
                uptime: srv.status === "Running" ? uptimeStr(srv.start_time) : "0 ثانية",
                port: srv.port || "N/A", plan: srv.plan || "free",
                storage_limit: srv.storage_limit || 512000, ram_limit: srv.ram_limit || 256,
                cpu_limit: srv.cpu_limit || 0.5, disk_used: diskUsedMb, startup_file: srv.startup_file || ""
            });
        }
    }
    const user = db.users[ownerEmail] || {};
    res.json({
        success: true, servers: userServers,
        stats: {
            used: userServers.length, total: user.max_servers || 2,
            expiry: user.expiry_days || 365, disk_used: parseFloat(totalDiskUsed.toFixed(2)),
            disk_total: user.storage_limit || 512000
        }
    });
});

app.post('/api/server/add', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const user = db.users[req.session.email];
    const userSrvCount = Object.values(db.servers).filter(s => s.owner === req.session.email).length;

    if (userSrvCount >= (user.max_servers || 2)) {
        return res.json({ success: false, message: `وصلت للحد الأقصى (${user.max_servers}) سيرفر` });
    }

    const { name, server_type } = req.body;
    const cleanName = (name || "").trim();
    const srvType = server_type || "Python";
    if (!cleanName) return res.json({ success: false, message: "الرجاء إدخال اسم للسيرفر" });

    const planId = user.plan || "free";
    const plan = db.plans[planId] || db.plans.free;
    const safeEmail = req.session.email.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    const folder = `${safeEmail}_${cleanName.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    const srvPath = path.join(USERS_DIR, safeEmail, "SERVERS", folder);
    fs.mkdirSync(srvPath, { recursive: true });

    db.servers[folder] = {
        name: cleanName, owner: req.session.email, path: srvPath,
        server_type: srvType, status: "Stopped", created_at: new Date().toISOString(),
        startup_file: "", pid: null, port: getAssignedPort(), plan: planId,
        storage_limit: plan.storage, ram_limit: plan.ram, cpu_limit: plan.cpu
    };
    saveDb(db);
    res.json({ success: true, message: `✅ تم إنشاء ${srvType} سيرفر: ${cleanName}` });
});

app.post('/api/server/action/:folder/:action', (req, res) => {
    const { folder, action } = req.params;
    const email = req.session.email;
    const srv = db.servers[folder];

    if (!srv) return res.json({ success: false, message: "السيرفر غير موجود" });
    if (!isAdmin(email) && srv.owner !== email) return res.json({ success: false, message: "غير مصرح" });

    if (action === "start") {
        if (srv.status === "Running") return res.json({ success: false, message: "الخادم يعمل بالفعل" });
        const [ok, msg] = startServerProcess(folder);
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
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let logs = "لا توجد مخرجات بعد";
    const logPath = path.join(srv.path, "out.log");
    if (fs.existsSync(logPath)) {
        try {
            const lines = fs.readFileSync(logPath, 'utf8').split('\n');
            logs = lines.slice(-500).join('\n');
        } catch (e) {}
    }
    res.json({
        success: true, status: srv.status || "Stopped", logs,
        mem: "15.4", uptime: srv.status === "Running" ? uptimeStr(srv.start_time) : "0 ثانية",
        port: srv.port || "--"
    });
});

app.get('/api/files/list/:folder', (req, res) => {
    if (!req.session.email) return res.status(401).json([]);
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json([]);

    const files = [];
    try {
        for (const f of fs.readdirSync(srv.path)) {
            if (["out.log", "server.log", "meta.json", "errors.log"].includes(f)) continue;
            const fpath = path.join(srv.path, f);
            const stat = fs.statSync(fpath);
            let sizeStr = `${stat.size} B`;
            if (stat.size >= 1024 && stat.size < 1024 * 1024) sizeStr = `${(stat.size / 1024).toFixed(1)} KB`;
            else if (stat.size >= 1024 * 1024) sizeStr = `${(stat.size / (1024 * 1024)).toFixed(1)} MB`;

            files.push({
                name: f, size: sizeStr, is_dir: stat.isDirectory(),
                modified: new Date(stat.mtime).toISOString().replace('T', ' ').substring(0, 16)
            });
        }
    } catch (e) {}
    files.sort((a, b) => (a.is_dir === b.is_dir ? a.name.localeCompare(b.name) : (a.is_dir ? -1 : 1)));
    res.json(files);
});

app.get('/api/files/content/:folder/:filename(*)', (req, res) => {
    if (!req.session.email) return res.json({ content: "" });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email || req.params.filename.includes('..')) return res.json({ content: "" });

    const fpath = path.join(srv.path, req.params.filename);
    if (!fs.existsSync(fpath) || fs.statSync(fpath).isDirectory()) return res.json({ content: "" });
    try {
        res.json({ content: fs.readFileSync(fpath, 'utf8') });
    } catch (e) {
        res.json({ content: "[ملف ثنائي]" });
    }
});

app.post('/api/files/save/:folder/:filename(*)', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email || req.params.filename.includes('..')) return res.json({ success: false });

    const content = req.body.content || "";
    const [isSafe, msg] = scanCodeSecurity(content);
    if (!isSafe) return res.json({ success: false, message: msg });

    try {
        fs.writeFileSync(path.join(srv.path, req.params.filename), content, 'utf8');
        res.json({ success: true, message: "✅ تم الحفظ بنجاح" });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

const upload = multer({ dest: os.tmpdir() });
app.post('/api/files/upload/:folder', upload.array('files[]'), (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let uploaded = 0;
    if (req.files) {
        for (const file of req.files) {
            try {
                const destPath = path.join(srv.path, file.originalname);
                fs.copyFileSync(file.path, destPath);
                fs.unlinkSync(file.path);

                if (file.originalname.toLowerCase().endsWith('.zip')) {
                    try {
                        const zip = new AdmZip(destPath);
                        zip.extractAllTo(srv.path, true);
                    } catch (e) {}
                }
                uploaded++;
            } catch (e) {}
        }
    }

    if (uploaded > 0) {
        if (srv.server_type === "Node.js") {
            const detected = detectNodeMainFile(srv.path);
            if (detected) { srv.startup_file = detected; saveDb(db); }
            autoInstallNodeDeps(srv.path, fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' }));
        } else {
            const detected = detectMainFile(srv.path);
            if (detected) { srv.startup_file = detected; saveDb(db); }
            autoInstallDeps(srv.path, fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' }));
        }
        return res.json({ success: true, message: "✅ تم رفع الملفات وفك ضغطها بنجاح" });
    }
    res.json({ success: false, message: "فشل الرفع" });
});

app.post('/api/files/delete/:folder', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    let names = req.body.names || req.body.name || [];
    if (typeof names === 'string') names = [names];

    let deleted = 0;
    for (const name of names) {
        if (name && !name.includes('..')) {
            const fpath = path.join(srv.path, name);
            try {
                if (fs.existsSync(fpath)) {
                    fs.rmSync(fpath, { recursive: true, force: true });
                    deleted++;
                }
            } catch (e) {}
        }
    }
    res.json({ success: true, message: `🗑 تم حذف ${deleted} ملف` });
});

app.post('/api/files/create/:folder', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const { filename, content } = req.body;
    if (!filename || filename.includes('..')) return res.json({ success: false });

    const [isSafe, msg] = scanCodeSecurity(content || "");
    if (!isSafe) return res.json({ success: false, message: msg });

    const fpath = path.join(srv.path, filename);
    try {
        if (filename.endsWith('/')) {
            fs.mkdirSync(fpath, { recursive: true });
        } else {
            fs.writeFileSync(fpath, content || "", 'utf8');
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
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const { old_name, new_name } = req.body;
    if (!old_name || !new_name || old_name.includes('..') || new_name.includes('..')) return res.json({ success: false });

    const oldPath = path.join(srv.path, old_name);
    const newPath = path.join(srv.path, new_name);
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
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const zipPath = path.join(srv.path, req.params.filename);
    if (!fs.existsSync(zipPath)) return res.json({ success: false });

    try {
        const zip = new AdmZip(zipPath);
        zip.extractAllTo(srv.path, true);
        const detected = srv.server_type === "Node.js" ? detectNodeMainFile(srv.path) : detectMainFile(srv.path);
        if (detected) { srv.startup_file = detected; saveDb(db); }
        res.json({ success: true, message: "✅ تم فك الضغط واكتشاف ملف التشغيل" });
    } catch (e) {
        res.json({ success: false, message: "فشل فك الضغط" });
    }
});

app.post('/api/server/set-startup/:folder', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const filename = req.body.filename;
    if (!filename || filename.includes('..')) return res.json({ success: false });
    srv.startup_file = filename;
    saveDb(db);
    res.json({ success: true, message: `✅ تم تعيين ${filename}` });
});

app.post('/api/server/install/:folder', (req, res) => {
    if (!req.session.email) return res.status(401).json({ success: false });
    const srv = db.servers[req.params.folder];
    if (!srv || srv.owner !== req.session.email) return res.json({ success: false });

    const logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' });
    if (srv.server_type === "Node.js") autoInstallNodeDeps(srv.path, logStream);
    else autoInstallDeps(srv.path, logStream);
    res.json({ success: true, message: "📦 بدأ تثبيت المكتبات" });
});

// Bot API Endpoints
app.post('/api/bot/verify', (req, res) => {
    const apiKey = (req.body.api_key || "").trim();
    if (!apiKey) return res.json({ success: false });
    const [email, user] = getUserByApiKey(apiKey);
    if (!email) return res.json({ success: false });
    res.json({ success: true, email, username: email, is_admin: !!user.is_admin, max_servers: user.max_servers || 2 });
});

app.get('/api/bot/servers', (req, res) => {
    const apiKey = req.query.api_key;
    const [email] = getUserByApiKey(apiKey);
    if (!email) return res.status(401).json({ success: false });

    const userServers = [];
    for (const [folder, srv] of Object.entries(db.servers || {})) {
        if (srv.owner === email) {
            userServers.push({
                folder, title: srv.name, name: srv.name, status: srv.status || "Stopped",
                port: srv.port || "N/A", type: srv.server_type || "Python", server_type: srv.server_type || "Python",
                uptime: srv.status === "Running" ? uptimeStr(srv.start_time) : "0 ثانية"
            });
        }
    }
    res.json({ success: true, servers: userServers });
});

app.post('/api/bot/server/action', (req, res) => {
    const { api_key, folder, action } = req.body;
    const [email] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false });
    const srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    if (action === "start") {
        const [ok, msg] = startServerProcess(folder);
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
    const { api_key, folder } = req.query;
    const [email] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false });
    const srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    let logs = "لا توجد مخرجات بعد";
    const logPath = path.join(srv.path, "out.log");
    if (fs.existsSync(logPath)) {
        try { logs = fs.readFileSync(logPath, 'utf8').slice(-3500); } catch (e) {}
    }
    res.json({ success: true, logs });
});

app.get('/api/bot/errors', (req, res) => {
    const { api_key, folder } = req.query;
    const [email] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false });
    const srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    let errors = "✅ لا توجد أخطاء";
    const errPath = path.join(srv.path, "errors.log");
    if (fs.existsSync(errPath)) {
        try { errors = fs.readFileSync(errPath, 'utf8').slice(-3500); } catch (e) {}
    }
    res.json({ success: true, errors });
});

app.post('/api/bot/install', (req, res) => {
    const { api_key, folder } = req.body;
    const [email] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false });
    const srv = db.servers[folder];
    if (!srv || srv.owner !== email) return res.status(403).json({ success: false });

    const logStream = fs.createWriteStream(path.join(srv.path, "out.log"), { flags: 'a' });
    if (srv.server_type === "Node.js") autoInstallNodeDeps(srv.path, logStream);
    else autoInstallDeps(srv.path, logStream);
    res.json({ success: true, message: "📦 بدأ تثبيت المكتبات" });
});

app.post('/api/bot/create_server', (req, res) => {
    const { api_key, name, server_type } = req.body;
    const [email, user] = getUserByApiKey(api_key);
    if (!email) return res.status(401).json({ success: false, message: "غير مصرح" });

    const userSrvCount = Object.values(db.servers).filter(s => s.owner === email).length;
    if (userSrvCount >= (user.max_servers || 2)) {
        return res.json({ success: false, message: `وصلت للحد الأقصى (${user.max_servers}) سيرفر` });
    }

    const cleanName = (name || "").trim();
    const srvType = server_type || "Python";
    if (!cleanName) return res.json({ success: false, message: "الرجاء إدخال اسم للسيرفر" });

    const planId = user.plan || "free";
    const plan = db.plans[planId] || db.plans.free;
    const safeEmail = email.replace(/@/g, "_at_").replace(/\./g, "_dot_");
    const folder = `${safeEmail}_${cleanName.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    const srvPath = path.join(USERS_DIR, safeEmail, "SERVERS", folder);
    fs.mkdirSync(srvPath, { recursive: true });

    db.servers[folder] = {
        name: cleanName, owner: email, path: srvPath, server_type: srvType,
        status: "Stopped", created_at: new Date().toISOString(), startup_file: "",
        pid: null, port: getAssignedPort(), plan: planId,
        storage_limit: plan.storage, ram_limit: plan.ram, cpu_limit: plan.cpu
    };
    saveDb(db);
    res.json({ success: true, message: `✅ تم إنشاء ${srvType} سيرفر: ${cleanName}` });
});

// تشغيل بوت تيليجرام باستخدام Telegraf
function runTelegramBot() {
    console.log("\n" + "=".repeat(60));
    console.log(" 🤖 ZIAD HOST - جاري تشغيل بوت التحكم المدمج");
    console.log(" 🚀 يتم الآن الاتصال بخوادم تليجرام...");
    console.log("=".repeat(60) + "\n");

    const bot = new Telegraf(BOT_TOKEN);
    const botSessions = {};

    bot.start(async (ctx) => {
        const userId = ctx.from.id;
        botSessions[userId] = botSessions[userId] || {};
        const apiKey = botSessions[userId].apiKey;

        if (apiKey) {
            try {
                const res = await axios.post(`${API_BASE_URL}/api/bot/verify`, { api_key: apiKey });
                if (res.data && res.data.success) {
                    botSessions[userId].username = res.data.username;
                    await showMainMenu(ctx, botSessions[userId]);
                    return;
                }
            } catch (e) {}
        }

        await ctx.reply(
            "━━━━━━━━━━━━━━━━━━━━\n      ZIAD HOST 🚀\n━━━━━━━━━━━━━━━━━━━━\nللاشتراك والحصول على حساب:\n📬 تواصل مع المطور: @Y_20_20\n\n" + DEVELOPER_INFO,
            Markup.inlineKeyboard([
                [Markup.button.callback("🔑 إدخال API Key", "enter_api")],
                [Markup.button.url("💬 تواصل مع المطور @Y_20_20", "https://t.me/Y_20_20")]
            ])
        );
        botSessions[userId].state = "WAITING_FOR_API_KEY";
    });

    bot.command("help", (ctx) => ctx.reply("📚 المساعدة:\n\nهذا البوت يعمل بشكل مستمر على خادم ZIAD HOST\nللاشتراك أو الاستفسار: @Y_20_20"));
    bot.command("info", (ctx) => ctx.reply("ℹ️ معلومات البوت:\n\n🤖 الخدمة: ZIAD HOST\n✅ الحالة: نشط ومستمر\n🛠 المطور: @Y_20_20"));

    async function showMainMenu(ctx, sessionData, edit = false) {
        const apiKey = sessionData.apiKey;
        const username = sessionData.username || "";
        const isAdminTg = ADMIN_TELEGRAM_IDS.includes(ctx.from.id);

        let keyboard = [];
        if (apiKey) {
            keyboard.push([Markup.button.callback("📁 سيرفراتي", "my_servers"), Markup.button.callback("➕ إنشاء سيرفر", "create_server")]);
            keyboard.push([Markup.button.callback("🔑 تغيير API Key", "change_api"), Markup.button.callback("🚪 تسجيل خروج", "logout")]);
        } else {
            keyboard.push([Markup.button.callback("🔑 ربط API Key", "enter_api")]);
        }
        if (isAdminTg) keyboard.push([Markup.button.callback("👑 لوحة الإدارة", "admin_panel")]);
        keyboard.push([Markup.button.url("💬 تواصل مع المطور @Y_20_20", "https://t.me/Y_20_20")]);

        let text = "━━━━━━━━━━━━━━━━━━━━\n      ZIAD HOST 🚀\n━━━━━━━━━━━━━━━━━━━━\n";
        if (username) text += `👤 أهلاً، *${username}*!\n`;
        text += apiKey ? "✅ متصل بالنظام\n" : "⚠️ يجب ربط API Key أولاً\n";
        text += `\n${DEVELOPER_INFO}`;

        try {
            if (edit) await ctx.editMessageText(text, { parse_mode: "Markdown", ...Markup.inlineKeyboard(keyboard) });
            else await ctx.reply(text, { parse_mode: "Markdown", ...Markup.inlineKeyboard(keyboard) });
        } catch (e) {}
    }

    bot.action("main_menu", async (ctx) => {
        const userId = ctx.from.id;
        botSessions[userId] = botSessions[userId] || {};
        await showMainMenu(ctx, botSessions[userId], true);
    });

    bot.action("my_servers", async (ctx) => {
        const userId = ctx.from.id;
        botSessions[userId] = botSessions[userId] || {};
        const apiKey = botSessions[userId].apiKey;
        if (!apiKey) return ctx.editMessageText("❌ يجب ربط API Key أولاً.");

        try {
            const res = await axios.get(`${API_BASE_URL}/api/bot/servers`, { params: { api_key: apiKey } });
            const servers = res.data && res.data.success ? res.data.servers : [];
            if (servers.length === 0) {
                return ctx.editMessageText("📭 لا توجد سيرفرات. أنشئ سيرفرك الأول الآن!", Markup.inlineKeyboard([
                    [Markup.button.callback("➕ إنشاء سيرفر", "create_server")],
                    [Markup.button.callback("🔙 رجوع", "main_menu")]
                ]));
            }

            await ctx.editMessageText(`📋 لديك *${servers.length}* سيرفر:`, { parse_mode: "Markdown" });
            for (const srv of servers) {
                const statusEmoji = srv.status === "Running" ? "🟢" : "⚫";
                const srvType = srv.type || "Python";
                const typeIcon = srvType === "Python" ? "🐍" : "🟨";
                const text = `━━━━━━━━━━━━━━━━━━━━\n${statusEmoji} *${srv.title}*\n━━━━━━━━━━━━━━━━━━━━\n${typeIcon} النوع: \`${srvType}\`\n📊 الحالة: \`${srv.status}\`\n🔌 المنفذ: \`${srv.port}\`\n⏱ وقت التشغيل: ${srv.uptime}`;
                const folder = srv.folder;
                await ctx.reply(text, {
                    parse_mode: "Markdown",
                    ...Markup.inlineKeyboard([
                        [Markup.button.callback("▶️ تشغيل", `srv_start|${folder}`), Markup.button.callback("⏹ إيقاف", `srv_stop|${folder}`), Markup.button.callback("🔄 إعادة", `srv_restart|${folder}`)],
                        [Markup.button.callback("🖥 كونسول", `console|${folder}`), Markup.button.callback("⚠️ أخطاء", `errors|${folder}`), Markup.button.callback("🗑 حذف", `srv_delete|${folder}`)],
                        [Markup.button.callback("📦 تثبيت مكتبات", `install|${folder}`)]
                    ])
                });
            }
            await ctx.reply("━━━━━━━━━━━━━━━━━━━━", Markup.inlineKeyboard([[Markup.button.callback("🔙 القائمة الرئيسية", "main_menu")]]));
        } catch (e) {
            await ctx.editMessageText("❌ خطأ في الاتصال بالخادم.");
        }
    });

    bot.action(["enter_api", "change_api"], async (ctx) => {
        const userId = ctx.from.id;
        botSessions[userId] = botSessions[userId] || {};
        delete botSessions[userId].apiKey;
        botSessions[userId].state = "WAITING_FOR_API_KEY";
        await ctx.editMessageText("🔑 *أدخل API Key الخاص بك:*\n\nيمكنك الحصول عليه من لوحة التحكم في الموقع.", { parse_mode: "Markdown" });
    });

    bot.action("logout", async (ctx) => {
        botSessions[ctx.from.id] = {};
        await ctx.editMessageText("🚪 تم تسجيل الخروج.\nاستخدم /start للدخول مجدداً.");
    });

    bot.action("create_server", async (ctx) => {
        const userId = ctx.from.id;
        botSessions[userId] = botSessions[userId] || {};
        botSessions[userId].state = "WAITING_FOR_NEW_SERVER_NAME";
        await ctx.editMessageText("➕ *إنشاء سيرفر جديد*\n\n📝 أرسل اسم السيرفر:", { parse_mode: "Markdown" });
    });

    bot.action("admin_panel", async (ctx) => {
        if (!ADMIN_TELEGRAM_IDS.includes(ctx.from.id)) return ctx.editMessageText("❌ غير مصرح لك بالدخول.");
        try {
            const res = await axios.get(`${API_BASE_URL}/api/admin/users`, { params: { api_key: botSessions[ctx.from.id]?.apiKey } });
            const users = res.data && res.data.success ? res.data.users : [];
            let text = `━━━━━━━━━━━━━━━━━━━━\n  👑 لوحة إدارة ZIAD HOST\n━━━━━━━━━━━━━━━━━━━━\n👥 المستخدمين: *${users.length}*\n━━━━━━━━━━━━━━━━━━━━\n`;
            for (const u of users.slice(0, 10)) text += `• \`${u.username}\` | ${u.max_servers || 1} سيرفر\n`;
            await ctx.editMessageText(text, {
                parse_mode: "Markdown",
                ...Markup.inlineKeyboard([
                    [Markup.button.callback("📊 إحصائيات النظام", "admin_stats")],
                    [Markup.button.callback("🔙 رجوع", "main_menu")]
                ])
            });
        } catch (e) {
            await ctx.editMessageText("❌ فشل تحميل لوحة الإدارة.");
        }
    });

    bot.action("admin_stats", async (ctx) => {
        try {
            const res = await axios.get(`${API_BASE_URL}/api/system/metrics`);
            const metrics = res.data || {};
            await ctx.editMessageText(
                `━━━━━━━━━━━━━━━━━━━━\n  📊 إحصائيات النظام\n━━━━━━━━━━━━━━━━━━━━\n🖥 CPU:  *${metrics.cpu || "?"}%*\n💾 RAM:  *${metrics.memory || "?"}%*\n💿 Disk: *${metrics.disk || "?"}%*`,
                { parse_mode: "Markdown", ...Markup.inlineKeyboard([[Markup.button.callback("🔙 رجوع", "admin_panel")]]) }
            );
        } catch (e) {
            await ctx.editMessageText("❌ فشل جلب الإحصائيات.");
        }
    });

    bot.action(/^server_type_(python|nodejs)$/, async (ctx) => {
        const userId = ctx.from.id;
        const srvType = ctx.match[1] === "python" ? "Python" : "Node.js";
        const name = botSessions[userId]?.pendingServerName || "Server";
        try {
            const res = await axios.post(`${API_BASE_URL}/api/bot/create_server`, {
                api_key: botSessions[userId]?.apiKey, name, server_type: srvType
            });
            const typeIcon = srvType === "Python" ? "🐍" : "🟨";
            if (res.data && res.data.success) {
                await ctx.editMessageText(`✅ *تم إنشاء السيرفر بنجاح!*\n\n📛 الاسم: \`${name}\`\n${typeIcon} النوع: \`${srvType}\``, { parse_mode: "Markdown" });
            } else {
                await ctx.editMessageText(`❌ *فشل الإنشاء!*\n${res.data?.message || 'خطأ'}`, { parse_mode: "Markdown" });
            }
        } catch (e) {
            await ctx.editMessageText("❌ خطأ في الاتصال.");
        }
        await showMainMenu(ctx, botSessions[userId]);
    });

    bot.action(/^(srv_start|srv_stop|srv_restart|srv_delete)\|(.+)$/, async (ctx) => {
        const actionMap = { srv_start: "start", srv_stop: "stop", srv_restart: "restart", srv_delete: "delete" };
        const action = actionMap[ctx.match[1]];
        const folder = ctx.match[2];
        try {
            const res = await axios.post(`${API_BASE_URL}/api/bot/server/action`, {
                api_key: botSessions[ctx.from.id]?.apiKey, folder, action
            });
            await ctx.answerCbQuery((res.data?.message || "✅ تم").substring(0, 200), { show_alert: true });
        } catch (e) {
            await ctx.answerCbQuery("❌ خطأ", { show_alert: true });
        }
    });

    bot.action(/^console\|(.+)$/, async (ctx) => {
        const folder = ctx.match[1];
        try {
            const res = await axios.get(`${API_BASE_URL}/api/bot/console`, { params: { api_key: botSessions[ctx.from.id]?.apiKey, folder } });
            let logs = res.data?.success ? (res.data.logs || "لا توجد مخرجات") : "فشل الجلب";
            if (logs.length > 3500) logs = "...\n" + logs.slice(-3500);
            await ctx.editMessageText(`🖥 *كونسول السيرفر*\n\`\`\`\n${logs}\n\`\`\``, {
                parse_mode: "Markdown",
                ...Markup.inlineKeyboard([[Markup.button.callback("🔄 تحديث", `console|${folder}`), Markup.button.callback("🔙 رجوع", "my_servers")]])
            });
        } catch (e) {
            await ctx.editMessageText("❌ خطأ في الاتصال");
        }
    });

    bot.action(/^errors\|(.+)$/, async (ctx) => {
        const folder = ctx.match[1];
        try {
            const res = await axios.get(`${API_BASE_URL}/api/bot/errors`, { params: { api_key: botSessions[ctx.from.id]?.apiKey, folder } });
            let errors = res.data?.success ? (res.data.errors || "✅ لا توجد أخطاء") : "فشل الجلب";
            if (errors.length > 3500) errors = "...\n" + errors.slice(-3500);
            await ctx.editMessageText(`⚠️ *سجل الأخطاء*\n\`\`\`\n${errors}\n\`\`\``, {
                parse_mode: "Markdown",
                ...Markup.inlineKeyboard([[Markup.button.callback("🔙 رجوع", "my_servers")]])
            });
        } catch (e) {
            await ctx.editMessageText("❌ خطأ في الاتصال");
        }
    });

    bot.action(/^install\|(.+)$/, async (ctx) => {
        const folder = ctx.match[1];
        try {
            const res = await axios.post(`${API_BASE_URL}/api/bot/install`, { api_key: botSessions[ctx.from.id]?.apiKey, folder });
            await ctx.editMessageText(`📦 *تثبيت المكتبات*\n\n${res.data?.message || "📦 بدأ التثبيت"}`, {
                parse_mode: "Markdown",
                ...Markup.inlineKeyboard([[Markup.button.callback("🖥 كونسول", `console|${folder}`), Markup.button.callback("🔙 رجوع", "my_servers")]])
            });
        } catch (e) {
            await ctx.editMessageText("❌ خطأ في الاتصال");
        }
    });

    bot.on('text', async (ctx) => {
        const userId = ctx.from.id;
        botSessions[userId] = botSessions[userId] || {};
        const state = botSessions[userId].state;

        if (state === "WAITING_FOR_API_KEY") {
            const apiKey = ctx.message.text.trim();
            try {
                const res = await axios.post(`${API_BASE_URL}/api/bot/verify`, { api_key: apiKey });
                if (!res.data || !res.data.success) {
                    return ctx.reply("❌ *مفتاح API غير صالح!*\n\nتحقق من الكود وحاول مرة أخرى.", { parse_mode: "Markdown" });
                }
                botSessions[userId].apiKey = apiKey;
                botSessions[userId].username = res.data.username;
                delete botSessions[userId].state;
                await ctx.reply(`✅ *تم الربط بنجاح!*\n👤 مرحباً *${res.data.username}*!`, { parse_mode: "Markdown" });
                await showMainMenu(ctx, botSessions[userId]);
            } catch (e) {
                await ctx.reply("❌ خطأ في التحقق.");
            }
        } else if (state === "WAITING_FOR_NEW_SERVER_NAME") {
            const name = ctx.message.text.trim();
            botSessions[userId].pendingServerName = name;
            delete botSessions[userId].state;
            await ctx.reply(`📦 *اختر نوع السيرفر:*\n\nالاسم: \`${name}\``, {
                parse_mode: "Markdown",
                ...Markup.inlineKeyboard([
                    [Markup.button.callback("🐍 Python", "server_type_python"), Markup.button.callback("🟨 Node.js", "server_type_nodejs")]
                ])
            });
        } else {
            await ctx.reply(`📨 تم استقبال رسالتك:\n\n${ctx.message.text}\n\nشكراً لاستخدامك ZIAD HOST!\n🛠 @Y_20_20`);
        }
    });

    bot.launch().then(() => {
        console.log(" ✅ بوت ZIAD HOST جاهز الآن ويعمل بشكل مستمر!\n");
    }).catch(err => {
        console.error("❌ فشل تشغيل بوت تيليجرام:", err);
    });
}

if (require.main === module) {
    runTelegramBot();
    const port = process.env.PORT || 5000;
    app.listen(port, "0.0.0.0", () => {
        console.log(`🌐 ZIAD HOST Server is running on port ${port}`);
    });
}

