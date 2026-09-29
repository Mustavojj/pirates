import express from 'express';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(__dirname));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const BOT_TOKEN = process.env.BOT_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const requestCooldown = new Map();
const notifiedUsers = new Set();
const getUserCache = new Map();
const activeWithdrawals = new Set();
const taskCompletionLocks = new Map();
const promoCodeLocks = new Map();

function logError(endpoint, error, extra = {}) {
    console.error(`❌ [${endpoint}] Error:`, error.message || error, Object.keys(extra).length ? JSON.stringify(extra) : '');
}

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    keyGenerator: (req) => req._userId?.toString() || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down.' }
});

const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: (req) => req._userId?.toString() || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait.' }
});

const veryStrictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    keyGenerator: (req) => req._userId?.toString() || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait longer.' }
});

app.use('/api/', generalLimiter);

function checkCooldown(userId, endpoint, cooldownMs = 1500) {
    const now = Date.now();
    const key = `${userId}_${endpoint}`;
    const lastCall = requestCooldown.get(key) || 0;
    if (now - lastCall < cooldownMs) return false;
    requestCooldown.set(key, now);
    return true;
}

function checkTaskCompletionCooldown(userId) {
    const now = Date.now();
    const key = `task_completion_${userId}`;
    const lastCompletion = taskCompletionLocks.get(key) || 0;
    const cooldownMs = 10000;
    if (now - lastCompletion < cooldownMs) {
        const remaining = Math.ceil((cooldownMs - (now - lastCompletion)) / 1000);
        return { allowed: false, remaining };
    }
    return { allowed: true, remaining: 0 };
}

function setTaskCompletionCooldown(userId) {
    taskCompletionLocks.set(`task_completion_${userId}`, Date.now());
}

function checkPromoCooldown(userId) {
    const now = Date.now();
    const key = `promo_${userId}`;
    const lastPromo = promoCodeLocks.get(key) || 0;
    const cooldownMs = 5000;
    if (now - lastPromo < cooldownMs) {
        const remaining = Math.ceil((cooldownMs - (now - lastPromo)) / 1000);
        return { allowed: false, remaining };
    }
    return { allowed: true, remaining: 0 };
}

function setPromoCooldown(userId) {
    promoCodeLocks.set(`promo_${userId}`, Date.now());
}

function validateUserId(userId) {
    return userId && typeof userId === 'number' && userId > 0;
}

function validateTelegramInitData(initData, botToken) {
    if (!initData || !botToken) {
        return { valid: false, error: 'Missing initData or bot token' };
    }
    try {
        const urlParams = new URLSearchParams(initData);
        const hash = urlParams.get('hash');
        if (!hash) return { valid: false, error: 'Missing hash' };
        urlParams.delete('hash');
        const dataCheckString = Array.from(urlParams.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');
        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
        const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
        if (calculatedHash !== hash) return { valid: false, error: 'Invalid hash' };
        const authDate = parseInt(urlParams.get('auth_date'));
        const now = Math.floor(Date.now() / 1000);
        if (now - authDate > 86400) return { valid: false, error: 'initData expired' };
        const userJson = urlParams.get('user');
        let user = null;
        if (userJson) {
            try { user = JSON.parse(userJson); } catch (e) { return { valid: false, error: 'Invalid user data' }; }
        }
        return { valid: true, user, authDate };
    } catch (error) {
        return { valid: false, error: error.message };
    }
}

function generateJWT(userId) {
    return jwt.sign({ userId, iat: Math.floor(Date.now() / 1000) }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyJWT(token) {
    try { return jwt.verify(token, JWT_SECRET); } catch (error) { return null; }
}

function authenticate(req, res, next) {
    let token = req.cookies?.token;
    if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) token = authHeader.split(' ')[1];
    }
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = verifyJWT(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });
    req._userId = decoded.userId;
    next();
}

async function checkBotIsAdminInChannel(channelUsername) {
    if (!BOT_TOKEN) return false;
    try {
        const botInfo = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`).then(r => r.json());
        if (!botInfo.ok) return false;
        const botId = botInfo.result.id;
        const botMember = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channelUsername}&user_id=${botId}`).then(r => r.json());
        if (!botMember.ok) return false;
        return ['administrator', 'creator'].includes(botMember.result?.status);
    } catch (error) { return false; }
}

async function checkUserInChannel(userId, channelUsername) {
    if (!BOT_TOKEN || !channelUsername) return true;
    try {
        const chatMember = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channelUsername}&user_id=${userId}`).then(r => r.json());
        return chatMember.ok && ['member', 'administrator', 'creator'].includes(chatMember.result?.status);
    } catch (error) { return false; }
}

const APP_CONFIG = {
    APP_NAME: "DOGS PIRATES 🏴‍☠️",
    BOT_USERNAME: "DogsPtsbot",
    MINIMUM_WITHDRAW: 500,
    WITHDRAWAL_FEES: 100,
    REFERRAL_PERCENTAGE: 10,
    MINING_SESSION_HOURS: 12,
    POWER_PER_DAY_RATE: 0.01,
    TASK_VERIFICATION_DELAY: 10,
    DEFAULT_USER_AVATAR: "https://i.ibb.co/jvBSQfvf/IMG-20260914-192504-728.jpg",
    TON_WALLET_ADDRESS: "UQAWoiLpbPqpHjpteK2CHGizA6OimyPXZBWsx9Nw1IMPyUrm",
    PAYMENT_WALLET: "UQAWoiLpbPqpHjpteK2CHGizA6OimyPXZBWsx9Nw1IMPyUrm",
    INTERSTITIAL_AD_BLOCK_ID: "int-47680",
    REWARD_AD_BLOCK_ID: "47678",
    BOT_LINK: "https://t.me/DogsPtsbot?start=",
    TASK_REWARD: 100,
    TASK_IMAGE: "https://i.ibb.co/jvBSQfvf/IMG-20260914-192504-728.jpg",
    DOGS_ICON: "https://i.ibb.co/m5JD7vwy/In-Collage.png",
    MINING_ICON: "https://i.ibb.co/m5JD7vwy/In-Collage.png",
    DOGS_TO_WITHDRAW_RATE: 1,
    GOLD_TO_POWER_RATE: 1,
    POWER_BONUS_PERCENTAGE: 10,
    REFERRAL_TASKS_PERCENTAGE: 20,
    REFERRAL_PROMO_PERCENTAGE: 20,
    REFERRAL_MINING_PERCENTAGE: 10,
    REFERRAL_MAX_PERCENTAGE: 50,
    REFERRAL_MAX_COMMISSION_DOGS: 20,
    REFERRAL_MAX_COMMISSION_POWER: 100,
    AD_REWARD_POWER: 20,
    MONETAG_AD_REWARD_POWER: 20,
    AD_COOLDOWN_MINUTES: 5,
    MONETAG_AD_COOLDOWN_MINUTES: 3,
    AD_DAILY_LIMIT: 10,
    MIN_CLAIM_DOGS: 1,
    PRICE_PER_100: 0.10,
    SOCIAL_DOGS_REWARD: 1,
    SPECIAL_TASK_PRICE: 10,
    SPECIAL_TASK_REWARD_POWER: 50,
    SPECIAL_TASK_REWARD_GOLD: 5,
    TASK_COMPLETION_COOLDOWN_SECONDS: 10,
    PROMO_CODE_COOLDOWN_SECONDS: 5,
    PROMO_CODE_POWER_PRICE_PER_1000: 0.05,
    PROMO_CODE_GOLD_PRICE_PER_1000: 0.10,
    PROMO_CODE_MIN_TOTAL: 50,
    PROMO_CODE_MAX_TOTAL: 5000,
    PROMO_CODES_CHANNEL: "https://t.me/DOGSPROMO",
    PROMO_CODES_CHANNEL_USERNAME: "DOGSPROMO",
    TASKS_CHANNEL: "@DOGSTASK",
    PAYMENTS_CHANNEL: "https://t.me/DOGSPAYO",
    QUESTS: {
        welcome_bonus: { reward: 1000, type: "power" },
        level_quests: [
            { target_level: 2, reward: 1000 },
            { target_level: 3, reward: 2000 },
            { target_level: 4, reward: 3000 },
            { target_level: 5, reward: 4000 },
            { target_level: 6, reward: 5000 },
            { target_level: 7, reward: 6000 },
            { target_level: 8, reward: 7000 },
            { target_level: 9, reward: 8000 },
            { target_level: 10, reward: 9000 }
        ],
        task_quests: [
            { target_tasks: 10, reward: 500 },
            { target_tasks: 50, reward: 1000 },
            { target_tasks: 100, reward: 2000 },
            { target_tasks: 500, reward: 3000 },
            { target_tasks: 1000, reward: 5000 }
        ],
        referral_quests: [
            { target_referrals: 5, reward: 1000 },
            { target_referrals: 10, reward: 2000 },
            { target_referrals: 25, reward: 4000 },
            { target_referrals: 50, reward: 7000 },
            { target_referrals: 100, reward: 10000 },
            { target_referrals: 250, reward: 15000 },
            { target_referrals: 500, reward: 20000 },
            { target_referrals: 1000, reward: 30000 }
        ]
    }
};

function calculateLevel(power) {
    if (power >= 600000) return 10;
    if (power >= 500000) return 9;
    if (power >= 400000) return 8;
    if (power >= 300000) return 7;
    if (power >= 200000) return 6;
    if (power >= 100000) return 5;
    if (power >= 80000) return 4;
    if (power >= 40000) return 3;
    if (power >= 20000) return 2;
    return 1;
}

async function updateUserLevel(userId) {
    const user = await getUser(userId);
    if (!user) return;
    const newLevel = calculateLevel(user.power_balance || 0);
    if (user.level !== newLevel) await updateUser(userId, { level: newLevel });
    return newLevel;
}

function getCurrentTime() { return Date.now(); }

function calculateMiningReward(powerBalance, startTime, endTime) {
    const sessionHours = (endTime - startTime) / 3600000;
    const dailyRate = (powerBalance / 1000) * 10;
    const hourlyRate = dailyRate / 24;
    return hourlyRate * sessionHours;
}

async function addReferralCommission(referrerId, amount, type) {
    if (!referrerId || amount <= 0) return;
    const referrer = await getUser(referrerId);
    if (!referrer || referrer.state === 'ban') return;
    const MAX_DOGS = APP_CONFIG.REFERRAL_MAX_COMMISSION_DOGS || 20;
    const MAX_POWER = APP_CONFIG.REFERRAL_MAX_COMMISSION_POWER || 100;
    let updates = {};
    let actualAmount = 0;
    if (type === 'dogs') {
        const current = referrer.referral_dogs_earnings || 0;
        actualAmount = Math.min(amount, MAX_DOGS);
        updates.referral_dogs_earnings = current + actualAmount;
    } else if (type === 'power') {
        const current = referrer.referral_power_earnings || 0;
        actualAmount = Math.min(amount, MAX_POWER);
        updates.referral_power_earnings = current + actualAmount;
    }
    if (Object.keys(updates).length > 0) await updateUser(referrerId, updates);
}

async function checkLargeTransaction(userId, amount, source) {
    if (amount >= 500) {
        const user = await getUser(userId);
        const adminId = process.env.ADMIN_USER_ID;
        if (adminId && user) {
            await sendTelegramNotification(adminId, '💰 LARGE TRANSACTION!',
                `User: ${user.first_name} (${userId})\n🐕 Amount: +${amount.toFixed(3)} DOGS\n📌 Source: ${source}`);
        }
    }
}

async function getUser(userId) {
    try {
        const { data, error } = await supabase.from('users').select('*').eq('id', userId).single();
        if (error && error.code !== 'PGRST116') throw error;
        return data;
    } catch (error) { return null; }
}

async function createUser(userData) {
    try {
        const { data, error } = await supabase.from('users').insert([userData]).select().single();
        if (error) throw error;
        return data;
    } catch (error) { throw error; }
}

async function updateUser(userId, updates) {
    try {
        const { data, error } = await supabase.from('users').update(updates).eq('id', userId).select().single();
        if (error) throw error;
        getUserCache.delete(`getUser_${userId}`);
        return data;
    } catch (error) { throw error; }
}

async function isMemoUsed(memo) {
    try {
        const { data } = await supabase.from('confirmed_memos').select('memo').eq('memo', memo).maybeSingle();
        return !!data;
    } catch (error) { return false; }
}

async function recordMemo(memo, userId) {
    const { error } = await supabase.from('confirmed_memos').insert([{ memo, user_id: userId, used_at: getCurrentTime() }]);
    if (error) throw error;
    return true;
}

async function getTasks(category, userId) {
    try {
        let query = supabase.from('tasks').select('*').eq('status', 'active');
        if (category) query = query.eq('category', category);
        const { data: tasks, error } = await query;
        if (error) throw error;
        const { data: completed } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId);
        const completedIds = new Set(completed?.map(t => t.task_id) || []);
        return tasks.filter(task => !completedIds.has(task.id)) || [];
    } catch (error) { return []; }
}

async function getSpecialTasks(userId) {
    try {
        const { data: tasks, error } = await supabase.from('special_tasks').select('*').eq('status', 'active');
        if (error) throw error;
        const { data: completed } = await supabase.from('user_completed_special_tasks').select('task_id').eq('user_id', userId);
        const completedIds = new Set(completed?.map(t => t.task_id) || []);
        return (tasks || []).map(task => ({
            ...task,
            is_completed: completedIds.has(task.id),
            can_complete: !completedIds.has(task.id) && task.owner !== userId
        }));
    } catch (error) { return []; }
}

async function getMySpecialTasks(userId) {
    try {
        const { data: tasks, error } = await supabase.from('special_tasks').select('*').eq('owner', userId).order('created_at', { ascending: false });
        if (error) throw error;
        return tasks || [];
    } catch (error) { return []; }
}

async function getCompletedTasks(userId) {
    try {
        const { data, error } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId);
        if (error) throw error;
        return data ? data.map(t => t.task_id) : [];
    } catch (error) { return []; }
}

async function getCompletedSpecialTasks(userId) {
    try {
        const { data, error } = await supabase.from('user_completed_special_tasks').select('task_id').eq('user_id', userId);
        if (error) throw error;
        return data ? data.map(t => t.task_id) : [];
    } catch (error) { return []; }
}

async function getWithdrawals(userId) {
    try {
        const { data, error } = await supabase.from('withdrawals').select('*').eq('user_id', userId).order('timestamp', { ascending: false }).limit(10);
        if (error) throw error;
        return data || [];
    } catch (error) { return []; }
}

async function getReferrals(userId) {
    try {
        const { data, error } = await supabase.from('users').select('id, first_name, username, created_at').eq('referred_by', userId);
        if (error) throw error;
        return data || [];
    } catch (error) { return []; }
}

async function getPromoCode(code) {
    try {
        const { data, error } = await supabase.from('promo_codes').select('*').eq('code', code).single();
        if (error && error.code !== 'PGRST116') throw error;
        return data;
    } catch (error) { return null; }
}

async function getMyPromoCodes(userId) {
    try {
        const { data, error } = await supabase.from('promo_codes').select('*').eq('owner', userId).order('created_at', { ascending: false });
        if (error) throw error;
        return data || [];
    } catch (error) { return []; }
}

async function getActivePromoCodes(userId) {
    try {
        const { data: codes, error } = await supabase.from('promo_codes').select('*').eq('status', 'active').gt('max_uses', 0);
        if (error) throw error;
        const { data: used } = await supabase.from('used_promo_codes').select('code').eq('user_id', userId);
        const usedCodes = new Set(used?.map(u => u.code) || []);
        return (codes || []).filter(c => !usedCodes.has(c.code) && (c.total_uses || 0) < c.max_uses && c.owner !== userId);
    } catch (error) { return []; }
}

async function usePromoCode(userId, code) {
    try {
        const { data, error } = await supabase.from('used_promo_codes').insert([{ user_id: userId, code, used_at: getCurrentTime() }]).select().single();
        if (error) throw error;
        return data;
    } catch (error) { throw error; }
}

async function incrementPromoUses(code) {
    try {
        const { data: promo } = await supabase.from('promo_codes').select('total_uses').eq('code', code).single();
        const newTotal = (promo?.total_uses || 0) + 1;
        const { data, error } = await supabase.from('promo_codes').update({ total_uses: newTotal }).eq('code', code).select().single();
        if (error) throw error;
        return data;
    } catch (error) { throw error; }
}

async function createWithdrawal(withdrawalData) {
    try {
        const { data, error } = await supabase.from('withdrawals').insert([withdrawalData]).select().single();
        if (error) throw error;
        return data;
    } catch (error) { throw error; }
}

async function sendTelegramNotification(userId, title, message, inlineButton = null) {
    if (!BOT_TOKEN || !userId) return;
    try {
        const payload = { chat_id: userId, text: message, parse_mode: 'HTML', disable_web_page_preview: true };
        if (inlineButton) {
            payload.reply_markup = { inline_keyboard: [[{ text: inlineButton.text, url: inlineButton.url }]] };
        }
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (error) { logError('sendTelegramNotification', error); }
}

async function sendWithdrawalProof(channelId, userId, wallet, dogsAmount, txHash) {
    if (!BOT_TOKEN || !channelId) return;
    try {
        const userIdStr = userId.toString();
        const maskedUserId = userIdStr.slice(0, -3) + '***';
        const walletFirst = wallet.substring(0, 5);
        const walletLast = wallet.substring(wallet.length - 5);
        const maskedWallet = walletFirst + '****' + walletLast;
        const explorerUrl = txHash ? `https://tonscan.org/tx/${txHash}` : '#';
        const message = `<b>🆕 New Withdrawal Confirmed!</b>\n\n` +
            `<b>👤 User:</b> ${maskedUserId}\n` +
            `<b>💰 Amount:</b> ${dogsAmount.toFixed(0)} DOGS\n` +
            `<b>📥 Wallet:</b> ${maskedWallet}\n` +
            `<b>⏳ Status:</b> Confirmed\n\n` +
            `<b>⛏️ MINE & EARN FREE DOGS</b>`;
        const payload = {
            chat_id: channelId,
            text: message,
            parse_mode: 'HTML',
            disable_web_page_preview: true,
            reply_markup: {
                inline_keyboard: [
                    [{ text: '🔘 View on Explorer', url: explorerUrl }],
                    [{ text: '🏴‍☠️ DOGS PIRATES', url: 'https://t.me/DogsPtsbot?start=start' }]
                ]
            }
        };
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (error) { logError('sendWithdrawalProof', error); }
}

class OxaPay {
    constructor(config) {
        this.apiKey = config.apiKey;
        this.sandbox = config.sandbox || false;
        this.baseUrl = this.sandbox ? 'https://sandbox.oxapay.com/v1' : 'https://api.oxapay.com/v1';
    }
    async request(endpoint, data) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { 'Content-Type': 'application/json', 'payout_api_key': this.apiKey };
        try {
            const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(data) });
            const responseText = await response.text();
            let result;
            try { result = JSON.parse(responseText); } catch (e) { throw new Error('Invalid response from OxaPay'); }
            if (!response.ok || result.status !== 200) throw new Error(result.message || result.error || `HTTP ${response.status}`);
            return result;
        } catch (error) { throw error; }
    }
    async createPayout(data) {
        try {
            const payload = { address: data.toAddress, amount: data.amount, currency: data.currency || 'DOGS', network: data.network || 'TON', description: data.description || 'Withdrawal' };
            const result = await this.request('/payout', payload);
            const trackId = result?.data?.track_id || result?.track_id;
            const status = result?.data?.status || result?.status || 'processing';
            const txHash = result?.data?.tx_hash || result?.tx_hash || null;
            return { ...result, trackId: trackId || 'N/A', status, txHash, success: true };
        } catch (error) { throw error; }
    }
    async getPayoutStatus(trackId) {
        const url = `${this.baseUrl}/payout/${trackId}`;
        const headers = { 'payout_api_key': this.apiKey, 'Content-Type': 'application/json' };
        try {
            const response = await fetch(url, { method: 'GET', headers });
            const responseText = await response.text();
            let result;
            try { result = JSON.parse(responseText); } catch (e) { throw new Error('Invalid response from OxaPay'); }
            if (!response.ok || result.status !== 200) throw new Error(result.message || result.error || `HTTP ${response.status}`);
            return result;
        } catch (error) { throw error; }
    }
}

async function checkPendingWithdrawals() {
    try {
        const { data: withdrawals, error } = await supabase.from('withdrawals').select('*').in('status', ['pending', 'processing']).limit(50);
        if (error || !withdrawals || withdrawals.length === 0) return;
        const oxapay = new OxaPay({ apiKey: process.env.OXAPAY_API_KEY, sandbox: process.env.NODE_ENV !== 'production' });
        for (const withdrawal of withdrawals) {
            try {
                const statusResult = await oxapay.getPayoutStatus(withdrawal.tx_id);
                if (statusResult && statusResult.data) {
                    const oxaPayStatus = statusResult.data.status;
                    if (oxaPayStatus === 'confirmed' || oxaPayStatus === 'completed') {
                        await supabase.from('withdrawals').update({ status: 'completed', tx_hash: statusResult.data.tx_hash || withdrawal.tx_hash }).eq('id', withdrawal.id);
                        const userMessage = `<b>✅ Your Withdrawal Confirmed!</b>\n\n` +
                            `💰 <code>${withdrawal.dogs_amount.toFixed(0)}</code> <b>DOGS has been sent</b>\n\n` +
                            `<a href="${statusResult.data.tx_hash ? `https://tonscan.org/tx/${statusResult.data.tx_hash}` : '#'}">🔘 View transaction on Explorer</a>\n\n`;
                        await sendTelegramNotification(withdrawal.user_id, '✅ Withdrawal Completed!', userMessage);
                        const user = await getUser(withdrawal.user_id);
                        const username = user?.username ? '@' + user.username : 'N/A';
                        const adminId = process.env.ADMIN_USER_ID;
                        const adminMessage = `<b>✅ Withdrawal Completed!</b>\n\n` +
                            `<b>👤 User:</b> ${withdrawal.user_id} (${username})\n` +
                            `<b>💰 Amount:</b> ${withdrawal.dogs_amount.toFixed(0)} DOGS\n` +
                            `<b>📥 Wallet:</b> ${withdrawal.wallet}\n` +
                            `<b>🔗 TX:</b> <a href="${statusResult.data.tx_hash ? `https://tonscan.org/tx/${statusResult.data.tx_hash}` : '#'}">View on Explorer</a>`;
                        await sendTelegramNotification(adminId, '✅ Withdrawal Completed!', adminMessage);
                        const proofChannel = APP_CONFIG.PAYMENTS_CHANNEL || process.env.PAYMENTS_CHANNEL;
                        if (proofChannel) {
                            const channelMatch = proofChannel.match(/t\.me\/([^\/\?]+)/);
                            if (channelMatch) {
                                await sendWithdrawalProof('@' + channelMatch[1], withdrawal.user_id, withdrawal.wallet, withdrawal.dogs_amount, statusResult.data.tx_hash || withdrawal.tx_hash);
                            }
                        }
                    }
                }
            } catch (error) { logError('checkPendingWithdrawals', error); }
        }
    } catch (error) { logError('checkPendingWithdrawals', error); }
}

setInterval(async () => { await checkPendingWithdrawals(); }, 60000);
setTimeout(() => { checkPendingWithdrawals(); }, 10000);

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/health', (req, res) => { res.status(200).send('OK'); });
app.get('/api/health', (req, res) => { res.json({ status: 'ok', time: getCurrentTime() }); });
app.get('/api/config', (req, res) => { res.json(APP_CONFIG); });
app.get('/api/current-time', (req, res) => { res.json({ serverTime: getCurrentTime() }); });

app.post('/api/check-bot-admin', authenticate, async (req, res) => {
    try {
        const { channel } = req.body;
        if (!channel) return res.status(400).json({ error: 'Channel is required' });
        const isAdmin = await checkBotIsAdminInChannel(channel);
        res.json({ isAdmin });
    } catch (error) {
        logError('/api/check-bot-admin', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const secretToken = req.headers['x-telegram-bot-api-secret-token'];
    if (!WEBHOOK_SECRET || secretToken !== WEBHOOK_SECRET) {
        console.warn('🚫 Unauthorized webhook from:', req.ip);
        return res.sendStatus(403);
    }
    try {
        const update = req.body;
        if (update.message && update.message.chat && update.message.chat.type === 'private') {
            const chatId = update.message.chat.id;
            const username = update.message.chat.username || '';
            const firstName = update.message.chat.first_name || 'User';
            const photoUrl = update.message.chat.photo_url || APP_CONFIG.DEFAULT_USER_AVATAR;
            const text = update.message.text;
            let referrerId = null;
            if (text && text.startsWith('/start')) {
                const parts = text.split(' ');
                if (parts.length > 1 && !isNaN(parts[1])) referrerId = parseInt(parts[1]);
            }
            const appLink = referrerId ? `https://t.me/DogsPtsbot/app?startapp=${referrerId}` : `https://t.me/DogsPtsbot/app`;
            const existingUser = await getUser(chatId);
            if (!existingUser) {
                const userData = {
                    id: chatId,
                    username: username || '',
                    first_name: firstName || 'User',
                    photo_url: photoUrl || APP_CONFIG.DEFAULT_USER_AVATAR,
                    created_at: getCurrentTime(),
                    power_balance: 0,
                    dogs_balance: 0,
                    gram_balance: 0,
                    referral_power_earnings: 0,
                    referral_dogs_earnings: 0,
                    level: 1,
                    total_tasks_completed: 0,
                    total_mining_starts: 0,
                    referral_reward_given: false,
                    state: 'active',
                    verified: true,
                    quests: { welcome_bonus_claimed: false, current_level_quest_index: 0, current_task_quest_index: 0, current_referral_quest_index: 0 },
                    mining_active: false,
                    mining_start_time: null,
                    mining_end_time: null,
                    pending_dogs_reward: 0,
                    total_referrals: 0,
                    referral_power: 0,
                    ad_watch_count: 0,
                    ad_last_watch: 0,
                    monetag_ad_last_watch: 0,
                    promotion: null,
                    last_withdraw_time: 0,
                    last_withdraw_attempt: 0,
                    referred_by_verified: false,
                    wallet: null,
                    task_count: 0,
                    special_tasks_count: 0,
                    promo_codes_created: 0,
                    last_task_completion_time: 0,
                    last_promo_time: 0
                };
                if (referrerId && referrerId !== chatId) userData.referred_by = referrerId;
                try { await createUser(userData); } catch (createError) { console.error('Failed to create user:', createError.message); }
            } else {
                const updates = {};
                if (username && username !== existingUser.username) updates.username = username;
                if (firstName && firstName !== existingUser.first_name) updates.first_name = firstName;
                if (Object.keys(updates).length > 0) await updateUser(chatId, updates);
            }
            await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    photo: 'https://i.ibb.co/jvBSQfvf/IMG-20260914-192504-728.jpg',
                    caption: `<b>🏴‍☠️ Welcome to DOGS PIRATES!</b>\n\n` +
                        `⛏️ Mine and earn <b>free DOGS!</b>\n\n` +
                        `🎁 Claim <b>1000 power</b> welcome bonus\n` +
                        `📋 Complete tasks\n` +
                        `👷‍♂️ Invite friends\n` +
                        `🎟 Claim promo codes\n\n` +
                        `💰 Withdraw your funds <b>for free</b>\n` +
                        `⚡ Up to <b>60%</b> from referrals earnings\n` +
                        `⚡ Start your work to get <b>free DOGS!</b>`,
                    parse_mode: 'HTML',
                    reply_markup: { inline_keyboard: [
                        [{ text: '🏴‍☠️ Start App', url: appLink }],
                        [{ text: '📋 TASKS', url: 'https://t.me/DOGSTASK' }, { text: '💸 PAYOUTS', url: 'https://t.me/DOGSPAYO' }],
                        [{ text: '📰 Official Channel', url: 'https://t.me/DOGSPTS' }]
                    ]}
                })
            });
        }
        res.sendStatus(200);
    } catch (error) {
        console.error('Webhook error:', error);
        res.sendStatus(500);
    }
});

app.post('/api/check-membership', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { channel } = req.body;
        if (!channel) return res.status(400).json({ error: 'Channel is required' });
        if (!BOT_TOKEN) return res.json({ isMember: true, error: 'bot_not_configured' });
        const isAdmin = await checkBotIsAdminInChannel(channel);
        if (!isAdmin) return res.json({ isMember: true, error: 'bot_not_admin' });
        const isMember = await checkUserInChannel(userId, channel);
        res.json({ isMember });
    } catch (error) {
        logError('/api/check-membership', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth', strictLimiter, async (req, res) => {
    try {
        const { initData, userId } = req.body;
        if (!initData) {
            return res.status(400).json({ error: 'Missing initData' });
        }
        const validation = validateTelegramInitData(initData, BOT_TOKEN);
        if (!validation.valid) {
            return res.status(403).json({ error: 'Invalid Telegram data: ' + validation.error });
        }
        const telegramUser = validation.user;
        if (!telegramUser || !telegramUser.id) {
            return res.status(403).json({ error: 'No user data in initData' });
        }
        if (userId && telegramUser.id !== userId) {
            return res.status(403).json({ error: 'User ID mismatch' });
        }
        let user = await getUser(telegramUser.id);
        if (!user) {
            const userData = {
                id: telegramUser.id,
                username: telegramUser.username || '',
                first_name: telegramUser.first_name || 'User',
                photo_url: telegramUser.photo_url || APP_CONFIG.DEFAULT_USER_AVATAR,
                created_at: getCurrentTime(),
                power_balance: 0,
                dogs_balance: 0,
                gram_balance: 0,
                referral_power_earnings: 0,
                referral_dogs_earnings: 0,
                level: 1,
                total_tasks_completed: 0,
                total_mining_starts: 0,
                referral_reward_given: false,
                state: 'active',
                verified: true,
                quests: { welcome_bonus_claimed: false, current_level_quest_index: 0, current_task_quest_index: 0, current_referral_quest_index: 0 },
                mining_active: false,
                mining_start_time: null,
                mining_end_time: null,
                pending_dogs_reward: 0,
                total_referrals: 0,
                referral_power: 0,
                ad_watch_count: 0,
                ad_last_watch: 0,
                monetag_ad_last_watch: 0,
                promotion: null,
                last_withdraw_time: 0,
                last_withdraw_attempt: 0,
                referred_by_verified: false,
                wallet: null,
                task_count: 0,
                special_tasks_count: 0,
                promo_codes_created: 0,
                last_task_completion_time: 0,
                last_promo_time: 0
            };
            try { user = await createUser(userData); } catch (createError) {
                user = await getUser(telegramUser.id);
                if (!user) return res.status(500).json({ error: 'Failed to create user' });
            }
        } else {
            const updates = {};
            if (telegramUser.username && telegramUser.username !== user.username) updates.username = telegramUser.username;
            if (telegramUser.first_name && telegramUser.first_name !== user.first_name) updates.first_name = telegramUser.first_name;
            if (telegramUser.photo_url && telegramUser.photo_url !== user.photo_url) updates.photo_url = telegramUser.photo_url;
            if (Object.keys(updates).length > 0) user = await updateUser(telegramUser.id, updates);
        }
        if (user.state === 'ban') return res.status(403).json({ error: 'Account banned' });
        const token = generateJWT(user.id);
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, user, token });
    } catch (error) {
        logError('/api/auth', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/refresh', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.state === 'ban') return res.status(403).json({ error: 'Account banned' });
        const token = generateJWT(userId);
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, token });
    } catch (error) {
        logError('/api/refresh', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/logout', authenticate, async (req, res) => {
    try { res.clearCookie('token'); res.json({ success: true }); } catch (error) {
        logError('/api/logout', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/check-mining-status', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user || !user.mining_active || !user.mining_start_time) return res.json({ success: true, notified: 0 });
        const totalDuration = (APP_CONFIG.MINING_SESSION_HOURS || 12) * 3600000;
        const elapsed = getCurrentTime() - user.mining_start_time;
        if (elapsed < totalDuration || notifiedUsers.has(userId)) return res.json({ success: true, notified: 0 });
        const reward = calculateMiningReward(user.power_balance || 0, user.mining_start_time, getCurrentTime());
        await updateUser(userId, { mining_active: false, mining_start_time: null, mining_end_time: null, pending_dogs_reward: reward });
        await sendTelegramNotification(user.id, '⛏️ Mining Stopped!',
            `🏴‍☠️ Your mining session has ended.\n\n📊 You earned ${reward.toFixed(3)} DOGS\n\n🎁 Claim your rewards and restart mining!`,
            { text: 'CLAIM NOW', url: 'https://t.me/DogsPtsbot/app' });
        notifiedUsers.add(userId);
        res.json({ success: true, notified: 1 });
    } catch (error) {
        logError('/api/check-mining-status', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/claim-welcome-bonus', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.quests?.welcome_bonus_claimed || user.power_balance > 1000) return res.status(400).json({ error: 'Already claimed' });
        const reward = APP_CONFIG.QUESTS.welcome_bonus.reward || 1000;
        const updatedUser = await updateUser(userId, { power_balance: (user.power_balance || 0) + reward, quests: { ...user.quests, welcome_bonus_claimed: true } });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward });
    } catch (error) {
        logError('/api/claim-welcome-bonus', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/get-user', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { referredBy } = req.body;
        const cacheKey = `getUser_${userId}`;
        const cached = getUserCache.get(cacheKey);
        const now = Date.now();
        if (cached && (now - cached.timestamp) < 3000) return res.json(cached.data);
        if (!checkCooldown(userId, req.path)) return res.status(429).json({ error: 'Too many requests. Please wait 5 seconds.' });
        let user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'user_not_registered' });
        if (user.state === 'ban') return res.status(403).json({ error: 'Account banned', banned: true });
        if (referredBy && !user.referred_by && referredBy !== userId) {
            await updateUser(userId, { referred_by: referredBy });
            user = await getUser(userId);
        }
        const [completedTasks, completedSpecialTasks, withdrawals] = await Promise.all([
            getCompletedTasks(userId),
            getCompletedSpecialTasks(userId),
            getWithdrawals(userId)
        ]);
        await updateUserLevel(userId);
        user = await getUser(userId);
        const responseData = { user, completedTasks, completedSpecialTasks, withdrawals };
        getUserCache.set(cacheKey, { data: responseData, timestamp: now });
        res.json(responseData);
    } catch (error) {
        logError('/api/get-user', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/update-user', authenticate, async (req, res) => { res.json({ success: true }); });

app.post('/api/update-photo', authenticate, async (req, res) => {
    try {
        const { photoUrl } = req.body;
        if (!photoUrl || typeof photoUrl !== 'string' || !photoUrl.startsWith('http')) return res.json({ success: false });
        await updateUser(req._userId, { photo_url: photoUrl });
        res.json({ success: true });
    } catch (error) {
        logError('/api/update-photo', error);
        res.json({ success: false });
    }
});

app.post('/api/start-mining', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { serverTime } = req.body;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.mining_active) return res.status(400).json({ error: 'Mining already active' });
        const currentTime = serverTime || getCurrentTime();
        const sessionHours = APP_CONFIG.MINING_SESSION_HOURS || 12;
        const miningEndTime = currentTime + (sessionHours * 3600000);
        notifiedUsers.delete(userId);
        let updatedUser = await updateUser(userId, {
            mining_active: true,
            mining_start_time: currentTime,
            mining_end_time: miningEndTime,
            pending_dogs_reward: 0,
            total_mining_starts: (user.total_mining_starts || 0) + 1
        });
        if (!user.referred_by_verified && user.referred_by) {
            const referrer = await getUser(user.referred_by);
            if (referrer) {
                await updateUser(user.referred_by, { total_referrals: (referrer.total_referrals || 0) + 1 });
                await updateUser(userId, { referred_by_verified: true });
                updatedUser = await getUser(userId);
            }
        }
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser });
    } catch (error) {
        logError('/api/start-mining', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/stop-mining', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (!user.mining_active) return res.status(400).json({ error: 'No active mining session' });
        const currentTime = getCurrentTime();
        const sessionMs = (APP_CONFIG.MINING_SESSION_HOURS || 12) * 3600000;
        const elapsed = currentTime - user.mining_start_time;
        if (elapsed < sessionMs) return res.status(400).json({ error: 'Mining session not ended yet' });
        const rewardAmount = calculateMiningReward(user.power_balance || 0, user.mining_start_time, currentTime);
        const updatedUser = await updateUser(userId, {
            mining_active: false,
            mining_start_time: null,
            mining_end_time: null,
            pending_dogs_reward: rewardAmount
        });
        res.json({ success: true, user: updatedUser, reward: rewardAmount });
    } catch (error) {
        logError('/api/stop-mining', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/claim-mining', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const level = calculateLevel(user.power_balance || 0);
        if (user.level !== level) { await updateUser(userId, { level }); user.level = level; }
        if (user.mining_active) return res.status(400).json({ error: 'Mining session still active' });
        const rewardAmount = user.pending_dogs_reward || 0;
        if (rewardAmount <= 0) return res.status(400).json({ error: 'No rewards to claim' });
        if (rewardAmount > 1000) return res.status(400).json({ error: 'Failed to claim reward' });
        const maxReward = (user.power_balance / 1000) * 5 * 13;
        if (rewardAmount > maxReward) return res.status(400).json({ error: 'Failed to claim reward' });
        const newDogsBalance = (user.dogs_balance || 0) + rewardAmount;
        const updatedUser = await updateUser(userId, {
            dogs_balance: newDogsBalance,
            pending_dogs_reward: 0,
            mining_start_time: null,
            mining_end_time: null,
            mining_active: false
        });
        notifiedUsers.delete(userId);
        await checkLargeTransaction(userId, rewardAmount, 'Mining Claim');
        if (user.referred_by) {
            const referralEarning = rewardAmount * (APP_CONFIG.REFERRAL_MINING_PERCENTAGE / 100);
            await addReferralCommission(user.referred_by, referralEarning, 'dogs');
        }
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, claimed: rewardAmount });
    } catch (error) {
        logError('/api/claim-mining', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/claim-quest', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { questType } = req.body;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        let reward = 0;
        let newIndex = 0;
        let quests = { ...user.quests };
        if (questType === 'level') {
            const index = user.quests?.current_level_quest_index || 0;
            const quest = APP_CONFIG.QUESTS.level_quests[index];
            if (!quest) return res.status(400).json({ error: 'No level quest available' });
            if (user.level < quest.target_level) return res.status(400).json({ error: 'Level requirement not met' });
            reward = quest.reward;
            newIndex = index + 1;
            quests.current_level_quest_index = newIndex;
        } else if (questType === 'task') {
            const index = user.quests?.current_task_quest_index || 0;
            const quest = APP_CONFIG.QUESTS.task_quests[index];
            if (!quest) return res.status(400).json({ error: 'No task quest available' });
            if (user.total_tasks_completed < quest.target_tasks) return res.status(400).json({ error: 'Task requirement not met' });
            reward = quest.reward;
            newIndex = index + 1;
            quests.current_task_quest_index = newIndex;
        } else if (questType === 'referral') {
            const index = user.quests?.current_referral_quest_index || 0;
            const quest = APP_CONFIG.QUESTS.referral_quests[index];
            if (!quest) return res.status(400).json({ error: 'No referral quest available' });
            if (user.total_referrals < quest.target_referrals) return res.status(400).json({ error: 'Referral requirement not met' });
            reward = quest.reward;
            newIndex = index + 1;
            quests.current_referral_quest_index = newIndex;
        } else return res.status(400).json({ error: 'Invalid quest type' });
        const updatedUser = await updateUser(userId, { power_balance: (user.power_balance || 0) + reward, quests });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward, questType, questIndex: newIndex });
    } catch (error) {
        logError('/api/claim-quest', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/complete-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId, isPartner, taskOwner } = req.body;
        const cooldownCheck = checkTaskCompletionCooldown(userId);
        if (!cooldownCheck.allowed) {
            return res.status(429).json({ error: `Please wait ${cooldownCheck.remaining} seconds before completing another task` });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { data: task, error: taskError } = await supabase.from('tasks')
            .select('reward, total, total_completed, category, owner, notified, name, verification, url')
            .eq('id', taskId).single();
        if (taskError || !task) return res.status(404).json({ error: 'Task not found' });
        if (task.verification && task.url) {
            const chatId = task.url.match(/t\.me\/([^\/\?]+)/)?.[1];
            if (chatId) {
                const isMember = await checkUserInChannel(userId, chatId);
                if (!isMember) return res.status(400).json({ error: 'Join the channel first' });
            }
        }
        if (task.notified) return res.status(400).json({ error: 'Task already limited!' });
        if (task.total_completed >= task.total) {
            if (!task.notified && task.owner && task.owner !== userId) {
                await sendTelegramNotification(task.owner, '<b>✅ Task Completed!</b>', `<b>🏴‍☠️ Your task "${task.name}" has been completed!</b>`);
            }
            await supabase.from('tasks').update({ status: 'completed', notified: true }).eq('id', taskId);
            return res.status(400).json({ error: 'Task already limited!' });
        }
        const { data: completed } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId).eq('task_id', taskId).single();
        if (completed) return res.status(400).json({ error: 'Task already completed by you' });
        setTaskCompletionCooldown(userId);
        const newTotalCompleted = (task.total_completed || 0) + 1;
        await supabase.from('tasks').update({ total_completed: newTotalCompleted }).eq('id', taskId);
        await supabase.from('user_completed_tasks').insert([{ user_id: userId, task_id: taskId, completed_at: getCurrentTime() }]);
        let totalCompleted = (user.total_tasks_completed || 0) + 1;
        let dogsReward = 0;
        if (task.category === 'social') dogsReward = APP_CONFIG.SOCIAL_DOGS_REWARD || 1;
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + task.reward,
            dogs_balance: (user.dogs_balance || 0) + dogsReward,
            total_tasks_completed: totalCompleted,
            last_task_completion_time: getCurrentTime()
        });
        if (task.category === 'social' && task.owner && task.owner !== userId) {
            const { data: taskData } = await supabase.from('tasks').select('total, total_completed, notified, name').eq('id', taskId).single();
            if (taskData && taskData.total_completed >= taskData.total && !taskData.notified) {
                await supabase.from('tasks').update({ status: 'completed', notified: true }).eq('id', taskId);
                await sendTelegramNotification(task.owner, '<b>✅ Task Completed!</b>', `<b>🏴‍☠️ Your task "${taskData.name}" has been completed!</b>`);
            }
        }
        if (user.referred_by) {
            const referralEarning = task.reward * (APP_CONFIG.REFERRAL_TASKS_PERCENTAGE / 100);
            await addReferralCommission(user.referred_by, referralEarning, 'power');
        }
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward: task.reward });
    } catch (error) {
        logError('/api/complete-task', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/special-tasks', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const tasks = await getSpecialTasks(userId);
        res.json({ tasks });
    } catch (error) {
        logError('/api/special-tasks', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/my-special-tasks', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const tasks = await getMySpecialTasks(userId);
        res.json({ tasks });
    } catch (error) {
        logError('/api/my-special-tasks', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/complete-special-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId } = req.body;
        const cooldownCheck = checkTaskCompletionCooldown(userId);
        if (!cooldownCheck.allowed) {
            return res.status(429).json({ error: `Please wait ${cooldownCheck.remaining} seconds before completing another task` });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { data: task, error: taskError } = await supabase.from('special_tasks').select('*').eq('id', taskId).single();
        if (taskError || !task) return res.status(404).json({ error: 'Task not found' });
        if (task.verification && task.url) {
            const chatId = task.url.match(/t\.me\/([^\/\?]+)/)?.[1];
            if (chatId) {
                const isMember = await checkUserInChannel(userId, chatId);
                if (!isMember) return res.status(400).json({ error: 'Join the channel first' });
            }
        }
        const { data: completed } = await supabase.from('user_completed_special_tasks').select('task_id').eq('user_id', userId).eq('task_id', taskId).single();
        if (completed && task.once_per_user !== false) return res.status(400).json({ error: 'Task already completed!' });
        setTaskCompletionCooldown(userId);
        const newTotalCompleted = (task.total_completed || 0) + 1;
        await supabase.from('special_tasks').update({ total_completed: newTotalCompleted }).eq('id', taskId);
        if (!completed) {
            await supabase.from('user_completed_special_tasks').insert([{ user_id: userId, task_id: taskId, completed_at: getCurrentTime() }]);
        }
        const rewardPower = task.reward_power || APP_CONFIG.SPECIAL_TASK_REWARD_POWER || 50;
        const rewardGold = task.reward_gold || APP_CONFIG.SPECIAL_TASK_REWARD_GOLD || 5;
        let totalCompleted = (user.total_tasks_completed || 0) + 1;
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + rewardPower,
            dogs_balance: (user.dogs_balance || 0) + rewardGold,
            total_tasks_completed: totalCompleted,
            special_tasks_count: (user.special_tasks_count || 0) + 1,
            last_task_completion_time: getCurrentTime()
        });
        if (task.owner && task.owner !== userId) {
            await sendTelegramNotification(task.owner, '<b>✅ Special Task Completed!</b>', `<b>🏴‍☠️ Someone completed your task "${task.name}"!</b>`);
        }
        if (user.referred_by) {
            const referralEarning = rewardPower * (APP_CONFIG.REFERRAL_TASKS_PERCENTAGE / 100);
            await addReferralCommission(user.referred_by, referralEarning, 'power');
        }
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, rewardPower, rewardGold });
    } catch (error) {
        logError('/api/complete-special-task', error);
        res.status(500).json({ error: error.message });
    }
});

async function verifyAndAddSpecialTask(userId, taskData, memo) {
    const address = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS;
    if (!address) return { success: false, error: 'Payment wallet not configured' };
    if (!memo.startsWith(`special_${userId}_`)) return { success: false, error: 'Invalid payment memo' };
    if (await isMemoUsed(memo)) return { success: false, error: 'Transaction already used' };
    const response = await fetch(`https://toncenter.com/api/v2/getTransactions?address=${address}&limit=5`);
    const data = await response.json();
    if (!data.ok) return { success: false, error: 'Payment API error' };
    let foundTx = null;
    if (data.result && data.result.length > 0) {
        foundTx = data.result.find(tx => { const msg = tx.in_msg?.message; return msg && msg.includes(memo); });
    }
    if (!foundTx) return { success: false, error: 'Payment not found' };
    const onChainMemo = foundTx.in_msg?.message || '';
    if (onChainMemo !== memo) return { success: false, error: 'Invalid payment memo' };
    const txAmount = parseFloat(foundTx.in_msg?.value) / 1000000000 || 0;
    const requiredAmount = APP_CONFIG.SPECIAL_TASK_PRICE || 10;
    if (txAmount < requiredAmount * 0.98) return { success: false, error: 'Insufficient payment amount' };
    const { data: existingTask } = await supabase.from('special_tasks').select('id').eq('id', memo).maybeSingle();
    if (existingTask) return { success: false, error: 'Task already exists' };
    let verification = taskData.verification || false;
    if (verification && taskData.link) {
        const channelMatch = taskData.link.match(/t\.me\/([^\/\?]+)/);
        if (channelMatch) {
            const isAdmin = await checkBotIsAdminInChannel(channelMatch[1]);
            if (!isAdmin) return { success: false, error: 'Bot is not admin in the channel. Please add @DogsPtsbot as admin.' };
        }
    }
    const taskToAdd = {
        id: memo,
        name: taskData.name,
        url: taskData.link,
        reward_power: APP_CONFIG.SPECIAL_TASK_REWARD_POWER || 50,
        reward_gold: APP_CONFIG.SPECIAL_TASK_REWARD_GOLD || 5,
        verification,
        owner: userId,
        total_completed: 0,
        status: 'active',
        once_per_user: true,
        created_at: getCurrentTime(),
        notified: false
    };
    const { data: taskResult, error: taskError } = await supabase.from('special_tasks').insert([taskToAdd]).select().single();
    if (taskError) return { success: false, error: 'Failed to add task' };
    const user = await getUser(userId);
    await updateUser(userId, { special_tasks_count: (user.special_tasks_count || 0) + 1 });
    await recordMemo(memo, userId);
    await sendSpecialTaskCreatedNotification(taskResult);
    return { success: true, task: taskResult, message: 'Payment verified and special task added' };
}

app.post('/api/check-payment', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { memo, amount, taskData, taskType } = req.body;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (taskType === 'special') {
            const result = await verifyAndAddSpecialTask(userId, taskData, memo);
            return res.json(result);
        }
        const address = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS;
        if (!address) return res.status(500).json({ error: 'Payment wallet not configured' });
        if (!memo.startsWith(`task_${userId}_`)) {
            return res.json({ success: false, error: 'Invalid payment memo' });
        }
        if (await isMemoUsed(memo)) return res.json({ success: false, error: 'Transaction already used' });
        const response = await fetch(`https://toncenter.com/api/v2/getTransactions?address=${address}&limit=3`);
        const data = await response.json();
        if (!data.ok) return res.status(500).json({ error: 'Payment API error' });
        let foundTx = null;
        if (data.result && data.result.length > 0) {
            foundTx = data.result.find(tx => { const msg = tx.in_msg?.message; return msg && msg.includes(memo); });
        }
        if (!foundTx) return res.json({ success: false, error: 'Payment not found' });
        const onChainMemo = foundTx.in_msg?.message || '';
        if (onChainMemo !== memo) return res.json({ success: false, error: 'Failed to create task.' });
        const txAmount = parseFloat(foundTx.in_msg?.value) / 1000000000 || 0;
        const rewardNum = parseInt(taskData.reward);
        const totalNum = parseInt(taskData.total);
        if (rewardNum > 100) return res.json({ success: false, error: 'Failed to create task.' });
        if (totalNum < 100 || totalNum > 5000) return res.json({ success: false, error: 'Failed to create task.' });
        if (rewardNum * totalNum > 50000) return res.json({ success: false, error: 'Failed to create task.' });
        const requiredAmount = (taskData.total * taskData.reward / 1000) * (APP_CONFIG.PRICE_PER_100 || 0.001);
        if (txAmount < requiredAmount * 0.98) return res.json({ success: false, error: 'Insufficient payment amount' });
        let verification = taskData.verification || false;
        if (verification && taskData.link) {
            const channelMatch = taskData.link.match(/t\.me\/([^\/\?]+)/);
            if (channelMatch) {
                const isAdmin = await checkBotIsAdminInChannel(channelMatch[1]);
                if (!isAdmin) return res.json({ success: false, error: 'Bot is not admin in the channel. Please add @DogsPtsbot as admin.' });
            }
        }
        const { data: existingTask } = await supabase.from('tasks').select('id').eq('id', memo).maybeSingle();
        if (existingTask) return res.json({ success: false, error: 'Failed to create task.' });
        const taskToAdd = {
            id: memo,
            name: taskData.name,
            url: taskData.link,
            category: 'social',
            reward: taskData.reward,
            total: taskData.total,
            verification,
            owner: userId,
            status: 'active',
            created_at: getCurrentTime(),
            total_completed: 0,
            notified: false
        };
        const { data: taskResult, error: taskError } = await supabase.from('tasks').insert([taskToAdd]).select().single();
        if (taskError) return res.status(500).json({ error: 'Failed to add task' });
        await updateUser(userId, { task_count: (user.task_count || 0) + 1 });
        await recordMemo(memo, userId);
        await sendTaskCreatedNotification(taskResult);
        res.json({ success: true, task: taskResult, message: 'Payment verified and task added' });
    } catch (error) {
        logError('/api/check-payment', error);
        res.status(500).json({ error: error.message });
    }
});

async function sendTaskCreatedNotification(task) {
    try {
        const CHANNEL_ID = APP_CONFIG.TASKS_CHANNEL;
        if (!BOT_TOKEN) return;
        const appLink = `https://t.me/DogsPtsbot/app`;
        const message = `<b>⚡ NEW TASK AVAILABLE!</b>\n\n` +
            `<b>📋 Task: ${task.name}</b>\n` +
            `<b>👷‍♂️ Target: ${task.total} </b>\n` +
            `<b>⏳ Status: ACTIVE</b>\n\n` +
            `<b>🎁 Reward: ${task.reward} POWER + ${APP_CONFIG.SOCIAL_DOGS_REWARD || 1} DOGS</b>`;
        const replyMarkup = { inline_keyboard: [[{ text: '✅ COMPLETE NOW', url: appLink }]] };
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHANNEL_ID, text: message, parse_mode: 'HTML', reply_markup: replyMarkup, disable_web_page_preview: true })
        });
    } catch (error) { console.error('Failed to send task notification:', error); }
}

async function sendSpecialTaskCreatedNotification(task) {
    try {
        const CHANNEL_ID = APP_CONFIG.TASKS_CHANNEL;
        if (!BOT_TOKEN) return;
        const appLink = `https://t.me/DogsPtsbot/app`;
        const message = `<b>⭐ NEW SPECIAL TASK!</b>\n\n` +
            `<b>📋 Task: ${task.name}</b>\n` +
            `<b>⏳ Status: UNLIMITED</b>\n` +
            `<b>👥 Total Completed: ${task.total_completed || 0}</b>\n\n` +
            `<b>🎁 Reward: ${task.reward_power} POWER + ${task.reward_gold} DOGS</b>`;
        const replyMarkup = { inline_keyboard: [[{ text: '⭐ COMPLETE NOW', url: appLink }]] };
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHANNEL_ID, text: message, parse_mode: 'HTML', reply_markup: replyMarkup, disable_web_page_preview: true })
        });
    } catch (error) { console.error('Failed to send special task notification:', error); }
}

async function sendPromoCodeCreatedNotification(promo) {
    try {
        const CHANNEL_ID = APP_CONFIG.PROMO_CODES_CHANNEL_USERNAME;
        if (!BOT_TOKEN || !CHANNEL_ID) return;
        const appLink = `https://t.me/DogsPtsbot/app`;
        const rewardDisplay = promo.reward_type === 'power' ? `${promo.reward_amount} POWER` : `${promo.reward_amount} DOGS`;
        const message = `<b>🎟 NEW PROMO CODE!</b>\n\n` +
            `<b>🎟 CODE:</b> <code>${promo.code}</code>\n` +
            `<b>🎁 Reward:</b> ${rewardDisplay}\n` +
            `<b>👥 Valid for:</b> ${promo.max_uses} ${promo.max_uses === 1 ? 'user' : 'users'}\n` +
            (promo.required_channel ? `<b>📢 Required:</b> @${promo.required_channel}\n` : '') +
            `<b>⏳ Status:</b> ACTIVE`;
        const replyMarkup = { inline_keyboard: [[{ text: '🎟 CLAIM NOW', url: appLink }]] };
        const sendResult = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: '@' + CHANNEL_ID, text: message, parse_mode: 'HTML', reply_markup: replyMarkup, disable_web_page_preview: true })
        });
        const sendData = await sendResult.json();
        if (sendData.ok && sendData.result?.message_id) {
            try {
                await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/pinChatMessage`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ chat_id: '@' + CHANNEL_ID, message_id: sendData.result.message_id, disable_notification: true })
                });
            } catch (pinError) { console.error('Pin error:', pinError.message); }
        }
    } catch (error) { console.error('Failed to send promo code notification:', error); }
}

app.post('/api/create-special-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { name, link, verification, memo } = req.body;
        if (!name || name.length < 5 || name.length > 20) return res.status(400).json({ error: 'Name must be between 5-20 characters' });
        if (!link || !link.startsWith('https://')) return res.status(400).json({ error: 'Please enter a valid link starting with https://' });
        if (!memo) return res.status(400).json({ error: 'Missing payment memo' });
        const result = await verifyAndAddSpecialTask(userId, { name, link, verification }, memo);
        res.json(result);
    } catch (error) {
        logError('/api/create-special-task', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/delete-special-task', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId } = req.body;
        const { data: task, error: checkError } = await supabase.from('special_tasks').select('owner').eq('id', taskId).single();
        if (checkError || !task) return res.status(404).json({ error: 'Task not found' });
        if (task.owner !== userId) return res.status(403).json({ error: 'Not authorized' });
        await supabase.from('special_tasks').delete().eq('id', taskId);
        await supabase.from('user_completed_special_tasks').delete().eq('task_id', taskId);
        res.json({ success: true });
    } catch (error) {
        logError('/api/delete-special-task', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/promo-codes', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const codes = await getActivePromoCodes(userId);
        res.json({ codes });
    } catch (error) {
        logError('/api/promo-codes', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/my-promo-codes', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const codes = await getMyPromoCodes(userId);
        res.json({ codes });
    } catch (error) {
        logError('/api/my-promo-codes', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/generate-promo-code', authenticate, strictLimiter, async (req, res) => {
    try {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code = 'PTS-';
        for (let i = 0; i < 4; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
        res.json({ code });
    } catch (error) {
        logError('/api/generate-promo-code', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/create-promo-code', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { code, rewardType, rewardAmount, maxUses, requiredChannel, notifyChannel, memo } = req.body;
        if (!code || code.length < 5 || code.length > 20) return res.status(400).json({ error: 'Code must be between 5-20 characters' });
        if (!/^[A-Z0-9\-]+$/i.test(code)) return res.status(400).json({ error: 'Code must be alphanumeric' });
        if (!['power', 'dogs'].includes(rewardType)) return res.status(400).json({ error: 'Invalid reward type' });
        const amount = parseInt(rewardAmount);
        if (isNaN(amount) || amount < 1 || amount > 1000000) return res.status(400).json({ error: 'Invalid reward amount' });
        const uses = parseInt(maxUses);
        if (isNaN(uses) || uses < APP_CONFIG.PROMO_CODE_MIN_TOTAL || uses > APP_CONFIG.PROMO_CODE_MAX_TOTAL) {
            return res.status(400).json({ error: `Max uses must be between ${APP_CONFIG.PROMO_CODE_MIN_TOTAL}-${APP_CONFIG.PROMO_CODE_MAX_TOTAL}` });
        }
        if (!memo) return res.status(400).json({ error: 'Missing payment memo' });
        if (!memo.startsWith(`promo_${userId}_`)) return res.status(400).json({ error: 'Invalid payment memo' });
        if (!memo.includes(`_${code.toUpperCase()}_`)) return res.status(400).json({ error: 'Memo does not match code' });
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const existingCode = await getPromoCode(code);
        if (existingCode) return res.status(400).json({ error: 'Code already exists' });
        if (await isMemoUsed(memo)) return res.status(400).json({ error: 'Transaction already used' });
        if (requiredChannel) {
            if (!/^[a-zA-Z0-9_]+$/.test(requiredChannel)) return res.status(400).json({ error: 'Invalid channel format' });
            const isAdmin = await checkBotIsAdminInChannel(requiredChannel);
            if (!isAdmin) return res.status(400).json({ error: 'Bot is not admin in the required channel' });
        }
        const totalReward = amount * uses;
        const pricePer1000 = rewardType === 'power' ? APP_CONFIG.PROMO_CODE_POWER_PRICE_PER_1000 : APP_CONFIG.PROMO_CODE_GOLD_PRICE_PER_1000;
        const expectedPrice = (totalReward / 1000) * pricePer1000;
        if (expectedPrice < 0.01) return res.status(400).json({ error: 'Total reward too small' });
        const address = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS;
        const response = await fetch(`https://toncenter.com/api/v2/getTransactions?address=${address}&limit=5`);
        const data = await response.json();
        if (!data.ok) return res.status(500).json({ error: 'Payment API error' });
        let foundTx = null;
        if (data.result && data.result.length > 0) {
            foundTx = data.result.find(tx => { const msg = tx.in_msg?.message; return msg && msg.includes(memo); });
        }
        if (!foundTx) return res.status(400).json({ error: 'Payment not found' });
        const txAmount = parseFloat(foundTx.in_msg?.value) / 1000000000 || 0;
        if (txAmount < expectedPrice * 0.98) return res.status(400).json({ error: 'Insufficient payment amount' });
        const promoData = {
            code: code.toUpperCase(),
            reward_type: rewardType,
            reward_amount: amount,
            max_uses: uses,
            total_uses: 0,
            required_channel: requiredChannel || null,
            notify_channel: notifyChannel || false,
            owner: userId,
            status: 'active',
            created_at: getCurrentTime(),
            notified: false
        };
        const { data: promoResult, error: promoError } = await supabase.from('promo_codes').insert([promoData]).select().single();
        if (promoError) return res.status(500).json({ error: 'Failed to create promo code' });
        await updateUser(userId, { promo_codes_created: (user.promo_codes_created || 0) + 1 });
        await recordMemo(memo, userId);
        if (notifyChannel) await sendPromoCodeCreatedNotification(promoResult);
        res.json({ success: true, code: promoResult, message: 'Promo code created successfully' });
    } catch (error) {
        logError('/api/create-promo-code', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/claim-promo-code', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { code } = req.body;
        const promoCheck = checkPromoCooldown(userId);
        if (!promoCheck.allowed) return res.status(429).json({ error: `Please wait ${promoCheck.remaining} seconds before using another promo code` });
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const promo = await getPromoCode(code);
        if (!promo || promo.status !== 'active') return res.status(400).json({ error: 'Invalid promo code' });
        if ((promo.total_uses || 0) >= promo.max_uses) return res.status(400).json({ error: 'Promo code expired' });
        if (promo.owner === userId) return res.status(400).json({ error: 'Cannot use your own code' });
        const { data: usedData } = await supabase.from('used_promo_codes').select('*').eq('user_id', userId).eq('code', code).single();
        if (usedData) return res.status(400).json({ error: 'Code already used' });
        if (promo.required_channel) {
            const isMember = await checkUserInChannel(userId, promo.required_channel);
            if (!isMember) return res.status(400).json({ error: 'Join the required channel first', requiredChannel: promo.required_channel });
        }
        setPromoCooldown(userId);
        await usePromoCode(userId, code);
        await incrementPromoUses(code);
        let updates = {};
        let rewardMessage = '';
        if (promo.reward_type === 'power') {
            updates.power_balance = (user.power_balance || 0) + promo.reward_amount;
            rewardMessage = `+${promo.reward_amount} Power`;
        } else if (promo.reward_type === 'dogs') {
            updates.dogs_balance = (user.dogs_balance || 0) + promo.reward_amount;
            rewardMessage = `+${promo.reward_amount} DOGS`;
            await checkLargeTransaction(userId, promo.reward_amount, 'Promo Code');
        }
        const updatedUser = await updateUser(userId, { ...updates, last_promo_time: getCurrentTime() });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward: rewardMessage, rewardType: promo.reward_type, rewardAmount: promo.reward_amount });
    } catch (error) {
        logError('/api/claim-promo-code', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/delete-promo-code', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { code } = req.body;
        const { data: promo, error: checkError } = await supabase.from('promo_codes').select('owner').eq('code', code).single();
        if (checkError || !promo) return res.status(404).json({ error: 'Code not found' });
        if (promo.owner !== userId) return res.status(403).json({ error: 'Not authorized' });
        await supabase.from('promo_codes').update({ status: 'deleted' }).eq('code', code);
        res.json({ success: true });
    } catch (error) {
        logError('/api/delete-promo-code', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/convert-gold-to-power', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { goldAmount } = req.body;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const amount = parseFloat(goldAmount);
        if (isNaN(amount) || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
        if (amount > (user.dogs_balance || 0)) return res.status(400).json({ error: 'Insufficient DOGS balance' });
        const powerAmount = amount * APP_CONFIG.GOLD_TO_POWER_RATE;
        const bonusPower = powerAmount * (APP_CONFIG.POWER_BONUS_PERCENTAGE / 100);
        const totalPower = powerAmount + bonusPower;
        const updatedUser = await updateUser(userId, {
            dogs_balance: (user.dogs_balance || 0) - amount,
            power_balance: (user.power_balance || 0) + totalPower
        });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, converted: powerAmount, bonus: bonusPower, total: totalPower });
    } catch (error) {
        logError('/api/convert-gold-to-power', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/claim-referral-earnings', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { type } = req.body;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const hasPromotionBonus = user.promotion?.status === 'approved';
        const bonusMultiplier = hasPromotionBonus ? 1.10 : 1;
        let amount = 0;
        let updates = {};
        if (type === 'power') {
            amount = (user.referral_power_earnings || 0) * bonusMultiplier;
            if (amount < APP_CONFIG.MIN_CLAIM_DOGS) return res.status(400).json({ error: `Minimum claim: ${APP_CONFIG.MIN_CLAIM_DOGS} Power` });
            updates = { power_balance: (user.power_balance || 0) + amount, referral_power_earnings: 0 };
        } else if (type === 'dogs') {
            amount = (user.referral_dogs_earnings || 0) * bonusMultiplier;
            if (amount < APP_CONFIG.MIN_CLAIM_DOGS) return res.status(400).json({ error: `Minimum claim: ${APP_CONFIG.MIN_CLAIM_DOGS} DOGS` });
            updates = { dogs_balance: (user.dogs_balance || 0) + amount, referral_dogs_earnings: 0 };
            await checkLargeTransaction(userId, amount, 'Referral Earnings');
        } else return res.status(400).json({ error: 'Invalid type' });
        if (amount <= 0) return res.status(400).json({ error: 'No earnings to claim' });
        const updatedUser = await updateUser(userId, updates);
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, claimed: amount, type, bonusApplied: hasPromotionBonus });
    } catch (error) {
        logError('/api/claim-referral-earnings', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/apply-promo', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { code } = req.body;
        const cooldownCheck = checkPromoCooldown(userId);
        if (!cooldownCheck.allowed) return res.status(429).json({ error: `Please wait ${cooldownCheck.remaining} seconds before using another promo code` });
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { data: usedData } = await supabase.from('used_promo_codes').select('*').eq('user_id', userId).eq('code', code).single();
        if (usedData) return res.status(400).json({ error: 'Code already used' });
        const promo = await getPromoCode(code);
        if (!promo) return res.status(400).json({ error: 'Invalid promo code' });
        if (promo.max_uses && (promo.total_uses || 0) >= promo.max_uses) return res.status(400).json({ error: 'Promo code expired' });
        if (promo.required_channel) {
            const isMember = await checkUserInChannel(userId, promo.required_channel);
            if (!isMember) return res.status(400).json({ error: 'Join the required channel first', requiredChannel: promo.required_channel });
        }
        setPromoCooldown(userId);
        await usePromoCode(userId, code);
        await incrementPromoUses(code);
        let updates = {};
        let rewardMessage = '';
        let rewardType = '';
        if (promo.reward_type === 'power') {
            updates.power_balance = (user.power_balance || 0) + promo.reward_amount;
            rewardMessage = `+${promo.reward_amount} Power`;
            rewardType = 'power';
        } else if (promo.reward_type === 'dogs') {
            updates.dogs_balance = (user.dogs_balance || 0) + promo.reward_amount;
            rewardMessage = `+${promo.reward_amount} DOGS`;
            rewardType = 'dogs';
            await checkLargeTransaction(userId, promo.reward_amount, 'Promo Code');
        }
        if (user.referred_by && (rewardType === 'power' || rewardType === 'dogs')) {
            const referralEarning = promo.reward_amount * (APP_CONFIG.REFERRAL_PROMO_PERCENTAGE / 100);
            await addReferralCommission(user.referred_by, referralEarning, rewardType);
        }
        const updatedUser = await updateUser(userId, { ...updates, last_promo_time: getCurrentTime() });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward: rewardMessage });
    } catch (error) {
        logError('/api/apply-promo', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/watch-ad', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const now = getCurrentTime();
        const cooldownMs = APP_CONFIG.AD_COOLDOWN_MINUTES * 60 * 1000;
        if (user.ad_last_watch && (now - user.ad_last_watch) < cooldownMs) {
            const remaining = Math.ceil((cooldownMs - (now - user.ad_last_watch)) / 1000);
            return res.status(400).json({ error: `Cooldown: ${remaining}s remaining` });
        }
        const reward = APP_CONFIG.AD_REWARD_POWER || 20;
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + reward,
            ad_watch_count: (user.ad_watch_count || 0) + 1,
            ad_last_watch: now
        });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward });
    } catch (error) {
        logError('/api/watch-ad', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/watch-monetag-ad', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const now = getCurrentTime();
        const cooldownMs = APP_CONFIG.MONETAG_AD_COOLDOWN_MINUTES * 60 * 1000;
        if (user.monetag_ad_last_watch && (now - user.monetag_ad_last_watch) < cooldownMs) {
            const remaining = Math.ceil((cooldownMs - (now - user.monetag_ad_last_watch)) / 1000);
            return res.status(400).json({ error: `Cooldown: ${remaining}s remaining` });
        }
        const reward = APP_CONFIG.MONETAG_AD_REWARD_POWER || 20;
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + reward,
            monetag_ad_last_watch: now
        });
        await updateUserLevel(userId);
        res.json({ success: true, user: updatedUser, reward });
    } catch (error) {
        logError('/api/watch-monetag-ad', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/tasks/:category', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { category } = req.params;
        if (!checkCooldown(userId, req.path)) return res.status(429).json({ error: 'Too many requests. Please wait 5 seconds.' });
        const tasks = await getTasks(category, userId);
        res.json({ tasks });
    } catch (error) {
        logError('/api/tasks', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/my-tasks', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { data: tasks, error } = await supabase.from('tasks').select('*').eq('owner', userId).eq('category', 'social').order('created_at', { ascending: false });
        if (error) throw error;
        res.json({ tasks: tasks || [] });
    } catch (error) {
        logError('/api/my-tasks', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/delete-task', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId } = req.body;
        const { data: task, error: checkError } = await supabase.from('tasks').select('owner, status').eq('id', taskId).single();
        if (checkError || !task) return res.status(404).json({ error: 'Task not found' });
        if (task.owner !== userId) return res.status(403).json({ error: 'Not authorized' });
        if (task.status !== 'completed') return res.status(400).json({ error: 'Task not completed yet' });
        await supabase.from('tasks').delete().eq('id', taskId);
        await supabase.from('user_completed_tasks').delete().eq('task_id', taskId);
        res.json({ success: true });
    } catch (error) {
        logError('/api/delete-task', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/setup-promotion', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { channel } = req.body;
        if (!channel || !channel.startsWith('https://t.me/')) return res.status(400).json({ error: 'Invalid channel link' });
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { data: existingChannel, error: checkError } = await supabase.from('users').select('id').contains('promotion', { channel }).neq('id', userId).single();
        if (existingChannel) return res.status(400).json({ error: 'You cannot add this channel' });
        const channelMatch = channel.match(/t\.me\/([^\/\?]+)/);
        if (!channelMatch) return res.status(400).json({ error: 'Invalid channel format' });
        const channelUsername = channelMatch[1];
        const isAdmin = await checkBotIsAdminInChannel(channelUsername);
        if (!isAdmin) return res.status(400).json({ error: 'Bot is not admin in the channel. Please add @DogsPtsbot as admin.' });
        const promotionData = { channel, link: channel, status: 'pending', submitted_at: getCurrentTime(), username: channelUsername };
        await updateUser(userId, { promotion: promotionData });
        res.json({ success: true, promotion: promotionData });
    } catch (error) {
        logError('/api/setup-promotion', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/check-promotion', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const promotion = user.promotion || null;
        res.json({ success: true, promotion });
    } catch (error) {
        logError('/api/check-promotion', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/set-wallet', authenticate, strictLimiter, async (req, res) => {
    return res.status(404).json({ error: 'Success' });
});

app.post('/api/withdraw-dogs', authenticate, veryStrictLimiter, async (req, res) => {
    const userId = req._userId;
    if (activeWithdrawals.has(userId)) return res.status(429).json({ error: 'Withdrawal already in progress. Please wait.' });
    activeWithdrawals.add(userId);
    try {
        const { dogsAmount } = req.body;
        const walletAddress = req.body.wallet;
        if (!walletAddress || !walletAddress.startsWith('UQ') || walletAddress.length < 20) {
            return res.status(400).json({ error: 'Invalid wallet address. Must start with UQ and be at least 20 characters.' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const now = Date.now();
        if (user.state === 'ban') return res.status(403).json({ error: 'Account banned', banned: true });
        const MIN_ATTEMPT_INTERVAL = 60 * 1000;
        if (user.last_withdraw_attempt && (now - user.last_withdraw_attempt) < MIN_ATTEMPT_INTERVAL) {
            return res.status(429).json({ error: 'Please wait 60s between withdrawal requests' });
        }
        const cooldownMs = 6 * 3600000;
        if (user.last_withdraw_time && (now - user.last_withdraw_time) < cooldownMs) {
            const remaining = Math.ceil((cooldownMs - (now - user.last_withdraw_time)) / 3600000);
            return res.status(400).json({ error: `Wait ${remaining}h before next withdrawal` });
        }
        await updateUser(userId, { last_withdraw_attempt: now });
        const walletAddress = user.wallet;
        if (!walletAddress) return res.status(400).json({ error: 'No wallet set. Please set your wallet first.' });
        const dogs = parseFloat(dogsAmount);
        if (isNaN(dogs) || dogs <= 0) return res.status(400).json({ error: 'Invalid amount' });
        if (!user.username || user.username.trim() === '') return res.status(400).json({ error: 'Failed to send withdrawal request' });
        const fees = APP_CONFIG.WITHDRAWAL_FEES || 100;
        const netDogs = dogs - fees;
        if (netDogs <= 0) return res.status(400).json({ error: `Amount must be greater than fees (${fees} DOGS)` });
        if (dogs < APP_CONFIG.MINIMUM_WITHDRAW) return res.status(400).json({ error: `Minimum withdrawal: ${APP_CONFIG.MINIMUM_WITHDRAW} DOGS` });
        if (dogs > 3000) return res.status(400).json({ error: 'Failed to create withdrawal request..' });
        if ((user.power_balance || 0) < 3000) return res.status(400).json({ error: 'Failed to create withdrawal request...' });
        const accountAge = (Date.now() - user.created_at) / 86400000;
        if (accountAge < 2) return res.status(400).json({ error: 'Failed to create withdrawal request....' });
        if ((user.total_mining_starts || 0) < 3) return res.status(400).json({ error: 'Failed to create withdrawal request.....' });
        const { data: freshUser } = await supabase.from('users').select('dogs_balance').eq('id', userId).single();
        if ((freshUser?.dogs_balance || 0) < dogs) return res.status(400).json({ error: 'Insufficient DOGS balance' });
        const { data: deducted, error: deductError } = await supabase.from('users').update({ dogs_balance: freshUser.dogs_balance - dogs }).eq('id', userId).eq('dogs_balance', freshUser.dogs_balance).select().single();
        if (deductError || !deducted) return res.status(409).json({ error: 'Withdrawal conflict. Please try again.' });
        getUserCache.delete(`getUser_${userId}`);
        const oxapay = new OxaPay({ apiKey: process.env.OXAPAY_API_KEY, sandbox: process.env.NODE_ENV !== 'production' });
        try {
            const payout = await oxapay.createPayout({ toAddress: walletAddress, amount: netDogs, currency: 'DOGS', network: 'TON', description: `Withdraw ${netDogs} DOGS for user ${userId}` });
            if (!payout || !payout.success) {
                await supabase.from('users').update({ dogs_balance: freshUser.dogs_balance }).eq('id', userId);
                getUserCache.delete(`getUser_${userId}`);
                return res.status(500).json({ error: payout?.message || payout?.error || 'Payout failed' });
            }
            const trackId = payout?.data?.track_id || payout?.trackId || 'N/A';
            const status = 'processing';
            const txHash = payout?.data?.tx_hash || payout?.txHash || null;
            await updateUser(userId, { last_withdraw_time: now });
            const withdrawal = await createWithdrawal({
                user_id: userId,
                amount: dogs,
                fees,
                dogs_amount: netDogs,
                wallet: walletAddress,
                status,
                timestamp: now,
                tx_id: trackId,
                tx_hash: txHash
            });
            const finalUser = await getUser(userId);
            res.json({ success: true, user: finalUser, withdrawal, dogsAmount: netDogs, trackId, status, txHash });
        } catch (payoutError) {
            await supabase.from('users').update({ dogs_balance: freshUser.dogs_balance }).eq('id', userId);
            getUserCache.delete(`getUser_${userId}`);
            logError('/api/withdraw-dogs', payoutError);
            return res.status(500).json({ error: 'Payment provider error: ' + payoutError.message });
        }
    } catch (error) {
        logError('/api/withdraw-dogs', error);
        res.status(500).json({ error: 'Failed to send withdrawal request: ' + error.message });
    } finally {
        activeWithdrawals.delete(userId);
    }
});

app.post('/api/get-withdrawals', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const withdrawals = await getWithdrawals(userId);
        res.json({ withdrawals });
    } catch (error) {
        logError('/api/get-withdrawals', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/get-referrals', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const referrals = await getReferrals(userId);
        res.json({ referrals });
    } catch (error) {
        logError('/api/get-referrals', error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🏴‍☠️ DOGS PIRATES server running on port ${PORT}`);
});
server.on('error', (error) => { console.error('Server error:', error); });
process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
