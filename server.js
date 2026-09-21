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

const requestCooldown = new Map();
const notifiedUsers = new Set();
const getUserCache = new Map();
const activeWithdrawals = new Set();

function logError(endpoint, error) {
    console.error(`❌ [${endpoint}] Error:`, error.message || error);
    if (error.stack) {
        console.error(`📚 Stack:`, error.stack);
    }
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

async function isDeviceUsedByOtherUser(deviceId, currentUserId) {
    if (!deviceId) return false;
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, device_id')
            .eq('device_id', deviceId)
            .neq('id', currentUserId)
            .single();
        if (error && error.code !== 'PGRST116') {
            logError('isDeviceUsedByOtherUser', error);
        }
        return !!data;
    } catch (error) {
        logError('isDeviceUsedByOtherUser', error);
        return false;
    }
}

function checkCooldown(userId, endpoint) {
    const now = Date.now();
    const key = `${userId}_${endpoint}`;
    const lastCall = requestCooldown.get(key) || 0;
    if (now - lastCall < 1500) return false;
    requestCooldown.set(key, now);
    return true;
}

function validateUserId(userId) {
    return userId && typeof userId === 'number' && userId > 0;
}

function generateJWT(userId, deviceId) {
    return jwt.sign({ userId, deviceId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyJWT(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function authenticate(req, res, next) {
    let token = req.cookies?.token;
    if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
    }
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = verifyJWT(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req._userId = decoded.userId;
    req._deviceId = decoded.deviceId;
    next();
}

async function validateDevice(userId, deviceId) {
    if (!deviceId || deviceId.length < 10) return false;
    try {
        const { data: user } = await supabase
            .from('users')
            .select('device_id')
            .eq('id', userId)
            .single();
        if (!user) return false;
        if (!user.device_id) return false;
        if (user.device_id !== deviceId) return false;
        return true;
    } catch (error) {
        return false;
    }
}

async function checkDeviceUsage(deviceId, currentUserId) {
    if (!deviceId || deviceId.length < 10) {
        return { allowed: false, reason: 'no_device' };
    }
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id')
            .eq('device_id', deviceId);
        if (error) return { allowed: false, reason: 'db_error' };
        const otherUsers = (data || []).filter(u => u.id !== currentUserId);
        if (otherUsers.length > 0) {
            return { allowed: false, reason: 'device_already_used' };
        }
        return { allowed: true };
    } catch (error) {
        return { allowed: false, reason: 'error' };
    }
}

async function checkBotIsAdminInChannel(channelUsername) {
    if (!BOT_TOKEN) return false;
    try {
        const botInfo = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`).then(r => r.json());
        if (!botInfo.ok) return false;
        const botId = botInfo.result.id;
        const botMember = await fetch(
            `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channelUsername}&user_id=${botId}`
        ).then(r => r.json());
        if (!botMember.ok) return false;
        return ['administrator', 'creator'].includes(botMember.result?.status);
    } catch (error) {
        return false;
    }
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
    if (user.level !== newLevel) {
        await updateUser(userId, { level: newLevel });
    }
    return newLevel;
}

function getCurrentTime() {
    return Date.now();
}

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
    if (Object.keys(updates).length > 0) {
        await updateUser(referrerId, updates);
    }
}

async function checkLargeTransaction(userId, amount, source) {
    if (amount >= 500) {
        const user = await getUser(userId);
        const adminId = process.env.ADMIN_USER_ID;
        if (adminId && user) {
            await sendTelegramNotification(
                adminId,
                '💰 LARGE TRANSACTION!',
                `User: ${user.first_name} (${userId})\n🐕 Amount: +${amount.toFixed(3)} DOGS\n📌 Source: ${source}`
            );
        }
    }
}

async function checkUserBanned(userId) {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('state')
            .eq('id', userId)
            .single();
        if (error) return false;
        return user.state === 'ban';
    } catch (error) {
        return false;
    }
}

async function getUser(userId) {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();
        if (error && error.code !== 'PGRST116') throw error;
        return data;
    } catch (error) {
        return null;
    }
}

async function createUser(userData) {
    try {
        const { data, error } = await supabase
            .from('users')
            .insert([userData])
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function updateUser(userId, updates) {
    try {
        const { data, error } = await supabase
            .from('users')
            .update(updates)
            .eq('id', userId)
            .select()
            .single();
        if (error) throw error;
        getUserCache.delete(`getUser_${userId}`);
        return data;
    } catch (error) {
        throw error;
    }
}

async function getTasks(category, userId) {
    try {
        let query = supabase
            .from('tasks')
            .select('*')
            .eq('status', 'active');
        if (category) {
            query = query.eq('category', category);
        }
        const { data: tasks, error } = await query;
        if (error) throw error;
        const { data: completed } = await supabase
            .from('user_completed_tasks')
            .select('task_id')
            .eq('user_id', userId);
        const completedIds = new Set(completed?.map(t => t.task_id) || []);
        const availableTasks = tasks.filter(task => !completedIds.has(task.id));
        return availableTasks || [];
    } catch (error) {
        return [];
    }
}

async function getCompletedTasks(userId) {
    try {
        const { data, error } = await supabase
            .from('user_completed_tasks')
            .select('task_id')
            .eq('user_id', userId);
        if (error) throw error;
        return data ? data.map(t => t.task_id) : [];
    } catch (error) {
        return [];
    }
}

async function getWithdrawals(userId) {
    try {
        const { data, error } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('user_id', userId)
            .order('timestamp', { ascending: false })
            .limit(10);
        if (error) throw error;
        return data || [];
    } catch (error) {
        return [];
    }
}

async function getReferrals(userId) {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, first_name, username, created_at')
            .eq('referred_by', userId);
        if (error) throw error;
        return data || [];
    } catch (error) {
        return [];
    }
}

async function getPromoCode(code) {
    try {
        const { data, error } = await supabase
            .from('promo_codes')
            .select('*')
            .eq('code', code)
            .single();
        if (error && error.code !== 'PGRST116') throw error;
        return data;
    } catch (error) {
        return null;
    }
}

async function usePromoCode(userId, code) {
    try {
        const { data, error } = await supabase
            .from('used_promo_codes')
            .insert([{ user_id: userId, code }])
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function incrementPromoUses(code) {
    try {
        const { data: promo } = await supabase
            .from('promo_codes')
            .select('total_uses')
            .eq('code', code)
            .single();
        const newTotal = (promo?.total_uses || 0) + 1;
        const { data, error } = await supabase
            .from('promo_codes')
            .update({ total_uses: newTotal })
            .eq('code', code)
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function createWithdrawal(withdrawalData) {
    try {
        const { data, error } = await supabase
            .from('withdrawals')
            .insert([withdrawalData])
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function updateStats(statName, increment) {
    try {
        const { data } = await supabase
            .from('stats')
            .select('value')
            .eq('key', statName)
            .single();
        if (data) {
            await supabase
                .from('stats')
                .update({ value: (data.value || 0) + increment })
                .eq('key', statName);
        } else {
            await supabase
                .from('stats')
                .insert([{ key: statName, value: increment }]);
        }
    } catch (error) {}
}

async function sendTelegramNotification(userId, title, message, inlineButton = null) {
    if (!BOT_TOKEN || !userId) return;
    try {
        const payload = {
            chat_id: userId,
            text: message,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        };
        if (inlineButton) {
            payload.reply_markup = {
                inline_keyboard: [
                    [{
                        text: inlineButton.text,
                        url: inlineButton.url
                    }]
                ]
            };
        }
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (error) {
        logError('sendTelegramNotification', error);
    }
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
                    [{
                        text: '🔘 View on Explorer',
                        url: explorerUrl
                    }],
                    [{
                        text: '🏴‍☠️ DOGS PIRATES',
                        url: 'https://t.me/DogsPtsbot?start=start'
                    }]
                ]
            }
        };
        
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (error) {
        logError('sendWithdrawalProof', error);
    }
}

class OxaPay {
    constructor(config) {
        this.apiKey = config.apiKey;
        this.sandbox = config.sandbox || false;
        this.baseUrl = this.sandbox 
            ? 'https://sandbox.oxapay.com/v1' 
            : 'https://api.oxapay.com/v1';
    }

    async request(endpoint, data) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            'payout_api_key': this.apiKey
        };
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(data)
            });
            const responseText = await response.text();
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (e) {
                throw new Error('Invalid response from OxaPay');
            }
            if (!response.ok || result.status !== 200) {
                throw new Error(result.message || result.error || `HTTP ${response.status}: ${response.statusText}`);
            }
            return result;
        } catch (error) {
            logError('OxaPay.request', error);
            throw error;
        }
    }

    async createPayout(data) {
        try {
            const payload = {
                address: data.toAddress,
                amount: data.amount,
                currency: data.currency || 'DOGS',
                network: data.network || 'TON',
                description: data.description || 'Withdrawal'
            };
            const result = await this.request('/payout', payload);
            const trackId = result?.data?.track_id || result?.track_id;
            const status = result?.data?.status || result?.status || 'processing';
            const txHash = result?.data?.tx_hash || result?.tx_hash || null;
            return { 
                ...result, 
                trackId: trackId || 'N/A',
                status: status,
                txHash: txHash,
                success: true
            };
        } catch (error) {
            logError('OxaPay.createPayout', error);
            throw error;
        }
    }

    async getPayoutStatus(trackId) {
        const url = `${this.baseUrl}/payout/${trackId}`;
        const headers = {
            'payout_api_key': this.apiKey,
            'Content-Type': 'application/json'
        };
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: headers
            });
            const responseText = await response.text();
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (e) {
                logError('OxaPay.getPayoutStatus', new Error('Invalid JSON: ' + responseText));
                throw new Error('Invalid response from OxaPay');
            }
            if (!response.ok || result.status !== 200) {
                const errorMsg = result.message || result.error || `HTTP ${response.status}`;
                logError('OxaPay.getPayoutStatus', new Error(errorMsg));
                throw new Error(errorMsg);
            }
            return result;
        } catch (error) {
            logError('OxaPay.getPayoutStatus', error);
            throw error;
        }
    }
}

async function checkPendingWithdrawals() {
    try {
        const { data: withdrawals, error } = await supabase
            .from('withdrawals')
            .select('*')
            .in('status', ['pending', 'processing'])
            .limit(50);
        if (error) {
            logError('checkPendingWithdrawals', error);
            return;
        }
        if (!withdrawals || withdrawals.length === 0) {
            return;
        }
        const oxapay = new OxaPay({
            apiKey: process.env.OXAPAY_API_KEY,
            sandbox: process.env.NODE_ENV !== 'production'
        });
        for (const withdrawal of withdrawals) {
            try {
                const statusResult = await oxapay.getPayoutStatus(withdrawal.tx_id);
                if (statusResult && statusResult.data) {
                    const oxaPayStatus = statusResult.data.status;
                    if (oxaPayStatus === 'confirmed' || oxaPayStatus === 'completed') {
                        await supabase
                            .from('withdrawals')
                            .update({ 
                                status: 'completed',
                                tx_hash: statusResult.data.tx_hash || withdrawal.tx_hash
                            })
                            .eq('id', withdrawal.id);
                        
                        const userMessage = `<b>✅ Your Withdrawal Confirmed!</b>\n\n` +
                            `💰 <code>${withdrawal.dogs_amount.toFixed(0)}</code> <b>DOGS has been sent</b>\n\n` +
                            `<a href="${statusResult.data.tx_hash ? `https://tonscan.org/tx/${statusResult.data.tx_hash}` : '#'}">🔘 View transaction on Explorer</a>\n\n`;
                        
                        await sendTelegramNotification(
                            withdrawal.user_id,
                            '✅ Withdrawal Completed!',
                            userMessage
                        );

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
                                await sendWithdrawalProof(
                                    '@' + channelMatch[1],
                                    withdrawal.user_id,
                                    withdrawal.wallet,
                                    withdrawal.dogs_amount,
                                    statusResult.data.tx_hash || withdrawal.tx_hash
                                );
                            }
                        }
                    }
                }
            } catch (error) {
                logError('checkPendingWithdrawals', error);
            }
        }
    } catch (error) {
        logError('checkPendingWithdrawals', error);
    }
}

setInterval(async () => {
    await checkPendingWithdrawals();
}, 60000);

setTimeout(() => {
    checkPendingWithdrawals();
}, 10000);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: getCurrentTime() });
});

app.get('/api/config', (req, res) => {
    res.json(APP_CONFIG);
});

app.get('/api/current-time', (req, res) => {
    res.json({ serverTime: getCurrentTime() });
});

app.post('/api/check-bot-admin', authenticate, async (req, res) => {
    try {
        const { channel } = req.body;
        if (!channel) {
            return res.status(400).json({ error: 'Channel is required' });
        }
        const isAdmin = await checkBotIsAdminInChannel(channel);
        res.json({ isAdmin });
    } catch (error) {
        logError('/api/check-bot-admin', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
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
                if (parts.length > 1 && !isNaN(parts[1])) {
                    referrerId = parseInt(parts[1]);
                }
            } 
             
            const appLink = referrerId 
                ? `https://t.me/DogsPtsbot/app?startapp=${referrerId}`
                : `https://t.me/DogsPtsbot/app`;

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
                    device_id: null,
                    quests: {
                        welcome_bonus_claimed: false,
                        current_level_quest_index: 0,
                        current_task_quest_index: 0,
                        current_referral_quest_index: 0
                    },
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
                    task_count: 0
                };
                
                if (referrerId && referrerId !== chatId) {
                    userData.referred_by = referrerId;
                }
                
                try {
                    await createUser(userData);
                } catch (createError) {
                    console.error('Failed to create user from webhook:', createError.message);
                }
            } else {
                const updates = {};
                if (username && username !== existingUser.username) {
                    updates.username = username;
                }
                if (firstName && firstName !== existingUser.first_name) {
                    updates.first_name = firstName;
                }
                if (Object.keys(updates).length > 0) {
                    await updateUser(chatId, updates);
                }
            }

            await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    photo: 'https://i.ibb.co/jvBSQfvf/IMG-20260914-192504-728.jpg',
                    caption: 
                        `<b>🏴‍☠️ Welcome to DOGS PIRATES!</b>\n\n` +
                        `⛏️ Mine and earn <b>free DOGS!</b>\n\n` +
                        `🎁 Claim <b>1000 power</b> welcome bonus\n` +
                        `📋 Complete tasks\n` +
                        `👷‍♂️ Invite friends\n` +
                        `🎟 Claim promo codes\n\n` +
                        `💰 Withdraw your funds <b>for free</b>\n` +
                        `⚡ Up to <b>60%</b> from referrals earnings\n` +
                        `⚡ Start your work to get <b>free DOGS!</b>`,
                    parse_mode: 'HTML',
                    reply_markup: {
                        inline_keyboard: [
                            [{ text: '🏴‍☠️ Start App', url: appLink }],
                            [
                                { text: '📋 TASKS', url: 'https://t.me/DOGSTASK' },
                                { text: '💸 PAYOUTS', url: 'https://t.me/DOGSPAYO' }
                            ],
                            [{ text: '📰 Official Channel', url: 'https://t.me/DOGSPTS' }]
                        ]
                    }
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
        
        if (!channel) {
            return res.status(400).json({ error: 'Channel is required' });
        }

        if (!BOT_TOKEN) {
            return res.json({ isMember: true, error: 'bot_not_configured' });
        }

        const isAdmin = await checkBotIsAdminInChannel(channel);
        if (!isAdmin) {
            return res.json({ isMember: true, error: 'bot_not_admin' });
        }

        const chatMember = await fetch(
            `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channel}&user_id=${userId}`
        ).then(r => r.json());

        const isMember = chatMember.ok && ['member', 'administrator', 'creator'].includes(chatMember.result?.status);
        
        res.json({ isMember });
    } catch (error) {
        logError('/api/check-membership', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth', strictLimiter, async (req, res) => {
    try {
        const { userId, deviceId, firstName, username, photoUrl } = req.body;
        if (!validateUserId(userId)) {
            return res.status(400).json({ error: 'Invalid user' });
        }
        if (!deviceId || deviceId.length < 10) {
            return res.status(403).json({ 
                error: 'device_required',
                message: 'Device ID is required' 
            });
        }
        
        const deviceCheck = await checkDeviceUsage(deviceId, userId);
        if (!deviceCheck.allowed) {
            return res.status(403).json({ 
                error: 'device_already_used',
                message: 'This device is already linked to another account' 
            });
        }

        if (username) {
            const { data: existingUser, error: checkError } = await supabase
                .from('users')
                .select('id, username')
                .eq('username', username)
                .neq('id', userId)
                .single();

            if (existingUser) {
                return res.status(400).json({ 
                    error: 'Cannot make your account' 
                });
            }
        }
        
        let user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ 
                error: 'user_not_registered',
                message: 'Please start the bot first to register'
            });
        }
        
        if (user.device_id && user.device_id !== deviceId) {
            const code = Math.floor(100000 + Math.random() * 900000).toString();
            
            await supabase.from('verification_codes').delete().eq('user_id', userId);
            
            await supabase.from('verification_codes').insert({
                user_id: userId,
                code: code,
                expires_at: getCurrentTime() + 300000,
                created_at: getCurrentTime(),
                used: false
            });
            
            await sendTelegramNotification(
                userId,
                '❗ New Device Detected!',
                `<b>📲 A new device is trying to access your account.</b>\n\n<b>🔐 Verification Code:</b> <code>${code}</code>\n\n<b>✋ If you are not the one who requested the code, just ignore this message.</b>`
            );
            return res.status(403).json({ error: 'new_device' });
        }
        
        if (!user.device_id && deviceId) {
            await updateUser(userId, { device_id: deviceId });
            user = await getUser(userId);
        }
        
        const token = generateJWT(userId, deviceId);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({ success: true, newUser: false, user, token, deviceId: user.device_id });
    } catch (error) {
        logError('/api/auth', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/verify-device', strictLimiter, async (req, res) => {
    try {
        const { userId, deviceId, code } = req.body;
        
        if (!validateUserId(userId) || !code) {
            return res.status(400).json({ error: 'Invalid request' });
        }
        
        const { data: verification, error } = await supabase
            .from('verification_codes')
            .select('*')
            .eq('user_id', userId)
            .eq('code', code)
            .eq('used', false)
            .single();
        
        if (error || !verification) {
            return res.status(400).json({ error: 'Invalid code' });
        }
        
        const currentTime = getCurrentTime();
        
        if (currentTime > verification.expires_at) {
            await supabase
                .from('verification_codes')
                .update({ used: true })
                .eq('id', verification.id);
            return res.status(400).json({ error: 'Code expired' });
        }
        
        const newDeviceId = deviceId || crypto.randomBytes(32).toString('hex');
        await updateUser(userId, { device_id: newDeviceId });
        await supabase
            .from('verification_codes')
            .update({ used: true })
            .eq('id', verification.id);
        
        const token = generateJWT(userId, newDeviceId);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        const user = await getUser(userId);
        res.json({ success: true, token, user, deviceId: newDeviceId });
    } catch (error) {
        console.error('❌ [verify-device] Fatal error:', error.message);
        logError('/api/verify-device', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/resend-device-code', strictLimiter, async (req, res) => {
    try {
        const { userId } = req.body;
        if (!validateUserId(userId)) {
            return res.status(400).json({ error: 'Invalid user' });
        }
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        
        await supabase.from('verification_codes').delete().eq('user_id', userId);
        
        await supabase.from('verification_codes').insert({
            user_id: userId,
            code: code,
            expires_at: getCurrentTime() + 300000,
            created_at: getCurrentTime(),
            used: false
        });

        await sendTelegramNotification(
            userId,
            '🔰 New Verification Code',
            `🔑 Your new verification code: <code>${code}</code>\n\n⏳ Valid for 5 minutes.`
        );
        res.json({ success: true });
    } catch (error) {
        logError('/api/resend-device-code', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/refresh', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const deviceId = req._deviceId;
        const user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.state === 'ban') {
            return res.status(403).json({ error: 'Account banned' });
        }
        const token = generateJWT(userId, deviceId);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({ success: true, token, deviceId });
    } catch (error) {
        logError('/api/refresh', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/logout', authenticate, async (req, res) => {
    try {
        res.clearCookie('token');
        res.json({ success: true });
    } catch (error) {
        logError('/api/logout', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/check-mining-status', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user || !user.mining_active || !user.mining_start_time) {
            return res.json({ success: true, notified: 0 });
        }
        const totalDuration = (APP_CONFIG.MINING_SESSION_HOURS || 12) * 3600000;
        const elapsed = getCurrentTime() - user.mining_start_time;
        if (elapsed < totalDuration) {
            return res.json({ success: true, notified: 0 });
        }
        if (notifiedUsers.has(userId)) {
            return res.json({ success: true, notified: 0 });
        }
        const reward = calculateMiningReward(
            user.power_balance || 0,
            user.mining_start_time,
            getCurrentTime()
        );
        await updateUser(userId, {
            mining_active: false,
            mining_start_time: null,
            mining_end_time: null,
            pending_dogs_reward: reward
        });
        await sendTelegramNotification(
            user.id,
            '⛏️ Mining Stopped!',
            `🏴‍☠️ Your mining session has ended.\n\n📊 You earned ${reward.toFixed(3)} DOGS\n\n🎁 Claim your rewards and restart mining!`,
            { text: 'CLAIM NOW', url: 'https://t.me/DogsPtsbot/app' }
        );
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
        if (user.quests?.welcome_bonus_claimed || user.power_balance > 1000) {
            return res.status(400).json({ error: 'Already claimed' });
        }
        const reward = APP_CONFIG.QUESTS.welcome_bonus.reward || 1000;
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + reward,
            quests: {
                ...user.quests,
                welcome_bonus_claimed: true
            }
        });
        await updateUserLevel(userId);
        res.json({
            success: true,
            user: updatedUser,
            reward: reward
        });
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
        if (cached && (now - cached.timestamp) < 3000) {
            return res.json(cached.data);
        }
        if (!checkCooldown(userId, req.path)) {
            return res.status(429).json({ error: 'Too many requests. Please wait 5 seconds.' });
        }
        let user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'user_not_registered' });
        }
        if (user.state === 'ban') {
            return res.status(403).json({ error: 'Account banned', banned: true });
        }
        if (referredBy && !user.referred_by && referredBy !== userId) {
            await updateUser(userId, { referred_by: referredBy });
            user = await getUser(userId);
        }
        const [completedTasks, withdrawals] = await Promise.all([
            getCompletedTasks(userId),
            getWithdrawals(userId)
        ]);
        await updateUserLevel(userId);
        user = await getUser(userId);
        const responseData = {
            user: user,
            completedTasks,
            withdrawals
        };
        getUserCache.set(cacheKey, { data: responseData, timestamp: now });
        res.json(responseData);
    } catch (error) {
        logError('/api/get-user', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/update-user', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const updates = req.body;
        delete updates.userId;
        delete updates.deviceId;
        delete updates.username;
        delete updates.firstName;
        delete updates.photoUrl;

        if (Object.keys(updates).length === 0) {
            return res.json({ success: true });
        }

        const dbUpdates = {};
        if (updates.powerBalance !== undefined) dbUpdates.power_balance = updates.powerBalance;
        if (updates.dogsBalance !== undefined) dbUpdates.dogs_balance = updates.dogsBalance;
        if (updates.gramBalance !== undefined) dbUpdates.gram_balance = updates.gramBalance;
        if (updates.quests !== undefined) dbUpdates.quests = updates.quests;
        if (updates.miningActive !== undefined) dbUpdates.mining_active = updates.miningActive;
        if (updates.miningStartTime !== undefined) dbUpdates.mining_start_time = updates.miningStartTime;
        if (updates.miningEndTime !== undefined) dbUpdates.mining_end_time = updates.miningEndTime;
        if (updates.pendingDogsReward !== undefined) dbUpdates.pending_dogs_reward = updates.pendingDogsReward;

        if (Object.keys(dbUpdates).length > 0) {
            await updateUser(userId, dbUpdates);
        }

        res.json({ success: true });
    } catch (error) {
        logError('/api/update-user', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/start-mining', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { serverTime } = req.body;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.mining_active) {
            return res.status(400).json({ error: 'Mining already active' });
        }
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
                const newTotal = (referrer.total_referrals || 0) + 1;
                await updateUser(user.referred_by, {
                    total_referrals: newTotal
                });
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
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (!user.mining_active) {
            return res.status(400).json({ error: 'No active mining session' });
        }
        const currentTime = getCurrentTime();
        const sessionMs = (APP_CONFIG.MINING_SESSION_HOURS || 12) * 3600000;
        const elapsed = currentTime - user.mining_start_time;
        if (elapsed < sessionMs) {
            return res.status(400).json({ error: 'Mining session not ended yet' });
        }
        const rewardAmount = calculateMiningReward(
            user.power_balance || 0,
            user.mining_start_time,
            currentTime
        );
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
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const level = calculateLevel(user.power_balance || 0);
        if (user.level !== level) {
            await updateUser(userId, { level: level });
            user.level = level;
        }
        if (user.mining_active) {
            return res.status(400).json({ error: 'Mining session still active' });
        }
        const rewardAmount = user.pending_dogs_reward || 0;
        if (rewardAmount <= 0) {
            return res.status(400).json({ error: 'No rewards to claim' });
        }
        if (rewardAmount > 1000) {
            return res.status(400).json({ error: 'Failed to claim reward' });
        }
        const maxReward = (user.power_balance / 1000) * 5 * 13;
        if (rewardAmount > maxReward) {
            return res.status(400).json({ error: 'Failed to claim reward' });
        }
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
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        let reward = 0;
        let newIndex = 0;
        let quests = { ...user.quests };
        if (questType === 'level') {
            const index = user.quests?.current_level_quest_index || 0;
            const quest = APP_CONFIG.QUESTS.level_quests[index];
            if (!quest) {
                return res.status(400).json({ error: 'No level quest available' });
            }
            if (user.level < quest.target_level) {
                return res.status(400).json({ error: 'Level requirement not met' });
            }
            reward = quest.reward;
            newIndex = index + 1;
            quests.current_level_quest_index = newIndex;
        } else if (questType === 'task') {
            const index = user.quests?.current_task_quest_index || 0;
            const quest = APP_CONFIG.QUESTS.task_quests[index];
            if (!quest) {
                return res.status(400).json({ error: 'No task quest available' });
            }
            if (user.total_tasks_completed < quest.target_tasks) {
                return res.status(400).json({ error: 'Task requirement not met' });
            }
            reward = quest.reward;
            newIndex = index + 1;
            quests.current_task_quest_index = newIndex;
        } else if (questType === 'referral') {
            const index = user.quests?.current_referral_quest_index || 0;
            const quest = APP_CONFIG.QUESTS.referral_quests[index];
            if (!quest) {
                return res.status(400).json({ error: 'No referral quest available' });
            }
            if (user.total_referrals < quest.target_referrals) {
                return res.status(400).json({ error: 'Referral requirement not met' });
            }
            reward = quest.reward;
            newIndex = index + 1;
            quests.current_referral_quest_index = newIndex;
        } else {
            return res.status(400).json({ error: 'Invalid quest type' });
        }
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + reward,
            quests: quests
        });
        await updateUserLevel(userId);
        res.json({
            success: true,
            user: updatedUser,
            reward: reward,
            questType: questType,
            questIndex: newIndex
        });
    } catch (error) {
        logError('/api/claim-quest', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/complete-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId, isPartner, taskOwner } = req.body;
        
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const { data: task, error: taskError } = await supabase
            .from('tasks')
            .select('reward, total, total_completed, category, owner, notified, name')
            .eq('id', taskId)
            .single();

        if (taskError || !task) {
            return res.status(404).json({ error: 'Task not found' });
        }

        if (task.notified) {
            return res.status(400).json({ error: 'Task already limited!' });
        }

        if (task.total_completed >= task.total) {
            if (!task.notified && task.owner && task.owner !== userId) {
                await sendTelegramNotification(
                    task.owner,
                    '<b>✅ Task Completed!</b>',
                    `<b>🏴‍☠️ Your task "${task.name}" has been completed!</b>`
                );
            }
            await supabase
                .from('tasks')
                .update({ status: 'completed', notified: true })
                .eq('id', taskId);
            return res.status(400).json({ error: 'Task already limited!' });
        }

        const { data: completed } = await supabase
            .from('user_completed_tasks')
            .select('task_id')
            .eq('user_id', userId)
            .eq('task_id', taskId)
            .single();

        if (completed) {
            return res.status(400).json({ error: 'Task already completed by you' });
        }

        const newTotalCompleted = (task.total_completed || 0) + 1;
        await supabase
            .from('tasks')
            .update({ total_completed: newTotalCompleted })
            .eq('id', taskId);

        await supabase
            .from('user_completed_tasks')
            .insert([{ user_id: userId, task_id: taskId, completed_at: getCurrentTime() }]);

        let totalCompleted = (user.total_tasks_completed || 0) + 1;
        
        let dogsReward = 0;
        if (task.category === 'social') {
            dogsReward = APP_CONFIG.SOCIAL_DOGS_REWARD || 1;
        }
        
        const updatedUser = await updateUser(userId, {
            power_balance: (user.power_balance || 0) + task.reward,
            dogs_balance: (user.dogs_balance || 0) + dogsReward,
            total_tasks_completed: totalCompleted
        });

        if (task.category === 'social' && task.owner && task.owner !== userId) {
            const { data: taskData } = await supabase
                .from('tasks')
                .select('total, total_completed, notified, name, reward')
                .eq('id', taskId)
                .single();

            if (taskData && taskData.total_completed >= taskData.total && !taskData.notified) {
                await supabase
                    .from('tasks')
                    .update({ status: 'completed', notified: true })
                    .eq('id', taskId);
                
                await sendTelegramNotification(
                    task.owner,
                    '<b>✅ Task Completed!</b>',
                    `<b>🏴‍☠️ Your task "${taskData.name}" has been completed!</b>`
                );
            }
        }

        if (user.referred_by) {
            const referralEarning = task.reward * (APP_CONFIG.REFERRAL_TASKS_PERCENTAGE / 100);
            await addReferralCommission(user.referred_by, referralEarning, 'power');
        }

        await updateUserLevel(userId);

        res.json({
            success: true,
            user: updatedUser,
            reward: task.reward
        });
    } catch (error) {
        logError('/api/complete-task', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/convert-gold-to-power', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { goldAmount } = req.body;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const amount = parseFloat(goldAmount);
        if (isNaN(amount) || amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }
        if (amount > (user.dogs_balance || 0)) {
            return res.status(400).json({ error: 'Insufficient DOGS balance' });
        }
        const powerAmount = amount * APP_CONFIG.GOLD_TO_POWER_RATE;
        const bonusPower = powerAmount * (APP_CONFIG.POWER_BONUS_PERCENTAGE / 100);
        const totalPower = powerAmount + bonusPower;
        const updatedUser = await updateUser(userId, {
            dogs_balance: (user.dogs_balance || 0) - amount,
            power_balance: (user.power_balance || 0) + totalPower
        });
        await updateUserLevel(userId);
        res.json({
            success: true,
            user: updatedUser,
            converted: powerAmount,
            bonus: bonusPower,
            total: totalPower
        });
    } catch (error) {
        logError('/api/convert-gold-to-power', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/claim-referral-earnings', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { type } = req.body;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const hasPromotionBonus = user.promotion?.status === 'approved';
        const bonusMultiplier = hasPromotionBonus ? 1.10 : 1;
        let amount = 0;
        let updates = {};
        if (type === 'power') {
            amount = (user.referral_power_earnings || 0) * bonusMultiplier;
            if (amount < APP_CONFIG.MIN_CLAIM_DOGS) {
                return res.status(400).json({ error: `Minimum claim: ${APP_CONFIG.MIN_CLAIM_DOGS} Power` });
            }
            updates = {
                power_balance: (user.power_balance || 0) + amount,
                referral_power_earnings: 0
            };
        } else if (type === 'dogs') {
            amount = (user.referral_dogs_earnings || 0) * bonusMultiplier;
            if (amount < APP_CONFIG.MIN_CLAIM_DOGS) {
                return res.status(400).json({ error: `Minimum claim: ${APP_CONFIG.MIN_CLAIM_DOGS} DOGS` });
            }
            updates = {
                dogs_balance: (user.dogs_balance || 0) + amount,
                referral_dogs_earnings: 0
            };
            await checkLargeTransaction(userId, amount, 'Referral Earnings');
        } else {
            return res.status(400).json({ error: 'Invalid type' });
        }
        if (amount <= 0) {
            return res.status(400).json({ error: 'No earnings to claim' });
        }
        const updatedUser = await updateUser(userId, updates);
        await updateUserLevel(userId);
        res.json({
            success: true,
            user: updatedUser,
            claimed: amount,
            type: type,
            bonusApplied: hasPromotionBonus
        });
    } catch (error) {
        logError('/api/claim-referral-earnings', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/apply-promo', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { code } = req.body;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { data: usedData } = await supabase
            .from('used_promo_codes')
            .select('*')
            .eq('user_id', userId)
            .eq('code', code)
            .single();
        if (usedData) {
            return res.status(400).json({ error: 'Code already used' });
        }
        const promo = await getPromoCode(code);
        if (!promo) {
            return res.status(400).json({ error: 'Invalid promo code' });
        }
        if (promo.max_uses && (promo.total_uses || 0) >= promo.max_uses) {
            return res.status(400).json({ error: 'Promo code expired' });
        }
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
        } else if (promo.reward_type === 'gram') {
            updates.gram_balance = (user.gram_balance || 0) + promo.reward_amount;
            rewardMessage = `+${promo.reward_amount} GRAM`;
            rewardType = 'gram';
        }
        if (user.referred_by && (rewardType === 'power' || rewardType === 'dogs')) {
            const referralEarning = promo.reward_amount * (APP_CONFIG.REFERRAL_PROMO_PERCENTAGE / 100);
            const type = rewardType === 'power' ? 'power' : 'dogs';
            await addReferralCommission(user.referred_by, referralEarning, type);
        }
        const updatedUser = await updateUser(userId, updates);
        await updateUserLevel(userId);
        res.json({
            success: true,
            user: updatedUser,
            reward: rewardMessage
        });
    } catch (error) {
        logError('/api/apply-promo', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/watch-ad', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
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
        res.json({
            success: true,
            user: updatedUser,
            reward: reward
        });
    } catch (error) {
        logError('/api/watch-ad', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/watch-monetag-ad', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
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
        res.json({
            success: true,
            user: updatedUser,
            reward: reward
        });
    } catch (error) {
        logError('/api/watch-monetag-ad', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/tasks/:category', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { category } = req.params;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        if (!checkCooldown(userId, req.path)) {
            return res.status(429).json({ error: 'Too many requests. Please wait 5 seconds.' });
        }
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
        const { data: tasks, error } = await supabase
            .from('tasks')
            .select('*')
            .eq('owner', userId)
            .eq('category', 'social')
            .order('created_at', { ascending: false });
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

        const { data: task, error: checkError } = await supabase
            .from('tasks')
            .select('owner, status')
            .eq('id', taskId)
            .single();

        if (checkError || !task) {
            return res.status(404).json({ error: 'Task not found' });
        }

        if (task.owner !== userId) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        if (task.status !== 'completed') {
            return res.status(400).json({ error: 'Task not completed yet' });
        }

        await supabase
            .from('tasks')
            .delete()
            .eq('id', taskId);

        await supabase
            .from('user_completed_tasks')
            .delete()
            .eq('task_id', taskId);

        res.json({ success: true });

    } catch (error) {
        logError('/api/delete-task', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/check-payment', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { memo, amount, taskData } = req.body;
        
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        
        if (!memo || memo.length < 5) {
            return res.json({ success: false, error: 'Invalid memo' });
        }
        
        const rewardNum = parseInt(taskData.reward);
        const totalNum = parseInt(taskData.total);
        
        if (rewardNum > 100) {
            return res.json({ success: false, error: 'Failed to create task.' });
        }
        if (totalNum < 100 || totalNum > 5000) {
            return res.json({ success: false, error: 'Failed to create task..' });
        }
        if (rewardNum * totalNum > 50000) {
            return res.json({ success: false, error: 'Failed to create task...' });
        }
        
        const { data: existingMemo } = await supabase
            .from('used_memos')
            .select('id, user_id, used_at')
            .eq('memo', memo)
            .maybeSingle();
        
        if (existingMemo) {
            return res.json({ 
                success: false, 
                error: 'This payment has already been used' 
            });
        }
        
        const user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const address = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS;
        const response = await fetch(`https://toncenter.com/api/v2/getTransactions?address=${address}&limit=3`);
        const data = await response.json();
        
        if (!data.ok) {
            return res.json({ success: false, error: 'Payment API error' });
        }
        
        let foundTx = null;
        if (data.result && data.result.length > 0) {
            foundTx = data.result.find(tx => {
                const msg = tx.in_msg?.message;
                return msg && msg.includes(memo);
            });
        }
        
        if (!foundTx) {
            return res.json({ success: false, error: 'Payment not found' });
        }
        
        const txHash = foundTx.transaction_id?.hash || 'unknown';
        const txAmount = parseFloat(foundTx.in_msg?.value) / 1000000000 || 0;
        const requiredAmount = (taskData.total * taskData.reward / 1000) * (APP_CONFIG.PRICE_PER_100 || 0.001);
        
        if (txAmount < requiredAmount * 0.95) {
            return res.json({ success: false, error: 'Insufficient payment amount' });
        }
        
        const onChainMemo = foundTx.in_msg?.message || '';
        
        if (onChainMemo !== memo) {
            return res.json({ success: false, error: 'Failed to create task.' });
        }
        
        const { data: existingTask } = await supabase
            .from('tasks')
            .select('id')
            .eq('id', memo)
            .maybeSingle();
        
        if (existingTask) {
            return res.json({ success: false, error: 'Failed to create task.' });
        }
        
        const taskId = memo;
        const taskToAdd = {
            id: taskId,
            name: taskData.name,
            url: taskData.link,
            category: 'social',
            reward: taskData.reward,
            total: taskData.total,
            verification: taskData.verification || false,
            owner: userId,
            status: 'active',
            created_at: getCurrentTime(),
            total_completed: 0,
            notified: false
        };
        
        const { data: taskResult, error: taskError } = await supabase
            .from('tasks')
            .insert([taskToAdd])
            .select()
            .single();
        
        if (taskError) {
            return res.status(500).json({ error: 'Failed to add task' });
        }
        
        await updateUser(userId, { task_count: (user.task_count || 0) + 1 });
        await sendTaskCreatedNotification(taskResult);
        
        return res.json({
            success: true,
            task: taskResult,
            message: 'Payment verified and task added'
        });
    } catch (error) {
        logError('/api/check-payment', error);
        res.status(500).json({ error: error.message });
    }
});

async function sendTaskCreatedNotification(task) {
    try {
        const CHANNEL_ID = '@DOGSTASK';
        if (!BOT_TOKEN) return;
        
        const appLink = `https://t.me/DogsPtsbot/app`;

        const message = `<b>⚡ NEW TASK AVAILABLE!</b>\n\n` +
            `<b>📋 Task: ${task.name}</b>\n` +
            `<b>👷‍♂️ Target: ${task.total} </b>\n` +
            `<b>⏳ Status: ACTIVE</b>\n\n` +
            `<b>🎁 Reward: ${task.reward} POWER + ${APP_CONFIG.SOCIAL_DOGS_REWARD || 1} DOGS</b>`;

        const replyMarkup = {
            inline_keyboard: [[
                { 
                    text: '✅ COMPLETE NOW', 
                    url: appLink 
                }
            ]]
        };

        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: CHANNEL_ID,
                text: message,
                parse_mode: 'HTML',
                reply_markup: replyMarkup,
                disable_web_page_preview: true
            })
        });

    } catch (error) {
        console.error('Failed to send task notification:', error);
    }
}

app.post('/api/setup-promotion', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { channel } = req.body;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }

        if (!channel || !channel.startsWith('https://t.me/')) {
            return res.status(400).json({ error: 'Invalid channel link' });
        }

        const user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { data: existingChannel, error: checkError } = await supabase
            .from('users')
            .select('id')
            .contains('promotion', { channel: channel })
            .neq('id', userId)
            .single();
        
        if (existingChannel) {
            return res.status(400).json({ error: 'You cannot add this channel' });
        }

        const channelMatch = channel.match(/t\.me\/([^\/\?]+)/);
        if (!channelMatch) {
            return res.status(400).json({ error: 'Invalid channel format' });
        }

        const channelUsername = channelMatch[1];

        const isAdmin = await checkBotIsAdminInChannel(channelUsername);
        if (!isAdmin) {
            return res.status(400).json({ error: 'Bot is not admin in the channel. Please add @DogsPtsbot as admin.' });
        }

        const promotionData = {
            channel: channel,
            link: channel,
            status: 'pending',
            submitted_at: getCurrentTime(),
            username: channelUsername
        };

        const updatedUser = await updateUser(userId, { 
            promotion: promotionData 
        });

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
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const promotion = user.promotion || null;
        res.json({ success: true, promotion });
    } catch (error) {
        logError('/api/check-promotion', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/set-wallet', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { wallet } = req.body;
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }

        const user = await getUser(userId);
        if (user.wallet && user.wallet !== wallet) {
            return res.status(400).json({ error: 'Wallet already set.' });
        }

        if (!wallet || !wallet.startsWith('UQ') || wallet.length < 20) {
            return res.status(400).json({ error: 'Invalid wallet address. Must start with UQ and be at least 20 characters.' });
        }

        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('wallet', wallet)
            .neq('id', userId)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'Cannot connect your wallet' });
        }

        const updatedUser = await updateUser(userId, { wallet: wallet });
        res.json({ success: true, user: updatedUser });
    } catch (error) {
        logError('/api/set-wallet', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/withdraw-dogs', authenticate, veryStrictLimiter, async (req, res) => {
    const userId = req._userId;
    
    if (activeWithdrawals.has(userId)) {
        return res.status(429).json({ error: 'Withdrawal already in progress. Please wait.' });
    }
    activeWithdrawals.add(userId);
    
    try {
        const { dogsAmount } = req.body;
        const requestDeviceId = req.body.deviceId || req.headers['x-device-id'];
        
        if (!requestDeviceId || requestDeviceId.length < 10) {
            return res.status(403).json({ error: 'Device ID required for withdrawal' });
        }
        
        const validDevice = await validateDevice(userId, requestDeviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Failed.' });
        }
        
        if (req._deviceId && req._deviceId !== requestDeviceId) {
            return res.status(403).json({ error: 'Failed..' });
        }
        
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const now = Date.now();

        if (user.state === 'ban') {
            return res.status(403).json({ error: 'Account banned', banned: true });
        }
        
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
        if (!walletAddress) {
            return res.status(400).json({ error: 'No wallet set. Please set your wallet first.' });
        }
        
        const dogs = parseFloat(dogsAmount);
        if (isNaN(dogs) || dogs <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        if (!user.username || user.username.trim() === '') {
            return res.status(400).json({ 
                error: 'Failed to send withdrawal request' 
            });
        } 
        
        const fees = APP_CONFIG.WITHDRAWAL_FEES || 100;
        const netDogs = dogs - fees;
        if (netDogs <= 0) {
            return res.status(400).json({ error: `Amount must be greater than fees (${fees} DOGS)` });
        }
        if (dogs < APP_CONFIG.MINIMUM_WITHDRAW) {
            return res.status(400).json({ error: `Minimum withdrawal: ${APP_CONFIG.MINIMUM_WITHDRAW} DOGS` });
        }
        if (dogs > 3000) {
            return res.status(400).json({ error: 'Failed to create withdrawal request..' });
        }
        if ((user.power_balance || 0) < 2001) {
            return res.status(400).json({ error: 'Failed to create withdrawal request...' });
        }
        
        const accountAge = (Date.now() - user.created_at) / 86400000;
        if (accountAge < 2) {
            return res.status(400).json({ error: 'Failed to create withdrawal request....' });
        }
        if ((user.total_mining_starts || 0) < 3) {
            return res.status(400).json({ error: 'Failed to create withdrawal request.....' });
        }

        const { data: freshUser } = await supabase
            .from('users')
            .select('dogs_balance')
            .eq('id', userId)
            .single();
        
        if ((freshUser?.dogs_balance || 0) < dogs) {
            return res.status(400).json({ error: 'Insufficient DOGS balance' });
        }
        
        const { data: deducted, error: deductError } = await supabase
            .from('users')
            .update({ dogs_balance: freshUser.dogs_balance - dogs })
            .eq('id', userId)
            .eq('dogs_balance', freshUser.dogs_balance)
            .select()
            .single();
        
        if (deductError || !deducted) {
            return res.status(409).json({ error: 'Withdrawal conflict. Please try again.' });
        }
        
        getUserCache.delete(`getUser_${userId}`);

        const oxapay = new OxaPay({
            apiKey: process.env.OXAPAY_API_KEY,
            sandbox: process.env.NODE_ENV !== 'production'
        });
        
        try {
            const payout = await oxapay.createPayout({
                toAddress: walletAddress,
                amount: netDogs,
                currency: 'DOGS',
                network: 'TON',
                description: `Withdraw ${netDogs} DOGS for user ${userId}`
            });
            
            if (!payout || !payout.success) {
                await supabase
                    .from('users')
                    .update({ dogs_balance: freshUser.dogs_balance })
                    .eq('id', userId);
                getUserCache.delete(`getUser_${userId}`);
                    
                return res.status(500).json({ 
                    error: payout?.message || payout?.error || 'Payout failed' 
                });
            }
            
            const trackId = payout?.data?.track_id || payout?.trackId || 'N/A';
            const status = 'processing';
            const txHash = payout?.data?.tx_hash || payout?.txHash || null;
            
            await updateUser(userId, { last_withdraw_time: now });
            
            const withdrawal = await createWithdrawal({
                user_id: userId,
                amount: dogs,
                fees: fees,
                dogs_amount: netDogs,
                wallet: walletAddress,
                status: status,
                timestamp: now,
                tx_id: trackId,
                tx_hash: txHash
            });
            
            const finalUser = await getUser(userId);
            
            res.json({
                success: true,
                user: finalUser,
                withdrawal: withdrawal,
                dogsAmount: netDogs,
                trackId: trackId,
                status: status,
                txHash: txHash
            });
        } catch (payoutError) {
            await supabase
                .from('users')
                .update({ dogs_balance: freshUser.dogs_balance })
                .eq('id', userId);
            getUserCache.delete(`getUser_${userId}`);
                
            logError('/api/withdraw-dogs', payoutError);
            return res.status(500).json({ 
                error: 'Payment provider error: ' + payoutError.message 
            });
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
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
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
        const validDevice = await validateDevice(userId, req._deviceId);
        if (!validDevice) {
            return res.status(403).json({ error: 'Device mismatch' });
        }
        const referrals = await getReferrals(userId);
        res.json({ referrals });
    } catch (error) {
        logError('/api/get-referrals', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/cleanup-nouser-highdogs', async (req, res) => {
    try {
        if (req.query.key !== process.env.ADMIN_CLEANUP_KEY) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        let toDelete = [];
        let page = 0;
        let hasMore = true;

        while (hasMore) {
            const { data, error } = await supabase
                .from('users')
                .select('id, username, dogs_balance')
                .or('username.is.null,username.eq.')
                .gt('dogs_balance', 2000)
                .range(page * 1000, (page + 1) * 1000 - 1);
            
            if (error) throw error;
            if (data?.length > 0) { toDelete = toDelete.concat(data.map(u => u.id)); page++; }
            if (!data || data.length < 1000) hasMore = false;
        }

        if (toDelete.length > 0) {
            const batchSize = 500;
            for (let i = 0; i < toDelete.length; i += batchSize) {
                const batch = toDelete.slice(i, i + batchSize);
                await supabase.from('user_completed_tasks').delete().in('user_id', batch);
                await supabase.from('withdrawals').delete().in('user_id', batch);
                await supabase.from('used_promo_codes').delete().in('user_id', batch);
                await supabase.from('verification_codes').delete().in('user_id', batch);
                await supabase.from('users').delete().in('id', batch);
            }
        }

        res.json({
            success: true,
            summary: {
                deleted: toDelete.length,
                deleted_ids: toDelete.slice(0, 100)
            }
        });
    } catch (error) {
        logError('/api/admin/cleanup-nouser-highdogs', error);
        res.status(500).json({ error: error.message });
    }
});


const PORT = process.env.PORT || 8080;

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🏴‍☠️ DOGS PIRATES server running on port ${PORT}`);
});

server.on('error', (error) => {
    console.error('Server error:', error);
});

process.on('SIGTERM', () => {
    server.close(() => {
        process.exit(0);
    });
});
