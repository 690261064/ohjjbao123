const crypto = require('crypto');

const SESSION_COOKIE_NAME = '__session';
const SESSION_DURATION_SECONDS = 1 * 60 * 60; // 1 hour

// Auto-generate session secret key on startup for better security
// 重要提示：为了让会话在 Space 重启后依然有效，建议您将此密钥存储在 Hugging Face 的 Secrets 中，
// 然后通过 process.env.SESSION_SECRET_KEY 读取。
// 但当前随机生成的方式不影响登录功能的修复。
const SESSION_SECRET_KEY = process.env.SESSION_SECRET_KEY || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET_KEY) {
    console.log("Auto-generated session secret key for this session. Set SESSION_SECRET_KEY env var for persistence.");
}


/**
 * Converts Buffer to Base64 URL safe string.
 * @param {Buffer} buffer
 * @returns {string}
 */
function bufferToBase64Url(buffer) {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Converts Base64 URL safe string to Buffer.
 * @param {string} base64url
 * @returns {Buffer}
 */
function base64UrlToBuffer(base64url) {
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
    // Padding is handled automatically by Buffer.from in newer Node versions
    return Buffer.from(base64url, 'base64');
}

/**
 * Generates a signed session token.
 * Payload: { exp: number }
 * @returns {Promise<string|null>} Session token or null on error.
 */
async function generateSessionToken() {
    try {
        const expiration = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
        const payload = JSON.stringify({ exp: expiration });
        const encodedPayload = bufferToBase64Url(Buffer.from(payload));

        // Use Node.js crypto for HMAC
        const hmac = crypto.createHmac('sha256', SESSION_SECRET_KEY);
        hmac.update(encodedPayload);
        const signature = hmac.digest(); // Returns a Buffer
        const encodedSignature = bufferToBase64Url(signature);

        return `${encodedPayload}.${encodedSignature}`;
    } catch (e) {
        console.error("Error generating session token:", e);
        return null;
    }
}

/**
 * Verifies the signature and expiration of a session token.
 * @param {string} token - The session token string.
 * @returns {Promise<boolean>} True if valid and not expired, false otherwise.
 */
async function verifySessionToken(token) {
    if (!token) {
        return false;
    }
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return false;

        const [encodedPayload, encodedSignature] = parts;
        const signatureBuffer = base64UrlToBuffer(encodedSignature);

        // Recalculate HMAC signature for comparison
        const hmac = crypto.createHmac('sha256', SESSION_SECRET_KEY);
        hmac.update(encodedPayload);
        const expectedSignatureBuffer = hmac.digest();

        // Compare signatures using timing-safe comparison
        if (!crypto.timingSafeEqual(signatureBuffer, expectedSignatureBuffer)) {
            console.warn("Session token signature mismatch.");
            return false;
        }

        // Decode payload and check expiration
        const payloadJson = base64UrlToBuffer(encodedPayload).toString();
        const payload = JSON.parse(payloadJson);

        const now = Math.floor(Date.now() / 1000);
        if (payload.exp <= now) {
            console.log("Session token expired.");
            return false;
        }

        return true; // Token is valid and not expired

    } catch (e) {
        console.error("Error verifying session token:", e);
        return false;
    }
}

/**
 * Extracts the session token from the request's cookies.
 * Uses cookie-parser middleware result.
 * @param {import('express').Request} req - Express request object.
 * @returns {string | null} The session token or null.
 */
function getSessionTokenFromCookie(req) {
    // cookie-parser middleware populates req.cookies
    return req.cookies?.[SESSION_COOKIE_NAME] || null;
}

/**
 * Sets the session cookie on the response.
 * @param {import('express').Response} res - Express response object.
 * @param {string} token - The session token.
 */
function setSessionCookie(res, token) {
    const expires = new Date(Date.now() + SESSION_DURATION_SECONDS * 1000);
    res.cookie(SESSION_COOKIE_NAME, token, {
        path: '/',
        expires: expires,
        httpOnly: true,
        // -- START OF FIX ---
        // 关键修复 1: 强制 secure 为 true。
        // 由于我们在 index.js 中设置了 'trust proxy'，Express 可以正确处理 HTTPS。
        secure: true, 
        
        // 关键修复 2: 设置 sameSite 为 'None' 以允许 iframe (跨站) 环境下传递 cookie。
        sameSite: 'None' 
        // -- END OF FIX ---
    });
}

/**
 * Clears the session cookie on the response.
 * @param {import('express').Response} res - Express response object.
 */
function clearSessionCookie(res) {
    res.cookie(SESSION_COOKIE_NAME, '', {
        path: '/',
        expires: new Date(0), // Set expiry date to the past
        httpOnly: true,
        // -- START OF FIX ---
        // 清除 cookie 时也必须使用相同的 secure 和 sameSite 属性，否则浏览器不会清除它。
        secure: true,
        sameSite: 'None'
        // -- END OF FIX ---
    });
}

/**
 * Verifies the session cookie from the request.
 * @param {import('express').Request} req - Express request object.
 * @returns {Promise<boolean>} True if the session is valid.
 */
async function verifySessionCookie(req) {
    const token = getSessionTokenFromCookie(req);
    if (!token) {
        return false;
    }
    return await verifySessionToken(token);
}

module.exports = {
    generateSessionToken,
    verifySessionToken,
    getSessionTokenFromCookie,
    setSessionCookie,
    clearSessionCookie,
    verifySessionCookie,
    SESSION_COOKIE_NAME,
};
