/**
 * 微信 JSSDK 签名接口示例（部署到 HTTPS 后使用）
 *
 * 用法：
 * 1. 在微信公众平台 → 设置与开发 → 公众号设置 → 功能设置 → JS接口安全域名
 *    填入你的游戏域名（如 game.example.com）
 * 2. 配置环境变量后运行：node wx-sign-server.example.js
 * 3. 在游戏 HTML 里设置 WECHAT_SHARE.signApi = 'https://你的域名/api/wx-sign'
 *
 * 环境变量：
 *   WX_APP_ID          公众号 AppID
 *   WX_APP_SECRET      公众号 AppSecret
 *   PORT               默认 8787
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');

const APP_ID = process.env.WX_APP_ID || '';
const APP_SECRET = process.env.WX_APP_SECRET || '';
const PORT = Number(process.env.PORT || 8787);

let tokenCache = { token: '', expires: 0 };
let ticketCache = { ticket: '', expires: 0 };

function getJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

async function getAccessToken() {
  if (tokenCache.token && Date.now() < tokenCache.expires) return tokenCache.token;
  const url = `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${APP_ID}&secret=${APP_SECRET}`;
  const data = await getJson(url);
  if (!data.access_token) throw new Error(data.errmsg || '获取 access_token 失败');
  tokenCache = { token: data.access_token, expires: Date.now() + (data.expires_in - 120) * 1000 };
  return tokenCache.token;
}

async function getJsapiTicket() {
  if (ticketCache.ticket && Date.now() < ticketCache.expires) return ticketCache.ticket;
  const token = await getAccessToken();
  const url = `https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=${token}&type=jsapi`;
  const data = await getJson(url);
  if (!data.ticket) throw new Error(data.errmsg || '获取 jsapi_ticket 失败');
  ticketCache = { ticket: data.ticket, expires: Date.now() + (data.expires_in - 120) * 1000 };
  return ticketCache.ticket;
}

function sign(ticket, url) {
  const nonceStr = crypto.randomBytes(8).toString('hex');
  const timestamp = Math.floor(Date.now() / 1000);
  const raw = `jsapi_ticket=${ticket}&noncestr=${nonceStr}&timestamp=${timestamp}&url=${url}`;
  const signature = crypto.createHash('sha1').update(raw).digest('hex');
  return { appId: APP_ID, timestamp, nonceStr, signature };
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  if (u.pathname !== '/api/wx-sign') {
    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }

  if (!APP_ID || !APP_SECRET) {
    res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: '请配置 WX_APP_ID 和 WX_APP_SECRET' }));
    return;
  }

  const pageUrl = u.searchParams.get('url') || '';
  if (!pageUrl.startsWith('https://')) {
    res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'url 必须是 https 完整链接' }));
    return;
  }

  try {
    const ticket = await getJsapiTicket();
    const body = sign(ticket, pageUrl);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: String(err.message || err) }));
  }
});

server.listen(PORT, () => {
  console.log(`wx-sign 示例服务: http://127.0.0.1:${PORT}/api/wx-sign?url=你的游戏https链接`);
});
