/**
 * Silva Method Mastery – CMS Backend
 * Cloudflare Worker + D1 database
 *
 * Routes:
 *   GET  /                      → Login page
 *   POST /auth/send-otp         → Send OTP to email
 *   POST /auth/verify-otp       → Verify OTP, issue session
 *   GET  /dashboard             → CMS dashboard (auth required)
 *   GET  /api/content           → Get all content (auth required)
 *   POST /api/content           → Save content to D1 (auth required)
 *   POST /api/publish           → Publish to GitHub (auth required)
 *   GET  /setup/gmail           → Start Gmail OAuth2 setup
 *   GET  /setup/gmail/callback  → Gmail OAuth2 callback
 *   GET  /logout                → Clear session
 *
 * Required Cloudflare Secrets (set via wrangler secret put):
 *   GOOGLE_CLIENT_ID     – Google OAuth2 Client ID
 *   GOOGLE_CLIENT_SECRET – Google OAuth2 Client Secret
 *   SESSION_SECRET       – Random string for signing sessions (min 32 chars)
 *   GITHUB_TOKEN         – GitHub PAT with repo Contents write permission
 */

const OTP_EXPIRY_MINS   = 10;
const SESSION_EXPIRY_HRS = 24;
const BASE_PATH = '/cms'; // URL prefix for all CMS routes

// ─── Helpers ────────────────────────────────────────────────────────────────

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateToken(len = 48) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let t = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  arr.forEach(b => t += chars[b % chars.length]);
  return t;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function html(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', ...extra }
  });
}

function redirect(location, headers = {}) {
  return new Response(null, { status: 302, headers: { Location: location, ...headers } });
}

async function getSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match  = cookie.match(/smm_session=([A-Za-z0-9]+)/);
  if (!match) return null;
  const token = match[1];
  const now   = Date.now();
  const row   = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token = ? AND expires_at > ?'
  ).bind(token, now).first();
  return row || null;
}

// ─── Gmail API (OAuth2) ──────────────────────────────────────────────────────

async function getGmailAccessToken(env) {
  const row = await env.DB.prepare('SELECT * FROM gmail_oauth WHERE id = 1').first();
  if (!row) return null;

  // Use cached access token if still valid (with 60s buffer)
  const now = Date.now();
  if (row.access_token && row.token_expiry && row.token_expiry - 60000 > now) {
    return row.access_token;
  }

  // Refresh the access token
  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: row.refresh_token,
      grant_type:    'refresh_token',
    }),
  });
  const data = await resp.json();
  if (!data.access_token) return null;

  const expiry = now + (data.expires_in || 3600) * 1000;
  await env.DB.prepare(
    'UPDATE gmail_oauth SET access_token = ?, token_expiry = ? WHERE id = 1'
  ).bind(data.access_token, expiry).run();

  return data.access_token;
}

async function sendGmailOTP(env, toEmail, otp) {
  const accessToken = await getGmailAccessToken(env);

  if (!accessToken) {
    // Dev-mode fallback: log OTP (visible in Cloudflare Workers Logs)
    console.log(`[DEV MODE] OTP for ${toEmail}: ${otp}`);
    return { ok: true, devMode: true };
  }

  const subject  = 'Your Silva Method Mastery CMS Login Code';
  const bodyText = `Your one-time login code is: ${otp}\n\nThis code expires in ${OTP_EXPIRY_MINS} minutes.\n\nIf you did not request this, please ignore this email.\n\n— Silva Method Mastery CMS`;

  // Build RFC 2822 email message
  const message = [
    `From: Silva Method Mastery CMS <${env.ADMIN_EMAIL}>`,
    `To: ${toEmail}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    bodyText,
  ].join('\r\n');

  const encodedMsg = btoa(unescape(encodeURIComponent(message)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const resp = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
    {
      method:  'POST',
      headers: {
        Authorization:  `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ raw: encodedMsg }),
    }
  );

  if (!resp.ok) {
    const err = await resp.text();
    console.error('Gmail send error:', err);
    return { ok: false, error: 'Failed to send email' };
  }
  return { ok: true };
}

// ─── GitHub API ──────────────────────────────────────────────────────────────

async function getGitHubFile(env, branch) {
  const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${env.SITE_FILE}?ref=${branch}`;
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept:        'application/vnd.github.v3+json',
      'User-Agent':  'SMM-CMS/1.0',
    },
  });
  if (!resp.ok) return null;
  return resp.json();
}

async function commitGitHubFile(env, branch, content, sha, message) {
  const url = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${env.SITE_FILE}`;
  const encoded = btoa(unescape(encodeURIComponent(content)));
  const resp = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization:  `Bearer ${env.GITHUB_TOKEN}`,
      Accept:         'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent':   'SMM-CMS/1.0',
    },
    body: JSON.stringify({
      message,
      content: encoded,
      sha,
      branch,
    }),
  });
  return resp.ok ? resp.json() : null;
}

function injectCMSContent(htmlStr, contentMap) {
  // Replace content between <!-- cms:KEY --> and <!-- /cms:KEY --> markers
  let result = htmlStr;
  for (const [key, value] of Object.entries(contentMap)) {
    const start = `<!-- cms:${key} -->`;
    const end   = `<!-- /cms:${key} -->`;
    const escaped_start = start.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const escaped_end   = end.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`${escaped_start}[\\s\\S]*?${escaped_end}`, 'g');
    if (re.test(result)) {
      result = result.replace(re, `${start}${value}${end}`);
    }
  }
  return result;
}

// ─── Content Definitions ─────────────────────────────────────────────────────

const CONTENT_SCHEMA = [
  {
    section: 'Hero',
    fields: [
      { key: 'hero.badge',    label: 'Badge Text',     type: 'text',     hint: 'Small label above headline' },
      { key: 'hero.headline', label: 'Headline',       type: 'text',     hint: 'Main headline (plain text part)' },
      { key: 'hero.headline_italic', label: 'Headline (italic gold)', type: 'text', hint: 'Second line of headline in gold italic' },
      { key: 'hero.subtitle', label: 'Subtitle',       type: 'textarea', hint: 'Paragraph below the headline' },
      { key: 'hero.video_label', label: 'Video Label', type: 'text',     hint: 'Caption under the video embed' },
    ]
  },
  {
    section: 'Lead Capture (Top)',
    fields: [
      { key: 'lead.heading',     label: 'Heading',      type: 'text',     hint: '' },
      { key: 'lead.subtitle',    label: 'Subtitle',     type: 'text',     hint: '' },
      { key: 'lead.button_text', label: 'Button Text',  type: 'text',     hint: '' },
      { key: 'lead.privacy',     label: 'Privacy Note', type: 'text',     hint: 'Small text below button' },
    ]
  },
  {
    section: 'Features (What You\'ll Experience)',
    fields: [
      { key: 'features.badge',   label: 'Badge',   type: 'text', hint: '' },
      { key: 'features.heading', label: 'Heading', type: 'text', hint: '' },
      { key: 'features.card1.title', label: 'Card 1 Title', type: 'text',     hint: '' },
      { key: 'features.card1.body',  label: 'Card 1 Body',  type: 'textarea', hint: '' },
      { key: 'features.card2.title', label: 'Card 2 Title', type: 'text',     hint: '' },
      { key: 'features.card2.body',  label: 'Card 2 Body',  type: 'textarea', hint: '' },
      { key: 'features.card3.title', label: 'Card 3 Title', type: 'text',     hint: '' },
      { key: 'features.card3.body',  label: 'Card 3 Body',  type: 'textarea', hint: '' },
    ]
  },
  {
    section: 'Testimonials',
    fields: [
      { key: 'testimonials.badge',   label: 'Badge',   type: 'text', hint: '' },
      { key: 'testimonials.heading', label: 'Heading (white)', type: 'text', hint: '' },
      { key: 'testimonials.heading_italic', label: 'Heading (gold italic)', type: 'text', hint: '' },
      { key: 'testimonials.t1.quote',  label: 'Testimonial 1 – Quote',  type: 'textarea', hint: '' },
      { key: 'testimonials.t1.author', label: 'Testimonial 1 – Author', type: 'text',     hint: 'Name' },
      { key: 'testimonials.t1.role',   label: 'Testimonial 1 – Role',   type: 'text',     hint: 'e.g. Hall of Fame Speaker' },
      { key: 'testimonials.t2.quote',  label: 'Testimonial 2 – Quote',  type: 'textarea', hint: '' },
      { key: 'testimonials.t2.author', label: 'Testimonial 2 – Author', type: 'text',     hint: '' },
      { key: 'testimonials.t2.role',   label: 'Testimonial 2 – Role',   type: 'text',     hint: '' },
      { key: 'testimonials.t3.quote',  label: 'Testimonial 3 – Quote',  type: 'textarea', hint: '' },
      { key: 'testimonials.t3.author', label: 'Testimonial 3 – Author', type: 'text',     hint: '' },
      { key: 'testimonials.t3.role',   label: 'Testimonial 3 – Role',   type: 'text',     hint: '' },
    ]
  },
  {
    section: 'About Gary',
    fields: [
      { key: 'about.badge',           label: 'Badge',               type: 'text',     hint: '' },
      { key: 'about.heading',         label: 'Heading (white)',      type: 'text',     hint: '' },
      { key: 'about.heading_italic',  label: 'Heading (gold italic)',type: 'text',     hint: '' },
      { key: 'about.bio1',            label: 'Bio Paragraph 1',     type: 'textarea', hint: '' },
      { key: 'about.bio2',            label: 'Bio Paragraph 2',     type: 'textarea', hint: '' },
      { key: 'about.bio3',            label: 'Bio Paragraph 3',     type: 'textarea', hint: '' },
      { key: 'about.tag1',            label: 'Tag 1',               type: 'text',     hint: 'e.g. CERTIFIED SILVA INSTRUCTOR' },
      { key: 'about.tag2',            label: 'Tag 2',               type: 'text',     hint: 'e.g. 15+ YEARS LEADERSHIP' },
      { key: 'about.tag3',            label: 'Tag 3',               type: 'text',     hint: 'e.g. SENIOR VICE PRESIDENT' },
    ]
  },
  {
    section: 'CTA (Bottom Download)',
    fields: [
      { key: 'cta.badge',        label: 'Badge',            type: 'text',     hint: '' },
      { key: 'cta.heading',      label: 'Heading (white)',  type: 'text',     hint: '' },
      { key: 'cta.heading_gold', label: 'Heading (gold)',   type: 'text',     hint: '' },
      { key: 'cta.subtitle',     label: 'Subtitle',         type: 'textarea', hint: '' },
      { key: 'cta.button_text',  label: 'Button Text',      type: 'text',     hint: '' },
      { key: 'cta.privacy',      label: 'Privacy Note',     type: 'text',     hint: '' },
    ]
  },
];

// ─── HTML Pages ──────────────────────────────────────────────────────────────

const COMMON_CSS = `
  :root{--navy:#0C1E35;--navy-card:#112544;--navy-sidebar:#0a1929;--gold:#C9A84C;--teal:#4EC3C8;--white:#fff;--muted:rgba(255,255,255,0.45);--danger:#e74c3c;--success:#2ecc71}
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--navy);color:var(--white);min-height:100vh;font-size:14px}
  a{color:var(--teal);text-decoration:none}
  .btn{display:inline-flex;align-items:center;gap:6px;padding:10px 22px;border-radius:4px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .18s;letter-spacing:.4px;text-decoration:none}
  .btn-gold{background:var(--gold);color:#1a0a00}.btn-gold:hover{background:#d4aa3a}
  .btn-outline{background:transparent;border:1px solid var(--gold);color:var(--gold)}.btn-outline:hover{background:rgba(201,168,76,.1)}
  .btn-teal{background:var(--teal);color:#003340}.btn-teal:hover{background:#3aacb1}
  .btn-danger{background:var(--danger);color:#fff}.btn-danger:hover{background:#c0392b}
  .btn-sm{padding:6px 14px;font-size:12px}
  input,textarea,select{width:100%;padding:10px 14px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);border-radius:4px;color:var(--white);font-size:13px;transition:border-color .2s;font-family:inherit}
  input:focus,textarea:focus{outline:none;border-color:var(--gold)}
  textarea{resize:vertical;min-height:90px;line-height:1.5}
  label{display:block;font-size:11px;font-weight:700;letter-spacing:1.2px;color:var(--teal);margin-bottom:5px;text-transform:uppercase}
  .field{margin-bottom:18px}
  .hint{font-size:11px;color:var(--muted);margin-top:4px}
  .card{background:var(--navy-card);border:1px solid rgba(201,168,76,.12);border-radius:8px;padding:24px;margin-bottom:20px}
  .msg{padding:12px 16px;border-radius:4px;margin-bottom:16px;font-size:13px;line-height:1.5}
  .msg-error{background:rgba(231,76,60,.12);border:1px solid rgba(231,76,60,.35);color:#f39c95}
  .msg-success{background:rgba(46,204,113,.12);border:1px solid rgba(46,204,113,.35);color:#82e6a5}
  .msg-info{background:rgba(78,195,200,.12);border:1px solid rgba(78,195,200,.35);color:#9ee8eb}
  .msg-warn{background:rgba(201,168,76,.12);border:1px solid rgba(201,168,76,.35);color:#e8d67a}
  .badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:1.5px;padding:3px 10px;border-radius:20px;text-transform:uppercase}
  .badge-gold{background:rgba(201,168,76,.15);color:var(--gold)}
  .badge-teal{background:rgba(78,195,200,.15);color:var(--teal)}
  .badge-green{background:rgba(46,204,113,.15);color:var(--success)}
`;

function loginPage(msg = '', base = '') {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Silva Method Mastery CMS</title>
<style>${COMMON_CSS}
  .login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .login-box{width:100%;max-width:420px}
  .login-header{text-align:center;margin-bottom:36px}
  .login-header .eyebrow{font-size:10px;letter-spacing:3px;color:var(--teal);margin-bottom:8px}
  .login-header h1{font-size:26px;font-weight:300;margin-bottom:4px}
  .login-header p{color:var(--muted);font-size:12px}
  .login-card{background:var(--navy-card);border:1px solid rgba(201,168,76,.15);border-radius:10px;padding:36px}
  .footer-note{text-align:center;margin-top:20px;font-size:11px;color:rgba(255,255,255,.25)}
</style></head><body>
<div class="login-wrap"><div class="login-box">
  <div class="login-header">
    <div class="eyebrow">SILVA METHOD MASTERY</div>
    <h1>CMS Admin</h1>
    <p>Content Management System</p>
  </div>
  <div class="login-card">
    ${msg}
    <div id="step1">
      <div class="field">
        <label>Email Address</label>
        <input type="email" id="email" placeholder="your@email.com">
      </div>
      <button class="btn btn-gold" style="width:100%" onclick="sendOTP()">Send One-Time Password &rarr;</button>
    </div>
    <div id="step2" style="display:none">
      <div class="msg msg-info" id="otp-info"></div>
      <div class="field">
        <label>One-Time Password</label>
        <input type="text" id="otp" placeholder="Enter 6-digit code" maxlength="6"
          style="font-size:24px;letter-spacing:8px;text-align:center" autocomplete="one-time-code">
      </div>
      <button class="btn btn-gold" style="width:100%;margin-bottom:10px" onclick="verifyOTP()">Verify &amp; Login &rarr;</button>
      <button class="btn btn-outline" style="width:100%;font-size:12px" onclick="goBack()">&larr; Use different email</button>
    </div>
    <div id="loading" style="display:none;text-align:center;padding:20px;color:var(--muted)">Sending code&hellip;</div>
  </div>
  <p class="footer-note">Secure OTP login &bull; Access restricted to authorised accounts</p>
</div></div>
<script>
const _B='${base}';
async function sendOTP(){
  const email=document.getElementById('email').value.trim();
  if(!email)return alert('Please enter your email');
  document.getElementById('step1').style.display='none';
  document.getElementById('loading').style.display='block';
  const r=await fetch(_B+'/auth/send-otp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
  const d=await r.json();
  document.getElementById('loading').style.display='none';
  if(d.ok){
    document.getElementById('otp-info').textContent='OTP sent to '+email+'. Check your inbox (and spam folder).';
    if(d.devMode)document.getElementById('otp-info').textContent+=' [Dev mode: check Cloudflare Worker logs for the OTP]';
    document.getElementById('step2').style.display='block';
    document.getElementById('otp').focus();
  }else{
    document.getElementById('step1').style.display='block';
    alert(d.error||'Failed to send OTP. Please try again.');
  }
}
async function verifyOTP(){
  const email=document.getElementById('email').value.trim();
  const otp=document.getElementById('otp').value.trim();
  if(otp.length!==6)return alert('Please enter the 6-digit code');
  const r=await fetch(_B+'/auth/verify-otp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,otp})});
  const d=await r.json();
  if(d.ok){window.location.href=_B+'/dashboard';}
  else{alert(d.error||'Invalid or expired OTP. Please try again.');}
}
function goBack(){
  document.getElementById('step2').style.display='none';
  document.getElementById('step1').style.display='block';
  document.getElementById('otp').value='';
}
document.addEventListener('keyup',e=>{if(e.key==='Enter'&&document.getElementById('step2').style.display!=='none')verifyOTP();});
</script></body></html>`;
}

function dashboardPage(session, content, isGmailConfigured, isGitHubConfigured, base = '') {
  const contentMap = {};
  for (const row of content) contentMap[row.content_key] = row.value;

  const gmailWarning = !isGmailConfigured
    ? `<div class="msg msg-warn">&#9888; Gmail not connected — OTPs are logged to Cloudflare Workers console (dev mode). <a href="${base}/setup/gmail">Connect Gmail &rarr;</a></div>`
    : '';
  const gitWarning = !isGitHubConfigured
    ? `<div class="msg msg-warn">&#9888; GitHub token not configured — Publish to website will not work until GITHUB_TOKEN secret is set.</div>`
    : '';

  let sectionsHTML = '';
  for (const section of CONTENT_SCHEMA) {
    const fields = section.fields.map(f => {
      const val = (contentMap[f.key] || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const input = f.type === 'textarea'
        ? `<textarea id="f_${f.key}" data-key="${f.key}">${val}</textarea>`
        : `<input type="text" id="f_${f.key}" data-key="${f.key}" value="${val}">`;
      const hint = f.hint ? `<div class="hint">${f.hint}</div>` : '';
      return `<div class="field"><label>${f.label}</label>${input}${hint}</div>`;
    }).join('');

    sectionsHTML += `
      <div class="card" id="section_${section.section.replace(/[^a-z0-9]/gi,'_')}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
          <h2 style="font-size:15px;font-weight:600;color:var(--gold)">${section.section}</h2>
        </div>
        ${fields}
      </div>`;
  }

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — Silva Method Mastery CMS</title>
<style>${COMMON_CSS}
  .layout{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
  .sidebar{background:var(--navy-sidebar);border-right:1px solid rgba(255,255,255,.07);padding:0;position:sticky;top:0;height:100vh;overflow-y:auto}
  .sidebar-logo{padding:24px 20px 16px;border-bottom:1px solid rgba(255,255,255,.07)}
  .sidebar-logo .eyebrow{font-size:9px;letter-spacing:2.5px;color:var(--teal);margin-bottom:4px}
  .sidebar-logo h1{font-size:15px;font-weight:600}
  .sidebar-logo p{font-size:11px;color:var(--muted);margin-top:2px}
  .sidebar-nav{padding:16px 0}
  .nav-label{font-size:9px;letter-spacing:1.8px;color:var(--muted);padding:8px 20px 4px;text-transform:uppercase}
  .nav-item{display:block;padding:9px 20px;font-size:13px;color:rgba(255,255,255,.7);cursor:pointer;border-left:3px solid transparent;transition:all .15s}
  .nav-item:hover{background:rgba(255,255,255,.05);color:var(--white);border-left-color:var(--gold)}
  .nav-item.active{background:rgba(201,168,76,.08);color:var(--gold);border-left-color:var(--gold)}
  .sidebar-footer{padding:16px 20px;border-top:1px solid rgba(255,255,255,.07);margin-top:auto}
  .main{padding:32px;max-width:860px}
  .page-header{margin-bottom:28px}
  .page-header h2{font-size:22px;font-weight:300;margin-bottom:4px}
  .page-header p{color:var(--muted);font-size:13px}
  .toolbar{display:flex;gap:10px;align-items:center;margin-bottom:24px;flex-wrap:wrap}
  .status-bar{font-size:12px;color:var(--muted);margin-left:auto}
  #save-status{font-size:12px;color:var(--teal);min-width:120px;text-align:right}
</style></head><body>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-logo">
      <div class="eyebrow">SILVA METHOD MASTERY</div>
      <h1>CMS Admin</h1>
      <p>Logged in as ${session.email}</p>
    </div>
    <nav class="sidebar-nav">
      <div class="nav-label">Content</div>
      ${CONTENT_SCHEMA.map(s =>
        `<a class="nav-item" onclick="scrollTo('section_${s.section.replace(/[^a-z0-9]/gi,'_')}')">${s.section}</a>`
      ).join('')}
      <div class="nav-label" style="margin-top:12px">System</div>
      <a class="nav-item" href="${base}/setup/gmail">Gmail Setup</a>
      <a class="nav-item" href="${base}/logout">Logout</a>
    </nav>
  </aside>
  <main class="main">
    <div class="page-header">
      <h2>Website Content Editor</h2>
      <p>Edit your website content below. Save drafts or publish directly to your site.</p>
    </div>
    ${gmailWarning}${gitWarning}
    <div class="toolbar">
      <button class="btn btn-outline btn-sm" onclick="saveAll()">&#128190; Save Draft</button>
      <button class="btn btn-teal btn-sm" onclick="publishSite('staging')">&#8593; Publish to Staging</button>
      <button class="btn btn-gold btn-sm" onclick="publishSite('main')">&#10003; Publish to Production</button>
      <span id="save-status"></span>
    </div>
    <div id="flash"></div>
    ${sectionsHTML}
    <div style="height:60px"></div>
  </main>
</div>
<script>
const _B='${base}';
function scrollTo(id){
  const el=document.getElementById(id);
  if(el)el.scrollIntoView({behavior:'smooth',block:'start'});
}
function getContentMap(){
  const map={};
  document.querySelectorAll('[data-key]').forEach(el=>{map[el.dataset.key]=el.value;});
  return map;
}
async function saveAll(){
  const map=getContentMap();
  document.getElementById('save-status').textContent='Saving\u2026';
  const r=await fetch(_B+'/api/content',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({page:'main',content:map})});
  const d=await r.json();
  document.getElementById('save-status').textContent=d.ok?'\u2713 Saved':'Failed to save';
  showFlash(d.ok?'success':'error',d.ok?'Draft saved successfully.':d.error||'Save failed.');
  setTimeout(()=>document.getElementById('save-status').textContent='',3000);
}
async function publishSite(branch){
  const label=branch==='main'?'production':'staging';
  if(!confirm('Publish to '+label+'? This will update the live '+label+' website.'))return;
  document.getElementById('save-status').textContent='Publishing\u2026';
  await saveAll();
  const r=await fetch(_B+'/api/publish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({branch})});
  const d=await r.json();
  document.getElementById('save-status').textContent='';
  showFlash(d.ok?'success':'error',d.ok?'Published to '+label+'! Site will update in ~1 minute.':d.error||'Publish failed.');
}
function showFlash(type,msg){
  const el=document.getElementById('flash');
  el.innerHTML='<div class="msg msg-'+type+'">'+msg+'</div>';
  setTimeout(()=>el.innerHTML='',6000);
}
// Auto-save indication
document.querySelectorAll('[data-key]').forEach(el=>{
  el.addEventListener('input',()=>{
    document.getElementById('save-status').textContent='\u25cf Unsaved changes';
  });
});
</script></body></html>`;
}

function gmailSetupPage(env, isConfigured, callbackUrl, base = '') {
  const authUrl = isConfigured ? '' : `https://accounts.google.com/o/oauth2/v2/auth?` + new URLSearchParams({
    client_id:     env.GOOGLE_CLIENT_ID || 'NOT_CONFIGURED',
    redirect_uri:  callbackUrl,
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/gmail.send',
    access_type:   'offline',
    prompt:        'consent',
  });

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gmail Setup — CMS</title>
<style>${COMMON_CSS}
  .wrap{max-width:600px;margin:60px auto;padding:0 20px}
  h1{font-size:22px;font-weight:400;margin-bottom:6px}
  p{color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:16px}
</style></head><body>
<div class="wrap">
  <div style="margin-bottom:24px"><a href="${base}/dashboard">&larr; Back to Dashboard</a></div>
  <h1>Gmail OAuth2 Setup</h1>
  ${isConfigured
    ? '<div class="msg msg-success">&#10003; Gmail is connected. OTPs will be sent from your Gmail account.</div>'
    : `<div class="msg msg-warn">&#9888; Gmail is not yet connected. OTPs are currently logged to Cloudflare Workers console only.</div>
       <div class="card">
         <h2 style="font-size:15px;color:var(--gold);margin-bottom:16px">One-Time Setup</h2>
         <p>To send OTPs from your Gmail account, you need to connect it once. This uses Google's secure OAuth2 — your password is never shared.</p>
         <p><strong>Prerequisites:</strong> You need a Google Cloud project with Gmail API enabled and OAuth2 credentials. See the setup guide in the documentation.</p>
         ${env.GOOGLE_CLIENT_ID
           ? `<a href="${authUrl}" class="btn btn-gold">Connect Gmail Account &rarr;</a>`
           : '<div class="msg msg-error">GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET secrets are not set. Add them as Cloudflare Worker secrets first.</div>'}
       </div>`
  }
  <div class="card" style="margin-top:20px">
    <h2 style="font-size:15px;color:var(--gold);margin-bottom:12px">Setup Instructions</h2>
    <ol style="padding-left:20px;line-height:2;font-size:13px;color:rgba(255,255,255,.8)">
      <li>Go to <a href="https://console.cloud.google.com" target="_blank">Google Cloud Console</a></li>
      <li>Create a new project (or use an existing one)</li>
      <li>Enable the <strong>Gmail API</strong></li>
      <li>Go to Credentials &rarr; Create OAuth 2.0 Client ID</li>
      <li>Application type: <strong>Web application</strong></li>
      <li>Add Authorised redirect URI: <code style="background:rgba(255,255,255,.08);padding:2px 6px;border-radius:3px">${callbackUrl}</code></li>
      <li>Copy the Client ID and Client Secret</li>
      <li>Set them as Cloudflare secrets: <code style="background:rgba(255,255,255,.08);padding:2px 6px;border-radius:3px">wrangler secret put GOOGLE_CLIENT_ID</code></li>
      <li>Then click "Connect Gmail Account" above</li>
    </ol>
  </div>
</div></body></html>`;
}

// ─── Route Handlers ──────────────────────────────────────────────────────────

async function handleSendOTP(request, env) {
  try {
    const { email } = await request.json();
    if (!email || email.toLowerCase().trim() !== env.ADMIN_EMAIL.toLowerCase()) {
      return json({ ok: false, error: 'This email is not authorised.' }, 403);
    }

    // Invalidate old OTPs for this email
    const now = Date.now();
    await env.DB.prepare('UPDATE otp_codes SET used = 1 WHERE email = ? AND used = 0').bind(email).run();

    const code      = generateOTP();
    const expiresAt = now + OTP_EXPIRY_MINS * 60 * 1000;

    await env.DB.prepare(
      'INSERT INTO otp_codes (email, code, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)'
    ).bind(email, code, now, expiresAt).run();

    const result = await sendGmailOTP(env, email, code);
    if (!result.ok) return json({ ok: false, error: result.error }, 500);

    return json({ ok: true, devMode: result.devMode || false });
  } catch (e) {
    console.error('sendOTP error:', e);
    return json({ ok: false, error: 'Server error' }, 500);
  }
}

async function handleVerifyOTP(request, env) {
  try {
    const { email, otp } = await request.json();
    const now = Date.now();

    const row = await env.DB.prepare(
      'SELECT * FROM otp_codes WHERE email = ? AND code = ? AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1'
    ).bind(email, otp, now).first();

    if (!row) return json({ ok: false, error: 'Invalid or expired OTP.' }, 401);

    await env.DB.prepare('UPDATE otp_codes SET used = 1 WHERE id = ?').bind(row.id).run();

    const token     = generateToken();
    const expiresAt = now + SESSION_EXPIRY_HRS * 3600 * 1000;
    await env.DB.prepare(
      'INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)'
    ).bind(token, email, now, expiresAt).run();

    const cookie = `smm_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_EXPIRY_HRS * 3600}`;
    return json({ ok: true }, 200, { 'Set-Cookie': cookie });
  } catch (e) {
    console.error('verifyOTP error:', e);
    return json({ ok: false, error: 'Server error' }, 500);
  }
}

async function handleGetContent(request, env) {
  const rows = await env.DB.prepare('SELECT * FROM content WHERE page = ?').bind('main').all();
  return json({ ok: true, content: rows.results });
}

async function handleSaveContent(request, env) {
  try {
    const { page, content } = await request.json();
    const now = Date.now();
    for (const [key, value] of Object.entries(content)) {
      await env.DB.prepare(
        'INSERT INTO content (page, content_key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(page, content_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
      ).bind(page, key, value, now).run();
    }
    return json({ ok: true });
  } catch (e) {
    console.error('saveContent error:', e);
    return json({ ok: false, error: 'Failed to save content' }, 500);
  }
}

async function handlePublish(request, env) {
  if (!env.GITHUB_TOKEN) {
    return json({ ok: false, error: 'GITHUB_TOKEN secret is not configured. Please add it as a Cloudflare Worker secret.' }, 400);
  }
  try {
    const { branch } = await request.json();
    if (!['staging', 'main'].includes(branch)) return json({ ok: false, error: 'Invalid branch' }, 400);

    // Get all saved content
    const rows = await env.DB.prepare('SELECT content_key, value FROM content WHERE page = ?').bind('main').all();
    const contentMap = {};
    for (const row of rows.results) contentMap[row.content_key] = row.value;

    // Get current HTML from GitHub
    const fileData = await getGitHubFile(env, branch);
    if (!fileData) return json({ ok: false, error: 'Could not fetch HTML from GitHub. Check GITHUB_TOKEN permissions.' }, 500);

    // Decode and inject content
    const currentHTML = decodeURIComponent(escape(atob(fileData.content.replace(/\n/g, ''))));
    const updatedHTML = injectCMSContent(currentHTML, contentMap);

    if (updatedHTML === currentHTML) {
      return json({ ok: true, message: 'No changes detected — content markers may not be set up yet.' });
    }

    // Commit back to GitHub
    const result = await commitGitHubFile(
      env, branch, updatedHTML, fileData.sha,
      `CMS: Update website content [${new Date().toISOString()}]`
    );

    if (!result) return json({ ok: false, error: 'Failed to commit to GitHub. Check token permissions.' }, 500);
    return json({ ok: true });
  } catch (e) {
    console.error('publish error:', e);
    return json({ ok: false, error: 'Publish failed: ' + e.message }, 500);
  }
}

async function handleGmailSetup(request, env) {
  const url         = new URL(request.url);
  const callbackUrl = `${url.origin}/cms/setup/gmail/callback`;
  const row         = await env.DB.prepare('SELECT id FROM gmail_oauth WHERE id = 1').first();
  return html(gmailSetupPage(env, !!row, callbackUrl, BASE_PATH));
}

async function handleGmailCallback(request, env) {
  const url  = new URL(request.url);
  const code = url.searchParams.get('code');
  if (!code) return html('<p>Error: No code returned. <a href="/cms/setup/gmail">Try again</a></p>', 400);

  const callbackUrl = `${url.origin}/setup/gmail/callback`;
  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri:  callbackUrl,
      grant_type:    'authorization_code',
    }),
  });
  const data = await resp.json();
  if (!data.refresh_token) {
    return html(`<p>Error: No refresh token. Make sure prompt=consent is set. Error: ${JSON.stringify(data)}</p>`, 400);
  }
  const now    = Date.now();
  const expiry = now + (data.expires_in || 3600) * 1000;
  await env.DB.prepare(
    'INSERT INTO gmail_oauth (id, refresh_token, access_token, token_expiry) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET refresh_token=excluded.refresh_token, access_token=excluded.access_token, token_expiry=excluded.token_expiry'
  ).bind(data.refresh_token, data.access_token || null, expiry).run();

  return redirect(BASE_PATH + '/setup/gmail');
}

// ─── Main Entry Point ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const method = request.method;

    // Strip BASE_PATH prefix so internal route matching stays the same
    let path = url.pathname;
    if (BASE_PATH && path.startsWith(BASE_PATH)) {
      path = path.slice(BASE_PATH.length) || '/';
    }

    // Public routes
    if (path === '/' && method === 'GET') return html(loginPage('', BASE_PATH));

    if (path === '/auth/send-otp' && method === 'POST')
      return handleSendOTP(request, env);

    if (path === '/auth/verify-otp' && method === 'POST')
      return handleVerifyOTP(request, env);

    if (path === '/logout') {
      const session = await getSession(request, env);
      if (session) {
        await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(session.token).run();
      }
      return redirect(BASE_PATH, { 'Set-Cookie': 'smm_session=; Path=/; Max-Age=0' });
    }

    // Auth-required routes
    const session = await getSession(request, env);
    if (!session) return redirect(BASE_PATH);

    if (path === '/dashboard' && method === 'GET') {
      const rows    = await env.DB.prepare('SELECT * FROM content WHERE page = ?').bind('main').all();
      const gmailOk = !!(await env.DB.prepare('SELECT id FROM gmail_oauth WHERE id = 1').first());
      const gitOk   = !!env.GITHUB_TOKEN;
      return html(dashboardPage(session, rows.results, gmailOk, gitOk, BASE_PATH));
    }

    if (path === '/api/content' && method === 'GET')  return handleGetContent(request, env);
    if (path === '/api/content' && method === 'POST') return handleSaveContent(request, env);
    if (path === '/api/publish' && method === 'POST') return handlePublish(request, env);
    if (path === '/setup/gmail' && method === 'GET')  return handleGmailSetup(request, env);
    if (path === '/setup/gmail/callback' && method === 'GET') return handleGmailCallback(request, env);

    return new Response('Not found', { status: 404 });
  },
};
