#!/usr/bin/env node
/**
 * Native Traders Limited — Wholesale Portal + Admin Backend
 * Zero npm dependencies. Run: node server.js
 */
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nt-secret-2024';
const DATA_DIR   = path.join(__dirname, 'data');
const PUB_DIR    = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

[DATA_DIR, PUB_DIR, UPLOAD_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, {recursive:true}); });

// ── DB ────────────────────────────────────────────────────────────────────────
const dbPath  = n => path.join(DATA_DIR, n+'.json');
const dbRead  = n => { try { return JSON.parse(fs.readFileSync(dbPath(n),'utf8')); } catch { return []; } };
const dbWrite = (n,d) => fs.writeFileSync(dbPath(n), JSON.stringify(d, null, 2));
const dbFind  = (n,fn) => dbRead(n).find(fn);
function dbInsert(n, rec) {
  const rows = dbRead(n);
  rec.id = rows.length ? Math.max(...rows.map(r=>r.id||0))+1 : 1;
  rec.created_at = new Date().toISOString();
  rows.push(rec); dbWrite(n, rows); return rec;
}
function dbUpdate(n, id, updates) {
  const rows = dbRead(n).map(r => r.id===id ? {...r,...updates, updated_at:new Date().toISOString()} : r);
  dbWrite(n, rows);
}

// ── Auth ──────────────────────────────────────────────────────────────────────
const hashPw   = pw => { const s=crypto.randomBytes(16).toString('hex'); return s+':'+crypto.scryptSync(pw,s,64).toString('hex'); };
const verifyPw = (pw,h) => { try { const [s,k]=h.split(':'); return crypto.scryptSync(pw,s,64).toString('hex')===k; } catch { return false; } };
const b64u     = b => Buffer.from(b).toString('base64url');
const signJwt  = p => { const h=b64u(JSON.stringify({alg:'HS256',typ:'JWT'})),b=b64u(JSON.stringify({...p,exp:Math.floor(Date.now()/1000)+7*86400})); return `${h}.${b}.${crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${b}`).digest('base64url')}`; };
const verifyJwt= t => { try { if(!t) return null; const [h,b,s]=t.split('.'); if(crypto.createHmac('sha256',JWT_SECRET).update(`${h}.${b}`).digest('base64url')!==s) return null; const p=JSON.parse(Buffer.from(b,'base64url').toString()); return p.exp<Math.floor(Date.now()/1000)?null:p; } catch { return null; } };
const parseCookies = req => Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(c=>{const i=c.indexOf('=');return[c.slice(0,i).trim(),decodeURIComponent(c.slice(i+1).trim())]}));
const getUser  = req => { const c=parseCookies(req); return verifyJwt(c.nt_token||(req.headers.authorization||'').replace('Bearer ','')); };
const mustAuth = (req,res) => { const u=getUser(req); if(!u){err(res,'Not authenticated',401);return null;} return u; };
const mustAdmin= (req,res) => { const u=getUser(req); if(!u||u.role!=='admin'){err(res,'Admin only',403);return null;} return u; };

// ── HTTP helpers ──────────────────────────────────────────────────────────────
const MIME = {'.html':'text/html','.css':'text/css','.js':'application/javascript','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.ico':'image/x-icon','.svg':'image/svg+xml','.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'};
const json = (res,d,s=200) => { res.writeHead(s,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'}); res.end(JSON.stringify(d)); };
const err  = (res,m,s=400) => json(res,{error:m},s);
const setCookie   = (res,n,v) => res.setHeader('Set-Cookie',`${n}=${v}; HttpOnly; Path=/; Max-Age=${7*86400}; SameSite=Lax`);
const clearCookie = (res,n)   => res.setHeader('Set-Cookie',`${n}=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);

// Read raw body (for multipart or JSON)
const readBody = req => new Promise((resolve,reject) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end',  () => resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});

// Parse multipart/form-data — returns { fields, files: [{fieldname, filename, data}] }
function parseMultipart(buffer, boundary) {
  const sep = Buffer.from('--' + boundary);
  const parts = [];
  let start = 0;
  while (true) {
    let idx = buffer.indexOf(sep, start);
    if (idx === -1) break;
    start = idx + sep.length;
    if (buffer[start] === 45 && buffer[start+1] === 45) break; // --
    if (buffer[start] === 13) start += 2; // CRLF
    const headerEnd = buffer.indexOf('\r\n\r\n', start);
    if (headerEnd === -1) break;
    const headerStr = buffer.slice(start, headerEnd).toString();
    const dataStart = headerEnd + 4;
    let dataEnd = buffer.indexOf('\r\n' + sep, dataStart);
    if (dataEnd === -1) dataEnd = buffer.length;
    const data = buffer.slice(dataStart, dataEnd);
    const nameMatch = headerStr.match(/name="([^"]+)"/);
    const filenameMatch = headerStr.match(/filename="([^"]+)"/);
    parts.push({ fieldname: nameMatch?.[1], filename: filenameMatch?.[1], data });
    start = dataEnd + 2;
  }
  return parts;
}

// ── Seed ──────────────────────────────────────────────────────────────────────
function seed() {
  if (!dbRead('users').length) {
    dbInsert('users', { email:'admin@nativetraders.co.nz', password_hash:hashPw('admin2024'), role:'admin', business_name:'Native Traders Limited', contact_name:'Admin', status:'approved' });
    dbInsert('users', { email:'demo@nativetraders.co.nz',  password_hash:hashPw('demo1234'),  role:'customer', business_name:'Demo Wholesale Ltd', contact_name:'Demo User', phone:'+64 21 000 0000', status:'approved' });
    console.log('Seeded users');
  }
  // products.json is seeded externally from XLSX — don't overwrite
  if (!dbRead('brands').length) {
    const brands = [
      {slug:'hungrry',   name:'Hungrry',    color:'#DC2626', logo:null},
      {slug:'albaker',   name:'Al Baker',   color:'#1E3A8A', logo:null},
      {slug:'bcnamkeen', name:'BC Namkeen', color:'#B45309', logo:null},
      {slug:'lazzat',    name:'Lazzat',     color:'#7C3AED', logo:null},
      {slug:'maniarrs',  name:'Maniarrs',   color:'#0F6E56', logo:null},
    ];
    brands.forEach(b => dbInsert('brands', b));
    console.log('Seeded brands');
  }
}

// ── XLSX import helper (spawns python3) ───────────────────────────────────────
function importXlsx(filePath) {
  return new Promise((resolve, reject) => {
    const { spawn } = require('child_process');
    const script = `
import sys, json, re
from openpyxl import load_workbook

wb = load_workbook(sys.argv[1], read_only=True)
products = []
id_counter = [1]

def clean(s): return re.sub(r'\\s+',' ',str(s or '').strip())
def to_f(v):
    try: return round(float(v),2) if v is not None else None
    except: return None
def categorise(n):
    n=n.upper()
    if any(x in n for x in ['ATTA','FLOUR','WHEAT']): return 'Flour & Grains'
    if any(x in n for x in ['MOMO','NAAN','PARATHA','ROTI','BREAD','FROZEN']): return 'Frozen & Bread'
    if any(x in n for x in ['MASALA','SPICE','TURMERIC','CUMIN','CORIANDER']): return 'Spices & Masala'
    if any(x in n for x in ['NAMKEEN','PAPAD','BHUJIA','CHIVDA','MIXTURE','FARSAN','SNACK','CHIPS']): return 'Snacks & Namkeen'
    if any(x in n for x in ['PICKLE','CHUTNEY','SAUCE','PASTE']): return 'Pickles & Sauces'
    if any(x in n for x in ['VERMICELLI','PASTA','NOODLE','SEVIYAN']): return 'Pasta & Noodles'
    if any(x in n for x in ['TEA','CHAI']): return 'Beverages & Tea'
    if any(x in n for x in ['SOAN','SWEET','LADOO','HALWA','JAMUN','RASGULL']): return 'Sweets'
    if any(x in n for x in ['SOAP','CREAM','LOTION','TOOTHPASTE','HAIR','OIL']): return 'Personal Care'
    if any(x in n for x in ['RUSK','BISCUIT','COOKIE','CAKE']): return 'Bakery'
    if any(x in n for x in ['RICE','BASMATI']): return 'Rice'
    return 'Other'

def make(brand, name, size, ws, rrp, moq=1):
    name=clean(name); size=clean(size)
    if not name or len(name)<2: return None
    p={'id':id_counter[0],'brand':brand,'name':name,'size':size,
       'ws_price':to_f(ws),'rrp':to_f(rrp),'category':categorise(name),
       'moq':moq,'active':True,'in_stock':True}
    id_counter[0]+=1
    return p

for sheet_name in wb.sheetnames:
    ws=wb[sheet_name]
    rows=list(ws.iter_rows(values_only=True))
    
    if sheet_name=='HUNGRRY':
        for row in rows[2:]:
            if not row or not row[1]: continue
            try: sr=int(row[0]); assert sr>0
            except: continue
            m=re.search(r'(\\d+\\s*(?:GMS?|KG|ML|PCS|GM)(?:\\s*X\\s*\\d+)?)', str(row[1]),re.I)
            p=make('Hungrry',row[1],m.group(1) if m else '',row[8],row[9],int(row[3]) if row[3] else 1)
            if p: products.append(p)
    
    elif sheet_name=='ALBAK ATTA':
        for row in rows[1:]:
            if not row or not row[4]: continue
            short=str(row[2] or '').strip(); full=str(row[4]).strip()
            name=short if short and len(short)<len(full) else full
            ws_p=to_f(row[11])
            rrp_p=round(ws_p*1.3,2) if ws_p else None
            p=make('Al Baker',name,str(row[5] or ''),ws_p,rrp_p)
            if p: products.append(p)
    
    elif sheet_name=='BC':
        for row in rows[2:]:
            if not row or not row[0]: continue
            desc=str(row[0]).strip()
            if not desc or desc.upper() in ['PRODUCT NAME','TOTAL','']: continue
            gms=row[1]; size=f"{int(gms)}g" if gms and str(gms).replace('.','').isdigit() else str(gms or '')
            p=make('BC Namkeen',desc,size,row[12],row[13])
            if p: products.append(p)
    
    elif sheet_name=='LAZZAT':
        for row in rows[2:]:
            if not row or not row[4]: continue
            desc=str(row[4]).strip()
            if not desc or 'DESCRIPTION' in desc.upper(): continue
            p=make('Lazzat',desc,str(row[5] or ''),None,None)
            if p: products.append(p)
    
    elif sheet_name=='MANIAARS':
        for row in rows[1:]:
            if not row or not row[0]: continue
            desc=str(row[0]).strip()
            if not desc: continue
            grams=row[3]; size=f"{int(grams)}g" if grams and str(grams).replace('.','').isdigit() else str(grams or '')
            p=make('Maniarrs',desc,size,row[9],row[10])
            if p: products.append(p)

print(json.dumps(products))
`;
    const py = spawn('python3', ['-c', script, filePath]);
    let out = '', errOut = '';
    py.stdout.on('data', d => out += d);
    py.stderr.on('data', d => errOut += d);
    py.on('close', code => {
      if (code !== 0) return reject(new Error(errOut || 'Python failed'));
      try { resolve(JSON.parse(out)); } catch(e) { reject(e); }
    });
  });
}

// ── Router ────────────────────────────────────────────────────────────────────
async function router(req, res) {
  const parsed = url.parse(req.url, true);
  const p = parsed.pathname.replace(/\/$/, '') || '/';
  const method = req.method.toUpperCase();

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── Auth ──────────────────────────────────────────────────────────────────
  if (p === '/api/auth/login' && method === 'POST') {
    const raw = await readBody(req);
    const { email, password } = JSON.parse(raw.toString());
    const user = dbFind('users', u => u.email === (email||'').toLowerCase().trim());
    if (!user || !verifyPw(password, user.password_hash)) return err(res, 'Invalid email or password', 401);
    if (user.status !== 'approved') return err(res, 'Account pending approval', 403);
    const token = signJwt({ id:user.id, email:user.email, role:user.role, business:user.business_name });
    setCookie(res, 'nt_token', token);
    return json(res, { ok:true, business:user.business_name, role:user.role });
  }

  if (p === '/api/auth/register' && method === 'POST') {
    const raw = await readBody(req);
    const { business_name, contact_name, email, password, phone } = JSON.parse(raw.toString());
    if (!business_name || !email || !password) return err(res, 'Required fields missing');
    if (dbFind('users', u => u.email === email.toLowerCase().trim())) return err(res, 'Email already registered', 409);
    dbInsert('users', { business_name, contact_name, email:email.toLowerCase().trim(), password_hash:hashPw(password), phone:phone||'', role:'customer', status:'pending' });
    return json(res, { ok:true, message:'Request received. You will be approved within 1 business day.' });
  }

  if (p === '/api/auth/logout' && method === 'POST') { clearCookie(res,'nt_token'); return json(res,{ok:true}); }
  if (p === '/api/auth/me'     && method === 'GET')  { const u=getUser(req); return u ? json(res,{business:u.business,email:u.email,role:u.role}) : err(res,'Not authenticated',401); }

  // ── Customer: Products ────────────────────────────────────────────────────
  if (p === '/api/products' && method === 'GET') {
    const u = mustAuth(req, res); if (!u) return;
    const { brand, category, search, instock } = parsed.query;
    const brands = dbRead('brands');
    let prods = dbRead('products').filter(p => p.active !== false);
    if (brand)    prods = prods.filter(p => p.brand.toLowerCase() === brand.toLowerCase());
    if (category) prods = prods.filter(p => p.category === category);
    if (instock)  prods = prods.filter(p => p.in_stock !== false);
    if (search)   { const q=search.toLowerCase(); prods = prods.filter(p => (p.name+p.brand+p.category).toLowerCase().includes(q)); }
    prods.sort((a,b) => a.brand.localeCompare(b.brand)||a.name.localeCompare(b.name));
    return json(res, prods);
  }

  if (p === '/api/brands' && method === 'GET') {
    mustAuth(req, res); if (!getUser(req)) return;
    return json(res, dbRead('brands').sort((a,b)=>a.name.localeCompare(b.name)));
  }

  // ── Customer: Orders ──────────────────────────────────────────────────────
  if (p === '/api/orders' && method === 'POST') {
    const u = mustAuth(req, res); if (!u) return;
    const { lines, notes } = JSON.parse((await readBody(req)).toString());
    if (!lines?.length) return err(res, 'No lines provided');
    const allProds = dbRead('products');
    let subtotal = 0;
    const resolved = lines.map(l => {
      const pr = allProds.find(x => x.id === l.product_id);
      if (!pr) throw new Error('Product not found: '+l.product_id);
      const lt = +(pr.ws_price * l.qty).toFixed(2); subtotal += lt;
      return { product_id:l.product_id, product_name:pr.name, brand:pr.brand, qty:l.qty, unit_price:pr.ws_price, line_total:lt };
    });
    const gst=+(subtotal*.15).toFixed(2), total=+(subtotal+gst).toFixed(2);
    const inv='INV-'+Date.now().toString().slice(-6);
    const order = dbInsert('orders',{user_id:u.id,invoice_number:inv,status:'pending',subtotal,gst,total,notes:notes||'',lines:resolved});
    return json(res,{ok:true,invoice_number:inv,total:total.toFixed(2)});
  }

  if (p === '/api/orders' && method === 'GET') {
    const u = mustAuth(req, res); if (!u) return;
    const orders = dbRead('orders').filter(o=>o.user_id===u.id).sort((a,b)=>b.created_at.localeCompare(a.created_at));
    return json(res, orders);
  }

  // ── Admin: Users ──────────────────────────────────────────────────────────
  if (p === '/api/admin/users' && method === 'GET') {
    mustAdmin(req,res); if(!getUser(req)||getUser(req).role!=='admin') return;
    return json(res, dbRead('users').map(u=>({id:u.id,business_name:u.business_name,contact_name:u.contact_name,email:u.email,phone:u.phone,role:u.role,status:u.status,created_at:u.created_at})));
  }
  if (p === '/api/admin/approve' && method === 'POST') {
    const u=mustAdmin(req,res); if(!u) return;
    const {id,status} = JSON.parse((await readBody(req)).toString());
    dbUpdate('users', id, {status: status||'approved'});
    return json(res,{ok:true});
  }

  // ── Admin: Orders ─────────────────────────────────────────────────────────
  if (p === '/api/admin/orders' && method === 'GET') {
    const u=mustAdmin(req,res); if(!u) return;
    return json(res, dbRead('orders').sort((a,b)=>b.created_at.localeCompare(a.created_at)));
  }
  if (p === '/api/admin/order-status' && method === 'POST') {
    const u=mustAdmin(req,res); if(!u) return;
    const {id,status}=JSON.parse((await readBody(req)).toString());
    dbUpdate('orders',id,{status}); return json(res,{ok:true});
  }
  if (p.match(/^\/api\/admin\/invoice\/.+$/) && method === 'GET') {
    const u=mustAdmin(req,res); if(!u) return;
    const inv=p.replace('/api/admin/invoice/','');
    const order=dbFind('orders',o=>o.invoice_number===inv);
    if(!order) return err(res,'Not found',404);
    const cust=dbFind('users',u=>u.id===order.user_id);
    return json(res,{...order,customer:cust||{}});
  }

  // ── Admin: Products ───────────────────────────────────────────────────────
  if (p === '/api/admin/products' && method === 'GET') {
    const u=mustAdmin(req,res); if(!u) return;
    return json(res, dbRead('products').sort((a,b)=>a.brand.localeCompare(b.brand)||a.name.localeCompare(b.name)));
  }
  if (p === '/api/admin/products' && method === 'POST') {
    const u=mustAdmin(req,res); if(!u) return;
    const body=JSON.parse((await readBody(req)).toString());
    if (!body.name||!body.brand) return err(res,'Name and brand required');
    const prods=dbRead('products');
    body.id = prods.length ? Math.max(...prods.map(r=>r.id||0))+1 : 1;
    body.active=true; body.in_stock=true; body.created_at=new Date().toISOString();
    prods.push(body); dbWrite('products',prods);
    return json(res,{ok:true,product:body});
  }
  if (p.match(/^\/api\/admin\/products\/\d+$/) && method === 'PUT') {
    const u=mustAdmin(req,res); if(!u) return;
    const id=parseInt(p.split('/').pop());
    const body=JSON.parse((await readBody(req)).toString());
    const allowed=['name','brand','category','size','ws_price','rrp','moq','in_stock','active','qty_desc'];
    const updates={};
    allowed.forEach(f=>{ if(body[f]!==undefined) updates[f]=body[f]; });
    if(updates.ws_price!==undefined) updates.ws_price=parseFloat(updates.ws_price)||null;
    if(updates.rrp!==undefined) updates.rrp=parseFloat(updates.rrp)||null;
    dbUpdate('products',id,updates);
    return json(res,{ok:true});
  }
  if (p.match(/^\/api\/admin\/products\/\d+$/) && method === 'DELETE') {
    const u=mustAdmin(req,res); if(!u) return;
    const id=parseInt(p.split('/').pop());
    dbUpdate('products',id,{active:false}); return json(res,{ok:true});
  }

  // ── Admin: Upload XLSX ────────────────────────────────────────────────────
  if (p === '/api/admin/upload' && method === 'POST') {
    const u=mustAdmin(req,res); if(!u) return;
    const ct = req.headers['content-type']||'';
    const bMatch = ct.match(/boundary=(.+)/);
    if (!bMatch) return err(res,'Expected multipart/form-data');
    const body = await readBody(req);
    const parts = parseMultipart(body, bMatch[1].trim());
    const file = parts.find(p=>p.filename&&p.filename.endsWith('.xlsx'));
    if (!file) return err(res,'No .xlsx file found in upload');
    const savePath = path.join(UPLOAD_DIR, `prices_${Date.now()}.xlsx`);
    fs.writeFileSync(savePath, file.data);
    try {
      const products = await importXlsx(savePath);
      dbWrite('products', products);
      // Rebuild brands from data
      const brandNames = [...new Set(products.map(p=>p.brand))];
      const existingBrands = dbRead('brands');
      const colors = ['#DC2626','#1E3A8A','#B45309','#7C3AED','#0F6E56','#BE185D','#065F46','#92400E'];
      brandNames.forEach((name,i) => {
        if (!existingBrands.find(b=>b.name===name)) {
          dbInsert('brands',{slug:name.toLowerCase().replace(/\s+/g,'-'),name,color:colors[i%colors.length],logo:null});
        }
      });
      return json(res,{ok:true,count:products.length,brands:brandNames});
    } catch(e) {
      return err(res,'Failed to parse XLSX: '+e.message);
    }
  }

  // ── Admin: Stats ──────────────────────────────────────────────────────────
  if (p === '/api/admin/stats' && method === 'GET') {
    const u=mustAdmin(req,res); if(!u) return;
    const prods=dbRead('products'); const orders=dbRead('orders'); const users=dbRead('users');
    return json(res,{
      products: prods.length,
      active_products: prods.filter(p=>p.active!==false).length,
      priced_products: prods.filter(p=>p.ws_price).length,
      orders: orders.length,
      pending_orders: orders.filter(o=>o.status==='pending').length,
      revenue: +orders.reduce((s,o)=>s+(o.total||0),0).toFixed(2),
      customers: users.filter(u=>u.role==='customer').length,
      pending_customers: users.filter(u=>u.status==='pending').length,
    });
  }

  // ── Static ────────────────────────────────────────────────────────────────
  if (p.startsWith('/api/')) return err(res,'Not found',404);

  let filePath = p==='/'||p==='' ? path.join(PUB_DIR,'index.html') : path.join(PUB_DIR,p);
  if (!filePath.startsWith(PUB_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext=path.extname(filePath).toLowerCase();
    res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream'});
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(200,{'Content-Type':'text/html'});
    fs.createReadStream(path.join(PUB_DIR,'index.html')).pipe(res);
  }
}

seed();
http.createServer(async (req,res) => {
  try { await router(req,res); }
  catch(e) { console.error(e); if(!res.headersSent) err(res,'Server error: '+e.message,500); }
}).listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   Native Traders — Wholesale Portal      ║`);
  console.log(`  ║   http://localhost:${PORT}                  ║`);
  console.log(`  ║                                          ║`);
  console.log(`  ║   Admin:    admin@nativetraders.co.nz    ║`);
  console.log(`  ║   Password: admin2024                    ║`);
  console.log(`  ║   Customer: demo@nativetraders.co.nz     ║`);
  console.log(`  ║   Password: demo1234                     ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
