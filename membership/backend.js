const enc=new TextEncoder();
const ORIGIN='https://memberkw.nadmo.id';
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const rand=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
const hash=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
async function password(p,s){let k=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(s),iterations:100000,hash:'SHA-256'},k,256))}
function equal(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
const j=(x,s=200,h={})=>new Response(JSON.stringify(x),{status:s,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...h}});
const err=(s,m)=>j({error:m},s);
const q=(e,s,...v)=>e.DB.prepare(s).bind(...v);
const clean=(v,n=120)=>typeof v==='string'?v.trim().slice(0,n):'';
const login=v=>clean(v,120).toLowerCase();
const goodpass=p=>typeof p==='string'&&p.length>=12&&p.length<=128;
async function throttle(e,key,max){let t=Math.floor(Date.now()/60000);let r=await q(e,'INSERT INTO rate_limits(key,window_start,attempts) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN window_start=excluded.window_start THEN attempts+1 ELSE 1 END,window_start=excluded.window_start RETURNING attempts',key,t).first();return r.attempts<=max}
async function session(e,r){let t=(r.headers.get('Cookie')||'').match(/(?:^|;\s*)kw_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!t)return null;return q(e,'SELECT a.id,a.role,a.unit_id,a.member_id FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires_at>? AND a.enabled=1',await hash(t),Date.now()).first()}
const admin=a=>a&&['super_admin','admin','sekretaris'].includes(a.role);
async function cardToken(e,id){let k=await crypto.subtle.importKey('raw',enc.encode(e.BRIDGE_KEY),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',k,enc.encode('kw-card:'+id)))}
async function photo(e,key,method,body,type){return fetch(ORIGIN+'/internal/photos/'+key,{method,headers:{'X-KW-Bridge':e.BRIDGE_KEY,...(type?{'Content-Type':type}:{})},body})}
async function handler(r,e){
 const u=new URL(r.url), p=u.pathname,m=r.method;
 if(!equal(r.headers.get('X-KW-Bridge'),e.BRIDGE_KEY))return err(403,'Akses ditolak');
 if(m!=='GET'&&m!=='HEAD'&&r.headers.get('Origin')!==ORIGIN)return err(403,'Origin tidak sah');
 const ip=clean(r.headers.get('X-KW-Client'),80)||'unknown';
 if(p==='/api/health'&&m==='GET'){await q(e,'SELECT 1 AS ok').first();return j({ok:true,version:'0.1.0',database:'connected'})}
 if(p==='/api/status'&&m==='GET'){let a=await q(e,"SELECT 1 AS ok FROM accounts WHERE role='super_admin' AND enabled=1 LIMIT 1").first();return j({registration_open:!!a})}
 if(p==='/api/setup'&&m==='POST'){
  if(!e.SETUP_TOKEN)return err(503,'Aktivasi pengurus belum dikonfigurasi');
  if(!await throttle(e,'setup:'+await hash(ip),3))return err(429,'Coba lagi nanti');
  let x=await r.json();if(!equal(x.token,e.SETUP_TOKEN))return err(403,'Kode tidak sah');
  let l=login(x.login);if(!l||!goodpass(x.password))return err(400,'Login dan sandi minimal 12 karakter diperlukan');
  let s=rand(),h=await password(x.password,s);
  let a=await q(e,"INSERT INTO accounts(id,unit_id,login,password_hash,password_salt,role) SELECT 'owner','CLG',?,?,?,'super_admin' WHERE NOT EXISTS(SELECT 1 FROM accounts WHERE role='super_admin')",l,h,s).run();
  if(!a.meta.changes)return err(409,'Pengurus sudah diaktifkan');
  return j({ok:true},201);
 }
 if(p==='/api/register'&&m==='POST'){
  if(!await q(e,"SELECT 1 AS ok FROM accounts WHERE role='super_admin' AND enabled=1 LIMIT 1").first())return err(503,'Pendaftaran belum dibuka');
  if(!await throttle(e,'register:'+await hash(ip),3))return err(429,'Coba lagi nanti');
  if(Number(r.headers.get('Content-Length')||0)>2500000)return err(413,'Foto maksimal 2 MB');
  let f=await r.formData(),g=(k,n)=>clean(f.get(k),n);
  let name=g('name',120),place=g('birth_place',100),date=g('birth_date',10),gender=g('gender',20),address=g('address',400),wa=g('whatsapp',25),year=Number(g('joined_year',4)),belt=g('belt',60),guardian=g('guardian_name',120),emergency=g('emergency_contact',100),l=login(f.get('login')),pw=f.get('password');
  let dob=new Date(date+'T00:00:00Z'),now=new Date(),adult=new Date(Date.UTC(now.getUTCFullYear()-18,now.getUTCMonth(),now.getUTCDate())),minor=dob>adult;
  if(!name||!place||! /^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(+dob)||dob.toISOString().slice(0,10)!==date||dob>now||dob.getUTCFullYear()<1900||!['Laki-laki','Perempuan'].includes(gender)||!address||!/^\+?[0-9]{8,16}$/.test(wa)||!Number.isInteger(year)||year<1940||year>now.getUTCFullYear()||!belt||!emergency||!l||!goodpass(pw)||f.get('consent')!=='yes'||(minor&&(!guardian||f.get('guardian_consent')!=='yes')))return err(400,'Periksa seluruh data dan persetujuan wali untuk anak');
  if(await q(e,'SELECT id FROM accounts WHERE login=?',l).first())return err(409,'Login tidak tersedia');
  let file=f.get('photo');if(!file||typeof file.arrayBuffer!=='function'||file.size<12||file.size>2000000)return err(400,'Foto wajib, maksimal 2 MB');
  let bytes=new Uint8Array(await file.arrayBuffer()),type=bytes[0]===255&&bytes[1]===216&&bytes[2]===255?'image/jpeg':bytes[0]===137&&bytes[1]===80&&bytes[2]===78&&bytes[3]===71?'image/png':String.fromCharCode(...bytes.slice(0,4))==='RIFF'&&String.fromCharCode(...bytes.slice(8,12))==='WEBP'?'image/webp':null;
  if(!type)return err(400,'Gunakan foto JPG, PNG atau WebP');
  let key=rand(),s=rand(),h=await password(pw,s),aid=crypto.randomUUID(),ts=now.toISOString();
  let put=await photo(e,key,'PUT',bytes,type);if(!put.ok)return err(503,'Penyimpanan foto belum tersedia');
  try{await e.DB.batch([q(e,'INSERT INTO members(unit_id,full_name,birth_place,birth_date,gender,address,whatsapp,joined_year,belt,guardian_name,emergency_contact,consent_at,guardian_consent_at,photo_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)','CLG',name,place,date,gender,address,wa,year,belt,guardian||null,emergency,ts,minor?ts:null,key),q(e,"INSERT INTO accounts(id,member_id,unit_id,login,password_hash,password_salt,role) VALUES(?,last_insert_rowid(),'CLG',?,?,?,'member')",aid,l,h,s)]);}catch(ex){await photo(e,key,'DELETE');return err(409,'Pendaftaran gagal, coba login lain')}
  return j({ok:true,status:'pending'},201);
 }
 if(p==='/api/login'&&m==='POST'){
  let x=await r.json(),l=login(x.login);
  if(!await throttle(e,'login-ip:'+await hash(ip),8)||!await throttle(e,'login-account:'+await hash(l),5))return err(429,'Coba lagi nanti');
  if(!goodpass(x.password))return err(401,'Login atau sandi salah');
  let a=await q(e,'SELECT * FROM accounts WHERE login=? AND enabled=1',l).first();
  let h=await password(x.password,a?.password_salt||'invalid-account-padding');if(!a||!equal(h,a.password_hash))return err(401,'Login atau sandi salah');
  let t=rand();await q(e,'INSERT INTO sessions VALUES(?,?,?)',await hash(t),a.id,Date.now()+86400000).run();return j({ok:true,role:a.role},200,{'Set-Cookie':'kw_session='+t+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400'});
 }
 if(p.startsWith('/api/verify/')&&m==='GET'){
  if(!await throttle(e,'verify:'+await hash(ip),30))return err(429,'Coba lagi nanti');
  let t=p.split('/').pop();if(!/^[a-f0-9]{64}$/.test(t))return j({status:'tidak ditemukan'},404);
  let a=await q(e,'SELECT m.status,c.revoked_at FROM cards c JOIN members m ON m.id=c.member_id WHERE c.token_hash=?',await hash(t)).first();
  if(!a)return j({status:'tidak ditemukan'},404);return j({status:a.revoked_at?'nonaktif':a.status==='active'?'valid':a.status==='suspended'?'ditangguhkan':'nonaktif',organization:'PPS Kertha Wisesa Celagigendong Pemecutan',type:'KTA internal'});
 }
 let a=await session(e,r);if(!a)return err(401,'Silakan masuk');
 if(p==='/api/logout'&&m==='POST'){let t=(r.headers.get('Cookie')||'').match(/kw_session=([a-f0-9]{64})/)?.[1];if(t)await q(e,'DELETE FROM sessions WHERE token_hash=?',await hash(t)).run();return j({ok:true},200,{'Set-Cookie':'kw_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'})}
 if(p==='/api/me'&&m==='GET'){
  let member=a.member_id?await q(e,'SELECT id,member_no,full_name,joined_year,belt,status,birth_place,birth_date,gender,address,whatsapp,guardian_name,emergency_contact FROM members WHERE id=? AND unit_id=?',a.member_id,a.unit_id).first():null;
  let c=member?.status==='active'?await q(e,'SELECT id FROM cards WHERE member_id=? AND revoked_at IS NULL',a.member_id).first():null;
  return j({role:a.role,member,verification:c?ORIGIN+'/verify/'+await cardToken(e,c.id):null});
 }
 if(p==='/api/members'&&m==='GET'){
  if(!admin(a))return err(403,'Akses ditolak');
  let rows=await q(e,'SELECT id,member_no,full_name,joined_year,belt,status,created_at FROM members WHERE unit_id=? ORDER BY id DESC LIMIT 200',a.unit_id).all();return j({members:rows.results});
 }
 let match=p.match(/^\/api\/members\/(\d+)(?:\/(approve|status|photo|reissue))?$/);
 if(match){
  let id=Number(match[1]),action=match[2],own=a.member_id===id;
  if(!admin(a)&&!(own&&action==='photo'&&m==='GET'))return err(403,'Akses ditolak');
  let member=await q(e,'SELECT * FROM members WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!member)return err(404,'Anggota tidak ditemukan');
  if(action==='photo'&&m==='GET'){let res=await photo(e,member.photo_key,'GET');if(!res.ok)return err(404,'Foto tidak tersedia');return new Response(res.body,{headers:{'Content-Type':res.headers.get('Content-Type'),'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}})}
  if(!action&&m==='GET'){delete member.photo_key;return j({member})}
  if(action==='approve'&&m==='POST'){
   if(member.status!=='pending')return err(409,'Anggota bukan pending');
   let no='KW-CLG-'+member.joined_year+'-'+String(id).padStart(4,'0'),cid=crypto.randomUUID(),t=await hash(await cardToken(e,cid));
   await e.DB.batch([q(e,"UPDATE members SET status='active',member_no=? WHERE id=? AND unit_id=? AND status='pending'",no,id,a.unit_id),q(e,'INSERT INTO cards(id,member_id,token_hash) VALUES(?,?,?)',cid,id,t),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'approve',String(id))]);return j({ok:true,member_no:no});
  }
  if(action==='status'&&m==='POST'){let x=await r.json();if(!member.member_no||!['active','inactive','alumni','suspended'].includes(x.status))return err(400,'Status tidak sah');await e.DB.batch([q(e,'UPDATE members SET status=? WHERE id=? AND unit_id=?',x.status,id,a.unit_id),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'status:'+x.status,String(id))]);return j({ok:true})}
  if(action==='reissue'&&m==='POST'){if(member.status!=='active')return err(409,'Anggota tidak aktif');let cid=crypto.randomUUID(),t=await hash(await cardToken(e,cid));await e.DB.batch([q(e,'UPDATE cards SET revoked_at=CURRENT_TIMESTAMP WHERE member_id=? AND revoked_at IS NULL',id),q(e,'INSERT INTO cards(id,member_id,token_hash) VALUES(?,?,?)',cid,id,t),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'reissue',String(id))]);return j({ok:true})}
 }
 return err(404,'Tidak ditemukan');
}
export default {async fetch(r,e){try{return await handler(r,e)}catch(ex){return err(500,'Terjadi gangguan sistem')}}};