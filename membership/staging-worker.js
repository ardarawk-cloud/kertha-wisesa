const enc=new TextEncoder();
const ORIGIN='https://kw-membership-core.balinightlife666.workers.dev';
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
async function session(e,r){let t=(r.headers.get('Cookie')||'').match(/(?:^|;\s*)kw_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!t)return null;return q(e,'SELECT a.id,a.role,a.unit_id,a.member_id FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires_at>? AND a.enabled=1 AND a.role IN (\'super_admin\',\'admin\')',await hash(t),Date.now()).first()}
const admin=a=>a&&['super_admin','admin','sekretaris'].includes(a.role);
async function cardToken(e,id){return id}
async function photo(e,key,method,body,type){if(!e.PHOTOS||!key||! /^[a-f0-9]{64}$/.test(key))return new Response(null,{status:503});if(method==='PUT'){await e.PHOTOS.put(key,body,{httpMetadata:{contentType:type}});return new Response(null,{status:201})}if(method==='DELETE'){await e.PHOTOS.delete(key);return new Response(null,{status:204})}let obj=await e.PHOTOS.get(key);return obj?new Response(obj.body,{headers:{'Content-Type':obj.httpMetadata?.contentType||'application/octet-stream'}}):new Response(null,{status:404})}
async function validatedImage(file){if(!file||typeof file.arrayBuffer!=='function'||file.size<12||file.size>2000000)return null;let bytes=new Uint8Array(await file.arrayBuffer()),type=bytes[0]===255&&bytes[1]===216&&bytes[2]===255?'image/jpeg':bytes[0]===137&&bytes[1]===80&&bytes[2]===78&&bytes[3]===71?'image/png':String.fromCharCode(...bytes.slice(0,4))==='RIFF'&&String.fromCharCode(...bytes.slice(8,12))==='WEBP'?'image/webp':null;return type?{bytes,type}:null}

async function directoryRows(e,kind,token=null){
 const today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'}),cutoff=(Number(today.slice(0,4))-18)+today.slice(4);
 let base,params=[];
 if(kind==='officers'){base="SELECT CAST(o.id AS TEXT) AS ref,o.unit_id,m.full_name,o.position,m.photo_key FROM officers o JOIN members m ON m.id=o.member_id AND m.unit_id=o.unit_id JOIN public_officer_approvals p ON p.unit_id=o.unit_id AND p.officer_ref=CAST(o.id AS TEXT) WHERE o.unit_id='CLG' AND o.revoked_at IS NULL AND m.status='active' AND o.term_start<=? AND o.term_end>=? AND m.birth_date<=? UNION ALL SELECT 'd'||o.id,o.unit_id,o.full_name,o.position,o.photo_key FROM officer_direct o JOIN public_officer_approvals p ON p.unit_id=o.unit_id AND p.officer_ref='d'||o.id WHERE o.unit_id='CLG' AND o.revoked_at IS NULL AND o.term_start<=? AND o.term_end>=?";params=[today,today,cutoff,today,today]}
 else if(kind==='athletes'){base="SELECT CAST(m.id AS TEXT) AS ref,m.unit_id,m.full_name,NULL AS position,m.photo_key FROM members m JOIN public_member_approvals p ON p.unit_id=m.unit_id AND p.kind='athletes' AND p.member_id=m.id WHERE m.unit_id='CLG' AND m.status='active' AND m.birth_date<=?";params=[cutoff]}
 else if(kind==='srikandi'){base="SELECT CAST(m.id AS TEXT) AS ref,m.unit_id,m.full_name,NULL AS position,m.photo_key FROM srikandi m JOIN public_member_approvals p ON p.unit_id=m.unit_id AND p.kind='srikandi' AND p.member_id=m.id WHERE m.unit_id='CLG' AND m.status='active'"}
 else return [];
 const sql="SELECT r.full_name,r.position,r.photo_key,p.token FROM ("+base+") r LEFT JOIN public_photo_approvals p ON p.unit_id=r.unit_id AND p.record_ref=r.ref AND p.kind=?"+(token?" WHERE p.token=?":"")+" ORDER BY r.full_name";
 const rows=await q(e,sql,...params,kind,...(token?[token]:[])).all();return rows.results;
}


function autoPublication(e,actor,kind,selector,value,ts){
 // The record is selected by its freshly generated unique photo key or officer card token.
 const tables={athletes:'members',srikandi:'srikandi',direct:'officer_direct',linked:'officers'};
 const table=tables[kind],officer=kind==='direct'||kind==='linked',group=officer?'officers':kind,ref=kind==='direct'?"'d'||id":"CAST(id AS TEXT)";
 if(!table||!['photo_key','card_token'].includes(selector))throw Error('Invalid publication source');
 const where=" FROM "+table+" WHERE unit_id=? AND "+selector+"=?";
 const name=officer?q(e,"INSERT INTO public_officer_approvals(unit_id,officer_ref,approved_at,approved_by) SELECT unit_id,"+ref+",?,?"+where,ts,actor.id,actor.unit_id,value):q(e,"INSERT INTO public_member_approvals(unit_id,kind,member_id,approved_at,approved_by) SELECT unit_id,?,id,?,?"+where,group,ts,actor.id,actor.unit_id,value);
 const portrait=q(e,"INSERT INTO public_photo_approvals(unit_id,kind,record_ref,token,approved_at,approved_by) SELECT unit_id,?,"+ref+",?,?,?"+where,group,rand(),ts,actor.id,actor.unit_id,value);
 const audit=q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) SELECT ?,unit_id,?,"+ref+where,actor.id,'auto_publish_'+group,actor.unit_id,value);
 return [name,portrait,audit];
}

async function handleApi(r,e){
 const u=new URL(r.url), p=u.pathname,m=r.method;
 if(u.origin!==ORIGIN)return err(403,'Gunakan domain resmi');
 if(m!=='GET'&&m!=='HEAD'&&r.headers.get('Origin')!==ORIGIN)return err(403,'Origin tidak sah');
 const ip=clean(r.headers.get('CF-Connecting-IP'),80)||'unknown';
 if(p==='/api/health'&&m==='GET'){await q(e,'SELECT 1 AS ok').first();await e.PHOTOS.list({limit:1});await q(e,'SELECT COUNT(*) AS n FROM officers').first();await q(e,'SELECT COUNT(*) AS n FROM srikandi').first();await q(e,'SELECT COUNT(*) AS n FROM athlete_contacts').first();return j({officers:true,ok:true,version:'0.3.10',database:'connected',photos:'connected',registration:false,admin_only:true})}
 if(p==='/api/status'&&m==='GET'){let a=await q(e,"SELECT 1 AS ok FROM accounts WHERE role='super_admin' AND enabled=1 LIMIT 1").first();return j({admin_ready:!!a,registration_open:false,admin_only:true})}

 if(p==='/api/public/organization'&&m==='GET'){
  const today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'});
  const activeSql="SELECT CAST(o.id AS TEXT) AS ref,m.full_name,o.position,o.term_start,o.term_end FROM officers o JOIN members m ON m.id=o.member_id AND m.unit_id=o.unit_id WHERE o.unit_id='CLG' AND o.revoked_at IS NULL AND m.status='active' AND o.term_start<=? AND o.term_end>=? UNION ALL SELECT 'd'||id AS ref,full_name,position,term_start,term_end FROM officer_direct WHERE unit_id='CLG' AND revoked_at IS NULL AND term_start<=? AND term_end>=?";
  let stats=await q(e,"SELECT (SELECT COUNT(*) FROM members WHERE unit_id='CLG' AND status='active') AS athletes,(SELECT COUNT(*) FROM srikandi WHERE unit_id='CLG' AND status='active') AS srikandi,(SELECT COUNT(*) FROM ("+activeSql+")) AS officers",today,today,today,today).first();
  const output=async kind=>(await directoryRows(e,kind)).map(r=>({full_name:r.full_name,...(kind==='officers'?{position:r.position}:{}),...(r.token&&r.photo_key?{photo_url:'https://memberkw.nadmo.id/api/public/photo/'+kind+'/'+r.token}:{})}));
  return j({organization:'PPS Kertha Wisesa Celagigendong Pemecutan',stats,officers:await output('officers'),athletes:await output('athletes'),srikandi:await output('srikandi'),updated_at:new Date().toISOString()});
 }


 const publicPhoto=p.match(/^\/api\/public\/photo\/(athletes|officers|srikandi)\/([a-f0-9]{64})$/);
 if(publicPhoto&&m==='GET'){let rows=await directoryRows(e,publicPhoto[1],publicPhoto[2]);if(!rows.length)return err(404,'Foto tidak tersedia');let img=await photo(e,rows[0].photo_key,'GET');let type=img.headers.get('Content-Type')||'';if(!img.ok||!/^image\/(png|jpeg|webp)$/.test(type))return err(404,'Foto tidak tersedia');return new Response(img.body,{headers:{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}})}

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
 if((p==='/api/register'||p==='/api/members')&&m==='POST'){
  const staff=p==='/api/members';if(!staff)return err(403,'Pendaftaran hanya melalui administrator');const actor=await session(e,r);
  if(staff&&!admin(actor))return err(actor?403:401,'Akses pengurus diperlukan');
  if(!staff&&(e.REGISTRATION_OPEN!=='true'||!e.PHOTOS||!await q(e,"SELECT 1 AS ok FROM accounts WHERE role='super_admin' AND enabled=1 LIMIT 1").first()))return err(503,'Pendaftaran belum dibuka');
  if(!await throttle(e,staff?'staff-register:'+actor.id:'register:'+await hash(ip),staff?30:3))return err(429,'Coba lagi nanti');
  if(Number(r.headers.get('Content-Length')||0)>2500000)return err(413,'Foto maksimal 2 MB');
  let f=await r.formData(),g=(k,n)=>clean(f.get(k),n);
  let name=g('name',120),place=g('birth_place',100),date=g('birth_date',10),gender=g('gender',20),address=g('address',400),wa=g('whatsapp',25),year=Number(g('joined_year',4)),belt=g('belt',60),guardian=g('guardian_name',120),emergency=g('emergency_contact',100),l=login(f.get('login')),pw=f.get('password');
  let dob=new Date(date+'T00:00:00Z'),now=new Date(),adult=new Date(Date.UTC(now.getUTCFullYear()-18,now.getUTCMonth(),now.getUTCDate())),minor=dob>adult;
  if(!name||!place||! /^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(+dob)||dob.toISOString().slice(0,10)!==date||dob>now||dob.getUTCFullYear()<1900||!['Laki-laki','Perempuan'].includes(gender)||!address||!/^\+?[0-9]{8,16}$/.test(wa)||!Number.isInteger(year)||year<1940||year>now.getUTCFullYear()||!belt||!emergency||(!staff&&(!l||!goodpass(pw)))||f.get('consent')!=='yes'||(minor&&(!guardian||f.get('guardian_consent')!=='yes')))return err(400,'Periksa seluruh data dan persetujuan wali untuk anak');
  if(f.get('publish_public')==='yes'&&minor)return err(400,'Identitas atlet anak tetap privat. Hilangkan centang publikasi.');
  if(!staff&&await q(e,'SELECT id FROM accounts WHERE login=?',l).first())return err(409,'Login tidak tersedia');
  let file=f.get('photo');if(!file||typeof file.arrayBuffer!=='function'||file.size<12||file.size>2000000)return err(400,'Foto wajib, maksimal 2 MB');
  let bytes=new Uint8Array(await file.arrayBuffer()),type=bytes[0]===255&&bytes[1]===216&&bytes[2]===255?'image/jpeg':bytes[0]===137&&bytes[1]===80&&bytes[2]===78&&bytes[3]===71?'image/png':String.fromCharCode(...bytes.slice(0,4))==='RIFF'&&String.fromCharCode(...bytes.slice(8,12))==='WEBP'?'image/webp':null;
  if(!type)return err(400,'Gunakan foto JPG, PNG atau WebP');
  let key=rand(),s=rand(),h=staff?null:await password(pw,s),aid=crypto.randomUUID(),ts=now.toISOString();
  let put=await photo(e,key,'PUT',bytes,type);if(!put.ok)return err(503,'Penyimpanan foto belum tersedia');
  if(staff){try{let rows=await e.DB.batch([q(e,'INSERT INTO members(unit_id,full_name,birth_place,birth_date,gender,address,whatsapp,joined_year,belt,guardian_name,emergency_contact,consent_at,guardian_consent_at,photo_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id',actor.unit_id,name,place,date,gender,address,wa,year,belt,guardian||null,emergency,ts,minor?ts:null,key),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?, 'create_member',last_insert_rowid())",actor.id,actor.unit_id),...(f.get('publish_public')==='yes'&&!minor?autoPublication(e,actor,'athletes','photo_key',key,ts):[])]);return j({ok:true,id:rows[0].results[0].id,status:'pending'},201)}catch(ex){await photo(e,key,'DELETE');return err(409,'Penyimpanan anggota gagal')}}
  try{await e.DB.batch([q(e,'INSERT INTO members(unit_id,full_name,birth_place,birth_date,gender,address,whatsapp,joined_year,belt,guardian_name,emergency_contact,consent_at,guardian_consent_at,photo_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)','CLG',name,place,date,gender,address,wa,year,belt,guardian||null,emergency,ts,minor?ts:null,key),q(e,"INSERT INTO accounts(id,member_id,unit_id,login,password_hash,password_salt,role) VALUES(?,last_insert_rowid(),'CLG',?,?,?,'member')",aid,l,h,s)]);}catch(ex){await photo(e,key,'DELETE');return err(409,'Pendaftaran gagal, coba login lain')}
  return j({ok:true,status:'pending'},201);
 }
 if(p==='/api/login'&&m==='POST'){
  let x=await r.json(),l=login(x.login);
  if(!await throttle(e,'login-ip:'+await hash(ip),8)||!await throttle(e,'login-account:'+await hash(l),5))return err(429,'Coba lagi nanti');
  if(!goodpass(x.password))return err(401,'Login atau sandi salah');
  let a=await q(e,'SELECT * FROM accounts WHERE login=? AND enabled=1',l).first();
  let h=await password(x.password,a?.password_salt||'invalid-account-padding');if(!a||!equal(h,a.password_hash)||!['super_admin','admin'].includes(a.role))return err(401,'Login atau sandi salah');
  let t=rand();await q(e,'INSERT INTO sessions VALUES(?,?,?)',await hash(t),a.id,Date.now()+86400000).run();return j({ok:true,role:a.role},200,{'Set-Cookie':'kw_session='+t+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400'});
 }
 if(p.startsWith('/api/verify/')&&m==='GET'){
  let t=p.split('/').pop();if(!/^[a-f0-9]{64}$/.test(t))return j({status:'tidak ditemukan'},404);
  if(!await throttle(e,'verify:'+await hash(ip),30))return err(429,'Coba lagi nanti');
  let a=await q(e,'SELECT m.status,c.revoked_at FROM cards c JOIN members m ON m.id=c.member_id WHERE c.token_hash=?',await hash(t)).first();
  if(!a){let o=await q(e,"SELECT o.revoked_at,o.term_start,o.term_end,m.status FROM officers o JOIN members m ON m.id=o.member_id WHERE o.card_token=?",t).first();if(!o){let direct=await q(e,'SELECT revoked_at,term_start,term_end FROM officer_direct WHERE card_token=?',t).first();if(direct){let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'});return j({status:!direct.revoked_at&&today>=direct.term_start&&today<=direct.term_end?'valid':'nonaktif',organization:'PPS Kertha Wisesa Celagigendong Pemecutan',type:'Kartu pengurus internal'})}let k=await q(e,'SELECT status FROM srikandi WHERE card_token=?',t).first();return k?j({status:k.status==='active'?'valid':'nonaktif',organization:'PPS Kertha Wisesa Celagigendong Pemecutan',type:'Kartu Srikandi internal'}):j({status:'tidak ditemukan'},404)}let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'});return j({status:o.revoked_at||today<o.term_start||today>o.term_end?'nonaktif':o.status==='active'?'valid':o.status==='suspended'?'ditangguhkan':'nonaktif',organization:'PPS Kertha Wisesa Celagigendong Pemecutan',type:'Kartu pengurus internal'})}return j({status:a.revoked_at?'nonaktif':a.status==='active'?'valid':a.status==='suspended'?'ditangguhkan':'nonaktif',organization:'PPS Kertha Wisesa Celagigendong Pemecutan',type:'KTA internal'});
 }
 if(p==='/api/srikandi-logo'&&m==='GET'){let obj=await e.PHOTOS.get('brand/srikandi-logo');if(!obj)return err(404,'Logo Srikandi belum diunggah');return new Response(obj.body,{headers:{'Content-Type':obj.httpMetadata.contentType,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}})}
 let a=await session(e,r);if(!a)return err(401,'Silakan masuk');
 if(p==='/api/logout'&&m==='POST'){let t=(r.headers.get('Cookie')||'').match(/kw_session=([a-f0-9]{64})/)?.[1];if(t)await q(e,'DELETE FROM sessions WHERE token_hash=?',await hash(t)).run();return j({ok:true},200,{'Set-Cookie':'kw_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'})}
 if(p==='/api/me'&&m==='GET'){
  let member=a.member_id?await q(e,'SELECT id,member_no,full_name,joined_year,belt,status,birth_place,birth_date,gender,address,whatsapp,guardian_name,emergency_contact FROM members WHERE id=? AND unit_id=?',a.member_id,a.unit_id).first():null;
  let c=member?.status==='active'?await q(e,'SELECT id FROM cards WHERE member_id=? AND revoked_at IS NULL',a.member_id).first():null;
  if(member)member.card_contact=await q(e,'SELECT phone,relationship FROM athlete_contacts WHERE member_id=?',member.id).first();let officer=member?await q(e,'SELECT id,position,term_start,term_end FROM officers WHERE member_id=? AND revoked_at IS NULL',member.id).first():null;return j({role:a.role,member,officer,verification:c?'https://memberkw.nadmo.id/verify/'+await cardToken(e,c.id):null});
 }


 if(p==='/api/srikandi-logo'&&m==='POST'){
  if(a.role!=='super_admin')return err(403,'Akses ditolak');
  let f=await r.formData(),file=f.get('photo'),img=await validatedImage(file);if(!img)return err(400,'Gunakan logo asli JPG, PNG atau WebP maksimal 2 MB');
  await e.PHOTOS.put('brand/srikandi-logo',img.bytes,{httpMetadata:{contentType:img.type}});await q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'srikandi_logo',?)",a.id,a.unit_id,'brand').run();return j({ok:true});
 }
 if(p==='/api/srikandi'&&m==='GET'){
  if(!admin(a))return err(403,'Akses ditolak');
  let rows=await q(e,'SELECT id,full_name,category,joined_year,status,member_no FROM srikandi WHERE unit_id=? ORDER BY id DESC LIMIT 500',a.unit_id).all();let approvals=await q(e,"SELECT member_id FROM public_member_approvals WHERE unit_id=? AND kind='srikandi'",a.unit_id).all();let published=new Set(approvals.results.map(x=>x.member_id));let pp=await q(e,"SELECT record_ref FROM public_photo_approvals WHERE unit_id=? AND kind='srikandi'",a.unit_id).all();let photos=new Set(pp.results.map(x=>x.record_ref));return j({members:rows.results.map(x=>({...x,published:published.has(x.id),photo_published:photos.has(String(x.id))})),logo_ready:!!await e.PHOTOS.head('brand/srikandi-logo')});
 }
 if(p==='/api/srikandi'&&m==='POST'){
  if(!admin(a))return err(403,'Akses ditolak');
  let f=await r.formData(),name=clean(f.get('name'),120),category=clean(f.get('category'),80),wa=clean(f.get('whatsapp'),25),year=Number(f.get('joined_year'));
  if(!name||!['Istri pengurus','Ibu atlet','Keluarga besar KW','Anggota Srikandi'].includes(category)||! /^\+?[0-9]{8,16}$/.test(wa)||!Number.isInteger(year)||year<1940||year>new Date().getFullYear()||f.get('consent')!=='yes')return err(400,'Periksa data dan persetujuan anggota');
  let img=await validatedImage(f.get('photo'));if(!img)return err(400,'Foto JPG, PNG atau WebP maksimal 2 MB diperlukan');
  let key=rand();await photo(e,key,'PUT',img.bytes,img.type);
  try{let rows=await e.DB.batch([q(e,'INSERT INTO srikandi(unit_id,full_name,category,joined_year,whatsapp,photo_key,consent_at) VALUES(?,?,?,?,?,?,?) RETURNING id',a.unit_id,name,category,year,wa,key,new Date().toISOString()),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'create_srikandi',last_insert_rowid())",a.id,a.unit_id),...(f.get('publish_public')==='yes'?autoPublication(e,a,'srikandi','photo_key',key,new Date().toISOString()):[])]);return j({ok:true,id:rows[0].results[0].id},201)}catch(ex){await photo(e,key,'DELETE');return err(409,'Gagal menyimpan data')}
 }
 let sr=p.match(/^\/api\/srikandi\/(\d+)(?:\/(photo|approve|status))?$/);
 if(sr){
  if(!admin(a))return err(403,'Akses ditolak');let id=Number(sr[1]),op=sr[2],k=await q(e,'SELECT * FROM srikandi WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!k)return err(404,'Srikandi tidak ditemukan');
  if(op==='photo'&&m==='GET'){let r=await photo(e,k.photo_key,'GET');return r.ok?new Response(r.body,{headers:{'Content-Type':r.headers.get('Content-Type'),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}):err(404,'Foto tidak ditemukan')}
  if(!op&&m==='GET'){let token=k.card_token;delete k.photo_key;delete k.card_token;return j({member:k,verification:k.status==='active'&&token?'https://memberkw.nadmo.id/verify/'+token:null})}
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  if(op==='approve'&&m==='POST'){if(k.status!=='pending')return err(409,'Status tidak sesuai');if(!await e.PHOTOS.head('brand/srikandi-logo'))return err(409,'Unggah logo Srikandi asli dahulu');let no='KW-SRK-'+k.joined_year+'-'+String(id).padStart(4,'0');await e.DB.batch([q(e,"UPDATE srikandi SET status='active',member_no=?,card_token=? WHERE id=? AND unit_id=? AND status='pending'",no,rand(),id,a.unit_id),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'approve_srikandi',?)",a.id,a.unit_id,String(id))]);return j({ok:true,member_no:no})}
  if(op==='status'&&m==='POST'){let x=await r.json();if(!k.member_no||!['active','inactive'].includes(x.status))return err(400,'Status tidak valid');await e.DB.batch([q(e,'UPDATE srikandi SET status=? WHERE id=? AND unit_id=?',x.status,id,a.unit_id),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'srikandi:'+x.status,String(id))]);return j({ok:true})}
 }
 let ec=p.match(/^\/api\/members\/(\d+)\/emergency$/);
 if(ec&&m==='POST'){
  if(!admin(a))return err(403,'Akses ditolak');let id=Number(ec[1]),member=await q(e,'SELECT id FROM members WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!member)return err(404,'Anggota tidak ditemukan');
  let x=await r.json(),phone=clean(x.phone,25),rel=clean(x.relationship,60);
  if(!/^\+?[0-9]{8,16}$/.test(phone)||!['Orang tua','Wali','Keluarga','Pengurus KW','Pelatih'].includes(rel)||x.consent!==true)return err(400,'Nomor dan persetujuan kontak diperlukan');
  await e.DB.batch([q(e,'INSERT INTO athlete_contacts(member_id,phone,relationship,consent_at) VALUES(?,?,?,?) ON CONFLICT(member_id) DO UPDATE SET phone=excluded.phone,relationship=excluded.relationship,consent_at=excluded.consent_at',id,phone,rel,new Date().toISOString()),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'update_emergency_contact',?)",a.id,a.unit_id,String(id))]);return j({ok:true})
 }


 if(p==='/api/officers/direct'&&m==='POST'){
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  let f=await r.formData(),name=clean(f.get('name'),120),wa=clean(f.get('whatsapp'),25),position=clean(f.get('position'),80),start=clean(f.get('term_start'),10),end=clean(f.get('term_end'),10);
  let dateOk=v=>/^\d{4}-\d{2}-\d{2}$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,10)===v;
  if(!name||! /^\+?[0-9]{8,16}$/.test(wa)||!position||!dateOk(start)||!dateOk(end)||start>end||f.get('consent')!=='yes')return err(400,'Periksa nama, WhatsApp, jabatan, masa bakti dan persetujuan');
  let img=await validatedImage(f.get('photo'));if(!img)return err(400,'Foto JPG, PNG atau WebP maksimal 2 MB diperlukan');
  let key=rand();await photo(e,key,'PUT',img.bytes,img.type);
  try{let rows=await e.DB.batch([q(e,'INSERT INTO officer_direct(unit_id,full_name,whatsapp,position,term_start,term_end,photo_key,card_token,consent_at) VALUES(?,?,?,?,?,?,?,?,?) RETURNING id',a.unit_id,name,wa,position,start,end,key,rand(),new Date().toISOString()),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'create_independent_officer','d'||last_insert_rowid())",a.id,a.unit_id),...(f.get('publish_public')==='yes'?autoPublication(e,a,'direct','photo_key',key,new Date().toISOString()):[])]);return j({ok:true,id:'d'+rows[0].results[0].id},201)}catch(ex){await photo(e,key,'DELETE');return err(409,'Gagal menyimpan pengurus')}
 }
 let directRoute=p.match(/^\/api\/officers\/d(\d+)(?:\/(photo|end|reissue))?$/);
 if(directRoute){
  if(!admin(a))return err(403,'Akses ditolak');let id=Number(directRoute[1]),op=directRoute[2];
  let o=await q(e,"SELECT *, 'KW-PGR-'||substr(term_start,1,4)||'-D'||printf('%04d',id) AS member_no FROM officer_direct WHERE id=? AND unit_id=?",id,a.unit_id).first();if(!o)return err(404,'Pengurus tidak ditemukan');
  if(op==='photo'&&m==='GET'){let r=await photo(e,o.photo_key,'GET');return r.ok?new Response(r.body,{headers:{'Content-Type':r.headers.get('Content-Type'),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}):err(404,'Foto tidak ditemukan')}
  if(!op&&m==='GET'){let token=o.card_token;delete o.card_token;delete o.photo_key;o.id='d'+id;o.status='active';o.photo_url='/api/officers/d'+id+'/photo';let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'});return j({officer:o,verification:!o.revoked_at&&today>=o.term_start&&today<=o.term_end?'https://memberkw.nadmo.id/verify/'+token:null})}
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  if(op==='end'&&m==='POST'){if(o.revoked_at)return err(409,'Masa bakti sudah berakhir');await e.DB.batch([q(e,'UPDATE officer_direct SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND unit_id=? AND revoked_at IS NULL',id,a.unit_id),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'end_independent_officer',?)",a.id,a.unit_id,'d'+id)]);return j({ok:true})}
  if(op==='reissue'&&m==='POST'){if(o.revoked_at)return err(409,'Kartu tidak aktif');await e.DB.batch([q(e,'UPDATE officer_direct SET card_token=? WHERE id=? AND unit_id=? AND revoked_at IS NULL',rand(),id,a.unit_id),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'reissue_independent_officer',?)",a.id,a.unit_id,'d'+id)]);return j({ok:true})}
 }





 if(p==='/api/directory/profile-publication'&&m==='POST'){
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  const x=await r.json(),kind=x.kind,ref=String(x.record_ref||'');
  if(!['athletes','officers','srikandi'].includes(kind)||!(kind==='officers'?/^d?\d+$/:/^\d+$/).test(ref)||typeof x.publish!=='boolean')return err(400,'Data tidak valid');
  const direct=kind==='officers'&&ref.startsWith('d'),id=Number(direct?ref.slice(1):ref);
  if(!Number.isSafeInteger(id)||id<1)return err(400,'Data tidak valid');
  const today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'}),cutoff=(Number(today.slice(0,4))-18)+today.slice(4);
  let member;
  if(kind==='officers')member=direct?await q(e,"SELECT photo_key,revoked_at,term_start,term_end FROM officer_direct WHERE id=? AND unit_id=?",id,a.unit_id).first():await q(e,"SELECT m.photo_key,m.birth_date,m.status,o.revoked_at,o.term_start,o.term_end FROM officers o JOIN members m ON m.id=o.member_id AND m.unit_id=o.unit_id WHERE o.id=? AND o.unit_id=?",id,a.unit_id).first();
  else member=await q(e,kind==='athletes'?'SELECT photo_key,status,birth_date FROM members WHERE id=? AND unit_id=?':'SELECT photo_key,status FROM srikandi WHERE id=? AND unit_id=?',id,a.unit_id).first();
  if(!member)return err(404,'Profil tidak ditemukan');
  if(x.publish){
   if(x.consent!==true||x.adult!==true)return err(400,'Persetujuan publikasi profil dewasa diperlukan');
   if((kind==='athletes'||(kind==='officers'&&!direct))&&(!member.birth_date||member.birth_date>cutoff))return err(403,'Identitas anak tetap privat');
   if(kind==='officers'&&(member.revoked_at||member.term_start>today||member.term_end<today))return err(409,'Pengurus belum atau tidak lagi aktif');
   if((kind!=='officers'||!direct)&&member.status!=='active')return err(409,'Profil belum aktif');
   if(!member.photo_key)return err(409,'Foto profil belum tersedia');
  }
  const ts=new Date().toISOString();
  const name=x.publish?(kind==='officers'?q(e,'INSERT INTO public_officer_approvals(unit_id,officer_ref,approved_at,approved_by) VALUES(?,?,?,?) ON CONFLICT(unit_id,officer_ref) DO UPDATE SET approved_at=excluded.approved_at,approved_by=excluded.approved_by',a.unit_id,ref,ts,a.id):q(e,'INSERT INTO public_member_approvals(unit_id,kind,member_id,approved_at,approved_by) VALUES(?,?,?,?,?) ON CONFLICT(unit_id,kind,member_id) DO UPDATE SET approved_at=excluded.approved_at,approved_by=excluded.approved_by',a.unit_id,kind,id,ts,a.id)):(kind==='officers'?q(e,'DELETE FROM public_officer_approvals WHERE unit_id=? AND officer_ref=?',a.unit_id,ref):q(e,'DELETE FROM public_member_approvals WHERE unit_id=? AND kind=? AND member_id=?',a.unit_id,kind,id));
  const portrait=x.publish?q(e,'INSERT INTO public_photo_approvals(unit_id,kind,record_ref,token,approved_at,approved_by) VALUES(?,?,?,?,?,?) ON CONFLICT(unit_id,kind,record_ref) DO UPDATE SET approved_at=excluded.approved_at,approved_by=excluded.approved_by',a.unit_id,kind,ref,rand(),ts,a.id):q(e,'DELETE FROM public_photo_approvals WHERE unit_id=? AND kind=? AND record_ref=?',a.unit_id,kind,ref);
  await e.DB.batch([name,portrait,q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,(x.publish?'publish_profile_':'hide_profile_')+kind,ref)]);return j({ok:true,published:x.publish});
 }

 if(p==='/api/directory/photo-publication'&&m==='POST'){
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  let x=await r.json(),kind=x.kind,ref=String(x.record_ref||'');
  if(!['athletes','officers','srikandi'].includes(kind)||!(kind==='officers'?/^d?\d+$/:/^\d+$/).test(ref)||typeof x.publish!=='boolean')return err(400,'Data tidak valid');
  if(x.publish){
   if(x.consent!==true||x.adult!==true)return err(400,'Persetujuan foto dan usia dewasa wajib');
   let approved=kind==='officers'?await q(e,'SELECT 1 AS ok FROM public_officer_approvals WHERE unit_id=? AND officer_ref=?',a.unit_id,ref).first():await q(e,'SELECT 1 AS ok FROM public_member_approvals WHERE unit_id=? AND kind=? AND member_id=?',a.unit_id,kind,Number(ref)).first();
   if(!approved)return err(409,'Publikasikan nama terlebih dahulu');
   let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'}),cutoff=(Number(today.slice(0,4))-18)+today.slice(4);
   let member=kind==='officers'?(ref.startsWith('d')?await q(e,'SELECT photo_key FROM officer_direct WHERE id=? AND unit_id=? AND revoked_at IS NULL AND term_start<=? AND term_end>=?',Number(ref.slice(1)),a.unit_id,today,today).first():await q(e,"SELECT m.photo_key FROM officers o JOIN members m ON m.id=o.member_id AND m.unit_id=o.unit_id WHERE o.id=? AND o.unit_id=? AND o.revoked_at IS NULL AND m.status='active' AND m.birth_date<=? AND o.term_start<=? AND o.term_end>=?",Number(ref),a.unit_id,cutoff,today,today).first()):await q(e,kind==='athletes'?"SELECT photo_key FROM members WHERE id=? AND unit_id=? AND status='active' AND birth_date<=?":"SELECT photo_key FROM srikandi WHERE id=? AND unit_id=? AND status='active'",Number(ref),a.unit_id,...(kind==='athletes'?[cutoff]:[])).first();
   if(!member?.photo_key)return err(403,'Foto tidak tersedia atau anggota tidak memenuhi syarat');
  }
  const stmt=x.publish?q(e,'INSERT INTO public_photo_approvals(unit_id,kind,record_ref,token,approved_at,approved_by) VALUES(?,?,?,?,?,?) ON CONFLICT(unit_id,kind,record_ref) DO UPDATE SET token=excluded.token,approved_at=excluded.approved_at,approved_by=excluded.approved_by',a.unit_id,kind,ref,rand(),new Date().toISOString(),a.id):q(e,'DELETE FROM public_photo_approvals WHERE unit_id=? AND kind=? AND record_ref=?',a.unit_id,kind,ref);
  await e.DB.batch([stmt,q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,(x.publish?'publish_photo_':'unpublish_photo_')+kind,ref)]);return j({ok:true});
 }

 if(p==='/api/directory/publication'&&m==='POST'){
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  let x=await r.json(),id=Number(x.member_id),kind=x.kind;
  if(!['athletes','srikandi'].includes(kind)||!Number.isSafeInteger(id)||id<1||typeof x.publish!=='boolean')return err(400,'Data tidak valid');
  let member=await q(e,kind==='athletes'?'SELECT id,status,birth_date FROM members WHERE id=? AND unit_id=?':'SELECT id,status FROM srikandi WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!member)return err(404,'Anggota tidak ditemukan');
  if(x.publish){if(member.status!=='active'||x.consent!==true||x.adult!==true)return err(400,'Hanya anggota dewasa aktif dengan persetujuan publikasi');let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'}),cutoff=(Number(today.slice(0,4))-18)+today.slice(4);if(kind==='athletes'&&(!member.birth_date||member.birth_date>cutoff))return err(403,'Identitas atlet anak tidak dipublikasikan');}
  let stmt=x.publish?q(e,'INSERT INTO public_member_approvals(unit_id,kind,member_id,approved_at,approved_by) VALUES(?,?,?,?,?) ON CONFLICT(unit_id,kind,member_id) DO UPDATE SET approved_at=excluded.approved_at,approved_by=excluded.approved_by',a.unit_id,kind,id,new Date().toISOString(),a.id):q(e,'DELETE FROM public_member_approvals WHERE unit_id=? AND kind=? AND member_id=?',a.unit_id,kind,id);
  await e.DB.batch([stmt,...(!x.publish?[q(e,'DELETE FROM public_photo_approvals WHERE unit_id=? AND kind=? AND record_ref=?',a.unit_id,kind,String(id))]:[]),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,(x.publish?'publish_':'unpublish_')+kind,String(id))]);return j({ok:true,published:x.publish});
 }

 if(p==='/api/officers/publication'&&m==='POST'){
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  let x=await r.json(),ref=String(x.officer_ref||'');if(!/^d?\d+$/.test(ref)||typeof x.publish!=='boolean')return err(400,'Data tidak valid');
  let direct=ref.startsWith('d'),id=Number(direct?ref.slice(1):ref);
  let row=await q(e,direct?'SELECT id FROM officer_direct WHERE id=? AND unit_id=?':'SELECT id FROM officers WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!row)return err(404,'Pengurus tidak ditemukan');
  if(x.publish&&x.consent!==true)return err(400,'Persetujuan publikasi wajib');
  let stmt=x.publish?q(e,'INSERT INTO public_officer_approvals(unit_id,officer_ref,approved_at,approved_by) VALUES(?,?,?,?) ON CONFLICT(unit_id,officer_ref) DO UPDATE SET approved_at=excluded.approved_at,approved_by=excluded.approved_by',a.unit_id,ref,new Date().toISOString(),a.id):q(e,'DELETE FROM public_officer_approvals WHERE unit_id=? AND officer_ref=?',a.unit_id,ref);
  await e.DB.batch([stmt,...(!x.publish?[q(e,"DELETE FROM public_photo_approvals WHERE unit_id=? AND kind='officers' AND record_ref=?",a.unit_id,ref)]:[]),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,x.publish?'publish_officer':'unpublish_officer',ref)]);
  return j({ok:true,published:x.publish});
 }

 if(p==='/api/officers'&&m==='GET'){
  if(!admin(a))return err(403,'Akses ditolak');
  let rows=await q(e,'SELECT o.id,o.member_id,o.position,o.term_start,o.term_end,o.revoked_at,m.full_name,m.member_no,m.status FROM officers o JOIN members m ON m.id=o.member_id AND m.unit_id=o.unit_id WHERE o.unit_id=? ORDER BY o.id DESC LIMIT 500',a.unit_id).all();let direct=await q(e,"SELECT 'd'||id AS id,full_name,position,term_start,term_end,revoked_at,'KW-PGR-'||substr(term_start,1,4)||'-D'||printf('%04d',id) AS member_no,'active' AS status FROM officer_direct WHERE unit_id=? ORDER BY id DESC LIMIT 500",a.unit_id).all();let approvals=await q(e,'SELECT officer_ref FROM public_officer_approvals WHERE unit_id=?',a.unit_id).all();let published=new Set(approvals.results.map(x=>x.officer_ref));let pp=await q(e,"SELECT record_ref FROM public_photo_approvals WHERE unit_id=? AND kind='officers'",a.unit_id).all();let photos=new Set(pp.results.map(x=>x.record_ref));return j({officers:[...direct.results,...rows.results].map(x=>({...x,published:published.has(String(x.id)),photo_published:photos.has(String(x.id))}))});
 }
 if(p==='/api/officers'&&m==='POST'){
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  let x=await r.json(),id=Number(x.member_id),position=clean(x.position,80),start=clean(x.term_start,10),end=clean(x.term_end,10);
  let dateOk=v=>/^\d{4}-\d{2}-\d{2}$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString().slice(0,10)===v;
  if(!Number.isSafeInteger(id)||id<1||!position||!dateOk(start)||!dateOk(end)||start>end)return err(400,'Jabatan dan masa bakti tidak valid');
  let member=await q(e,'SELECT id,status,birth_date FROM members WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!member||member.status!=='active')return err(409,'Anggota harus aktif terlebih dahulu');
  if(await q(e,'SELECT id FROM officers WHERE member_id=? AND revoked_at IS NULL',id).first())return err(409,'Akhiri masa bakti sebelumnya sebelum membuat kartu baru');
  let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'}),cutoff=(Number(today.slice(0,4))-18)+today.slice(4);if(x.publish_public==='yes'&&(!member.birth_date||member.birth_date>cutoff))return err(400,'Identitas anggota anak tetap privat');let token=rand();let rows=await e.DB.batch([q(e,'INSERT INTO officers(member_id,unit_id,position,term_start,term_end,card_token) VALUES(?,?,?,?,?,?) RETURNING id',id,a.unit_id,position,start,end,token),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'appoint_officer',?)",a.id,a.unit_id,String(id)),...(x.publish_public==='yes'?autoPublication(e,a,'linked','card_token',token,new Date().toISOString()):[])]);return j({ok:true,id:rows[0].results[0].id},201);
 }
 let officerRoute=p.match(/^\/api\/officers\/(\d+)(?:\/(end|reissue))?$/);
 if(officerRoute){
  let id=Number(officerRoute[1]),op=officerRoute[2];
  let o=await q(e,'SELECT o.*,m.full_name,m.member_no,m.status FROM officers o JOIN members m ON m.id=o.member_id AND m.unit_id=o.unit_id WHERE o.id=? AND o.unit_id=?',id,a.unit_id).first();
  if(!o)return err(404,'Pengurus tidak ditemukan');
  if(!admin(a)&&a.member_id!==o.member_id)return err(403,'Akses ditolak');
  if(!op&&m==='GET'){let token=o.card_token;delete o.card_token;let today=new Date().toLocaleDateString('sv-SE',{timeZone:'Asia/Makassar'});return j({officer:o,verification:!o.revoked_at&&o.status==='active'&&today>=o.term_start&&today<=o.term_end?'https://memberkw.nadmo.id/verify/'+token:null})}
  if(!['super_admin','admin'].includes(a.role))return err(403,'Akses ditolak');
  if(op==='end'&&m==='POST'){if(o.revoked_at)return err(409,'Masa bakti sudah berakhir');await e.DB.batch([q(e,'UPDATE officers SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND unit_id=? AND revoked_at IS NULL',id,a.unit_id),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'end_officer',?)",a.id,a.unit_id,String(id))]);return j({ok:true})}
  if(op==='reissue'&&m==='POST'){if(o.revoked_at||o.status!=='active')return err(409,'Kartu tidak aktif');await e.DB.batch([q(e,'UPDATE officers SET card_token=? WHERE id=? AND unit_id=? AND revoked_at IS NULL',rand(),id,a.unit_id),q(e,"INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,'reissue_officer',?)",a.id,a.unit_id,String(id))]);return j({ok:true})}
 }

 if(p==='/api/members'&&m==='GET'){
  if(!admin(a))return err(403,'Akses ditolak');
  let rows=await q(e,'SELECT id,member_no,full_name,joined_year,belt,status,created_at FROM members WHERE unit_id=? ORDER BY id DESC LIMIT 200',a.unit_id).all();let approvals=await q(e,"SELECT member_id FROM public_member_approvals WHERE unit_id=? AND kind='athletes'",a.unit_id).all();let published=new Set(approvals.results.map(x=>x.member_id));let pp=await q(e,"SELECT record_ref FROM public_photo_approvals WHERE unit_id=? AND kind='athletes'",a.unit_id).all();let photos=new Set(pp.results.map(x=>x.record_ref));return j({members:rows.results.map(x=>({...x,published:published.has(x.id),photo_published:photos.has(String(x.id))}))});
 }
 let match=p.match(/^\/api\/members\/(\d+)(?:\/(approve|status|photo|reissue))?$/);
 if(match){
  let id=Number(match[1]),action=match[2],own=a.member_id===id;
  if(!admin(a)&&!(own&&action==='photo'&&m==='GET'))return err(403,'Akses ditolak');
  let member=await q(e,'SELECT * FROM members WHERE id=? AND unit_id=?',id,a.unit_id).first();if(!member)return err(404,'Anggota tidak ditemukan');
  if(action==='photo'&&m==='GET'){let res=await photo(e,member.photo_key,'GET');if(!res.ok)return err(404,'Foto tidak tersedia');return new Response(res.body,{headers:{'Content-Type':res.headers.get('Content-Type'),'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}})}
  if(!action&&m==='GET'){delete member.photo_key;member.card_contact=await q(e,'SELECT phone,relationship FROM athlete_contacts WHERE member_id=?',id).first();let c=member.status==='active'?await q(e,'SELECT id FROM cards WHERE member_id=? AND revoked_at IS NULL',id).first():null;return j({member,verification:c?'https://memberkw.nadmo.id/verify/'+await cardToken(e,c.id):null})}
  if(action==='approve'&&m==='POST'){
   if(!['admin','super_admin'].includes(a.role))return err(403,'Persetujuan hanya oleh admin');
   if(!member.photo_key)return err(409,'Foto belum tersedia');
   if(member.status!=='pending')return err(409,'Anggota bukan pending');
   let no='KW-CLG-'+member.joined_year+'-'+String(id).padStart(4,'0'),cid=rand(),t=await hash(await cardToken(e,cid));
   await e.DB.batch([q(e,"UPDATE members SET status='active',member_no=? WHERE id=? AND unit_id=? AND status='pending'",no,id,a.unit_id),q(e,'INSERT INTO cards(id,member_id,token_hash) VALUES(?,?,?)',cid,id,t),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'approve',String(id))]);return j({ok:true,member_no:no});
  }
  if(action==='status'&&m==='POST'){if(!['admin','super_admin'].includes(a.role))return err(403,'Akses ditolak');let x=await r.json();if(!member.member_no||!['active','inactive','alumni','suspended'].includes(x.status))return err(400,'Status tidak sah');await e.DB.batch([q(e,'UPDATE members SET status=? WHERE id=? AND unit_id=?',x.status,id,a.unit_id),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'status:'+x.status,String(id))]);return j({ok:true})}
  if(action==='reissue'&&m==='POST'){if(!['admin','super_admin'].includes(a.role))return err(403,'Akses ditolak');if(member.status!=='active')return err(409,'Anggota tidak aktif');let cid=rand(),t=await hash(await cardToken(e,cid));await e.DB.batch([q(e,'UPDATE cards SET revoked_at=CURRENT_TIMESTAMP WHERE member_id=? AND revoked_at IS NULL',id),q(e,'INSERT INTO cards(id,member_id,token_hash) VALUES(?,?,?)',cid,id,t),q(e,'INSERT INTO audit_log(actor_id,unit_id,action,target_id) VALUES(?,?,?,?)',a.id,a.unit_id,'reissue',String(id))]);return j({ok:true})}
 }
 return err(404,'Tidak ditemukan');
}

const LOGO='https://kerthawisesa.nadmo.id/assets/kertha-wisesa-logo.webp?v=20261016-full';
const sec={'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Permissions-Policy':'camera=(), microphone=(), geolocation=()','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"};
const res=(body,type,status=200,extra={})=>new Response(body,{status,headers:{...sec,'Content-Type':type,...extra}});
const page='<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#191611"><title>KW Digital Membership</title><link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/logo.webp"><link rel="stylesheet" href="/style.css"></head><body><header><a href="/" class="brand"><img src="/logo.webp" alt="Logo perguruan"><span><strong>PPS KERTHA WISESA</strong><small>CELAGIGENDONG PEMECUTAN</small></span></a><nav><a href="/register">Daftar</a><a href="/login">Masuk</a></nav></header><main id="app" aria-live="polite"></main><footer><a href="https://kerthawisesa.nadmo.id/">Website perguruan</a> · <a href="https://kaskw.nadmo.id/">KASKW</a><p>Powered by NADMO Studio</p></footer><script src="/app.js" defer></script></body></html>';
const css='*{box-sizing:border-box}body{margin:0;background:#f7f5f0;color:#29251e;font:16px system-ui,sans-serif}header{background:#191611;color:#fff;padding:14px max(16px,calc((100vw - 960px)/2));display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;border-bottom:3px solid #ba9348}.brand{display:flex;align-items:center;gap:9px;text-decoration:none;color:inherit}.brand img{width:48px;height:48px;object-fit:contain}.brand small{display:block;font-size:10px;letter-spacing:.5px}nav{display:flex;gap:15px}nav a,footer a{color:inherit}main{max-width:960px;margin:auto;padding:24px 16px;min-height:65vh}.panel{background:#fff;border:1px solid #e1dacf;border-radius:14px;padding:20px;margin:12px 0;box-shadow:0 3px 12px #00000008}.hero{padding:28px 20px;background:#231e16;color:white;border-radius:14px;border:1px solid #ab894b}.hero h1{font-size:clamp(26px,5vw,42px);margin:8px 0}.kicker{font-size:12px;letter-spacing:2px;color:#e5c77c}h2{font-size:22px;margin:0 0 16px}p{line-height:1.6}label{display:block;margin:12px 0 4px;font-weight:600}input:not([type=checkbox]),select,textarea{width:100%;padding:12px;border:1px solid #b7afa1;border-radius:8px;background:#fff;font:inherit}input[type=checkbox]{width:18px;height:18px;vertical-align:middle}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}button,.btn{border:0;padding:12px 16px;border-radius:8px;background:#855f21;color:#fff;font:600 15px system-ui;cursor:pointer;text-decoration:none;display:inline-block}button:disabled{opacity:.5;cursor:wait}.secondary{background:#37332c}.note{color:#595247;font-size:14px}.message{margin:10px 0;color:#8a3220;white-space:pre-wrap}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}.stat{border:1px solid #ddd3c4;padding:12px;border-radius:8px}.stat strong{display:block;font-size:28px}table{width:100%;border-collapse:collapse;min-width:490px}td,th{text-align:left;padding:9px;border-bottom:1px solid #e4ded3}td button{padding:7px 10px}.scroll{overflow-x:auto}.photo{width:100px;max-height:130px;object-fit:contain}.kta{max-width:100%;height:auto;border:1px solid #ddd;display:block;margin:12px 0}footer{background:#191611;color:#ddd;text-align:center;padding:22px;font-size:13px}footer p{margin:5px}.check{font-weight:400}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:0 16px}@media print{header,footer,button,.actions,.no-print{display:none!important}main{padding:0}.panel{box-shadow:none;border:0}.kta{width:85.6mm;height:53.98mm;margin:0;border:0}@page{size:85.6mm 53.98mm;margin:0}}';
const app="const root=document.querySelector('#app'),path=location.pathname, E=(tag,text,cls)=>{let e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e},add=(p,...c)=>{p.append(...c);return p},link=(t,url)=>{let e=E('a',t,'btn');e.href=url;return e},panel=title=>add(E('section',undefined,'panel'),E('h2',title)),statusLabel=s=>({pending:'Menunggu verifikasi',active:'Aktif',inactive:'Nonaktif',alumni:'Alumni',suspended:'Ditangguhkan'}[s]||s),msg=E('div',undefined,'message');\nasync function api(p,data){let opt={credentials:'same-origin'};if(data!==undefined){opt.method='POST';if(data instanceof FormData)opt.body=data;else{opt.headers={'Content-Type':'application/json'};opt.body=JSON.stringify(data)}}let r=await fetch('/api'+p,opt),x=await r.json();if(!r.ok)throw Error(x.error||x.status||'Gangguan sistem');return x}\nfunction field(form,label,name,type='text',required=true){let w=E('div'),l=E('label',label),i=E('input');i.id='f-'+name;i.name=name;i.type=type;i.required=required;l.htmlFor=i.id;if(type==='password'){i.minLength=12;i.maxLength=128}if(type==='file')i.accept='image/jpeg,image/png,image/webp';add(w,l,i);form.append(w);return i}\nfunction check(form,label,name,required){let l=E('label',undefined,'check'),i=E('input');i.type='checkbox';i.name=name;i.value='yes';i.required=required;add(l,i,document.createTextNode(' '+label));form.append(l);return i}\nfunction submit(form,label,fn){let b=E('button',label);b.type='submit';form.append(b,msg);form.onsubmit=async ev=>{ev.preventDefault();b.disabled=true;msg.textContent='';try{await fn(new FormData(form))}catch(e){msg.textContent=e.message}finally{b.disabled=false}}}\nfunction action(t,fn){let b=E('button',t);b.onclick=async()=>{b.disabled=true;try{await fn()}catch(e){alert(e.message)}finally{b.disabled=false}};return b}\nfunction home(){let h=E('section',undefined,'hero');add(h,E('div','PORTAL KEANGGOTAAN DIGITAL','kicker'),E('h1','Satu perguruan. Satu identitas.'),E('p','Pendaftaran anggota, KTA digital dan administrasi PPS Kertha Wisesa Celagigendong Pemecutan.'),add(E('div',undefined,'actions'),link('Daftar anggota','/register'),link('Masuk ke akun','/login')));root.append(h);let p=panel('Panduan keanggotaan');add(p,E('p','Daftar → Verifikasi pengurus → Nomor anggota → KTA digital.'),E('p','KTA merupakan identitas internal Celagigendong, bukan KTA tingkat DPC, DPD atau DPP.'),E('p','Verifikasi kartu dilakukan melalui QR yang tertera pada KTA.'));root.append(p);let i=panel('Privasi dan bantuan');add(i,E('p','Data anggota hanya dapat diakses oleh pihak berwenang. Informasi pribadi tidak ditampilkan pada halaman verifikasi publik.'),link('Kebijakan privasi','/privacy'));root.append(i);api('/status').then(x=>{if(!x.registration_open){let n=panel('Persiapan layanan');add(n,E('p','Pendaftaran belum dibuka. Pengurus perlu menyelesaikan aktivasi akun.'),link('Aktivasi pengurus','/setup'));root.prepend(n)}}).catch(()=>{})}\nfunction credentials(setup=false){let p=panel(setup?'Aktivasi pengurus pertama':'Masuk anggota atau pengurus'),f=E('form');if(setup)field(f,'Kode aktivasi sekali pakai','token','password');field(f,'Nama pengguna','login');field(f,'Sandi (minimal 12 karakter)','password','password');submit(f,setup?'Aktifkan':'Masuk',async d=>{await api(setup?'/setup':'/login',Object.fromEntries(d));location.href=setup?'/login':'/dashboard'});p.append(f);root.append(p)}\nasync function register(){let p=panel('Pendaftaran anggota'),s=await api('/status');if(!s.registration_open){p.append(E('p','Pendaftaran belum dibuka oleh pengurus.'));root.append(p);return}let f=E('form'),g=E('div',undefined,'grid');field(g,'Nama lengkap','name');field(g,'Tempat lahir','birth_place');field(g,'Tanggal lahir','birth_date','date');let w=E('div'),l=E('label','Jenis kelamin'),i=E('select');i.name='gender';for(let v of ['Laki-laki','Perempuan']){let o=E('option',v);o.value=v;i.append(o)}add(w,l,i);g.append(w);field(g,'Alamat','address');field(g,'Nomor WhatsApp (angka, tanpa spasi)','whatsapp','tel');field(g,'Tahun bergabung','joined_year','number');field(g,'Tingkatan sabuk','belt');field(g,'Nama wali (wajib bagi anak)','guardian_name','text',false);field(g,'Kontak darurat','emergency_contact','tel');field(g,'Nama pengguna','login');field(g,'Sandi minimal 12 karakter','password','password');field(g,'Foto anggota, maksimal 2 MB','photo','file');f.append(g,E('p','Unit: Celagigendong Pemecutan. Status awal: menunggu verifikasi.','note'));check(f,'Saya menyetujui pengelolaan data untuk administrasi keanggotaan.','consent',true);check(f,'Untuk anggota anak, saya adalah wali yang berwenang dan menyetujui pendaftaran.','guardian_consent',false);submit(f,'Kirim pendaftaran',async d=>{await api('/register',d);root.replaceChildren(add(panel('Pendaftaran diterima'),E('p','Silakan masuk untuk melihat status verifikasi.'),link('Masuk','/login')))});p.append(f);root.append(p)}\nfunction qr(str){let bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>i)&1)};let bytes=new TextEncoder().encode(str);if(bytes.length>106)throw Error('QR terlalu panjang');put(4,4);put(bytes.length,8);for(let b of bytes)put(b,8);put(0,Math.min(4,864-bits.length));while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let k=0;data.length<108;k++)data.push(k%2?17:236);let exp=Array(512),log=Array(256),x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];let mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0,gen=[1];for(let i=0;i<26;i++){let n=Array(gen.length+1).fill(0);gen.forEach((v,j)=>{n[j]^=v;n[j+1]^=mul(v,exp[i])});gen=n}let ecc=data.concat(Array(26).fill(0));for(let i=0;i<108;i++){let v=ecc[i];if(v)for(let j=0;j<gen.length;j++)ecc[i+j]^=mul(v,gen[j])}data=data.concat(ecc.slice(108));let n=37,m=Array.from({length:n},()=>Array(n).fill(null));for(let [r,c] of [[0,0],[0,n-7],[n-7,0]])for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++){if(r+y<0||r+y>=n||c+x<0||c+x>=n)continue;m[r+y][c+x]=(y>=0&&y<=6&&(x===0||x===6))||(x>=0&&x<=6&&(y===0||y===6))||(y>=2&&y<=4&&x>=2&&x<=4)}for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)m[30+y][30+x]=Math.max(Math.abs(x),Math.abs(y))===2||(!x&&!y);for(let i=8;i<n-8;i++){if(m[i][6]===null)m[i][6]=i%2===0;if(m[6][i]===null)m[6][i]=i%2===0}let fmt=0x77c4;for(let i=0;i<15;i++){let v=!!((fmt>>i)&1);m[i<6?i:i<8?i+1:n-15+i][8]=v;m[8][i<8?n-i-1:i===8?7:14-i]=v}m[n-8][8]=true;let row=n-1,dir=-1,bi=0;for(let col=n-1;col>0;col-=2){if(col===6)col--;while(true){for(let c of [col,col-1])if(m[row][c]===null){let dark=bi<data.length*8?!!(data[bi>>3]&(1<<(7-bi%8))):false;m[row][c]=dark!==((row+c)%2===0);bi++}row+=dir;if(row<0||row>=n){row-=dir;dir=-dir;break}}}return m}\nasync function loadImg(url){return new Promise((resolve,reject)=>{let i=new Image();i.onload=()=>resolve(i);i.onerror=reject;i.src=url})}\nasync function card(p,m,v){let c=E('canvas');c.className='kta';c.width=1011;c.height=638;let x=c.getContext('2d');x.fillStyle='#191611';x.fillRect(0,0,1011,638);x.fillStyle='#ba9348';x.fillRect(0,0,1011,13);x.fillRect(0,625,1011,13);x.fillStyle='#fff';x.font='bold 40px sans-serif';x.fillText('PPS KERTHA WISESA',150,80);x.font='bold 27px sans-serif';x.fillText('CELAGIGENDONG PEMECUTAN',150,120);x.font='22px sans-serif';x.fillText('KARTU ANGGOTA INTERNAL',40,185);try{x.drawImage(await loadImg('/logo.webp'),35,30,90,90)}catch{}try{let i=await loadImg('/api/members/'+m.id+'/photo'),scale=Math.min(220/i.width,275/i.height);x.drawImage(i,40,210,i.width*scale,i.height*scale)}catch{}x.font='bold 32px sans-serif';x.fillText(m.full_name.slice(0,40),285,270,680);x.font='26px sans-serif';x.fillText(m.member_no,285,322);x.fillText('Bergabung: '+m.joined_year,285,365);x.fillText('Status: Aktif',285,408);let matrix=qr(v),size=5,ox=735,oy=360;x.fillStyle='#fff';x.fillRect(ox,oy,225,225);x.fillStyle='#111';matrix.forEach((row,y)=>row.forEach((b,z)=>{if(b)x.fillRect(ox+(z+4)*size,oy+(y+4)*size,size,size)}));x.fillStyle='#e5c77c';x.font='20px sans-serif';x.fillText('Verifikasi melalui QR',40,590);p.append(c,add(E('div',undefined,'actions'),action('Unduh PNG',()=>{let a=E('a');a.href=c.toDataURL('image/png');a.download=m.member_no+'.png';a.click()}),action('Cetak / simpan PDF',()=>window.print())))}\nasync function dashboard(){let me;try{me=await api('/me')}catch{location.href='/login';return}let top=panel(me.role==='member'?'Dashboard anggota':'Dashboard pengurus');top.append(E('p','Akses: '+me.role),action('Keluar',async()=>{await api('/logout',{});location.href='/'}));root.append(top);if(me.member){let m=me.member,p=panel('Profil saya');for(let [k,v] of [['Nama',m.full_name],['Nomor anggota',m.member_no||'Belum diterbitkan'],['Status',statusLabel(m.status)],['Sabuk',m.belt],['Tahun bergabung',m.joined_year]])p.append(E('p',k+': '+v));root.append(p);if(me.verification){let k=panel('KTA Digital');root.append(k);await card(k,m,me.verification)}return}if(!['super_admin','admin','sekretaris'].includes(me.role))return;let r=await api('/members'),p=panel('Database anggota'),st=E('div',undefined,'stats');for(let s of ['pending','active','inactive','alumni','suspended'])add(st,add(E('div',undefined,'stat'),E('strong',String(r.members.filter(m=>m.status===s).length)),E('small',statusLabel(s))));p.append(st);let tbl=E('table'),head=E('tr');for(let s of ['Nama','Nomor','Status','Tindakan'])head.append(E('th',s));tbl.append(head);for(let m of r.members){let tr=E('tr'),td=E('td');add(tr,E('td',m.full_name),E('td',m.member_no||'—'),E('td',statusLabel(m.status)),td);td.append(action('Lihat',async()=>{let d=await api('/members/'+m.id),detail=panel('Detail anggota'),a=d.member;for(let [k,v] of [['Nama',a.full_name],['Lahir',a.birth_place+' / '+a.birth_date],['Alamat',a.address],['WhatsApp',a.whatsapp],['Wali',a.guardian_name||'—'],['Kontak darurat',a.emergency_contact]])detail.append(E('p',k+': '+v));let im=E('img');im.src='/api/members/'+m.id+'/photo';im.className='photo';detail.append(im);if(m.status==='pending')detail.append(action('Setujui anggota',async()=>{if(confirm('Setujui dan terbitkan KTA?')){await api('/members/'+m.id+'/approve',{});location.reload()}}));else{let sel=E('select');for(let s of ['active','inactive','alumni','suspended']){let o=E('option',statusLabel(s));o.value=s;sel.append(o)}sel.value=m.status;detail.append(sel,action('Ubah status',async()=>{await api('/members/'+m.id+'/status',{status:sel.value});location.reload()}));if(m.status==='active')detail.append(action('Terbitkan ulang KTA',async()=>{if(confirm('QR lama tidak akan berlaku. Lanjutkan?')){await api('/members/'+m.id+'/reissue',{});location.reload()}}))}detail.append(action('Tutup',()=>detail.remove()));p.prepend(detail)}));tbl.append(tr)}p.append(add(E('div',undefined,'scroll'),tbl));if(!r.members.length)p.append(E('p','Belum ada anggota terdaftar.'));root.append(p)}\nasync function verify(){let p=panel('Verifikasi kartu anggota'),t=path.split('/').pop();try{let d=await api('/verify/'+encodeURIComponent(t));p.append(E('h2',d.status.toUpperCase()),E('p',d.organization),E('p','Identitas internal Celagigendong.'))}catch(e){p.append(E('p',e.message))}root.append(p)}\nif('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});(async()=>{try{if(path==='/')home();else if(path==='/login')credentials();else if(path==='/setup')credentials(true);else if(path==='/register')await register();else if(path==='/dashboard')await dashboard();else if(path.startsWith('/verify/'))await verify();else if(path==='/privacy')root.append(add(panel('Privasi keanggotaan'),E('p','Data pendaftaran digunakan untuk administrasi dan verifikasi keanggotaan internal. Data tidak ditampilkan kepada publik. Foto disimpan secara privat. Anggota atau wali dapat menghubungi pengurus untuk koreksi atau permintaan penghapusan data.'),E('p','Data anak memerlukan persetujuan wali. KTA hanya menampilkan informasi yang diperlukan.')))}catch(e){root.append(add(panel('Layanan belum tersedia'),E('p',e.message)))}})();";

export default {async fetch(r,e){try{let u=new URL(r.url),p=u.pathname;
 if(u.origin!==ORIGIN)return res('Gunakan domain resmi','text/plain',403);
 if(p.startsWith('/internal/'))return res('Not found','text/plain',404);
 if(p.startsWith('/api/')){
  if(Number(r.headers.get('Content-Length')||0)>2500000)return res('Terlalu besar','text/plain',413);
  return await handleApi(r,e);
 }
 if(p==='/logo.webp'){let b=await fetch(LOGO);if(!b.ok||!b.headers.get('Content-Type')?.startsWith('image/'))return res('Logo unavailable','text/plain',503);return res(b.body,b.headers.get('Content-Type'),200,{'Cache-Control':'public,max-age=3600'})}
 if(p==='/manifest.webmanifest')return res(JSON.stringify({name:'PPS Kertha Wisesa Celagigendong Pemecutan',short_name:'KW Member',lang:'id',start_url:'/',scope:'/',display:'standalone',background_color:'#f7f5f0',theme_color:'#191611',icons:[{src:'/logo.webp',sizes:'1024x1024',type:'image/webp',purpose:'any'}]}),'application/manifest+json');
 if(p==='/sw.js')return res("self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('fetch',e=>{if(e.request.mode==='navigate')e.respondWith(fetch(e.request).catch(()=>new Response('KW Membership membutuhkan koneksi internet.',{headers:{'Content-Type':'text/plain;charset=utf-8'}})))});",'application/javascript');
 if(p==='/style.css')return res(css,'text/css; charset=utf-8');
 if(p==='/app.js')return res(app,'application/javascript; charset=utf-8');
 if(r.method!=='GET')return res('Method not allowed','text/plain',405);
 if(['/', '/register','/login','/dashboard','/setup','/privacy'].includes(p)||/^\/verify\/[^/]+$/.test(p))return res(page,'text/html; charset=utf-8');
 return res('Tidak ditemukan','text/plain; charset=utf-8',404)
 }catch(ex){return res('Gangguan sistem','text/plain; charset=utf-8',503)}}};