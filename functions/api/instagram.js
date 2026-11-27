const USERNAME = 'ppskerthawisesa';
const json = (data, status = 200, ttl = 0) => new Response(JSON.stringify(data), { status, headers: {'Content-Type':'application/json; charset=utf-8','Cache-Control':ttl ? 'public, max-age=60, s-maxage='+ttl : 'no-store','X-Content-Type-Options':'nosniff'} });
function safeUrl(value, instagramOnly=false) {try {const u=new URL(value); if(u.protocol!=='https:' || u.username || u.password) return null; if(instagramOnly && !['instagram.com','www.instagram.com'].includes(u.hostname)) return null; return u.href;} catch {return null;}}
export async function onRequestGet({request, env, waitUntil}) {
  const token=env.KW_INSTAGRAM_TOKEN;
  if(!token) return json({status:'not_connected',username:USERNAME,posts:[]});
  const version=/^v[0-9]+\.0$/.test(env.KW_INSTAGRAM_API_VERSION||'')?env.KW_INSTAGRAM_API_VERSION:'v27.0';
  const cache= caches.default;
  const key=new Request(new URL('/api/instagram',request.url).href);
  try {
    const cached=await cache.match(key); if(cached) return cached;
    const base='https://graph.instagram.com/'+version+'/';
    const read=async(path,params)=>{const url=new URL(base+path); for(const [k,v] of Object.entries(params))url.searchParams.set(k,v);const r=await fetch(url,{headers:{Authorization:'Bearer '+token},signal:AbortSignal.timeout(12000)}); if(!r.ok) throw new Error('upstream');return r.json();};
    const user=await read('me',{fields:'user_id,username'});
    if(String(user.username||'').toLowerCase()!==USERNAME || !/^\d+$/.test(String(user.user_id||user.id))) return json({status:'account_mismatch',username:USERNAME,posts:[]},503);
    const feed=await read(String(user.user_id||user.id)+'/media',{fields:'id,caption,media_type,media_url,thumbnail_url,permalink,timestamp,children{media_type,media_url,thumbnail_url}',limit:'12'});
    if(!Array.isArray(feed.data)) throw new Error('invalid_data');
    const posts=feed.data.slice(0,12).map(p=>({id:String(p.id),caption:String(p.caption||'').slice(0,2200),type:p.media_type,date:p.timestamp,link:safeUrl(p.permalink,true),image:safeUrl(p.media_type==='VIDEO'?p.thumbnail_url:p.media_url)||safeUrl(p.children?.data?.[0]?.media_type==='VIDEO'?p.children?.data?.[0]?.thumbnail_url:p.children?.data?.[0]?.media_url)})).filter(p=>p.link);
    const response=json({status:'connected',username:USERNAME,updated_at:new Date().toISOString(),posts},200,900);
    waitUntil(cache.put(key,response.clone()).catch(()=>{}));
    return response;
  } catch {return json({status:'unavailable',username:USERNAME,posts:[]},503);}
}