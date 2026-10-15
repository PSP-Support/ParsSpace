from html import escape

def get_public_page_html(uuid_key: str) -> str:
    key = escape(str(uuid_key), quote=True)
    return f'''<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pars Space Subscription</title>
<style>body{{margin:0;background:#080a10;color:#f5f0e8;font-family:system-ui,sans-serif;padding:24px}}.card{{max-width:760px;margin:40px auto;padding:24px;border:1px solid #2c313c;border-radius:22px;background:#11141b;box-shadow:0 20px 70px #0008}}h1{{margin-top:0}}.cfg{{padding:12px;margin:10px 0;border:1px solid #2c313c;border-radius:14px;background:#0c0f15;word-break:break-all;direction:ltr;text-align:left;font:12px monospace}}button{{border:0;border-radius:10px;padding:9px 14px;cursor:pointer}}</style></head>
<body><div class="card"><h1>Pars Space</h1><p>Subscription</p><div id="out">در حال بارگذاری...</div></div>
<script>
const key={key!r};
async function load(){{const r=await fetch('/api/public/sub/'+encodeURIComponent(key));const d=await r.json();if(!r.ok)throw new Error(d.detail||'Subscription not found');let html='<h3>'+esc(d.name||'Subscription')+'</h3><p>'+esc(d.desc||'')+'</p>';(d.links||[]).forEach((x,i)=>{{html+='<div class="cfg"><b>'+esc(x.label||('Config '+(i+1)))+'</b><br>'+esc(x.vless_link||'')+'<br><button onclick="navigator.clipboard.writeText('+JSON.stringify(x.vless_link||'')+')">کپی</button></div>'}});document.getElementById('out').innerHTML=html||'کانفیگی وجود ندارد';}}
function esc(x){{return String(x??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}
load().catch(e=>document.getElementById('out').textContent=e.message);
</script></body></html>'''
