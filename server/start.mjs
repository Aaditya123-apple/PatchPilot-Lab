import http from 'node:http';
import {readFile,readdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {handleNebius} from './nebius-review.mjs';
// Development-only shared-process quota adapter. Production uses atomic D1 SQL.
function localQuota(){const rows=new Map();return {prepare(sql){return {bind(...args){return {async first(){const [key,expiry,max]=args,old=rows.get(key);if(old&&old.used>=max)return null;const row={used:(old?.used||0)+1,expires_at:expiry};rows.set(key,row);return row;},async run(){for(const [key,row]of rows)if(row.expires_at<args[0])rows.delete(key);return {};}};}};}};}
const root=fileURLToPath(new URL('../',import.meta.url));
const allowed=new Set((await readdir(root)).filter(name=>!name.startsWith('.')&&/\.(html|css|js|mjs|py|json|whl|zip|wasm|svg)$/.test(name)&&!['package.json','source-files.json','patchpilot-source.zip'].includes(name)));
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json','.svg':'image/svg+xml','.wasm':'application/wasm','.py':'text/plain; charset=utf-8'};
const DB=localQuota();const port=Number(process.env.PORT||3000);
http.createServer(async(req,res)=>{
 try{
  const host=req.headers.host||'localhost:'+port;
  const url=new URL(req.url,'http://'+host);
  if(url.pathname.startsWith('/api/nebius/')){
   const abort=new AbortController();res.on('close',()=>{if(!res.writableEnded)abort.abort();});
   let bytes=0;const parts=[];for await(const part of req){bytes+=part.length;if(bytes>30000){res.writeHead(413,{'content-type':'application/json'}).end(JSON.stringify({message:'Request too large.'}));return;}parts.push(part);}
   const request=new Request(url,{method:req.method,headers:req.headers,body:['GET','HEAD'].includes(req.method)?undefined:Buffer.concat(parts),signal:abort.signal});
   const response=await handleNebius(request,{...process.env,DB},{clientIp:req.socket.remoteAddress||'local'});
   res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));return;
  }
  if(!['GET','HEAD'].includes(req.method)){res.writeHead(405).end();return;}
  const name=decodeURIComponent(url.pathname.slice(1))||'index.html';if(!allowed.has(name)){res.writeHead(404).end('Not found.');return;}
  const data=await readFile(path.join(root,name));res.writeHead(200,{'content-type':mime[path.extname(name)]||'application/octet-stream','x-content-type-options':'nosniff','cache-control':'no-store'});res.end(req.method==='HEAD'?undefined:data);
 }catch{res.writeHead(500,{'content-type':'text/plain'}).end('The request could not complete.');}
}).listen(port,'127.0.0.1',()=>console.log('PatchPilot: http://127.0.0.1:'+port+' — local static checks and optional Nebius AI.'));
