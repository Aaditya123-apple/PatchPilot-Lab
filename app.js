const $=id=>document.getElementById(id);
if(new URL(location.href).searchParams.has('embed'))document.body.classList.add('embedded');
let worker,ready=false,busy=false,loadingInput=false,last=null,pending=null,timer,loadTimer;
let requestId=0,revision=0,inputRequest=0;
const kind=f=>f.kind||f.category||'Bug';
const isPerformance=f=>kind(f)==='Performance';
const isSecurity=f=>kind(f)==='Security';
const isCleanup=f=>['Cleanup','Maintainability'].includes(kind(f));
const motion=()=>matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth';
function el(tag,text='',cls=''){const n=document.createElement(tag);n.textContent=text;if(cls)n.className=cls;return n;}
function syncRun(){$('run').disabled=!ready||busy||loadingInput;}
function finish(){busy=false;clearTimeout(timer);$('cancel').hidden=true;$('run').textContent='Analyse code →';$('code').setAttribute('aria-busy','false');syncRun();}
function fail(message){$('error').textContent=message;$('error').hidden=false;if(!pending)finish();}
function stopEngine(message){worker?.terminate();ready=false;pending=null;clearTimeout(loadTimer);fail(message);$('retry').hidden=false;$('status').textContent='Engine unavailable · retry when ready';}
function init(){
  worker?.terminate();clearTimeout(loadTimer);clearTimeout(timer);ready=false;pending=null;finish();
  $('status').textContent='Loading analysis engine…';$('retry').hidden=true;$('error').hidden=true;
  try{worker=new Worker('worker.js?v=3',{type:'module'});}catch{stopEngine('Your browser could not start the analysis engine. Open this site in a current browser with JavaScript enabled.');return;}
  const current=worker;
  loadTimer=setTimeout(()=>stopEngine('The engine could not finish loading. Check your connection and retry.'),120000);
  worker.onmessage=({data})=>{
    if(current!==worker)return;
    if(data.type==='progress'&&!ready){$('status').textContent=data.message;return;}
    if(data.type==='ready'){clearTimeout(loadTimer);ready=true;$('status').textContent='Ready · Python & JavaScript checks';syncRun();return;}
    if(data.type==='error'){
      if(data.id!==undefined&&data.id!==pending?.id)return;
      if(!ready){stopEngine('The engine could not load. Check your connection, then choose Retry engine.');return;}
      pending=null;fail(data.message);$('status').textContent='Analysis could not complete · try again';return;
    }
    if(data.type!=='result'||!pending||data.id!==pending.id)return;
    const scanned=pending;pending=null;finish();
    if(scanned.revision!==revision){$('status').textContent='Input changed during analysis · analyse again';return;}
    last={...data.result,input:scanned.code,name:scanned.name,language:scanned.language};
    render(last);$('status').textContent='Analysis complete';
  };
  worker.onerror=()=>{if(current===worker)stopEngine('The analysis engine stopped. Your code is still in the editor. Retry to reload it.');};
  worker.onmessageerror=()=>{if(current===worker)stopEngine('The engine could not return its result. Retry the engine and analyse again.');};
}
function download(name,content,type='text/plain'){
  const url=URL.createObjectURL(new Blob([content],{type})),a=el('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);
}
function invalidate(){revision++;last=null;$('results').hidden=true;$('error').hidden=true;if(ready&&!busy)$('status').textContent='Input changed · analyse again';}
function editorChanged(){
  const count=$('code').value.split('\n').length,bytes=new TextEncoder().encode($('code').value).length;
  $('gutter').textContent=Array.from({length:count},(_,i)=>i+1).join('\n');$('lines').textContent=count+(count===1?' line':' lines');
  $('bytes').textContent=(bytes/1000).toFixed(1)+' / 200 KB';$('bytes').classList.toggle('over-limit',bytes>200000);$('gutter').scrollTop=$('code').scrollTop;invalidate();
}
function jump(line){
  const input=$('code'),parts=input.value.split('\n'),index=Math.min(parts.length,Math.max(1,line))-1,start=parts.slice(0,index).reduce((n,s)=>n+s.length+1,0);
  input.focus();input.setSelectionRange(start,start+(parts[index]?.length||0));input.scrollTop=Math.max(0,index*23-70);$('gutter').scrollTop=input.scrollTop;input.scrollIntoView({behavior:motion(),block:'center'});
}
function card(f){
  const box=el('article','','finding'),head=el('div','','finding-head');
  head.append(el('span',f.severity||'Notice','severity '+f.severity),el('span',kind(f),'kind'),el('strong',f.title));box.append(head);
  const meta=el('div','','finding-meta'),line=el('button','Line '+f.line,'line-link');line.title='Select this line in your code';line.onclick=()=>jump(f.line);
  meta.append(line,el('span',f.rule_id),el('span',f.confidence||'Rule-based'));if(f.cwe)meta.append(el('span',f.cwe));box.append(meta,el('p',f.description));
  if(f.snippet)box.append(el('pre',f.snippet));box.append(el('p','What to change: '+f.recommendation,'recommendation'));
  if(f.fix_example){
    const heading=el('div','','proposal-heading'),copy=el('button','Copy proposal');heading.append(el('span','Suggested approach · review assumptions'),copy);
    copy.onclick=async()=>{try{await navigator.clipboard.writeText(f.fix_example);copy.textContent='Copied';}catch{copy.textContent='Select the code below to copy';}};
    box.append(heading,el('pre',f.fix_example,'proposal-example'));
  }
  return box;
}
function empty(target,title,body){const n=el('div','','empty');n.append(el('strong',title),el('span',body));target.append(n);}
function showIssues(){
  if(!last)return;
  const value=$('filter').value,severity=$('severity').value,query=$('finding-search').value.trim().toLowerCase(),all=last.findings.filter(f=>!isPerformance(f));
  const list=all.filter(f=>(value==='all'||value==='security'&&isSecurity(f)||value==='cleanup'&&isCleanup(f)||value==='errors'&&!isSecurity(f)&&!isCleanup(f))&&(severity==='all'||f.severity===severity)&&(!query||[f.title,f.rule_id,f.description,f.recommendation,f.snippet,'line '+f.line].join(' ').toLowerCase().includes(query)));
  $('findings').replaceChildren(...list.map(card));$('issue-count').textContent=list.length+' of '+all.length+' issues';
  if(!list.length)empty($('findings'),all.length?'No matching findings.':'No issues detected by these checks.',all.length?'Reset the filters or try another search.':'Run your project tests to check behaviour that static analysis cannot verify.');
}
function tab(name){for(const id of ['issues','performance','patch']){$(id+'-view').hidden=id!==name;$('tab-'+id).setAttribute('aria-selected',String(id===name));$('tab-'+id).tabIndex=id===name?0:-1;}}
function render(r){
  $('results').hidden=false;$('error').hidden=true;
  const errors=r.findings.filter(f=>!isPerformance(f)&&!isSecurity(f)&&!isCleanup(f)),security=r.findings.filter(isSecurity),performance=r.findings.filter(isPerformance);
  $('metrics').replaceChildren();
  for(const [n,label] of [[errors.length,'Errors & reliability'],[security.length,'Security flags'],[performance.length,'Efficiency proposals'],[r.resolved.length,'Resolved in proposed code']]){const box=el('div','','metric');box.append(el('strong',String(n)),el('span',label));$('metrics').append(box);}
  $('summary').textContent=r.findings.length?`${r.findings.length} findings. ${r.remaining.length} detected in the proposed code.${r.syntax_valid===false?' Fix the syntax first, then analyse again for deeper checks.':''}`:'No findings from these checks. Run your project tests to verify correctness and security.';
  $('result-context').textContent=r.name+' · '+({python:'Python',javascript:'JavaScript',typescript:'TypeScript · security only',other:'Text patterns only'}[r.language])+' · '+new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  $('filter').value='all';$('severity').value='all';$('finding-search').value='';
  $('tab-issues').textContent='Issues · '+(r.findings.length-performance.length);$('tab-performance').textContent='Improve efficiency · '+performance.length;$('tab-patch').textContent='Proposed code'+(r.diff?' · available':'');showIssues();
  $('performance').replaceChildren(...performance.map(card));if(!performance.length)empty($('performance'),'No targeted performance issues found.','Profile your actual workload for bottlenecks that static analysis cannot measure.');
  $('before').textContent=r.input;$('after').textContent=r.patched;$('diff').textContent=r.diff||'No supported automatic change was proposed.';
  $('review').textContent=r.diff?`${r.resolved.length} findings resolved by this proposal. ${r.remaining.length} detected in the revision; repairing syntax may reveal additional issues. The revised Python syntax was checked. Test the behaviour before using it.`:'No supported automatic patch is available for this input. The issue and efficiency views explain changes you can make manually.';
  $('notes').replaceChildren(...r.notes.map(n=>el('p',n)));for(const id of ['download-patch','download-code','apply-proposal'])$(id).disabled=!r.diff;
  tab('issues');
}
$('run').onclick=()=>{
  if(!ready||busy||loadingInput)return;
  const code=$('code').value;if(!code.trim()){fail('Paste code or load an example first.');return;}if(new TextEncoder().encode(code).length>200000){fail('Choose a file smaller than 200 KB.');return;}
  busy=true;syncRun();$('run').textContent='Analysing…';$('cancel').hidden=false;$('error').hidden=true;$('results').hidden=true;$('code').setAttribute('aria-busy','true');$('status').textContent='Checking syntax, issues, and improvements…';
  pending={id:++requestId,revision,code,name:$('name').value.replace(/[^\w.\-]/g,'_')||'snippet.py',language:$('language').value};last=null;
  try{worker.postMessage(pending);timer=setTimeout(()=>stopEngine('Analysis exceeded 30 seconds. Your code is preserved. Try a smaller file and retry the engine.'),30000);}catch{stopEngine('The engine could not start this scan. Retry the engine and analyse again.');}
};
$('cancel').onclick=()=>stopEngine('Analysis cancelled. Your code is preserved. Retry to reload the engine.');$('retry').onclick=init;
const samples={python:{bugs:'def total_price(prices):\n    subtotal = sum([price for price in prices])\n    return subtotla / 0\n\ndef find_matches(items, rows):\n    for item in items:\n        for row in rows:\n            if item["id"] == row["id"]:\n                print(row)\n',syntax:'def greet(name)\n    return "Hello, " + name\n'},javascript:{bugs:'function findMatches(items, rows) {\n  for (const item of items) {\n    for (const row of rows) {\n      if (item.id == row.id) console.log(row);\n    }\n  }\n  return 10 / 0;\n}\n',syntax:'function greet(name {\n  return "Hello, " + name;\n}\n'}};
function endInput(){loadingInput=false;$('example').disabled=false;$('example').textContent='Load example';syncRun();}
function cancelInput(){inputRequest++;endInput();}
$('example').onclick=async()=>{
  const token=++inputRequest,rev=revision,language=$('language').value,sample=$('sample').value;
  loadingInput=true;$('example').disabled=true;$('example').textContent='Loading…';syncRun();
  try{
    let code,lang=language==='javascript'?'javascript':'python',name=lang==='python'?'example.py':'example.js';
    if(sample==='security'){const r=await fetch('example.py');if(!r.ok)throw Error('Example could not load.');code=await r.text();lang='python';name='vulnerable_app.py';}else code=samples[lang][sample];
    if(token!==inputRequest||rev!==revision)return;
    $('code').value=code;$('name').value=name;$('language').value=lang;coverage();editorChanged();
  }catch{if(token===inputRequest)fail('The example could not load. Check your connection or paste code directly.');}
  finally{if(token===inputRequest)endInput();}
};
$('clear').onclick=()=>{cancelInput();$('code').value='';editorChanged();};
$('code').oninput=()=>{cancelInput();editorChanged();};$('code').onscroll=()=>{$('gutter').scrollTop=$('code').scrollTop;};
$('code').onkeydown=e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();$('run').click();}};
$('upload').onclick=()=>$('file').click();
$('file').onchange=async()=>{
  const file=$('file').files[0];$('file').value='';if(!file)return;
  cancelInput();const token=++inputRequest,rev=revision;
  if(file.size>200000){fail('Choose a file smaller than 200 KB.');return;}
  loadingInput=true;syncRun();
  try{
    const code=await file.text();if(token!==inputRequest||rev!==revision)return;
    if(code.includes('\0')){fail('This looks like a binary file. Choose a UTF-8 text source file.');return;}
    $('code').value=code;$('name').value=file.name;
    const ext=file.name.split('.').pop().toLowerCase();$('language').value=['py','pyw'].includes(ext)?'python':['js','mjs','cjs','jsx'].includes(ext)?'javascript':['ts','tsx'].includes(ext)?'typescript':'other';
    coverage();editorChanged();
  }catch{if(token===inputRequest)fail('The file could not be read. Choose a UTF-8 text source file.');}
  finally{if(token===inputRequest)endInput();}
};
function coverage(){const labels={python:'Python: syntax, compile context, undefined names, static bugs, security, and performance hints.',javascript:'JavaScript: syntax (no JSX), selected bug patterns, security, and performance hints. No undefined-name checks.',typescript:'TypeScript: security patterns only. TypeScript syntax and types are not checked.',other:'Other files: secret and text-pattern checks only.'};$('coverage').textContent=labels[$('language').value];}
$('language').onchange=()=>{cancelInput();coverage();invalidate();};$('name').oninput=()=>{cancelInput();invalidate();};
$('filter').onchange=showIssues;$('severity').onchange=showIssues;$('finding-search').oninput=showIssues;
$('reset-filters').onclick=()=>{$('filter').value='all';$('severity').value='all';$('finding-search').value='';showIssues();};
for(const name of ['issues','performance','patch']){
  $('tab-'+name).onclick=()=>tab(name);
  $('tab-'+name).onkeydown=e=>{const names=['issues','performance','patch'];let next;if(e.key==='ArrowRight')next=names[(names.indexOf(name)+1)%3];if(e.key==='ArrowLeft')next=names[(names.indexOf(name)+2)%3];if(e.key==='Home')next='issues';if(e.key==='End')next='patch';if(next){e.preventDefault();tab(next);$('tab-'+next).focus();}};
}
$('report').onclick=()=>{if(last)download('patchpilot-report.json',JSON.stringify(last,null,2),'application/json');};
$('download-patch').onclick=()=>{if(last?.diff)download('patchpilot.patch',last.diff);};$('download-code').onclick=()=>{if(last?.diff)download(last.name,last.patched);};
$('apply-proposal').onclick=()=>{if(!last?.diff)return;const code=last.patched;cancelInput();$('code').value=code;editorChanged();$('status').textContent='Proposal loaded · analyse it again';$('code').focus();};
coverage();editorChanged();init();
