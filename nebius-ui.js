(()=>{
 const by=id=>document.getElementById(id), make=(tag,value='',cls='')=>{const n=document.createElement(tag);n.textContent=value;if(cls)n.className=cls;return n;};
 let configured=false,controller=null,snapshot=null,generation=0,review=null;
 const message=(s,error=false)=>{by('ai-status').textContent=s;by('ai-status').classList.toggle('ai-error',error);};
 function invalidateAI(){generation++;controller?.abort();controller=null;review=null;by('ai-output').hidden=true;by('ai-consent').checked=false;by('ai-run').disabled=!configured;by('ai-cancel').hidden=true;message(configured?'Input changed · confirm this snippet to request a new AI review.':'AI review is currently unavailable. Local checks are ready to use.');}
 document.addEventListener('patchpilot:inputchanged',invalidateAI);
 async function status(){
  try{const response=await fetch('/api/nebius/status',{cache:'no-store'}),data=await response.json();configured=response.ok&&data.configured===true;by('ai-run').disabled=!configured;message(configured?'Configured · '+data.model+' · Nebius Token Factory':'AI review is currently unavailable. Local checks are ready to use.');}
  catch{message('AI review is currently unavailable. Local checks are ready to use.');}
 }
 const bulletList=(target,items)=>{for(const text of items||[])target.append(make('li',text));};
 async function renderAI(data,token){
  review=data;by('ai-output').hidden=false;by('ai-summary').textContent=data.summary;by('ai-findings').replaceChildren();
  for(const finding of data.findings){const card=make('article','','finding');card.append(make('strong',finding.title),make('p',finding.severity+' · '+finding.category+' · '+(finding.line?'Line '+finding.line:'Location requires review')+' · AI proposal'),make('p',finding.explanation),make('p','Suggested change: '+finding.recommendation,'recommendation'));by('ai-findings').append(card);}
  if(!data.findings.length)by('ai-findings').append(make('p','The model reported no findings. This is not proof of correctness.'));
  by('ai-trace').replaceChildren();for(const step of data.trace){const p=make('p',step.stage+' · '+step.requested_model+' · '+step.latency_ms+' ms · '+(step.prompt_tokens??'unreported')+' input / '+(step.completion_tokens??'unreported')+' output tokens');by('ai-trace').append(p);}
  by('ai-changes').replaceChildren();bulletList(by('ai-changes'),data.proposal.changes);by('ai-tests').replaceChildren();bulletList(by('ai-tests'),data.proposal.tests);by('ai-risks').replaceChildren();bulletList(by('ai-risks'),data.proposal.risks);
  by('ai-code').textContent=data.proposal.revised_code||'No complete revision was proposed. Review the findings and the intended behaviour before editing.';
  by('ai-code-actions').hidden=!data.proposal.revised_code;by('ai-load').disabled=true;
  if(data.proposal.revised_code){
   by('ai-validation').textContent='Checking the proposed syntax locally…';
   const validation=await validateAIProposal(data.proposal.revised_code,snapshot.language,snapshot.name);
   if(token!==generation)return;
   data.verification={...data.verification,syntax:validation.valid===true?'passed':validation.valid===false?'failed':'not checked',static_findings:validation.findings??null,runtime_tests:'not run',performance:'not benchmarked'};
   by('ai-validation').textContent=validation.message+' Runtime behaviour and speed have not been tested.';
   by('ai-load').disabled=validation.valid!==true;
  }else by('ai-validation').textContent='No code revision to check. Test ideas below have not been run.';
 }
 by('ai-run').onclick=async()=>{
  if(!configured||controller)return;
  if(!by('ai-consent').checked){message('Confirm that this snippet may be sent to Nebius before requesting AI review.',true);return;}
  const code=by('code').value;if(!code.trim()){message('Paste a snippet first.',true);return;}if(new TextEncoder().encode(code).length>10000||code.split('\n').length>400){message('Use at most 10 KB and 400 lines for AI review. Local checks accept up to 200 KB.',true);return;}
  const token=++generation;snapshot={code,language:by('language').value,name:by('name').value};controller=new AbortController();const current=controller;const timeout=setTimeout(()=>current.abort(),110000);by('ai-run').disabled=true;by('ai-cancel').hidden=false;by('ai-output').hidden=true;
  message('Nemotron is reviewing the snippet and preparing a conservative fix…');
  try{
   const response=await fetch('/api/nebius/review',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...snapshot,consent:true,diagnostics:last?.findings||[]}),signal:current.signal});
   let data;try{data=await response.json();}catch{throw Error('The review service returned an unreadable response. Try again later.');}
   if(token!==generation)return;if(!response.ok)throw Error(data.message||'AI review could not complete.');
   await renderAI(data,token);if(token===generation)message('Nebius review complete · '+data.trace.length+' inference call'+(data.trace.length===1?'':'s')+' · '+data.requested_model);
  }catch(e){if(token===generation)message(e.name==='AbortError'?'AI review stopped. Local checks remain available.':e.message,true);}
  finally{clearTimeout(timeout);if(token===generation){controller=null;by('ai-run').disabled=!configured;by('ai-cancel').hidden=true;}}
 };
 by('ai-cancel').onclick=()=>{generation++;controller?.abort();controller=null;by('ai-run').disabled=!configured;by('ai-cancel').hidden=true;by('ai-output').hidden=true;review=null;message('AI review cancelled.');};
 by('ai-load').onclick=()=>{if(!review?.proposal.revised_code)return;const candidate=review.proposal.revised_code;by('code').value=candidate;editorChanged();by('code').focus();by('status').textContent='AI proposal loaded · run local checks again';};
 by('ai-download').onclick=()=>{if(review?.proposal.revised_code)download(snapshot.name||'proposed-code.txt',review.proposal.revised_code);};
 by('ai-report').onclick=()=>{if(review)download('patchpilot-nebius-review.json',JSON.stringify({...review,input:snapshot.code},null,2),'application/json');};
 status();
})();
