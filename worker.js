import {loadPyodide} from './pyodide.mjs';
import {inspectJS} from './analysis-js.mjs?v=4';
const ROOT=new URL('./',self.location.href).href;
let engine;
async function start(){
  postMessage({type:'progress',message:'Loading the local Python runtime…'});
  engine=await loadPyodide({indexURL:ROOT});
  postMessage({type:'progress',message:'Preparing name, security, and bug checks…'});
  await engine.loadPackage('pydantic');
  const wheel=await fetch('pyflakes.whl');if(!wheel.ok)throw Error('Could not load Python diagnostics');
  engine.FS.writeFile('/pyflakes.whl',new Uint8Array(await wheel.arrayBuffer()));
  engine.runPython('import zipfile\nzipfile.ZipFile("/pyflakes.whl").extractall("/app")');
  engine.FS.mkdirTree('/app/src');
  const files=['__init__.py','models.py','scanner.py','rules.py','pyanalysis.py','fixers.py'];
  await Promise.all(files.map(async file=>{const r=await fetch('engine-'+file);if(!r.ok)throw Error('Could not load scanner source');engine.FS.writeFile('/app/src/'+file,await r.text());}));
  const r=await fetch('audit.py?v=4');if(!r.ok)throw Error('Could not load audit adapter');
  const diagnostics=await fetch('diagnostics.py?v=4');if(!diagnostics.ok)throw Error('Could not load debugging rules');engine.FS.writeFile('/app/diagnostics.py',await diagnostics.text());
  engine.runPython('import sys\nsys.path.insert(0,"/app")');
  engine.runPython(await r.text());
  postMessage({type:'ready'});
}
const ready=start();
ready.catch(e=>postMessage({type:'error',message:'Could not load the Python engine. Check your connection and press Retry. '+e.message}));
onmessage=async({data})=>{
  try {await ready;
  if(data.operation==='validate'){
   let validation;
   if(data.language==='python'){
    engine.globals.set('audit_payload',JSON.stringify(data));const check=JSON.parse(engine.runPython('audit(audit_payload)'));
    validation={valid:check.syntax_valid,findings:check.findings.length,message:check.syntax_valid?'Python syntax checked. '+check.findings.length+' static findings detected.':'The AI proposal has a Python syntax error; it cannot be loaded.'};
   }else if(data.language==='javascript'){
    const check={syntax_valid:true,findings:[],remaining:[],notes:[]};inspectJS(data,check);
    validation={valid:check.syntax_valid,findings:check.findings.length,message:check.syntax_valid?'JavaScript syntax checked. '+check.findings.length+' targeted findings detected.':'The AI proposal has a JavaScript syntax error; it cannot be loaded.'};
   }else validation={valid:null,message:'Syntax validation is not available for this language. Review with your compiler before use.'};
   postMessage({type:'validation',id:data.id,validation});return;
  }
  engine.globals.set('audit_payload',JSON.stringify(data));const result=JSON.parse(engine.runPython('audit(audit_payload)'));if(data.language==='javascript')inspectJS(data,result);if(data.language==='typescript')result.notes.push('TypeScript has security-pattern checks only; no TypeScript compiler or type checker is included.');result.findings.sort((a,b)=>({Critical:0,High:1,Medium:2,Low:3}[a.severity]??4)-({Critical:0,High:1,Medium:2,Low:3}[b.severity]??4)||a.line-b.line||(a.column||1)-(b.column||1));postMessage({type:'result',result,id:data.id});}
  catch(e){postMessage({type:'error',id:data.id,message:'This file could not be analysed. Try a smaller snippet, check its language, or reload the engine.'});}
};
