import {loadPyodide} from './pyodide.mjs';
const ROOT=new URL('./',self.location.href).href;
let engine;
async function start(){
  engine=await loadPyodide({indexURL:ROOT});
  await engine.loadPackage('pydantic');
  engine.FS.mkdirTree('/app/src');
  const files=['__init__.py','models.py','scanner.py','rules.py','pyanalysis.py','fixers.py'];
  await Promise.all(files.map(async file=>{const r=await fetch('engine-'+file);if(!r.ok)throw Error('Could not load scanner source');engine.FS.writeFile('/app/src/'+file,await r.text());}));
  const r=await fetch('audit.py');if(!r.ok)throw Error('Could not load audit adapter');
  engine.runPython('import sys\nsys.path.insert(0,"/app")');
  engine.runPython(await r.text());
  postMessage({type:'ready'});
}
const ready=start();
ready.catch(e=>postMessage({type:'error',message:'Could not load the Python engine. Check your connection and press Retry. '+e.message}));
onmessage=async({data})=>{
  try {await ready; engine.globals.set('audit_payload',JSON.stringify(data));const result=JSON.parse(engine.runPython('audit(audit_payload)'));postMessage({type:'result',result});}
  catch(e){postMessage({type:'error',message:e.message});}
};
