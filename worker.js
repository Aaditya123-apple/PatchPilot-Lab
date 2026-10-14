import {loadPyodide} from './pyodide.mjs';
import {parse} from './acorn.mjs';
const ROOT=new URL('./',self.location.href).href;
let engine;
async function start(){
  engine=await loadPyodide({indexURL:ROOT});
  await engine.loadPackage('pydantic');
  const wheel=await fetch('pyflakes.whl');if(!wheel.ok)throw Error('Could not load Python diagnostics');
  engine.FS.writeFile('/pyflakes.whl',new Uint8Array(await wheel.arrayBuffer()));
  engine.runPython('import zipfile\nzipfile.ZipFile("/pyflakes.whl").extractall("/app")');
  engine.FS.mkdirTree('/app/src');
  const files=['__init__.py','models.py','scanner.py','rules.py','pyanalysis.py','fixers.py'];
  await Promise.all(files.map(async file=>{const r=await fetch('engine-'+file);if(!r.ok)throw Error('Could not load scanner source');engine.FS.writeFile('/app/src/'+file,await r.text());}));
  const r=await fetch('audit.py');if(!r.ok)throw Error('Could not load audit adapter');
  const diagnostics=await fetch('diagnostics.py');if(!diagnostics.ok)throw Error('Could not load debugging rules');engine.FS.writeFile('/app/diagnostics.py',await diagnostics.text());
  engine.runPython('import sys\nsys.path.insert(0,"/app")');
  engine.runPython(await r.text());
  postMessage({type:'ready'});
}
const ready=start();
ready.catch(e=>postMessage({type:'error',message:'Could not load the Python engine. Check your connection and press Retry. '+e.message}));
onmessage=async({data})=>{
  try {await ready; engine.globals.set('audit_payload',JSON.stringify(data));const result=JSON.parse(engine.runPython('audit(audit_payload)'));if(data.language==='javascript')inspectJS(data,result);if(data.language==='typescript')result.notes.push('TypeScript has security-pattern checks only; no TypeScript compiler or type checker is included.');postMessage({type:'result',result});}
  catch(e){postMessage({type:'error',message:e.message});}
};
function inspectJS(data,result){
 let tree,error;for(const sourceType of ['module','script']){try{tree=parse(data.code,{ecmaVersion:'latest',sourceType,locations:true});error=null;break;}catch(e){error=e;}}
 const add=(rule,title,description,recommendation,node,kind='Bug',example='')=>{const line=node?.loc?.start?.line||1;const conditional=kind==='Performance'||rule==='JS-EQUALITY';const f={id:rule+'@'+data.name+':'+line,file:data.name,line,rule_id:rule,title,description,recommendation,kind,category:kind,severity:kind==='Performance'?'Low':rule==='JS-EQUALITY'?'Medium':'High',confidence:conditional?'Conditional':'High',snippet:data.code.split('\n')[line-1]||'',fix_example:example};result.findings.push(f);result.remaining.push(f);};
 if(error){result.syntax_valid=false;add('JS-SYNTAX','JavaScript syntax error',error.message,'Check the marked token and preceding line for missing delimiters, commas or incomplete expressions.',{loc:{start:{line:error.loc?.line||1}}},'Syntax');return;}
 const walk=(node,depth=0)=>{if(!node||typeof node!=='object')return;const loop=['ForStatement','ForOfStatement','ForInStatement','WhileStatement','DoWhileStatement'].includes(node.type);
 if(loop&&depth>0)add('JS-OPT-NESTED','Review nested-loop cost','Independent nested loops can perform O(n × m) iterations; this is not a benchmark.','For repeated key matching, consider a Map or Set. Preserve ordering, duplicates and equality semantics.',node,'Performance','const byId = new Map(rows.map(row => [row.id, row]));\nconst match = byId.get(id);');
 if(node.type==='BinaryExpression'&&['/','%'].includes(node.operator)&&node.right?.type==='Literal'&&node.right.value===0)add('JS-ZERO','Literal zero divisor','Number division by zero yields Infinity or NaN; BigInt division by zero throws.','Use the intended divisor or guard zero and non-finite inputs.',node);
 if(node.type==='BinaryExpression'&&['==','!='].includes(node.operator))add('JS-EQUALITY','Review coercive equality','This comparison can equate values of different types.','Use strict equality when coercion is not intentional. Review existing behaviour before changing it.',node,'Bug','if (value === expected) { /* ... */ }');
 for(const value of Object.values(node)){if(Array.isArray(value))for(const child of value)walk(child,depth+(loop?1:0));else if(value?.type)walk(value,depth+(loop?1:0));}};walk(tree);
}
