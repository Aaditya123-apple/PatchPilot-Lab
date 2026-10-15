import {parse} from './acorn.mjs';

// AST-only checks. Submitted code is parsed and is never executed.
export function inspectJS(data,result){
  let tree,error;
  for(const sourceType of ['module','script']){
    try{tree=parse(data.code,{ecmaVersion:'latest',sourceType,locations:true});error=null;break;}
    catch(e){error=e;}
  }
  const lines=data.code.split('\n');
  const add=(rule,title,description,recommendation,node,kind='Bug',example='',conditional=false)=>{
    const line=node?.loc?.start?.line||1,column=(node?.loc?.start?.column||0)+1;
    const f={id:`${rule}@${data.name}:${line}:${column}`,file:data.name,line,column,rule_id:rule,title,description,recommendation,kind,category:kind,severity:kind==='Performance'?'Low':conditional?'Medium':'High',confidence:conditional?'Conditional':'High',snippet:lines[line-1]||'',fix_example:example};
    result.findings.push(f);result.remaining.push(f);
  };
  if(error){
    result.syntax_valid=false;result.revised_valid=false;
    add('JS-SYNTAX','JavaScript syntax error',error.message,'Check the marked token and preceding line for missing delimiters, commas or incomplete expressions.',{loc:{start:error.loc}},'Syntax');
    result.notes.push('Syntax must be valid before the JavaScript AST checks can run. Text-based security checks still ran.');
    return;
  }
  const functions=new Set(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression']);
  const loops=new Set(['ForStatement','ForOfStatement','ForInStatement','WhileStatement','DoWhileStatement']);
  const walk=(node,depth=0)=>{
    if(!node||typeof node.type!=='string')return;
    if(functions.has(node.type))depth=0;
    const loop=loops.has(node.type);
    if(loop&&depth>0)add('JS-OPT-NESTED','Review nested-loop cost','Independent nested loops can perform O(n × m) iterations; this is not a benchmark.','For repeated key matching, consider a Map or Set. Preserve ordering, duplicates and equality semantics.',node,'Performance','const byId = new Map(rows.map(row => [row.id, row]));\nconst match = byId.get(id);',true);
    if(node.type==='BinaryExpression'){
      if(['/','%'].includes(node.operator)&&node.right.type==='Literal'&&(node.right.value===0||node.right.value===0n))
        add('JS-ZERO','Literal zero divisor','Number division by zero yields Infinity or NaN; BigInt division by zero throws.','Use the intended divisor or guard zero and non-finite inputs.',node);
      if(['==','!='].includes(node.operator))add('JS-EQUALITY','Review coercive equality','This comparison can equate values of different types.','Use strict equality when coercion is not intentional. Review existing behaviour before changing it.',node,'Bug','if (value === expected) { /* ... */ }',true);
      if(node.left.type==='Literal'&&node.right.type==='Literal'&&['+','-','*','/','%','**','|','&','^','<<','>>','>>>'].includes(node.operator)){
        const a=typeof node.left.value,b=typeof node.right.value;
        if((a==='bigint'&&b==='number')||(b==='bigint'&&a==='number'))
          add('JS-BIGINT','Mixed BigInt arithmetic','This arithmetic mixes a BigInt with another literal type and throws TypeError.','Convert both operands to the intended numeric type. Check for precision loss when converting BigInt to Number.',node);
      }
    }
    if(node.type==='MemberExpression'&&!node.optional&&node.object.type==='Literal'&&node.object.value===null)
      add('JS-NULL','Property access on null','Accessing a property on null throws TypeError if reached.','Check for a missing value before accessing the property, or use optional chaining when undefined is an acceptable result.',node);
    if(node.type==='CallExpression'&&['Literal','ArrayExpression','ObjectExpression'].includes(node.callee.type)&&!node.optional)
      add('JS-CALL','Value is not callable','This literal value cannot be called as a function and throws TypeError if reached.','Check for a missing operator, comma or semicolon, or call the intended function.',node);
    if(node.type==='NewExpression'&&node.callee.type==='Identifier'&&node.callee.name==='Promise'&&functions.has(node.arguments[0]?.type)&&node.arguments[0].async)
      add('JS-ASYNC-EXECUTOR','Review async Promise executor','An async executor returns a promise that the Promise constructor ignores. Rejections after await can leave the outer promise pending.','Use an async function directly, or keep the Promise executor synchronous and handle rejection explicitly.',node,'Bug','async function load() {\n  return await fetch(url);\n}',true);
    if(['IfStatement','WhileStatement','DoWhileStatement'].includes(node.type)&&node.test?.type==='AssignmentExpression'&&node.test.operator==='=')
      add('JS-CONDITION','Review assignment in condition','This condition assigns a value and then tests that value. An equality comparison may have been intended.','If comparison was intended, use ===. If assignment is deliberate, keep it and make the intent clear.',node.test,'Bug','if (value === expected) { /* ... */ }',true);
    if(node.type==='ObjectExpression'){
      const seen=new Map();
      for(const prop of node.properties){
        if(prop.type!=='Property'||prop.computed||prop.kind!=='init')continue;
        const key=prop.key.type==='Identifier'?prop.key.name:String(prop.key.value);
        if(seen.has(key))add('JS-DUPLICATE-KEY','Object key repeated',`The later ${JSON.stringify(key)} property overwrites an earlier property with the same key.`,'Use distinct keys or remove the unintended duplicate.',prop);
        seen.set(key,prop);
      }
    }
    if(node.type==='BlockStatement'||node.type==='Program'){
      let ended=false;
      for(const stmt of node.body){
        if(stmt.type==='FunctionDeclaration'||stmt.type==='EmptyStatement')continue;
        if(ended){add('JS-UNREACHABLE','Unreachable statement','A preceding unconditional return, throw, break or continue exits this block before this statement.','Move required work before the exit, or remove the unreachable statement.',stmt);break;}
        if(['ReturnStatement','ThrowStatement','BreakStatement','ContinueStatement'].includes(stmt.type))ended=true;
      }
    }
    for(const value of Object.values(node)){
      if(Array.isArray(value)){for(const child of value)walk(child,depth+(loop?1:0));}
      else if(value?.type)walk(value,depth+(loop?1:0));
    }
  };
  walk(tree);
}
