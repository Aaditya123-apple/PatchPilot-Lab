"""Static debugging and performance hints. Never executes submitted source."""
import ast
import copy
import difflib
from pyflakes.checker import Checker

def finding(name,code,node,rule,title,detail,tip,kind='Bug',example='',confidence='High'):
    line=getattr(node,'lineno',1) or 1
    return dict(id=f'{rule}@{name}:{line}',file=name,line=line,column=(getattr(node,'col_offset',0) or 0)+1,rule_id=rule,title=title,description=detail,recommendation=tip,kind=kind,category=kind,severity='Low' if kind in ('Performance','Cleanup') else 'High',confidence=confidence,source='analysis',snippet=code.splitlines()[line-1] if line<=len(code.splitlines()) else '',fix_example=example)

TIPS={
 'UndefinedName':('Undefined name','Define or import the name, or correct its spelling before using it.'),
 'UndefinedLocal':('Local variable used before assignment','Assign this local on every path before reading it. Check whether a later assignment shadows an outer variable.'),
 'UnusedImport':('Unused import','Remove the import if unnecessary. Preserve imports deliberately used for side effects or re-exports.'),
 'UnusedVariable':('Unused local variable','Use this value, or remove the unused assignment while preserving required side effects.'),
 'RedefinedWhileUnused':('Unused name redefined','Check whether this definition unintentionally replaces an earlier import or function.'),
 'MultiValueRepeatedKeyLiteral':('Dictionary key repeated','Use distinct keys. The later value silently overwrites the earlier value.'),
 'FStringMissingPlaceholders':('F-string has no placeholders','Remove the f prefix, or add the missing {expression}.'),
 'ReturnOutsideFunction':('Return outside a function','Move return into a function body.'),
 'BreakOutsideLoop':('Break outside a loop','Use break only inside a for or while loop.'),
 'ContinueOutsideLoop':('Continue outside a loop','Use continue only inside a for or while loop.')}

def nested_loop(body):
    pending=list(body)
    while pending:
        child=pending.pop()
        if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
            continue
        if isinstance(child,(ast.For,ast.AsyncFor,ast.While)):
            return True
        pending.extend(ast.iter_child_nodes(child))
    return False

def syntax_finding(exc,code,name):
    tip='Check the highlighted token and preceding line for missing delimiters, colons or incomplete expressions.'
    text=exc.msg.lower()
    if 'indent' in text:tip='Indent this block consistently with four spaces. Do not mix tabs and spaces.'
    elif "':'" in text:tip='Add a colon at the end of the block header, then indent the block body.'
    elif 'closed' in text or 'unmatched' in text:tip='Balance parentheses, brackets or braces; inspect the opening delimiter and preceding line.'
    elif 'unterminated string' in text:tip='Close the quoted string, or use triple quotes for multiline text.'
    out=finding(name,code,exc,'PY-SYNTAX','Python syntax error',exc.msg,tip,'Syntax');out['column']=exc.offset or 1;return out

def inspect(tree,code,name):
    out=[]
    names={n.id for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}|{n.arg for n in ast.walk(tree) if isinstance(n,ast.arg)}|{n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
    for msg in Checker(tree,filename=name).messages:
        cls=type(msg).__name__;title,tip=TIPS.get(cls,(cls,'Review this Python diagnostic and its surrounding scope.'))
        kind='Cleanup' if cls in ('UnusedImport','UnusedVariable','FStringMissingPlaceholders') else 'Bug'
        if cls=='UndefinedName':
            matches=difflib.get_close_matches(str(msg.message_args[0]),sorted(names),n=1,cutoff=.78)
            if matches:tip+=f' Did you mean {matches[0]!r}? Confirm it belongs to this scope.'
        f=finding(name,code,msg,'PYF-'+cls,title,msg.message % msg.message_args,tip,kind);f['column']=msg.col+1;out.append(f)
    def add(node,rule,title,detail,tip,kind='Bug',example='',confidence='High'):
        out.append(finding(name,code,node,rule,title,detail,tip,kind,example,confidence))
    for n in ast.walk(tree):
        if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Div,ast.FloorDiv,ast.Mod)) and isinstance(n.right,ast.Constant) and type(n.right.value) in (int,float) and n.right.value==0:
            add(n,'DBG-ZERO','Literal zero divisor','This expression raises ZeroDivisionError if this path executes.','Use the intended nonzero divisor, or guard a dynamic denominator before division.',example='if denominator != 0:\n    result = numerator / denominator')
        if isinstance(n,ast.Subscript) and isinstance(n.value,(ast.List,ast.Tuple)) and isinstance(n.slice,ast.Constant) and type(n.slice.value) is int and not -len(n.value.elts)<=n.slice.value<len(n.value.elts):
            add(n,'DBG-INDEX','Literal index out of range','This index is outside the literal collection. It raises IndexError if reached.','Use a valid index or check the collection length first.')
        if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Constant) and n.value.value is None and not hasattr(None,n.attr):
            add(n,'DBG-NONE','Attribute access on None','This access raises AttributeError if reached.','Obtain the intended object and handle its missing-value case before accessing the attribute.')
        if isinstance(n,ast.Compare) and any(isinstance(op,(ast.Is,ast.IsNot)) and any(isinstance(v,ast.Constant) and type(v.value) in (str,int,float) for v in (left,right)) for left,op,right in zip([n.left,*n.comparators],n.ops,n.comparators)):
            add(n,'DBG-IDENTITY','Identity used for a value comparison','is checks object identity, not value equality. Results can depend on object reuse.','Use == or != for equal values. Keep is None and singleton identity checks.',example='if value == expected:\n    ...')
        if isinstance(n,(ast.For,ast.AsyncFor,ast.While)) and nested_loop(n.body):
            add(n,'OPT-NESTED','Review nested-loop cost','Independent nested loops can require O(n × m) iterations. This is a structural estimate, not a benchmark.','For repeated key matching, build a dictionary or set once. Preserve duplicates, ordering and hashability requirements.','Performance','by_id = {row.id: row for row in rows}\nfor item in items:\n    match = by_id.get(item.id)','Conditional')
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {'sum','any','all','min','max'} and n.args and isinstance(n.args[0],ast.ListComp):
            candidate=copy.deepcopy(n);old=candidate.args[0];candidate.args[0]=ast.GeneratorExp(elt=old.elt,generators=old.generators)
            add(n,'OPT-GENERATOR','Avoid an intermediate list','The comprehension materialises a whole list. A generator can reduce extra memory from O(n) to O(1); any/all can also short-circuit.','Use streaming evaluation only when it preserves required side effects and error timing. Benchmark representative inputs.','Performance',ast.unparse(candidate),'Conditional')
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='pop' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value==0:
            add(n,'OPT-QUEUE','Review front-removal cost','For a list, pop(0) shifts remaining elements in O(n). Repeated removal can be quadratic.','Confirm the receiver is a list. For a FIFO queue without list-specific operations, use deque.popleft().','Performance','from collections import deque\nqueue = deque(items)\nitem = queue.popleft()','Conditional')
        if isinstance(n,ast.Compare):
            for op,value in zip(n.ops,n.comparators):
                if isinstance(op,(ast.In,ast.NotIn)) and isinstance(value,ast.List) and len(value.elts)>=4:
                    add(n,'OPT-MEMBERSHIP','Consider a set for repeated membership','List membership scans up to n values. A prebuilt set provides average O(1) lookup with build and memory costs.','For frequent checks with hashable values, build the set once outside the loop. Unhashable search values and altered equality semantics make this conditional.','Performance','allowed = set(values)  # build once; values must be hashable\nif item in allowed:\n    ...','Conditional')
        # Literal-only checks: inspect syntax, never evaluate submitted expressions.
        if isinstance(n,ast.Subscript) and isinstance(n.ctx,ast.Load):
            index=n.slice.value if isinstance(n.slice,ast.Constant) else None
            if isinstance(n.slice,ast.UnaryOp) and isinstance(n.slice.op,ast.USub) and isinstance(n.slice.operand,ast.Constant) and type(n.slice.operand.value) is int:
                index=-n.slice.operand.value
            length=len(n.value.elts) if isinstance(n.value,(ast.List,ast.Tuple)) else len(n.value.value) if isinstance(n.value,ast.Constant) and isinstance(n.value.value,(str,bytes)) else None
            if length is not None and type(index) is int and not -length<=index<length:
                if not any(f['rule_id']=='DBG-INDEX' and f['line']==n.lineno and f['column']==n.col_offset+1 for f in out):
                    add(n,'DBG-INDEX','Literal index out of range','This index is outside the literal sequence. It raises IndexError if reached.','Use a valid index or check the sequence length first.')
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Constant):
            add(n,'DBG-CALL','Literal value is not callable','This literal cannot be called as a function. It raises TypeError if reached.','Check for a missing operator or comma, or call the intended function instead.')
        if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add) and isinstance(n.left,ast.Constant) and isinstance(n.right,ast.Constant):
            a,b=type(n.left.value),type(n.right.value)
            if (a is str and b in (int,float,complex,bool,bytes)) or (b is str and a in (int,float,complex,bool,bytes)):
                add(n,'DBG-TYPE','Incompatible literal addition','These literal types cannot be added in Python. It raises TypeError if reached.','Convert to the intended common type explicitly, or use an f-string for formatting.')
        if isinstance(n,ast.Assert) and isinstance(n.test,ast.Tuple) and n.test.elts:
            add(n,'DBG-ASSERT','Tuple assertion always passes','A nonempty tuple is truthy, so assert (condition, message) does not test the condition.','Use assert condition, message without wrapping the pair in parentheses.')
    # Locations are part of the identity, so several issues on one line remain distinct.
    for f in out:
        f['id']=f"{f['rule_id']}@{name}:{f['line']}:{f['column']}"
    return out
