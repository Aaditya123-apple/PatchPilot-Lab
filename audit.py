import ast
import difflib
import json
from src.models import SourceFile
from src.scanner import static_scan, compare_findings
from src.fixers import apply_rule_fixes
from diagnostics import inspect, syntax_finding

def audit(payload):
    item = json.loads(payload)
    code, name, language = item['code'], item['name'], item['language']
    if len(code.encode('utf-8')) > 200000:
        raise ValueError('Please use a file smaller than 200 KB.')
    if not code.strip():
        raise ValueError('Paste or load some code first.')
    extra=[]; syntax_valid=True
    if language == 'python':
        try:
            tree=ast.parse(code)
            extra=inspect(tree,code,name)
        except SyntaxError as exc:
            extra=[syntax_finding(exc,code,name)]
            syntax_valid=False
    source = SourceFile(path=name, language=language, content=code)
    before = static_scan(source) if syntax_valid else []
    patch = apply_rule_fixes(code, before) if language == 'python' and syntax_valid else None
    fixed = patch.code if patch else code
    revised_valid=syntax_valid
    if not syntax_valid and language=='python':
        line=extra[0]['line']; text=code.splitlines(keepends=True)
        if "':'" in extra[0]['description'] and 0<line<=len(text) and '#' not in text[line-1]:
            text[line-1]=text[line-1].rstrip('\r\n')+':'+ ('\n' if text[line-1].endswith('\n') else '')
            proposal=''.join(text)
            try:
                ast.parse(proposal)
                fixed=proposal; revised_valid=True
                extra[0]['fix_example']=text[line-1].strip()
            except SyntaxError: pass
    after = static_scan(SourceFile(path=name, language=language, content=fixed)) if revised_valid else []
    resolved, unresolved, new = compare_findings(before, after)
    if not syntax_valid and revised_valid: resolved=[extra[0]['id']]
    diff = ''.join(difflib.unified_diff(code.splitlines(True), fixed.splitlines(True), fromfile='a/'+name, tofile='b/'+name))
    findings=[{**f.model_dump(mode='json'),'kind':f.category.value,'confidence':'Rule-based','fix_example':''} for f in before]+extra
    remaining=[{**f.model_dump(mode='json'),'kind':f.category.value} for f in after]
    if language=='python' and revised_valid: remaining+=inspect(ast.parse(fixed),fixed,name)
    elif not syntax_valid: remaining+=extra
    findings.sort(key=lambda f:({'Critical':0,'High':1,'Medium':2,'Low':3}.get(f['severity'],4),f['line']))
    return json.dumps(dict(findings=findings, remaining=remaining, patched=fixed, diff=diff, resolved=resolved, unresolved=unresolved, new=[f.model_dump(mode='json') for f in new], syntax_valid=syntax_valid, revised_valid=revised_valid, notes=(patch.notes if patch else [])+(['The missing colon was repaired in the proposal, and its syntax was checked.'] if not syntax_valid and revised_valid else [])+['Performance examples are proposals, not automatically applied or benchmarked.','Static analysis cannot detect every runtime or logic error. Run your project tests to verify behaviour.']))
