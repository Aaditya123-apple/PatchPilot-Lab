import ast
import difflib
import json
from src.models import SourceFile
from src.scanner import static_scan, compare_findings
from src.fixers import apply_rule_fixes

def audit(payload):
    item = json.loads(payload)
    code, name, language = item['code'], item['name'], item['language']
    if len(code.encode('utf-8')) > 200000:
        raise ValueError('Please use a file smaller than 200 KB.')
    if not code.strip():
        raise ValueError('Paste or load some code first.')
    if language == 'python':
        ast.parse(code)
    source = SourceFile(path=name, language=language, content=code)
    before = static_scan(source)
    patch = apply_rule_fixes(code, before) if language == 'python' else None
    fixed = patch.code if patch else code
    after = static_scan(SourceFile(path=name, language=language, content=fixed))
    resolved, unresolved, new = compare_findings(before, after)
    diff = ''.join(difflib.unified_diff(code.splitlines(True), fixed.splitlines(True), fromfile='a/'+name, tofile='b/'+name))
    return json.dumps(dict(findings=[f.model_dump(mode='json') for f in before], remaining=[f.model_dump(mode='json') for f in after], patched=fixed, diff=diff, resolved=resolved, unresolved=unresolved, new=[f.model_dump(mode='json') for f in new], notes=patch.notes if patch else ['Automatic fixes are available for supported Python rules only.']))
