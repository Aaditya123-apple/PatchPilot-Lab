"""Python static analysis: import resolution, lightweight taint tracking and the rule checks.

Taint tracking is intra-procedural and deliberately simple. Values from web requests
(`request.args`, `request.GET`, route parameters, ...) are "web" tainted; `input()` and
`sys.argv` are "local" tainted. Taint flows through assignments, string building, calls and
attribute access, and stops at sanitizers such as int(), escape() or secure_filename().
Path, redirect, SSRF and similar sinks only fire on web taint, so command-line tools that
open the file named on their command line are not flagged.
"""

from __future__ import annotations

import ast
import re
import stat
from typing import Iterator

from .models import Severity
from .rules import RULES

# ---------------------------------------------------------------- shared helpers


def call_name(func: ast.AST) -> str:
    """Dotted name of a call target as written, e.g. 'subprocess.run' or 'conn.execute'."""
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def is_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return any(isinstance(side, (ast.Constant, ast.JoinedStr, ast.BinOp)) for side in (node.left, node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return isinstance(node, ast.Call) and call_name(node.func) in {"list", "dict", "set"} and not node.args


_SECRET_NAME = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|secret|secret_key|api_key|apikey|access_key|private_key|"
    r"auth_token|access_token|token|credentials?|client_secret)$"
)
_SAFE_SECRET_VALUE = re.compile(r"^(?:changeme|example|placeholder|xxx+|\*+|<.*>|\$\{.*\}|test|none|null|todo)$", re.I)


def snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def is_secret_name(name: str | None) -> bool:
    return bool(name) and bool(_SECRET_NAME.search(snake(name)))  # type: ignore[arg-type]


def looks_like_secret(value: object, min_len: int = 6) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    return len(v) >= min_len and " " not in v and not _SAFE_SECRET_VALUE.match(v)


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        return node.slice.value  # e.g. request.form['password']
    return None


def high_entropy(value: str) -> bool:
    """Random-looking token: long, mixes letters and digits, no spaces or path/URL punctuation."""
    if len(value) < 20 or re.search(r"[\s/\\.:]", value):
        return False
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return classes >= 3 or (classes == 2 and len(set(value)) >= 12 and re.search(r"\d", value) is not None)


def secret_target(targets: list[ast.AST], value: ast.AST | None) -> str | None:
    """Name of a secret-like target assigned a literal credential, else None."""
    if not (isinstance(value, ast.Constant) and looks_like_secret(value.value)):
        return None
    for t in targets:
        name = _target_name(t)
        if not name:
            continue
        last = snake(name).split("_")[-1]
        if is_secret_name(name) and last != value.value.lower():  # type: ignore[union-attr]
            return name
        if last in ("key", "keys") and high_entropy(value.value):  # type: ignore[arg-type]
            return name
    return None


def _names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _names(elt)]
    if isinstance(target, ast.Starred):
        return _names(target.value)
    return []


_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_BINDING_TYPES = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor, ast.comprehension,
                  ast.withitem, ast.NamedExpr)


def index_scopes(tree: ast.AST) -> tuple[dict[ast.AST, list[ast.AST]], list[ast.AST]]:
    """One pass over the tree: nodes grouped by the function (or module) scope they belong to, plus imports."""
    scopes: dict[ast.AST, list[ast.AST]] = {tree: []}
    imports: list[ast.AST] = []
    stack = [(child, tree) for child in ast.iter_child_nodes(tree)]
    while stack:
        node, scope = stack.pop()
        scopes[scope].append(node)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.append(node)
        if isinstance(node, _SCOPE_TYPES):
            scopes[node] = []
            scope = node
        stack.extend((child, scope) for child in ast.iter_child_nodes(node))
    return scopes, imports


def scope_nodes(root: ast.AST) -> Iterator[ast.AST]:
    """Nodes in root's own scope, without descending into nested functions or lambdas."""
    stack = list(ast.iter_child_nodes(root))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))


# ---------------------------------------------------------------- import resolution

STAR_EXPORTS = {
    "Crypto.Cipher": {"AES", "DES", "DES3", "ARC2", "ARC4", "Blowfish", "CAST", "XOR"},
    "Cryptodome.Cipher": {"AES", "DES", "DES3", "ARC2", "ARC4", "Blowfish", "CAST"},
    "Crypto.Hash": {"MD2", "MD4", "MD5", "SHA", "SHA1"},
    "flask": {"request", "redirect", "render_template_string", "make_response", "send_file", "Markup"},
    "os": {"system", "popen", "remove", "unlink", "chmod"},
    "subprocess": {"call", "run", "Popen", "check_call", "check_output", "getoutput"},
    "pickle": {"load", "loads"},
}


class ImportMap:
    """Maps local names to the fully qualified names they were imported as."""

    def __init__(self, tree: ast.AST, import_nodes: list[ast.AST] | None = None) -> None:
        self.aliases: dict[str, str] = {}
        self.star: list[str] = []
        self.modules: set[str] = set()
        for node in import_nodes if import_nodes is not None else ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.modules.add(a.name.split(".")[0])
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        head = a.name.split(".")[0]
                        self.aliases.setdefault(head, head)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self.modules.add(node.module.split(".")[0])
                for a in node.names:
                    if a.name == "*":
                        self.star.append(node.module)
                    else:
                        self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def resolve(self, dotted: str) -> str:
        if not dotted:
            return ""
        head, _, rest = dotted.partition(".")
        base = self.aliases.get(head)
        if base is None:
            for mod in self.star:
                if head in STAR_EXPORTS.get(mod, ()):
                    base = f"{mod}.{head}"
                    break
        if base is None:
            return dotted
        return f"{base}.{rest}" if rest else base


# ---------------------------------------------------------------- rule tables

WEB_ATTRS = {
    "args", "form", "values", "json", "files", "cookies", "headers", "data", "stream", "GET", "POST",
    "FILES", "COOKIES", "META", "body", "query_params", "path_params", "get_json", "get_data", "query_string",
}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "websocket", "api_route", "api_view"}
SANITIZERS = {
    "int", "float", "bool", "len", "escape", "quote", "quote_plus", "secure_filename", "basename", "abs",
    "round", "hash", "escape_filter_chars", "escape_dn_chars", "hexdigest", "uuid4", "isdigit", "isalnum",
    "literal_eval", "safe_join", "normpath_safe",
}
SHELL_FUNCS = {"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4", "commands.getoutput", "commands.getstatusoutput",
               "subprocess.getoutput", "subprocess.getstatusoutput"}
SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen"}
DESERIALIZE = {
    "pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads", "_pickle.loads",
    "marshal.load", "marshal.loads", "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads",
    "shelve.open", "jsonpickle.decode", "jsonpickle.loads", "pandas.read_pickle", "joblib.load",
}
WEAK_HASH = {
    "hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD2.new", "Crypto.Hash.MD4.new", "Crypto.Hash.MD5.new",
    "Crypto.Hash.SHA.new", "Crypto.Hash.SHA1.new", "Cryptodome.Hash.MD5.new", "Cryptodome.Hash.SHA1.new",
    "cryptography.hazmat.primitives.hashes.MD5", "cryptography.hazmat.primitives.hashes.SHA1",
}
WEAK_HASH_NAMES = {"md5", "sha1", "md4", "md2", "sha"}
FAST_HASHES = {"hashlib.md5", "hashlib.sha1", "hashlib.sha224", "hashlib.sha256", "hashlib.sha384",
               "hashlib.sha512", "hashlib.blake2b", "hashlib.blake2s", "hashlib.new"}
WEAK_CIPHERS = {"DES", "DES3", "ARC2", "ARC4", "Blowfish", "CAST", "XOR"}
WEAK_CRYPTOGRAPHY = {"ARC4", "Blowfish", "IDEA", "CAST5", "SEED", "TripleDES"}
WEAK_CURVES = {"SECP192R1", "SECT163K1", "SECT163R2"}
PATH_FUNCS = {
    "open", "io.open", "codecs.open", "os.open", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.replace", "os.listdir", "os.makedirs", "os.mkdir", "shutil.rmtree", "shutil.copy",
    "shutil.copyfile", "shutil.copy2", "shutil.move", "pathlib.Path", "flask.send_file", "send_file",
    "tarfile.open", "zipfile.ZipFile",
}
REDIRECTS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
URL_OPENERS = {"urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request", "urllib.urlopen",
               "urllib.urlretrieve", "urllib2.urlopen", "urllib.request.URLopener", "urllib.request.FancyURLopener"}
REGEX_FUNCS = {f"re.{f}" for f in ("compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split")}
LOG_LEVELS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log", "fatal"}
LOGGER_NAMES = {"logging", "logger", "log", "_logger", "_log", "LOGGER", "LOG"}
XSS_SINKS = {"render_template_string", "Markup", "mark_safe", "SafeString", "make_response", "HttpResponse",
             "Response", "HTMLResponse"}
MARK_SAFE = {"Markup", "mark_safe", "SafeString", "SafeText"}
XML_STDLIB = ("xml.etree.ElementTree.", "xml.etree.cElementTree.", "xml.dom.minidom.", "xml.dom.pulldom.",
              "xml.sax.", "xml.dom.expatbuilder.")
XML_FUNCS = {"parse", "fromstring", "XML", "XMLParser", "iterparse", "XMLID", "fromstringlist", "parseString",
             "make_parser", "create_parser"}
LXML_FUNCS = {"parse", "fromstring", "XML", "iterparse", "RestrictedElement", "GlobalParserTLS", "getDefaultParser"}
INSECURE_TLS = {
    "ssl.CERT_NONE", "ssl.PROTOCOL_SSLv2", "ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1",
    "ssl.TLSVersion.SSLv3", "ssl.TLSVersion.TLSv1", "ssl.TLSVersion.TLSv1_1", "OpenSSL.SSL.SSLv2_METHOD",
    "OpenSSL.SSL.SSLv3_METHOD", "OpenSSL.SSL.TLSv1_METHOD", "OpenSSL.SSL.TLSv1_1_METHOD",
}
RANDOM_FUNCS = {f"random.{f}" for f in ("random", "randint", "randrange", "choice", "choices", "getrandbits",
                                         "sample", "uniform", "shuffle")}
SECURITY_CONTEXT = re.compile(
    r"(?:^|_)(?:token|secret|password|passwd|pwd|session|session_id|nonce|salt|otp|csrf|key|api_key|auth|reset|"
    r"verification|random_string|random_str|pin|uid|uuid|code)(?:_|$)"
)
WEB_FRAMEWORKS = {"flask", "django", "werkzeug", "starlette", "fastapi", "bottle", "tornado", "aiohttp"}
PASSWORD_WORD = re.compile(r"(?:^|_)(?:password|passwd|pwd|passphrase|pass)$")
TEMP_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm")
STAT_VALUES = {f"stat.{n}": getattr(stat, n) for n in dir(stat) if n.startswith("S_I")}


def _fold_mode(node: ast.AST) -> int | None:
    """Evaluate a chmod mode made of int literals and stat.S_* constants combined with |."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Attribute):
        return STAT_VALUES.get(call_name(node))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.BitOr, ast.Add)):
        left, right = _fold_mode(node.left), _fold_mode(node.right)
        if left is not None and right is not None:
            return left | right
    return None


def _const_bytes(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
        return True
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult) and (
        _const_bytes(node.left) or _const_bytes(node.right)
    )


# ---------------------------------------------------------------- analyzer


class PythonAnalyzer(ast.NodeVisitor):
    """Walks a module once and records (line, rule_id, severity override) hits."""

    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.scope_index, import_nodes = index_scopes(tree)
        self.imports = ImportMap(tree, import_nodes)
        self.hits: dict[tuple[int, str], Severity] = {}
        self._scopes: list[tuple[set[str], set[str], set[str], set[str], bool, str]] = []
        self.has_sources = True
        self._async: list[bool] = []

    # ---- bookkeeping
    def run(self) -> dict[tuple[int, str], Severity | None]:
        tw, ta, dyn, consts = self.scope_taint(self.tree, set(), set(), False)
        self._scopes.append((tw, ta, dyn, consts, False, ""))
        self.visit(self.tree)
        return self.hits

    def add(self, node: ast.AST, rule: str, severity: Severity | None = None) -> None:
        """Record a hit; if a line triggers a rule twice, keep the higher severity."""
        key = (getattr(node, "lineno", 1), rule)
        effective = severity or RULES[rule].severity
        prev = self.hits.get(key)
        if prev is None or effective.rank > prev.rank:
            self.hits[key] = effective

    def resolve(self, node: ast.AST) -> str:
        return self.imports.resolve(call_name(node))

    @property
    def web(self) -> set[str]:
        return self._scopes[-1][0]

    @property
    def local(self) -> set[str]:
        return self._scopes[-1][1]

    @property
    def dynamic(self) -> set[str]:
        return self._scopes[-1][2]

    @property
    def consts(self) -> set[str]:
        return self._scopes[-1][3]

    @property
    def in_route(self) -> bool:
        return self._scopes[-1][4]

    @property
    def func_name(self) -> str:
        return self._scopes[-1][5]

    def const_bytes(self, node: ast.AST | None) -> bool:
        return node is not None and (_const_bytes(node) or (isinstance(node, ast.Name) and node.id in self.consts))

    def is_static(self, e: ast.AST | None) -> bool:
        """True if the expression is built only from literals and names that only hold literals."""
        if e is None:
            return True
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.Name):
            return e.id in self.consts
        if isinstance(e, ast.BinOp):
            return self.is_static(e.left) and self.is_static(e.right)
        if isinstance(e, ast.JoinedStr):
            return all(self.is_static(v.value) for v in e.values if isinstance(v, ast.FormattedValue))
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
            return all(self.is_static(x) for x in e.elts)
        if isinstance(e, ast.Dict):
            return all(self.is_static(v) for v in e.values)
        if isinstance(e, ast.Starred):
            return self.is_static(e.value)
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format":
            return self.is_static(e.func.value) and all(self.is_static(a) for a in e.args) and all(
                self.is_static(k.value) for k in e.keywords
            )
        return False

    @property
    def in_async(self) -> bool:
        return bool(self._async) and self._async[-1]

    # ---- taint
    def _is_request(self, node: ast.AST) -> bool:
        name = call_name(node)
        return name.split(".")[-1] in ("request", "req") if name else False

    def tainted(self, e: ast.AST | None, names: set[str], local: bool) -> bool:
        if e is None:
            return False
        if isinstance(e, ast.Name):
            return e.id in names
        if isinstance(e, ast.Attribute):
            if e.attr in WEB_ATTRS and self._is_request(e.value):
                return True
            if local and self.resolve(e) == "sys.argv":
                return True
            return self.tainted(e.value, names, local)
        if isinstance(e, ast.Subscript):
            return self.tainted(e.value, names, local)
        if isinstance(e, ast.Call):
            name = self.resolve(e.func)
            if name.rsplit(".", 1)[-1] in SANITIZERS:
                return False
            if local and name in ("input", "raw_input"):
                return True
            if isinstance(e.func, ast.Attribute) and self.tainted(e.func.value, names, local):
                return True
            return any(self.tainted(a, names, local) for a in e.args) or any(
                self.tainted(k.value, names, local) for k in e.keywords
            )
        if isinstance(e, ast.BinOp):
            return self.tainted(e.left, names, local) or self.tainted(e.right, names, local)
        if isinstance(e, ast.JoinedStr):
            return any(self.tainted(v.value, names, local) for v in e.values if isinstance(v, ast.FormattedValue))
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
            return any(self.tainted(x, names, local) for x in e.elts)
        if isinstance(e, ast.Dict):
            return any(self.tainted(v, names, local) for v in e.values)
        if isinstance(e, ast.IfExp):
            return self.tainted(e.body, names, local) or self.tainted(e.orelse, names, local)
        if isinstance(e, ast.BoolOp):
            return any(self.tainted(v, names, local) for v in e.values)
        if isinstance(e, (ast.Starred, ast.NamedExpr, ast.Await)):
            return self.tainted(e.value, names, local)
        return False

    def is_route(self, fn: ast.AST) -> bool:
        for d in getattr(fn, "decorator_list", []):
            target = d.func if isinstance(d, ast.Call) else d
            if call_name(target).split(".")[-1] in ROUTE_DECORATORS and "." in call_name(target):
                return True
        return False

    def scope_taint(
        self, root: ast.AST, web: set[str], local: set[str], route: bool
    ) -> tuple[set[str], set[str], set[str], set[str]]:
        tw, ta, dyn, consts = set(web), set(local), set(), set()
        nonconst: set[str] = set()  # a name is constant only if every binding of it is a literal
        track = self.has_sources
        if route and isinstance(root, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = root.args
            params = {p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]} - {"self", "cls", "request", "req"}
            tw |= params
            ta |= params
        nodes = [n for n in self.scope_index.get(root, ()) if isinstance(n, _BINDING_TYPES)]
        if not nodes:
            return tw, ta, dyn, consts
        for _ in range(5 if track else 1):
            before = (len(tw), len(ta), len(dyn))
            for n in nodes:
                pairs: list[tuple[ast.AST, ast.AST]] = []
                if isinstance(n, ast.Assign):
                    pairs = [(t, n.value) for t in n.targets]
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    pairs = [(n.target, n.value)]
                elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                    pairs = [(n.target, n.iter)]
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    pairs = [(n.optional_vars, n.context_expr)]
                elif isinstance(n, ast.NamedExpr):
                    pairs = [(n.target, n.value)]
                for target, value in pairs:
                    names = _names(target)
                    if not names:
                        continue
                    if track and self.tainted(value, tw, False):
                        tw.update(names)
                    if track and self.tainted(value, ta, True):
                        ta.update(names)
                    if _const_bytes(value) and not isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension, ast.withitem)):
                        consts.update(names)
                    else:
                        nonconst.update(names)
                    if is_dynamic_string(value) or (isinstance(value, ast.Name) and value.id in dyn):
                        dyn.update(names)
                    elif isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add) and isinstance(n.target, ast.Name):
                        if isinstance(value, (ast.Name, ast.JoinedStr, ast.BinOp)) and not is_str(value):
                            dyn.update(names)
            if (len(tw), len(ta), len(dyn)) == before:
                break
        return tw, ta, dyn, consts - nonconst

    def tw(self, e: ast.AST | None) -> bool:
        return self.has_sources and self.tainted(e, self.web, False)

    def ta(self, e: ast.AST | None) -> bool:
        return self.has_sources and self.tainted(e, self.local, True)

    # ---- scopes
    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        self._check_defaults(node)
        parent = self._scopes[-1]
        route = self.is_route(node)
        tw, ta, dyn, consts = self.scope_taint(node, parent[0], parent[1], route)
        self._scopes.append((tw, ta, dyn, consts, route, node.name))
        self._async.append(is_async)
        self.generic_visit(node)
        self._async.pop()
        self._scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node, True)

    def _check_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        a = node.args
        positional = [*a.posonlyargs, *a.args]
        pairs = list(zip(positional[len(positional) - len(a.defaults):], a.defaults))
        pairs += [(arg, d) for arg, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None]
        for arg, d in pairs:
            if is_mutable_default(d):
                self.add(d, "PY010")
            if isinstance(d, ast.Constant) and is_secret_name(arg.arg) and looks_like_secret(d.value):
                self.add(d, "PY008")
        self._check_toctou(node)

    def _check_toctou(self, fn: ast.AST) -> None:
        calls = [n for n in self.scope_index.get(fn, ()) if isinstance(n, ast.Call) and n.args]
        checked = {ast.dump(n.args[0]) for n in calls
                   if call_name(n.func) in ("os.path.exists", "os.path.isfile", "os.access", "path.exists", "path.isfile")}
        if not checked:
            return
        for n in calls:
            if self.resolve(n.func) in ("open", "io.open", "os.open") and ast.dump(n.args[0]) in checked:
                self.add(n, "PY045")

    # ---- statements
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.add(node, "PY009")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        it = node.iter
        if (isinstance(it, ast.Call) and call_name(it.func) == "range" and len(it.args) == 1
                and isinstance(it.args[0], ast.Call) and call_name(it.args[0].func) == "len"):
            self.add(node, "PY011")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._assignment(node, node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._assignment(node, [node.target], node.value)
        self.generic_visit(node)

    def _assignment(self, node: ast.AST, targets: list[ast.AST], value: ast.AST) -> None:
        if secret_target(targets, value):
            self.add(node, "PY008")
        for t in targets:
            if isinstance(t, ast.Attribute):
                if t.attr == "check_hostname" and is_const(value, False):
                    self.add(node, "PY028")
                if t.attr == "verify" and is_const(value, False):
                    self.add(node, "PY006")
            if isinstance(t, ast.Subscript) and self.tw(value):
                header = str(t.slice.value).lower() if isinstance(t.slice, ast.Constant) else ""
                if header == "location":
                    self.add(node, "PY017")
                elif isinstance(t.value, ast.Attribute) and t.value.attr == "headers":
                    self.add(node, "PY024")
        if is_str(value) and value.value.startswith(TEMP_PREFIXES):  # type: ignore[attr-defined]
            self.add(node, "PY034")
        if self._random_call(value) and any(SECURITY_CONTEXT.search(snake(n)) for t in targets for n in _names(t)):
            self.add(node, "PY030")

    def visit_Return(self, node: ast.Return) -> None:
        v = node.value
        if v is not None:
            if self._random_call(v) and SECURITY_CONTEXT.search(snake(self.func_name)):
                self.add(node, "PY030")
            if self.in_route:
                if any(isinstance(c, ast.Call) and self.resolve(c.func).startswith("traceback.format_") for c in ast.walk(v)):
                    self.add(node, "PY043")
                if isinstance(v, (ast.JoinedStr, ast.BinOp, ast.Name)) and self.tw(v):
                    self.add(node, "PY023", Severity.MEDIUM)
        self.generic_visit(node)

    def _random_call(self, node: ast.AST) -> bool:
        return any(isinstance(c, ast.Call) and self.resolve(c.func) in RANDOM_FUNCS for c in ast.walk(node))

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        for op, right in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Is, ast.IsNot)):
                lit = [x for x in (node.left, right) if isinstance(x, ast.Constant)
                       and x.value is not None and not isinstance(x.value, bool) and x.value is not Ellipsis]
                if lit:
                    self.add(node, "PY044")
            if isinstance(op, (ast.Eq, ast.NotEq)):
                names = [_target_name(x) for x in operands]
                consts = [x for x in operands if isinstance(x, ast.Constant) and looks_like_secret(x.value, 4)]
                if consts and any(n and PASSWORD_WORD.search(snake(n)) for n in names):
                    self.add(node, "PY008")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            name = self.resolve(node)
            if name in INSECURE_TLS:
                self.add(node, "PY028")
            if name.endswith(".MODE_ECB") and name.split(".")[0] in ("Crypto", "Cryptodome"):
                self.add(node, "PY026")
        self.generic_visit(node)

    # ---- calls
    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call) -> None:  # noqa: C901 - one table-driven dispatcher
        name = self.resolve(node.func)
        parts = name.split(".")
        last, root = parts[-1], parts[0]
        owner = parts[-2] if len(parts) > 1 else ""
        args = node.args
        first = args[0] if args else None
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        values = [*args, *kw.values()]
        any_web = self.has_sources and any(self.tw(v) for v in values)
        any_local = self.has_sources and any(self.ta(v) for v in values)
        mods = self.imports.modules

        # code execution
        if name in ("eval", "exec") and not (is_str(first) and not any_local):
            self.add(node, "PY001")
        if name == "compile" and first is not None and self.ta(first):
            self.add(node, "PY001")

        # commands
        shell = is_const(kw.get("shell"), True)
        if name in SHELL_FUNCS or (root == "subprocess" and shell):
            self.add(node, "PY002", Severity.LOW if is_str(first) else None)
        elif root == "subprocess" and last in SUBPROCESS and first is not None and self.ta(first):
            self.add(node, "PY002", None if is_str(first) or not isinstance(first, (ast.List, ast.Tuple)) else Severity.MEDIUM)
        if name in SHELL_FUNCS or root == "subprocess" or last == "system":
            cmd = first.value if is_str(first) else None  # type: ignore[union-attr]
            if isinstance(first, (ast.List, ast.Tuple)):
                cmd = " ".join(e.value for e in first.elts if is_str(e))  # type: ignore[attr-defined]
            if cmd and "*" in cmd and re.match(r"\s*(?:\S*/)?(?:chown|chmod|tar|rsync)\b", cmd):
                self.add(node, "PY048")

        # deserialization / parsing
        if name in DESERIALIZE:
            self.add(node, "PY003")
        if name == "torch.load" and not is_const(kw.get("weights_only"), True):
            self.add(node, "PY003")
        if name == "numpy.load" and is_const(kw.get("allow_pickle"), True):
            self.add(node, "PY003")
        if name == "yaml.unsafe_load":
            self.add(node, "PY004")
        if name == "yaml.load":
            loader = kw.get("Loader") or (args[1] if len(args) > 1 else None)
            if not (loader is not None and "Safe" in self.resolve(loader)):
                self.add(node, "PY004")
        if any(name.startswith(p) for p in XML_STDLIB) and last in XML_FUNCS:
            self.add(node, "PY025")
        if name.startswith("lxml.etree."):
            if last == "XMLParser" and not is_const(kw.get("resolve_entities"), False):
                self.add(node, "PY025", Severity.HIGH)
            elif last in LXML_FUNCS:
                self.add(node, "PY025")
        if last in ("extractall", "extract") and "tarfile" in mods and "filter" not in kw:
            self.add(node, "PY037")

        # hashing and crypto
        no_security = is_const(kw.get("usedforsecurity"), False)
        if name in WEAK_HASH and not no_security:
            self.add(node, "PY005")
        if name == "hashlib.new" and is_str(first) and first.value.lower().replace("-", "") in WEAK_HASH_NAMES and not no_security:  # type: ignore[union-attr]
            self.add(node, "PY005")
        if name in FAST_HASHES and any(
            (isinstance(x, ast.Name) and PASSWORD_WORD.search(snake(x.id)))
            or (isinstance(x, ast.Attribute) and PASSWORD_WORD.search(snake(x.attr)))
            for v in args for x in ast.walk(v)
        ):
            self.add(node, "PY039")
        if name in ("hashlib.pbkdf2_hmac", "hashlib.scrypt"):
            salt = kw.get("salt") or (args[2] if name == "hashlib.pbkdf2_hmac" and len(args) > 2 else None)
            if salt is not None and _const_bytes(salt):
                self.add(node, "PY040")
        cipher_mod = len(parts) >= 4 and parts[0] in ("Crypto", "Cryptodome") and parts[1] == "Cipher"
        if cipher_mod and last == "new":
            if parts[2] in WEAK_CIPHERS:
                self.add(node, "PY026")
            elif parts[2] == "AES" and len(args) == 1 and "mode" not in kw:
                self.add(node, "PY026", Severity.MEDIUM)
            if self.const_bytes(first):
                self.add(node, "PY041")
            iv = kw.get("iv") or kw.get("IV") or (args[2] if len(args) > 2 else None)
            if self.const_bytes(iv):
                self.add(node, "PY038")
        if name.startswith("cryptography.hazmat.primitives.ciphers."):
            if (owner == "algorithms" and last in WEAK_CRYPTOGRAPHY) or (owner == "modes" and last == "ECB"):
                self.add(node, "PY026")
            if owner == "modes" and self.const_bytes(first):
                self.add(node, "PY038")
            if owner == "algorithms" and self.const_bytes(first):
                self.add(node, "PY041")
        if name in ("jwt.encode", "jwt.decode") and len(args) > 1 and is_str(args[1]):
            self.add(node, "PY041")
        if name == "hmac.new" and self.const_bytes(first):
            self.add(node, "PY041")
        if name.endswith(("RSA.generate", "DSA.generate")) and is_const_int(first):
            size = first.value  # type: ignore[union-attr]
            if size < 2048:
                self.add(node, "PY027", None if size < 1024 else Severity.MEDIUM)
        if name.endswith(("rsa.generate_private_key", "dsa.generate_private_key")):
            key = kw.get("key_size") or (args[1] if "rsa." in name and len(args) > 1 else first if "dsa." in name else None)
            if is_const_int(key) and key.value < 2048:  # type: ignore[union-attr]
                self.add(node, "PY027", None if key.value < 1024 else Severity.MEDIUM)  # type: ignore[union-attr]
        if name.endswith("ec.generate_private_key") and any(
            isinstance(x, (ast.Call, ast.Attribute)) and call_name(x.func if isinstance(x, ast.Call) else x).split(".")[-1] in WEAK_CURVES
            for x in values
        ):
            self.add(node, "PY027")
        if name in ("jwt.decode", "jose.jwt.decode"):
            options = kw.get("options")
            off = isinstance(options, ast.Dict) and any(
                is_str(k) and k.value == "verify_signature" and is_const(v, False)  # type: ignore[union-attr]
                for k, v in zip(options.keys, options.values)
            )
            algs = kw.get("algorithms")
            none_alg = isinstance(algs, (ast.List, ast.Tuple)) and any(is_str(e) and e.value.lower() == "none" for e in algs.elts)  # type: ignore[attr-defined]
            if off or is_const(kw.get("verify"), False) or none_alg:
                self.add(node, "PY029")
        if name in ("python_jwt.process_jwt", "jwt.process_jwt") or (last == "process_jwt" and "python_jwt" in mods):
            self.add(node, "PY029")
        for key in ("FilterExpression", "KeyConditionExpression", "ConditionExpression"):
            if key in kw and (is_dynamic_string(kw[key]) or self.ta(kw[key])):
                self.add(node, "PY050")
        if last in ("find", "find_one", "find_one_and_update", "aggregate") and "pymongo" in mods and first is not None:
            where_keys = [k for d in ast.walk(first) if isinstance(d, ast.Dict) for k in d.keys]
            if any(is_str(k) and k.value == "$where" for k in where_keys):  # type: ignore[union-attr]
                self.add(node, "PY050")
        if name in RANDOM_FUNCS and any(isinstance(k, str) and SECURITY_CONTEXT.search(snake(k)) for k in kw):
            self.add(node, "PY030")
        if last == "set_cookie" and self.imports.modules & WEB_FRAMEWORKS and not (
            is_const(kw.get("secure"), True) and is_const(kw.get("httponly"), True)
        ):
            self.add(node, "PY042")
        if name in ("re.sub", "re.subn", "re.compile") and is_str(first) and "<script" in first.value.lower():  # type: ignore[union-attr]
            self.add(node, "PY051")

        # TLS / transport
        if name == "ssl._create_unverified_context":
            self.add(node, "PY028")
        if name == "ssl.wrap_socket":
            self.add(node, "PY028", Severity.MEDIUM)
        if last == "set_missing_host_key_policy" and any(
            self.resolve(v.func if isinstance(v, ast.Call) else v).endswith(("AutoAddPolicy", "WarningPolicy")) for v in args
        ):
            self.add(node, "PY028")
        if root in ("requests", "httpx") and is_const(kw.get("verify"), False):
            self.add(node, "PY006")
        if name in ("telnetlib.Telnet", "ftplib.FTP"):
            self.add(node, "PY031")
        if name in ("wsgiref.handlers.CGIHandler", "twisted.web.twcgi.CGIScript", "twisted.web.twcgi.CGIDirectory"):
            self.add(node, "PY046")
        if root == "requests" and last in HTTP_VERBS and len(parts) == 2 and "timeout" not in kw:
            self.add(node, "PY036")

        # binding, permissions, temp files, debug
        if last == "bind" and isinstance(first, ast.Tuple) and first.elts and is_str(first.elts[0]) \
                and first.elts[0].value in ("0.0.0.0", "::"):  # type: ignore[attr-defined]
            self.add(node, "PY032")
        if last == "run" and is_str(kw.get("host")) and kw["host"].value == "0.0.0.0":  # type: ignore[attr-defined]
            self.add(node, "PY032")
        if last == "run" and is_const(kw.get("debug"), True):
            self.add(node, "PY014")
        if name in ("os.chmod", "os.fchmod", "os.lchmod") or (last == "chmod" and root not in ("os",)):
            mode_node = args[1] if name.startswith("os.") and len(args) > 1 else (first if not name.startswith("os.") else None)
            mode_node = kw.get("mode", mode_node)
            mode = _fold_mode(mode_node) if mode_node is not None else None
            if mode is not None:
                if mode & stat.S_IWOTH:
                    self.add(node, "PY033", Severity.HIGH)
                elif mode & stat.S_IXGRP or mode & stat.S_IWGRP:
                    self.add(node, "PY033")
        if name == "tempfile.mktemp":
            self.add(node, "PY015")
        if any(is_str(v) and v.value.startswith(TEMP_PREFIXES) for v in values):  # type: ignore[attr-defined]
            self.add(node, "PY034")

        # async performance
        if self.in_async and name == "time.sleep":
            self.add(node, "PY012")
        if self.in_async and (name in URL_OPENERS or (root == "requests" and last in HTTP_VERBS)):
            self.add(node, "PY013")

        # secrets in keyword arguments
        for k in node.keywords:
            if k.arg and is_secret_name(k.arg) and isinstance(k.value, ast.Constant) and looks_like_secret(k.value.value, 4):
                self.add(node, "PY008")

        # SQL
        if last in ("execute", "executemany", "executescript") and first is not None and (
            is_dynamic_string(first) or self.ta(first) or (isinstance(first, ast.Name) and first.id in self.dynamic)
        ):
            self.add(node, "PY007")
        if "django" in mods and (last in ("raw", "RawSQL")) and first is not None and not is_str(first):
            self.add(node, "PY007", None if is_dynamic_string(first) or self.ta(first) else Severity.MEDIUM)
        if "django" in mods and last == "extra" and any(
            not is_str(e) for v in kw.values() if isinstance(v, (ast.List, ast.Tuple)) for e in v.elts
        ):
            self.add(node, "PY007", Severity.MEDIUM)

        # template engines and markup
        if name in ("jinja2.Environment", "jinja2.Template", "jinja2.environment.Environment"):
            auto = kw.get("autoescape")
            if auto is None or is_const(auto, False):
                self.add(node, "PY035")
        if name.startswith("mako.template.Template") or name == "mako.lookup.TemplateLookup":
            self.add(node, "PY035", Severity.MEDIUM)
        if last in MARK_SAFE and first is not None and not self.is_static(first) and not self.tw(first):
            self.add(node, "PY023", Severity.MEDIUM)

        # web taint sinks
        url_arg = kw.get("url") or (args[1] if last == "request" and len(args) > 1 else first)
        if name in URL_OPENERS and url_arg is not None and not is_str(url_arg) and not self.tw(url_arg):
            self.add(node, "PY047")
        if not any_web and not any_local:
            return
        if (name in PATH_FUNCS or last == "send_file") and any(self.tw(v) for v in args[:2]):
            self.add(node, "PY016")
            mode = kw.get("mode") or (args[1] if len(args) > 1 else None)
            if name in ("open", "io.open") and is_str(mode) and any(c in mode.value for c in "wax"):  # type: ignore[union-attr]
                self.add(node, "PY049")
        if last == "save" and first is not None and self.tw(first):
            self.add(node, "PY049")
        if last in REDIRECTS and (self.tw(first) or self.tw(kw.get("location")) or self.tw(kw.get("url"))):
            self.add(node, "PY017")
        if ((root in ("requests", "httpx") and last in HTTP_VERBS) or name in URL_OPENERS
                or name.startswith(("http.client.HTTP", "aiohttp."))) and self.tw(url_arg):
            self.add(node, "PY018")
        if name in REGEX_FUNCS and self.tw(first):
            self.add(node, "PY019")
        if last in ("search", "search_s", "search_st", "search_ext", "search_ext_s") and (
            mods & {"ldap", "ldap3"}) and any_web:
            self.add(node, "PY020")
        if (last == "xpath" or last == "XPath") and any_web:
            self.add(node, "PY021")
        if last in ("find", "findall", "iterfind", "findtext") and self.imports.modules & {"xml", "lxml"} and self.tw(first):
            self.add(node, "PY021")
        if last in LOG_LEVELS and (root == "logging" or owner in LOGGER_NAMES) and any_local:
            self.add(node, "PY022")
        if last in XSS_SINKS and first is not None and self.tw(first):
            self.add(node, "PY023")
        if last in ("add", "set", "__setitem__") and owner == "headers" and any_web:
            self.add(node, "PY024")


def is_const_int(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool)


_SOURCE_HINT = re.compile(
    r"\b(?:request|req)\.(?:" + "|".join(sorted(WEB_ATTRS)) + r")\b"
    r"|\binput\s*\(|sys\.argv|raw_input|@[\w.]+\.(?:route|get|post|put|delete|patch|websocket|api_route)\b"
)


def analyze_python(source: str) -> dict[tuple[int, str], Severity] | None:
    """Run every Python rule. Returns None if the source does not parse."""
    if source.startswith("﻿"):
        source = source[1:]  # byte-order mark; line numbers are unaffected
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    analyzer = PythonAnalyzer(tree)
    analyzer.has_sources = bool(_SOURCE_HINT.search(source))  # skip taint propagation when nothing is untrusted
    try:
        return analyzer.run()
    except RecursionError:  # pathologically deep nesting: keep whatever was found before the limit
        return analyzer.hits
