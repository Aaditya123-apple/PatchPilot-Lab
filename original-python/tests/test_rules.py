# Credential-like strings in this test file are fictional scanner fixtures, never usable secrets.
"""Golden tests for the static rules: each vulnerable snippet must trigger its rule, each safe one must not."""

from __future__ import annotations

import textwrap

import pytest

from src.models import Severity, SourceFile
from src.scanner import RULES, static_scan

FLASK = "from flask import Flask, request, redirect, make_response\napp = Flask(__name__)\n"


def rules_for(code: str, path: str = "t.py") -> dict[str, Severity]:
    findings = static_scan(SourceFile(path=path, language="python", content=textwrap.dedent(code)))
    out: dict[str, Severity] = {}
    for f in findings:
        if f.rule_id not in out or f.severity.rank > out[f.rule_id].rank:
            out[f.rule_id] = f.severity
    return out


def route(body: str) -> str:
    return FLASK + "@app.route('/x')\ndef view():\n" + textwrap.indent(textwrap.dedent(body), "    ")


POSITIVE = [
    ("PY001", route("code = request.args['c']\ncompile(code, 'x', 'exec')")),
    ("PY002", "from os import system\ndef f(cmd):\n    system(cmd)\n"),
    ("PY002", "import subprocess as sp\ndef f(cmd):\n    sp.call(cmd, shell=True)\n"),
    ("PY003", "import torch\nmodel = torch.load('m.pt')\n"),
    ("PY003", "import pandas as pd\ndf = pd.read_pickle(path)\n"),
    ("PY004", "import yaml\ndata = yaml.load(text, Loader=yaml.Loader)\n"),
    ("PY005", "import hashlib\nh = hashlib.new('md5')\n"),
    ("PY007", "def f(cur, name):\n    q = 'SELECT * FROM t WHERE n = ' + name\n    cur.execute(q)\n"),
    ("PY008", "def connect():\n    return db.connect(user='app', password='NOT_A_REAL_TEST_CREDENTIAL_123')\n"),
    ("PY008", "API_KEY = 'NOT_A_REAL_TEST_CREDENTIAL_123'\n"),
    ("PY016", route("name = request.args['f']\nreturn open('files/' + name).read()")),
    ("PY017", route("return redirect(request.args.get('next'))")),
    ("PY017", route("resp = make_response('')\nresp.headers['Location'] = request.args['n']\nreturn resp")),
    ("PY018", "import requests\n" + route("return requests.get(request.args['url'], timeout=5).text")),
    ("PY019", "import re\n" + route("return str(re.search(request.args['p'], 'text'))")),
    ("PY020", "import ldap\n" + route("conn = ldap.initialize('ldap://x')\nreturn conn.search_s('dc=x', 2, '(uid=' + request.args['u'] + ')')")),
    ("PY021", "from lxml import etree\n" + route("return tree.xpath(\"//u[@n='\" + request.args['n'] + \"']\")")),
    ("PY022", "import logging\nname = input('Name: ')\nlogging.info('user ' + name)\n"),
    ("PY023", route("return make_response('<b>' + request.args['n'] + '</b>')")),
    ("PY024", route("resp = make_response('')\nresp.headers['X-User'] = request.args['h']\nreturn resp")),
    ("PY025", "import xml.etree.ElementTree as ET\nroot = ET.fromstring(data)\n"),
    ("PY026", "from Crypto.Cipher import DES\nc = DES.new(key)\n"),
    ("PY026", "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_ECB)\n"),
    ("PY027", "from Crypto.PublicKey import RSA\nk = RSA.generate(1024)\n"),
    ("PY028", "import ssl\nctx = ssl._create_unverified_context()\n"),
    ("PY028", "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE\n"),
    ("PY028", "import paramiko\nc = paramiko.SSHClient()\nc.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"),
    ("PY029", "import jwt\ndef f(t):\n    return jwt.decode(t, options={'verify_signature': False})\n"),
    ("PY030", "import random\ndef make_reset_token():\n    return random.randint(0, 10**8)\n"),
    ("PY031", "import ftplib\nftp = ftplib.FTP('files.example.com')\n"),
    ("PY032", "import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 8080))\n"),
    ("PY033", "import os\nos.chmod('run.sh', 0o777)\n"),
    ("PY034", "with open('/tmp/report.txt', 'w') as f:\n    f.write('x')\n"),
    ("PY035", "import jinja2\nenv = jinja2.Environment(loader=jinja2.FileSystemLoader('.'))\n"),
    ("PY036", "import requests\nr = requests.get('https://example.com')\n"),
    ("PY037", "import tarfile\nwith tarfile.open('a.tgz') as t:\n    t.extractall('out')\n"),
    ("PY038", "from Crypto.Cipher import AES\niv = b'0' * 16\nc = AES.new(key, AES.MODE_CBC, iv)\n"),
    ("PY039", "import hashlib\ndef store(password):\n    return hashlib.sha256(password.encode()).hexdigest()\n"),
    ("PY040", "import hashlib\nh = hashlib.pbkdf2_hmac('sha256', pw, b'fixed-salt', 100000)\n"),
    ("PY041", "from Crypto.Cipher import AES\nc = AES.new(b'0123456789abcdef', AES.MODE_GCM)\n"),
    ("PY042", FLASK + "@app.route('/l')\ndef login():\n    r = make_response('ok')\n    r.set_cookie('sid', 'v')\n    return r\n"),
    ("PY043", "import traceback\n" + route("try:\n    pass\nexcept Exception:\n    return traceback.format_exc()")),
    ("PY044", "def f(x):\n    return x is 'admin'\n"),
    ("PY045", "import os\ndef read(p):\n    if os.path.exists(p):\n        return open(p).read()\n"),
    ("PY046", "from wsgiref.handlers import CGIHandler\nCGIHandler().run(app)\n"),
    ("PY048", "import os\nos.system('tar czf backup.tgz *')\n"),
    ("PY049", route("f = request.files['doc']\nf.save('uploads/' + f.filename)")),
    ("PY050", "def get(table, name):\n    return table.scan(FilterExpression=name + ' = :u')\n"),
    ("PY051", "import re\ndef clean(s):\n    return re.sub(r'<script.*?>.*?</script>', '', s)\n"),
    ("GEN004", "access = 'user\u202e \u2066// admin\u2069 \u2066'\n"),
]

NEGATIVE = [
    ("PY016", "import sys\nwith open(sys.argv[1]) as f:\n    print(f.read())\n"),
    ("PY016", "from werkzeug.utils import secure_filename\n" + route("return open(secure_filename(request.args['f'])).read()")),
    ("PY008", "token_type = 'unstructured'\n"),
    ("PY008", "import os\nPASSWORD_FIELD = 'password'\npassword = os.environ['APP_PASSWORD']\n"),
    ("PY001", "exec('print(1)')\n"),
    ("PY005", "import hashlib\nh = hashlib.md5(data, usedforsecurity=False)\n"),
    ("PY004", "import yaml\ndata = yaml.load(text, Loader=yaml.SafeLoader)\n"),
    ("PY036", "import requests\nr = requests.get('https://example.com', timeout=5)\n"),
    ("PY018", "import requests\nr = requests.get('https://example.com', timeout=5)\n"),
    ("PY033", "import os\nos.chmod('secret.txt', 0o600)\n"),
    ("PY030", "import random\ndef roll_dice():\n    return random.randint(1, 6)\n"),
    ("PY035", "import jinja2\nenv = jinja2.Environment(autoescape=True)\n"),
    ("PY037", "import tarfile\nwith tarfile.open('a.tgz') as t:\n    t.extractall('out', filter='data')\n"),
    ("PY044", "def f(x):\n    return x is None\n"),
    ("PY025", "import defusedxml.ElementTree as ET\nroot = ET.fromstring(data)\n"),
    ("PY017", route("return redirect('/home')")),
    ("PY002", "import subprocess\nsubprocess.run(['ls', '-l'])\n"),
    ("PY007", "def f(cur, name):\n    cur.execute('SELECT * FROM t WHERE n = ?', (name,))\n"),
    ("PY032", "import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 8080))\n"),
]


@pytest.mark.parametrize(("rule", "code"), POSITIVE, ids=[f"{r}-{i}" for i, (r, _) in enumerate(POSITIVE)])
def test_rule_fires(rule: str, code: str) -> None:
    assert rule in rules_for(code)


@pytest.mark.parametrize(("rule", "code"), NEGATIVE, ids=[f"{r}-safe-{i}" for i, (r, _) in enumerate(NEGATIVE)])
def test_rule_stays_quiet_on_safe_code(rule: str, code: str) -> None:
    assert rule not in rules_for(code)


def test_suppression_comments_and_static_markup() -> None:
    assert "PY005" not in rules_for("import hashlib\nh = hashlib.md5(b'x')  # nosec - cache key only\n")
    assert "PY002" not in rules_for("import os\ndef f(c):\n    os.system(c)  # patchpilot: ignore\n")
    safe = "from django.utils import safestring\nlabel = 'secure'\nhtml = safestring.mark_safe('<b>{}</b>'.format(label))\n"
    assert "PY023" not in rules_for(safe)
    unsafe = "from django.utils import safestring\ndef f(label):\n    return safestring.mark_safe('<b>%s</b>' % label)\n"
    assert "PY023" in rules_for(unsafe)
    branchy = ("from django.utils import safestring\ndef f(x):\n    try:\n        s = render(x)\n"
               "    except Exception:\n        s = 'Secure'\n    return safestring.mark_safe(s)\n")
    assert "PY023" in rules_for(branchy)  # one branch is constant, the other is not


def test_constant_shell_command_is_low_severity() -> None:
    assert rules_for("import os\nos.system('ls -l')\n")["PY002"] is Severity.LOW
    assert rules_for("import os\ndef f(c):\n    os.system('ls ' + c)\n")["PY002"] is Severity.HIGH


def test_world_writable_chmod_is_high() -> None:
    assert rules_for("import os, stat\nos.chmod('f', stat.S_IRWXU | stat.S_IWOTH)\n")["PY033"] is Severity.HIGH
    assert rules_for("import os\nos.chmod('f', 0o755)\n")["PY033"] is Severity.MEDIUM


def test_taint_flows_through_variables_and_stops_at_sanitizers() -> None:
    flows = route("a = request.args['p']\nb = a.strip()\nc = 'data/' + b\nreturn open(c).read()")
    assert "PY016" in rules_for(flows)
    cleaned = route("a = int(request.args['p'])\nreturn open('data/%d' % a).read()")
    assert "PY016" not in rules_for(cleaned)


def test_every_rule_is_documented_and_tested() -> None:
    tested = {r for r, _ in POSITIVE}
    python_rules = {r for r in RULES if r.startswith("PY")}
    covered_elsewhere = {"PY006", "PY009", "PY010", "PY011", "PY012", "PY013", "PY014", "PY015", "PY047"}
    assert python_rules - tested - covered_elsewhere == set()
    for rule in RULES.values():
        assert rule.title and rule.description and rule.recommendation
