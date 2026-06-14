"""
rules_security.py — расширенная база правил безопасности (100+ правил).

Покрытие:
  OWASP Top 10 2021, CWE Top 25, SANS Top 25.
  Поддержка: Python, JavaScript, TypeScript, Go, Java, PHP, Ruby, C#.

Каждое правило: SecurityRule с метаданными для CI/CD, compliance, отчётов.
"""

from __future__ import annotations

import dataclasses
import re
from functools import lru_cache
from typing import List, Pattern


@dataclasses.dataclass(frozen=True)
class SecurityRule:
    id:          str
    title:       str
    severity:    str          # critical | high | medium | low
    cwe:         str
    owasp:       str          # A01:2021 ... A10:2021
    category:    str
    languages:   tuple        # ("python", "javascript", ...) или ("*",)
    pattern:     Pattern
    description: str
    fix_before:  str
    fix_after:   str
    confidence:  str = "medium"
    references:  tuple = ()

    @property
    def cvss(self) -> float:
        return {"critical": 9.3, "high": 7.5, "medium": 5.0, "low": 2.5}[self.severity]


def _rx(p: str) -> Pattern:
    return re.compile(p, re.MULTILINE | re.IGNORECASE)


# ═════════════════════════════════════════════════════════════════════════════
# A03:2021 — INJECTION (SQL, NoSQL, OS, LDAP, XPath, ...)
# ═════════════════════════════════════════════════════════════════════════════

INJECTION_RULES: List[SecurityRule] = [
    SecurityRule(
        "INJ-SQL-001", "SQL-инъекция — f-строка в execute()", "critical",
        "CWE-89", "A03:2021", "sql", ("python",),
        _rx(r'(?:cursor|conn|connection|db|session)\.execute\s*\(\s*f["\']'),
        "F-строка в SQL-запросе позволяет инъекцию произвольного SQL. "
        "Атака: ' OR 1=1-- читает всю БД, '; DROP TABLE-- удаляет данные.",
        'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))',
        "high", ("https://owasp.org/Top10/A03_2021-Injection/",),
    ),
    SecurityRule(
        "INJ-SQL-002", "SQL-инъекция — конкатенация строк", "critical",
        "CWE-89", "A03:2021", "sql", ("python", "java", "csharp"),
        _rx(r'["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^"\']*["\']\s*\+'),
        "Конкатенация пользовательских данных в SQL-строку.",
        '"SELECT * FROM users WHERE name=" + name',
        'cursor.execute("SELECT * FROM users WHERE name=%s", (name,))',
        "high",
    ),
    SecurityRule(
        "INJ-SQL-003", "SQL-инъекция — оператор % форматирования", "critical",
        "CWE-89", "A03:2021", "sql", ("python",),
        _rx(r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*%s[^"\']*["\']\s*%\s*'),
        "Форматирование строк через % для SQL-запроса.",
        'query = "SELECT * FROM t WHERE id=%s" % uid',
        'cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))',
    ),
    SecurityRule(
        "INJ-SQL-004", "SQL-инъекция — .format() в запросе", "critical",
        "CWE-89", "A03:2021", "sql", ("python",),
        _rx(r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*\{[^}]*\}[^"\']*["\']\s*\.format\s*\('),
        "Метод .format() подставляет данные в SQL-строку.",
        '"SELECT * FROM t WHERE id={}".format(uid)',
        'cursor.execute("SELECT * FROM t WHERE id=%s", (uid,))',
    ),
    SecurityRule(
        "INJ-NOSQL-001", "NoSQL-инъекция MongoDB через $where", "high",
        "CWE-943", "A03:2021", "nosql", ("python", "javascript"),
        _rx(r'\$where\s*[:=]|find\s*\(\s*\{[^}]*\$ne'),
        "MongoDB $where/$ne операторы с пользовательским вводом обходят аутентификацию.",
        'db.users.find({"$where": user_input})',
        'db.users.find({"name": sanitized_name})  # явная схема',
    ),
    SecurityRule(
        "INJ-CMD-001", "Command Injection — shell=True", "critical",
        "CWE-78", "A03:2021", "command", ("python",),
        _rx(r'subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True'),
        "shell=True передаёт команду в /bin/sh без экранирования. "
        "Атака через ; | $() && даёт полный OS shell.",
        'subprocess.run(cmd, shell=True)',
        'subprocess.run(shlex.split(cmd), shell=False)',
        "high",
    ),
    SecurityRule(
        "INJ-CMD-002", "Command Injection — os.system / os.popen", "high",
        "CWE-78", "A03:2021", "command", ("python",),
        _rx(r'\bos\.(system|popen|execl[ep]?|execv[ep]?|spawnl[ep]?|spawnv[ep]?)\s*\('),
        "Прямой вызов оболочки без экранирования аргументов.",
        'os.system(f"ping {host}")',
        'subprocess.run(["ping", host], check=True, timeout=5)',
    ),
    SecurityRule(
        "INJ-CMD-003", "Command Injection — Node.js child_process", "critical",
        "CWE-78", "A03:2021", "command", ("javascript", "typescript"),
        _rx(r'(?:exec|execSync)\s*\(\s*[`"\'][^`"\']*\$\{|child_process\.exec\s*\('),
        "child_process.exec с интерполяцией — RCE через инъекцию команд.",
        'exec(`ping ${host}`)',
        'execFile("ping", [host], callback)',
    ),
    SecurityRule(
        "INJ-LDAP-001", "LDAP-инъекция", "high",
        "CWE-90", "A03:2021", "ldap", ("python", "java"),
        _rx(r'(?:search|search_s|bind)\s*\([^)]*(\+|\.format|f["\'])[^)]*\)'),
        "LDAP-фильтр с пользовательскими данными → обход аутентификации, дамп каталога.",
        'conn.search_s(base, scope, f"(uid={user})")',
        'conn.search_s(base, scope, "(uid=%s)", [escape_filter_chars(user)])',
    ),
    SecurityRule(
        "INJ-XPATH-001", "XPath-инъекция", "high",
        "CWE-643", "A03:2021", "xpath", ("python", "java", "csharp"),
        _rx(r'(?:xpath|XPath|evaluate)\s*\([^)]*(\+|\.format|f["\'])'),
        "XPath-запрос с пользовательским вводом обходит проверки в XML-хранилищах.",
        'tree.xpath(f"//user[name=\'{name}\']")',
        'tree.xpath("//user[name=$name]", name=name)',
    ),
    SecurityRule(
        "INJ-SSTI-001", "Server-Side Template Injection (Jinja2)", "critical",
        "CWE-94", "A03:2021", "ssti", ("python",),
        _rx(r'render_template_string\s*\([^)]*(\+|f["\']|\.format)'),
        "render_template_string с пользовательским вводом → RCE через {{config}} или "
        "{{''.__class__.__mro__[1].__subclasses__()}}.",
        'render_template_string(f"Hello {name}")',
        'render_template("hello.html", name=name)',
        "high",
    ),
    SecurityRule(
        "INJ-EVAL-001", "RCE через eval()", "critical",
        "CWE-95", "A03:2021", "rce", ("python",),
        _rx(r'\beval\s*\('),
        "eval() компилирует и выполняет произвольную строку как Python-код. "
        "Любой пользовательский ввод даёт полный захват процесса.",
        'result = eval(user_input)',
        'result = ast.literal_eval(user_input)  # только литералы',
        "high",
    ),
    SecurityRule(
        "INJ-EXEC-001", "RCE через exec()", "critical",
        "CWE-95", "A03:2021", "rce", ("python",),
        _rx(r'\bexec\s*\('),
        "exec() выполняет произвольный блок Python-кода. Прямой путь к RCE.",
        'exec(user_code)',
        '# Перепишите логику без exec(); используйте словарь функций',
        "high",
    ),
    SecurityRule(
        "INJ-SSTI-002", "Template Injection — Jinja2.Template()", "critical",
        "CWE-94", "A03:2021", "ssti", ("python",),
        _rx(r'(?:jinja2\.)?Template\s*\([^)]*(\+|f["\']|user|request)'),
        "Динамическое создание шаблона из пользовательского ввода.",
        'Template(user_template).render()',
        '# Используйте предопределённые шаблоны из файлов',
    ),
    SecurityRule(
        "INJ-XXE-001", "XML External Entity (XXE)", "high",
        "CWE-611", "A05:2021", "xxe", ("python",),
        _rx(r'(?:etree\.(?:parse|fromstring)|minidom\.parse(?:String)?|lxml\.etree)\s*\('),
        "XML-парсер без отключения external entities. "
        "Атака: <!ENTITY xxe SYSTEM 'file:///etc/passwd'> читает файлы сервера.",
        'tree = etree.parse(xml_source)',
        'parser = etree.XMLParser(resolve_entities=False, no_network=True)\n'
        'tree = etree.parse(xml_source, parser)',
    ),
    SecurityRule(
        "INJ-CRLF-001", "CRLF / HTTP Response Splitting", "medium",
        "CWE-93", "A03:2021", "crlf", ("python",),
        _rx(r'(?:headers\[|set_header|add_header|response\.headers)\s*[^)]*(\+|\.format|f["\'])'),
        "Пользовательские данные в HTTP-заголовке без фильтрации newline → "
        "HTTP Response Splitting, инъекция заголовков, XSS.",
        'response.headers["X-User"] = user_input',
        'response.headers["X-User"] = user_input.replace("\\r","").replace("\\n","")',
    ),
    SecurityRule(
        "INJ-LOG-001", "Log Injection / Log4Shell-style", "medium",
        "CWE-117", "A09:2021", "log", ("python", "java"),
        _rx(r'(?:logging\.(?:info|debug|warning|error|critical)|logger\.\w+)\s*\([^)]*\+[^)]*(?:request|input|user)'),
        "Пользовательский ввод в логах без санитизации → фальсификация журнала, Log4Shell.",
        'logging.info("User logged in: " + user_input)',
        'logging.info("User logged in", extra={"user": sanitize(user_input)})',
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# A02:2021 — CRYPTOGRAPHIC FAILURES
# ═════════════════════════════════════════════════════════════════════════════

CRYPTO_RULES: List[SecurityRule] = [
    SecurityRule(
        "CRY-HASH-001", "Устаревший хэш MD5", "high",
        "CWE-327", "A02:2021", "crypto", ("python",),
        _rx(r'hashlib\.md5\s*\('),
        "MD5 ломается за миллисекунды rainbow tables. Коллизии генерируются за секунды.",
        'h = hashlib.md5(data).hexdigest()',
        'h = hashlib.sha256(data).hexdigest()  # bcrypt/argon2 для паролей',
        "high",
    ),
    SecurityRule(
        "CRY-HASH-002", "Устаревший хэш SHA-1", "high",
        "CWE-327", "A02:2021", "crypto", ("python",),
        _rx(r'hashlib\.sha1\s*\('),
        "SHA-1 криптографически сломан с 2017 (SHAttered). Не для паролей и подписей.",
        'h = hashlib.sha1(data).hexdigest()',
        'h = hashlib.sha256(data).hexdigest()',
    ),
    SecurityRule(
        "CRY-RAND-001", "Небезопасный PRNG для security-контекста", "medium",
        "CWE-338", "A02:2021", "crypto", ("python",),
        _rx(r'\brandom\.(?:random|randint|choice|shuffle|sample|uniform|getrandbits)\s*\('),
        "MT19937 предсказуем после 624 наблюдений. Токены, ключи, nonce взламываются.",
        'token = str(random.randint(0, 999999))',
        'token = secrets.token_hex(16)',
    ),
    SecurityRule(
        "CRY-RAND-002", "Math.random() для криптографии (JS)", "medium",
        "CWE-338", "A02:2021", "crypto", ("javascript", "typescript"),
        _rx(r'Math\.random\s*\(\s*\)'),
        "Math.random() не криптографически стоек. Используйте crypto.getRandomValues().",
        'const token = Math.random().toString(36)',
        'const token = crypto.randomUUID()',
    ),
    SecurityRule(
        "CRY-ECB-001", "AES в режиме ECB", "high",
        "CWE-327", "A02:2021", "crypto", ("python",),
        _rx(r'(?:AES\.new|Cipher\.new|modes\.ECB)[^)]*(?:MODE_ECB|ECB)'),
        "ECB-режим не использует IV → одинаковые блоки plaintext дают одинаковый ciphertext.",
        'cipher = AES.new(key, AES.MODE_ECB)',
        'cipher = AES.new(key, AES.MODE_GCM)  # authenticated encryption',
    ),
    SecurityRule(
        "CRY-TIMING-001", "Timing Attack — сравнение секретов через ==", "medium",
        "CWE-208", "A02:2021", "crypto", ("python",),
        _rx(r'\b(?:token|secret|hmac|signature|password|api_key|hash)\s*==\s*[^=]'),
        "== прерывается на первом несовпадении байта. Атакующий восстанавливает значение "
        "измерением времени ответа.",
        'if token == expected_token:',
        'if hmac.compare_digest(token.encode(), expected_token.encode()):',
    ),
    SecurityRule(
        "CRY-KEY-001", "Хардкод криптографического ключа / IV", "critical",
        "CWE-321", "A02:2021", "crypto", ("python",),
        _rx(r'(?:AES_KEY|SECRET_KEY|ENCRYPTION_KEY|CIPHER_KEY|IV)\s*=\s*b?["\'][^"\']{8,}["\']'),
        "Ключ шифрования в исходнике — компрометация кода = расшифровка всех данных.",
        'AES_KEY = b"1234567890123456"',
        'AES_KEY = os.getenv("AES_KEY").encode()  # из vault/env',
    ),
    SecurityRule(
        "CRY-TLS-001", "Устаревшая версия TLS/SSL", "high",
        "CWE-326", "A02:2021", "crypto", ("python",),
        _rx(r'ssl\.(?:PROTOCOL_TLSv1\b|PROTOCOL_SSLv[23]|PROTOCOL_TLSv1_1)'),
        "TLS 1.0/1.1 и SSLv2/3 подвержены POODLE, BEAST, CRIME, DROWN атакам.",
        'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)',
        'ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # TLS 1.2+',
    ),
    SecurityRule(
        "CRY-HMAC-001", "Hash Length Extension — hash(secret+data)", "high",
        "CWE-327", "A02:2021", "crypto", ("python",),
        _rx(r'hashlib\.(?:md5|sha1|sha256)\s*\(\s*(?:secret|key)\s*\+'),
        "Прямое хэширование secret+data уязвимо к length extension attack.",
        'sig = hashlib.sha256(secret + data).hexdigest()',
        'sig = hmac.new(secret, data, hashlib.sha256).hexdigest()',
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# A07:2021 — IDENTIFICATION AND AUTHENTICATION FAILURES
# ═════════════════════════════════════════════════════════════════════════════

AUTH_RULES: List[SecurityRule] = [
    SecurityRule(
        "AUTH-SECRET-001", "Хардкод секрета / API-ключа", "critical",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'(?:password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key|'
            r'access[_-]?key|client[_-]?secret|aws[_-]?secret)\s*[:=]\s*["\'][^"\']{6,}["\']'),
        "Секрет зашит в код — виден в git log, docker inspect, любом форке репозитория.",
        'API_KEY = "sk-prod-abc123xyz"',
        'API_KEY = os.getenv("API_KEY")',
        "high",
    ),
    SecurityRule(
        "AUTH-SECRET-002", "AWS Access Key в коде", "critical",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'AKIA[0-9A-Z]{16}'),
        "AWS Access Key ID в исходном коде — полная компрометация AWS-аккаунта.",
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        'aws_key = os.getenv("AWS_ACCESS_KEY_ID")',
        "high",
    ),
    SecurityRule(
        "AUTH-SECRET-003", "Приватный ключ (PEM) в коде", "critical",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "Приватный ключ в исходном коде. Немедленно ротируйте.",
        '-----BEGIN RSA PRIVATE KEY-----',
        '# Храните ключи в защищённом vault, читайте через env',
        "high",
    ),
    SecurityRule(
        "AUTH-JWT-001", "JWT алгоритм none", "critical",
        "CWE-345", "A07:2021", "jwt", ("python", "javascript"),
        _rx(r'algorithm[s]?\s*[:=]\s*\[?\s*["\']none["\']'),
        "alg=none создаёт валидный JWT без подписи — любой пользователь становится admin.",
        'jwt.decode(token, algorithms=["none"])',
        'jwt.decode(token, SECRET, algorithms=["HS256"])',
        "high",
    ),
    SecurityRule(
        "AUTH-JWT-002", "JWT verify=False — подпись не проверяется", "critical",
        "CWE-347", "A07:2021", "jwt", ("python",),
        _rx(r'jwt\.decode\s*\([^)]*verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False'),
        "Декодирование JWT без проверки подписи — токен можно подделать.",
        'jwt.decode(token, verify=False)',
        'jwt.decode(token, SECRET, algorithms=["HS256"])',
    ),
    SecurityRule(
        "AUTH-JWT-003", "Слабый JWT-секрет", "high",
        "CWE-326", "A07:2021", "jwt", ("python", "javascript"),
        _rx(r'(?:jwt[_-]?secret|JWT_SECRET|secret[_-]?key)\s*[:=]\s*["\'](?:secret|password|'
            r'123456|test|key|admin|changeme|jwt)["\']'),
        "Словарный или короткий JWT-секрет ломается jwt-cracker за секунды.",
        'JWT_SECRET = "secret"',
        'JWT_SECRET = secrets.token_hex(32)  # 256 бит',
    ),
    SecurityRule(
        "AUTH-PWD-001", "Пароль в открытом виде без хэширования", "high",
        "CWE-256", "A07:2021", "password", ("python",),
        _rx(r'(?:user\.password|self\.password)\s*=\s*(?:password|request)'),
        "Пароль сохраняется без хэширования. При утечке БД все пароли открыты.",
        'user.password = request.form["password"]',
        'user.password = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())',
    ),
    SecurityRule(
        "AUTH-SESS-001", "Предсказуемый session ID", "high",
        "CWE-330", "A07:2021", "session", ("python",),
        _rx(r'session(?:_id)?\s*=\s*(?:str\s*\(\s*)?(?:random\.|time\.|md5|hashlib\.md5)'),
        "Предсказуемый session ID — перебор за секунды.",
        'session_id = md5(str(time.time()))',
        'session_id = secrets.token_urlsafe(32)',
    ),
    SecurityRule(
        "AUTH-COOKIE-001", "Cookie без Secure / HttpOnly", "medium",
        "CWE-614", "A05:2021", "cookie", ("python",),
        _rx(r'(?:response\.)?set_cookie\s*\([^)]*\)'),
        "Cookie без флагов Secure/HttpOnly/SameSite доступны через XSS и по HTTP.",
        'response.set_cookie("session", val)',
        'response.set_cookie("session", val, secure=True, httponly=True, samesite="Strict")',
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# A08:2021 — SOFTWARE AND DATA INTEGRITY FAILURES (deserialization)
# ═════════════════════════════════════════════════════════════════════════════

DESER_RULES: List[SecurityRule] = [
    SecurityRule(
        "DES-PICKLE-001", "RCE через pickle.loads()", "critical",
        "CWE-502", "A08:2021", "deserialization", ("python",),
        _rx(r'pickle\.loads?\s*\('),
        "pickle.loads() выполняет __reduce__ при десериализации — тривиальный RCE.",
        'data = pickle.loads(payload)',
        'data = json.loads(payload)',
        "high",
    ),
    SecurityRule(
        "DES-YAML-001", "RCE через yaml.load() без SafeLoader", "high",
        "CWE-502", "A08:2021", "deserialization", ("python",),
        _rx(r'yaml\.load\s*\((?![^)]*Safe)'),
        "yaml.load() выполняет !!python/object теги — RCE через специальный payload.",
        'config = yaml.load(stream)',
        'config = yaml.safe_load(stream)',
    ),
    SecurityRule(
        "DES-MARSHAL-001", "Небезопасная десериализация marshal", "high",
        "CWE-502", "A08:2021", "deserialization", ("python",),
        _rx(r'marshal\.loads?\s*\('),
        "marshal не предназначен для недоверенных данных.",
        'obj = marshal.loads(data)',
        'obj = json.loads(data)',
    ),
    SecurityRule(
        "DES-NODE-001", "Node.js небезопасная десериализация", "critical",
        "CWE-502", "A08:2021", "deserialization", ("javascript", "typescript"),
        _rx(r'(?:node-serialize|serialize-javascript)|unserialize\s*\('),
        "node-serialize позволяет RCE через _$$ND_FUNC$$_ payload.",
        'const obj = unserialize(userInput)',
        'const obj = JSON.parse(userInput)',
    ),
    SecurityRule(
        "DES-PHP-001", "PHP unserialize() недоверенных данных", "critical",
        "CWE-502", "A08:2021", "deserialization", ("php",),
        _rx(r'unserialize\s*\('),
        "PHP unserialize с POP-chain → RCE через magic methods.",
        '$obj = unserialize($_POST["data"]);',
        '$obj = json_decode($_POST["data"], true);',
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# A01:2021 — BROKEN ACCESS CONTROL
# ═════════════════════════════════════════════════════════════════════════════

ACCESS_RULES: List[SecurityRule] = [
    SecurityRule(
        "ACC-PATH-001", "Path Traversal — open() с конкатенацией", "high",
        "CWE-22", "A01:2021", "access", ("python",),
        _rx(r'open\s*\([^)]*(\+|\.format\s*\(|f["\'])[^)]*\)'),
        "../../etc/passwd через user_path. Чтение любого файла сервера.",
        'open(base_dir + user_path)',
        'safe = (Path(base_dir) / user_path).resolve()\n'
        'assert safe.is_relative_to(base_dir)\nopen(safe)',
    ),
    SecurityRule(
        "ACC-PATH-002", "Path Traversal — send_file с параметром", "high",
        "CWE-22", "A01:2021", "access", ("python",),
        _rx(r'send_file\s*\([^)]*request\.(?:args|params|form)'),
        "send_file с пользовательским путём → скачивание любого файла.",
        'send_file(request.args["path"])',
        'send_from_directory(SAFE_DIR, secure_filename(name))',
    ),
    SecurityRule(
        "ACC-REDIRECT-001", "Open Redirect", "medium",
        "CWE-601", "A01:2021", "access", ("python",),
        _rx(r'redirect\s*\([^)]*request\.(?:args|params|form|GET|POST)'),
        "Редирект на URL из запроса без проверки → фишинг под видом вашего домена.",
        'return redirect(request.args.get("next"))',
        'next_url = request.args.get("next", "/")\n'
        'if not next_url.startswith("/"): next_url = "/"\nreturn redirect(next_url)',
    ),
    SecurityRule(
        "ACC-MASS-001", "Mass Assignment — **request присваивается модели", "high",
        "CWE-915", "A01:2021", "access", ("python",),
        _rx(r'\*\*request\.(?:POST|data|json|form|GET)'),
        "Все поля запроса присваиваются модели — атакующий задаёт role, is_admin.",
        'User(**request.POST.dict())',
        'User(name=request.POST["name"])  # явный allowlist',
    ),
    SecurityRule(
        "ACC-PRIV-001", "Privilege Escalation — привилегия из запроса", "high",
        "CWE-269", "A01:2021", "access", ("python",),
        _rx(r'(?:is_admin|is_staff|role|permissions|is_superuser)\s*=\s*request\.'),
        "Привилегированное поле присваивается из пользовательского запроса.",
        'user.is_admin = request.POST.get("is_admin")',
        '# Привилегии устанавливает только администратор через отдельный endpoint',
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# A10:2021 — SSRF
# ═════════════════════════════════════════════════════════════════════════════

SSRF_RULES: List[SecurityRule] = [
    SecurityRule(
        "SSRF-001", "SSRF — requests с пользовательским URL", "high",
        "CWE-918", "A10:2021", "ssrf", ("python",),
        _rx(r'(?:requests|httpx)\.(?:get|post|put|head|patch|delete)\s*\(\s*(?![\'"`])'),
        "Сервер делает HTTP-запрос по URL атакующего → AWS metadata (169.254.169.254), "
        "Redis, внутренние сервисы.",
        'resp = requests.get(user_url)',
        'resp = requests.get(validated_url, timeout=5)\n'
        '# validated_url прошёл whitelist доменов и блокировку private IP',
    ),
    SecurityRule(
        "SSRF-002", "SSRF — urllib с пользовательским URL", "high",
        "CWE-918", "A10:2021", "ssrf", ("python",),
        _rx(r'urllib\.request\.(?:urlopen|Request)\s*\(\s*(?![\'"`])'),
        "urllib поддерживает file://, ftp://, gopher:// — расширенный вектор SSRF.",
        'urllib.request.urlopen(user_url)',
        '# Валидируйте схему (только https) и домен перед запросом',
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# A05:2021 — SECURITY MISCONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

CONFIG_RULES: List[SecurityRule] = [
    SecurityRule(
        "CFG-SSL-001", "SSL-проверка отключена (verify=False)", "high",
        "CWE-295", "A05:2021", "config", ("python",),
        _rx(r'verify\s*=\s*False'),
        "verify=False отключает всю цепочку доверия TLS — MITM перехватывает трафик.",
        'requests.get(url, verify=False)',
        'requests.get(url)  # verify=True по умолчанию',
    ),
    SecurityRule(
        "CFG-DEBUG-001", "DEBUG=True в production", "medium",
        "CWE-489", "A05:2021", "config", ("python",),
        _rx(r'\bDEBUG\s*=\s*True\b'),
        "Раскрывает stack trace, переменные, конфиги в HTTP 500-ответах.",
        'DEBUG = True',
        'DEBUG = os.getenv("DEBUG", "false").lower() == "true"',
    ),
    SecurityRule(
        "CFG-CORS-001", "CORS wildcard Access-Control-Allow-Origin: *", "medium",
        "CWE-942", "A05:2021", "config", ("python", "javascript"),
        _rx(r'(?:Access-Control-Allow-Origin["\']?\s*[:,]\s*["\']?\*|allow_origins\s*=\s*\[?\s*["\']\*["\'])'),
        "Любой сайт может читать авторизованные ответы вашего API.",
        'CORS(app, origins="*")',
        'CORS(app, origins=["https://yourapp.com"])',
    ),
    SecurityRule(
        "CFG-BIND-001", "Сервер слушает 0.0.0.0 без явной защиты", "low",
        "CWE-668", "A05:2021", "config", ("python",),
        _rx(r'(?:host|HOST)\s*=\s*["\']0\.0\.0\.0["\']'),
        "Привязка к 0.0.0.0 открывает сервис на всех интерфейсах.",
        'app.run(host="0.0.0.0")',
        '# Убедитесь, что firewall ограничивает доступ',
    ),
    SecurityRule(
        "CFG-ASSERT-001", "assert для логики безопасности", "medium",
        "CWE-617", "A04:2021", "config", ("python",),
        _rx(r'^\s*assert\s+(?:user|request|auth|is_|has_|can_|permission)'),
        "assert отключается в python -O. В production проверки молча пропускаются.",
        'assert user.is_authenticated',
        'if not user.is_authenticated:\n    raise PermissionError()',
    ),
    # ── HTML / клиентская безопасность ──
    SecurityRule(
        "HTML-XSS-001", "XSS через innerHTML с переменной", "high",
        "CWE-79", "A03:2021", "xss", ("html", "javascript", "typescript"),
        _rx(r'\.innerHTML\s*=\s*(?![\'"`])'),
        "Присваивание innerHTML непроверенных данных ведёт к XSS.",
        'el.innerHTML = userInput',
        'el.textContent = userInput  // или DOMPurify.sanitize()',
    ),
    SecurityRule(
        "HTML-XSS-002", "document.write()", "high",
        "CWE-79", "A03:2021", "xss", ("html", "javascript"),
        _rx(r'document\.write(?:ln)?\s*\('),
        "document.write вставляет контент без экранирования — вектор XSS.",
        'document.write(data)',
        'Используйте безопасную вставку через textContent/createElement',
    ),
    SecurityRule(
        "HTML-XSS-003", "Inline-обработчик событий", "medium",
        "CWE-79", "A03:2021", "xss", ("html",),
        _rx(r'<[^>]+\son(?:click|load|error|mouseover)\s*=\s*["\']'),
        "Inline-обработчики (onclick=...) усложняют CSP и поощряют XSS.",
        '<button onclick="doStuff()">',
        'Вынесите обработчик в JS: el.addEventListener("click", ...)',
    ),
    SecurityRule(
        "HTML-JS-001", "eval() в inline-скрипте", "critical",
        "CWE-95", "A03:2021", "rce", ("html", "javascript", "typescript"),
        _rx(r'\beval\s*\('),
        "eval() в браузере выполняет произвольный JS — критический XSS/RCE.",
        'eval(userCode)',
        'JSON.parse() для данных; избегайте eval',
    ),
    SecurityRule(
        "HTML-CFG-001", "target=_blank без rel=noopener", "low",
        "CWE-1022", "A05:2021", "config", ("html",),
        _rx(r'target\s*=\s*["\']_blank["\'](?![^>]*rel\s*=)'),
        "Ссылка target=_blank без rel=noopener даёт доступ к window.opener (tabnabbing).",
        '<a href="..." target="_blank">',
        '<a href="..." target="_blank" rel="noopener noreferrer">',
    ),
    SecurityRule(
        "HTML-CFG-002", "Подключение скрипта по http://", "medium",
        "CWE-319", "A02:2021", "config", ("html",),
        _rx(r'<script[^>]+src\s*=\s*["\']http://'),
        "Скрипт по http:// уязвим к MITM-подмене. Используйте https.",
        '<script src="http://cdn.example/lib.js">',
        '<script src="https://cdn.example/lib.js" integrity="sha384-...">',
    ),
    # ── Расширенные секреты ──
    SecurityRule(
        "SEC-GITHUB-001", "GitHub Personal Access Token", "critical",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'gh[pousr]_[A-Za-z0-9]{36,}'),
        "GitHub-токен в коде даёт доступ к репозиториям. Немедленно отзовите.",
        'token = "ghp_xxxxxxxxxxxx"', 'token = os.getenv("GITHUB_TOKEN")',
    ),
    SecurityRule(
        "SEC-SLACK-001", "Slack-токен", "critical",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'xox[baprs]-[0-9A-Za-z-]{10,}'),
        "Slack-токен открывает доступ к рабочему пространству.",
        'SLACK = "xoxb-..."', 'SLACK = os.getenv("SLACK_TOKEN")',
    ),
    SecurityRule(
        "SEC-STRIPE-001", "Stripe Secret Key", "critical",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'sk_live_[0-9a-zA-Z]{24,}'),
        "Боевой ключ Stripe — доступ к платежам. Отзовите немедленно.",
        'sk_live_xxx', 'os.getenv("STRIPE_SECRET")',
    ),
    SecurityRule(
        "SEC-PK-001", "Приватный ключ (PEM)", "critical",
        "CWE-798", "A02:2021", "secrets", ("*",),
        _rx(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
        "Приватный ключ в репозитории компрометирует всю криптографию.",
        '-----BEGIN PRIVATE KEY-----', 'Храните ключи вне кода (vault, env)',
    ),
    SecurityRule(
        "SEC-GOOGLE-001", "Google API Key", "high",
        "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'AIza[0-9A-Za-z_-]{35}'),
        "Google API-ключ в коде. Ограничьте по домену/IP и вынесите в env.",
        'AIzaSy...', 'os.getenv("GOOGLE_API_KEY")',
    ),
    # ── Mass assignment / IDOR ──
    SecurityRule(
        "ACC-MASS-002", "Mass assignment (вся форма в модель)", "high",
        "CWE-915", "A08:2021", "access", ("python",),
        _rx(r'\.update\s*\(\s*\*\*request\.(?:json|form|data|POST)'),
        "Передача всех полей запроса в модель позволяет подменить служебные поля (is_admin).",
        'user.update(**request.json)', 'Берите только разрешённые поля явным списком',
    ),
    # ── Открытый редирект ──
    SecurityRule(
        "ACC-REDIR-001", "Открытый редирект", "medium",
        "CWE-601", "A01:2021", "access", ("python",),
        _rx(r'redirect\s*\(\s*request\.(?:args|GET|params|query)'),
        "Редирект на URL из запроса позволяет фишинг (открытый редирект).",
        'redirect(request.args["next"])', 'Проверяйте next по whitelist',
    ),
    # ── Timing attack ──
    SecurityRule(
        "CRY-TIMING-002", "Сравнение секретов через ==", "medium",
        "CWE-208", "A02:2021", "crypto", ("python",),
        _rx(r'(?:token|secret|password|hmac|signature|api_key)\s*==\s*'),
        "Обычное == уязвимо к timing-атаке. Используйте constant-time сравнение.",
        'if token == expected:', 'if hmac.compare_digest(token, expected):',
    ),
    # ── GraphQL ──
    SecurityRule(
        "CFG-GQL-001", "GraphQL introspection включён", "low",
        "CWE-200", "A05:2021", "config", ("python", "javascript"),
        _rx(r'introspection\s*[:=]\s*True|graphiql\s*[:=]\s*True'),
        "Introspection в production раскрывает всю схему API атакующему.",
        'introspection=True', 'introspection=False в production',
    ),
    # ── Регекс ReDoS ──
    SecurityRule(
        "DOS-REDOS-001", "Потенциальный ReDoS (вложенные кванторы)", "medium",
        "CWE-1333", "A06:2021", "dos", ("python", "javascript"),
        _rx(r're\.(?:match|search|findall|compile)\s*\([^)]*\([^)]*[+*]\)[+*]'),
        "Вложенные кванторы в regex могут вызвать катастрофический backtracking (DoS).",
        r're.match(r"(a+)+", s)', 'Упростите regex или используйте timeout',
    ),
    # ── XSS расширенный ──
    SecurityRule(
        "XSS-DJANGO-001", "Django |safe / mark_safe с переменной", "high",
        "CWE-79", "A03:2021", "xss", ("python",),
        _rx(r'mark_safe\s*\(|\|\s*safe\b'),
        "mark_safe/|safe отключают экранирование — XSS если данные от пользователя.",
        '{{ user_input|safe }}', 'Не отключайте экранирование для пользовательских данных',
    ),
    SecurityRule(
        "XSS-REACT-001", "dangerouslySetInnerHTML", "high",
        "CWE-79", "A03:2021", "xss", ("javascript", "typescript"),
        _rx(r'dangerouslySetInnerHTML'),
        "dangerouslySetInnerHTML вставляет HTML без санитизации — XSS.",
        'dangerouslySetInnerHTML={{__html: data}}', 'DOMPurify.sanitize(data)',
    ),
    # ── Flask/Django config ──
    SecurityRule(
        "CFG-SECRET-001", "Пустой или дефолтный SECRET_KEY", "high",
        "CWE-798", "A02:2021", "config", ("python",),
        _rx(r'SECRET_KEY\s*=\s*["\'](?:|changeme|secret|dev|test|123)["\']'),
        "Слабый SECRET_KEY ломает подпись сессий и CSRF-защиту.",
        'SECRET_KEY = "dev"', 'SECRET_KEY = os.getenv("SECRET_KEY")  # случайный 50+ симв',
    ),
    SecurityRule(
        "CFG-HOST-001", "ALLOWED_HOSTS = ['*']", "medium",
        "CWE-16", "A05:2021", "config", ("python",),
        _rx(r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']'),
        "ALLOWED_HOSTS=['*'] открывает Host header атаки.",
        "ALLOWED_HOSTS = ['*']", "ALLOWED_HOSTS = ['yourdomain.com']",
    ),
    # ── Загрузка файлов ──
    SecurityRule(
        "ACC-UPLOAD-001", "Сохранение файла с именем от пользователя", "high",
        "CWE-434", "A04:2021", "access", ("python",),
        _rx(r'\.save\s*\([^)]*\.filename\)|save\s*\(\s*os\.path\.join\([^)]*filename'),
        "Сохранение с пользовательским именем → path traversal / загрузка .php/.py.",
        'f.save(f.filename)', 'secure_filename() + проверка расширения',
    ),
    # ── Доп. инъекции ──
    SecurityRule("INJ-XPATH-002", "XPath-инъекция", "high", "CWE-643", "A03:2021", "xpath", ("python","java"),
        _rx(r'\.(?:xpath|find|findall|evaluate)\s*\([^)]*[+%]\s*'),
        "Конкатенация в XPath-запрос → инъекция.", 'tree.xpath("//user[@id="+uid+"]")', "Параметризованные XPath"),
    SecurityRule("INJ-TEMPLATE-003", "SSTI — string.Template/format", "high", "CWE-1336", "A03:2021", "ssti", ("python",),
        _rx(r'(?:Template|format_map)\s*\([^)]*request\.|\.format\s*\(\*\*request'),
        "Пользовательский ввод в шаблон → SSTI.", 'Template(user_input)', "Не передавайте ввод в шаблонизатор"),
    SecurityRule("INJ-LOG-002", "Log injection (CRLF)", "low", "CWE-117", "A09:2021", "log", ("python","java"),
        _rx(r'log(?:ger)?\.(?:info|warning|error|debug)\s*\([^)]*\+\s*request'),
        "Неэкранированный ввод в лог → подделка записей.", 'log.info("user "+request.args["u"])', "Экранируйте \\n \\r"),
    SecurityRule("INJ-HEADER-001", "HTTP Response Splitting", "high", "CWE-113", "A03:2021", "crlf", ("python",),
        _rx(r'(?:headers\[|set_header|add_header)\s*[^)]*request\.(?:args|GET|form)'),
        "Ввод в HTTP-заголовок → инъекция CRLF.", 'resp.headers["X"]=request.args["v"]', "Валидируйте на \\r\\n"),
    # ── Крипто (расширение) ──
    SecurityRule("CRY-DES-001", "Устаревший шифр DES/3DES", "high", "CWE-327", "A02:2021", "crypto", ("python","java"),
        _rx(r'\b(?:DES|TripleDES|3DES|ARC4|RC4|Blowfish)\b'),
        "DES/RC4/Blowfish считаются взломанными.", 'Cipher.DES', "AES-256-GCM"),
    SecurityRule("CRY-ECB-002", "Режим шифрования ECB", "high", "CWE-327", "A02:2021", "crypto", ("python","java"),
        _rx(r'MODE_ECB|ECBMode|"ECB"|AES/ECB'),
        "ECB раскрывает паттерны данных. Используйте GCM/CBC+HMAC.", 'AES.MODE_ECB', "AES.MODE_GCM"),
    SecurityRule("CRY-STATIC-IV-001", "Статический IV/nonce", "high", "CWE-329", "A02:2021", "crypto", ("python",),
        _rx(r'(?:iv|nonce)\s*=\s*[\'"][^\'"]{8,}[\'"]|IV\s*=\s*b[\'"]'),
        "Фиксированный IV ломает безопасность шифрования.", 'iv = "0000000000000000"', "os.urandom(16) каждый раз"),
    SecurityRule("CRY-WEAK-KEY-001", "Короткий ключ RSA (<2048)", "high", "CWE-326", "A02:2021", "crypto", ("python",),
        _rx(r'(?:key_size|bits)\s*=\s*(?:512|768|1024)\b'),
        "RSA <2048 бит небезопасен.", 'key_size=1024', "key_size=2048 или выше"),
    SecurityRule("CRY-PBKDF-001", "Мало итераций KDF", "medium", "CWE-916", "A02:2021", "crypto", ("python",),
        _rx(r'(?:iterations|rounds)\s*=\s*(?:[1-9]\d{0,3})\b'),
        "Малое число итераций упрощает брутфорс хэша.", 'iterations=1000', "PBKDF2 ≥600000, лучше argon2"),
    # ── Auth/session (расширение) ──
    SecurityRule("AUTH-COOKIE-002", "Cookie без HttpOnly", "medium", "CWE-1004", "A05:2021", "cookie", ("python",),
        _rx(r'set_cookie\s*\((?![^)]*httponly\s*=\s*True)'),
        "Cookie без HttpOnly доступна JS → кража через XSS.", 'set_cookie("s", v)', 'set_cookie("s", v, httponly=True, secure=True)'),
    SecurityRule("AUTH-COOKIE-003", "Cookie без Secure", "medium", "CWE-614", "A05:2021", "cookie", ("python",),
        _rx(r'set_cookie\s*\((?![^)]*secure\s*=\s*True)'),
        "Cookie без Secure уходит по http.", 'set_cookie("s", v)', 'secure=True'),
    SecurityRule("AUTH-SESSION-002", "session без срока/fixation", "low", "CWE-384", "A07:2021", "session", ("python",),
        _rx(r'session\.permanent\s*=\s*True'),
        "Бессрочная сессия повышает риск угона.", 'session.permanent=True', "Задайте разумный таймаут"),
    SecurityRule("AUTH-BASIC-001", "HTTP Basic Auth по http", "medium", "CWE-319", "A02:2021", "config", ("python",),
        _rx(r'HTTPBasicAuth\s*\(|Authorization.*Basic\s'),
        "Basic Auth передаёт пароль в base64 — только по HTTPS.", 'HTTPBasicAuth(u,p)', "OAuth/токены по HTTPS"),
    # ── Config/infra (расширение) ──
    SecurityRule("CFG-PICKLE-CACHE-001", "Pickle как сериализатор кэша/сессии", "high", "CWE-502", "A08:2021", "deserialization", ("python",),
        _rx(r'(?:SESSION_SERIALIZER|serializer)\s*=\s*[\'"]?pickle'),
        "Pickle-сессии = RCE при компрометации ключа.", 'serializer=pickle', "json-сериализатор"),
    SecurityRule("CFG-FLASK-DEBUG-001", "Flask app.run(debug=True)", "high", "CWE-489", "A05:2021", "config", ("python",),
        _rx(r'\.run\s*\([^)]*debug\s*=\s*True'),
        "debug=True даёт Werkzeug-консоль = RCE.", 'app.run(debug=True)', "debug=False в production"),
    SecurityRule("CFG-CORS-CRED-001", "CORS: credentials + wildcard", "high", "CWE-942", "A05:2021", "config", ("python","javascript"),
        _rx(r'allow_credentials\s*=\s*True[^;]*allow_origins\s*=\s*\[[\'"]\*'),
        "credentials + origin=* — критическая утечка.", 'allow_origins=["*"], allow_credentials=True', "Явные домены"),
    SecurityRule("CFG-TRUST-PROXY-001", "Доверие всем прокси", "medium", "CWE-348", "A05:2021", "config", ("python",),
        _rx(r'ProxyFix\s*\([^)]*x_for\s*=\s*\d{2,}|trusted_proxies\s*=\s*[\'"]?\*'),
        "Доверие X-Forwarded-For от всех → подмена IP.", 'x_for=10', "Доверяйте только своим прокси"),
    SecurityRule("CFG-TLS-VER-001", "Принудительный TLS 1.0/1.1", "high", "CWE-327", "A02:2021", "config", ("python",),
        _rx(r'PROTOCOL_TLSv1(?:_1)?\b|ssl_version\s*=\s*ssl\.PROTOCOL_TLSv1\b'),
        "TLS 1.0/1.1 устарели.", 'ssl.PROTOCOL_TLSv1', "TLS 1.2+ (PROTOCOL_TLS_CLIENT)"),
    # ── SSRF/доступ (расширение) ──
    SecurityRule("SSRF-METADATA-001", "Доступ к cloud-метаданным", "high", "CWE-918", "A10:2021", "ssrf", ("*",),
        _rx(r'169\.254\.169\.254|metadata\.google\.internal'),
        "Запрос к 169.254.169.254 — типичная цель SSRF (кража cloud-кредов).", 'requests.get("http://169.254.169.254/")', "Блокируйте link-local в исходящих"),
    SecurityRule("ACC-IDOR-001", "Прямой доступ по ID из запроса", "medium", "CWE-639", "A01:2021", "access", ("python",),
        _rx(r'\.(?:get|filter|get_object_or_404)\s*\([^)]*id\s*=\s*request\.(?:args|GET|POST)'),
        "Объект по ID без проверки владельца → IDOR.", 'Doc.objects.get(id=request.GET["id"])', "Проверяйте owner == current_user"),
    SecurityRule("ACC-DEBUG-ROUTE-001", "Debug/admin endpoint без защиты", "medium", "CWE-489", "A05:2021", "access", ("python",),
        _rx(r'@app\.route\s*\(\s*[\'"]/(?:debug|admin|internal|_test)'),
        "Служебный роут без авторизации.", '@app.route("/debug")', "Требуйте admin-роль"),
    # ── Прочее ──
    SecurityRule("MISC-TODO-SEC-001", "TODO/FIXME про безопасность", "low", "CWE-546", "A09:2021", "config", ("*",),
        _rx(r'#\s*(?:TODO|FIXME|HACK|XXX).*(?:secur|auth|password|token|vuln|inject)'),
        "Незакрытая заметка о безопасности.", '# TODO: fix auth bypass', "Закройте до релиза"),
    SecurityRule("MISC-PRINT-SECRET-001", "Печать секрета в stdout", "low", "CWE-532", "A09:2021", "log", ("python",),
        _rx(r'print\s*\([^)]*(?:password|secret|token|api_key)\b'),
        "Печать секрета попадает в логи.", 'print(password)', "Не логируйте секреты"),
    SecurityRule("MISC-ASSERT-PERM-002", "Проверка прав через assert", "medium", "CWE-617", "A04:2021", "access", ("python",),
        _rx(r'assert\s+(?:current_user|user)\.(?:is_admin|is_staff|is_superuser)'),
        "assert отключается флагом -O.", 'assert user.is_admin', "if not user.is_admin: raise"),
    SecurityRule("MISC-EXEC-IMPORT-001", "Динамический __import__/importlib с вводом", "high", "CWE-470", "A03:2021", "rce", ("python",),
        _rx(r'(?:__import__|importlib\.import_module)\s*\([^)]*request\.'),
        "Импорт модуля по имени из запроса → RCE.", '__import__(request.args["m"])', "Whitelist модулей"),
    SecurityRule("MISC-GETATTR-001", "getattr с пользовательским именем", "medium", "CWE-470", "A03:2021", "rce", ("python",),
        _rx(r'getattr\s*\([^,]+,\s*request\.(?:args|GET|POST|form)'),
        "getattr по имени из запроса → доступ к произвольным атрибутам.", 'getattr(obj, request.args["f"])', "Whitelist атрибутов"),
    SecurityRule("MISC-TEMPFILE-001", "Небезопасный mktemp", "medium", "CWE-377", "A01:2021", "access", ("python",),
        _rx(r'tempfile\.mktemp\s*\(|os\.tmpnam\s*\('),
        "mktemp уязвим к race condition.", 'tempfile.mktemp()', "tempfile.mkstemp() / NamedTemporaryFile"),
    SecurityRule("MISC-YAML-CLOAD-001", "yaml CLoader без safe", "high", "CWE-502", "A08:2021", "deserialization", ("python",),
        _rx(r'yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:C?Loader|FullLoader)'),
        "FullLoader/CLoader всё ещё может инстанцировать объекты.", 'yaml.load(s, Loader=Loader)', "yaml.safe_load(s)"),
    SecurityRule("MISC-SUBPROCESS-PARTIAL-001", "subprocess с конкатенацией", "high", "CWE-78", "A03:2021", "command", ("python",),
        _rx(r'subprocess\.(?:run|call|Popen|check_output)\s*\(\s*[\'"][^\'"]*[\'"]\s*\+'),
        "Склейка строк в команду → инъекция.", 'subprocess.run("ls "+path)', "Список аргументов, shell=False"),
    SecurityRule("MISC-JINJA-AUTOESCAPE-001", "Jinja2 autoescape=False", "high", "CWE-79", "A03:2021", "xss", ("python",),
        _rx(r'autoescape\s*=\s*False|Environment\s*\((?![^)]*autoescape)'),
        "Отключённое автоэкранирование Jinja → XSS.", 'Environment(autoescape=False)', "autoescape=select_autoescape()"),
    SecurityRule("MISC-WILDCARD-IMPORT-001", "from x import *", "low", "CWE-710", "A06:2021", "config", ("python",),
        _rx(r'^from\s+\S+\s+import\s+\*'),
        "Wildcard-импорт скрывает источник имён, мешает аудиту.", 'from os import *', "Явные импорты"),
    SecurityRule("MISC-HTTP-NOVERIFY-CTX-001", "ssl _create_unverified_context", "high", "CWE-295", "A02:2021", "config", ("python",),
        _rx(r'_create_unverified_context|CERT_NONE'),
        "Отключение проверки сертификата → MITM.", 'ssl._create_unverified_context()', "create_default_context()"),
    SecurityRule("MISC-DJANGO-CSRF-EXEMPT-001", "csrf_exempt", "medium", "CWE-352", "A01:2021", "config", ("python",),
        _rx(r'@csrf_exempt'),
        "Отключение CSRF-защиты на view.", '@csrf_exempt', "Не отключайте CSRF без причины"),
    SecurityRule("MISC-SQL-RAW-001", "Django .raw()/extra()", "high", "CWE-89", "A03:2021", "sql", ("python",),
        _rx(r'\.(?:raw|extra)\s*\([^)]*[%+]\s*|\.raw\s*\(\s*f[\'"]'),
        "raw/extra с конкатенацией → SQLi.", '.raw("SELECT..."+x)', "Параметры: .raw(sql, [params])"),
    SecurityRule("MISC-OPEN-WRITE-001", "Запись файла по пути из запроса", "high", "CWE-22", "A01:2021", "access", ("python",),
        _rx(r'open\s*\([^,)]*request\.(?:args|form|GET|POST)[^,)]*,\s*[\'"][wa]'),
        "Запись по пользовательскому пути → перезапись файлов.", 'open(request.args["p"],"w")', "Валидируйте путь, фиксируйте директорию"),
    SecurityRule("MISC-EVAL-INPUT-001", "ast.literal_eval это ок, eval(input())", "critical", "CWE-95", "A03:2021", "rce", ("python",),
        _rx(r'eval\s*\(\s*input\s*\('),
        "eval(input()) = прямой RCE.", 'eval(input())', "int(input()) / ast.literal_eval"),
    SecurityRule("MISC-WEAK-SALT-001", "Хэш пароля без соли", "high", "CWE-759", "A02:2021", "crypto", ("python",),
        _rx(r'hashlib\.(?:sha256|sha512)\s*\([^)]*password[^)]*\)\.hexdigest'),
        "Хэш пароля без соли уязвим к rainbow tables.", 'sha256(password).hexdigest()', "bcrypt/argon2 с солью"),
    SecurityRule("MISC-FLASK-SEND-FILE-001", "send_file с путём из запроса", "high", "CWE-22", "A01:2021", "access", ("python",),
        _rx(r'send_file\s*\([^)]*request\.(?:args|GET)'),
        "send_file по пользовательскому пути → чтение произвольных файлов.", 'send_file(request.args["f"])', "Whitelist + safe_join"),
    SecurityRule("MISC-NODE-CHILD-001", "Node child_process.exec с шаблоном", "critical", "CWE-78", "A03:2021", "command", ("javascript","typescript"),
        _rx(r'(?:child_process\.)?exec(?:Sync)?\s*\(\s*`[^`]*\$\{'),
        "Шаблонная строка в exec → command injection.", 'exec(`ls ${dir}`)', "execFile с массивом аргументов"),
    SecurityRule("MISC-JS-SETTIMEOUT-STR-001", "setTimeout со строкой", "medium", "CWE-95", "A03:2021", "rce", ("javascript",),
        _rx(r'set(?:Timeout|Interval)\s*\(\s*[\'"]'),
        "Строка в setTimeout исполняется как eval.", 'setTimeout("code()",1)', "Передавайте функцию"),
    SecurityRule("MISC-JS-LOCALSTORAGE-TOKEN-001", "Токен в localStorage", "low", "CWE-922", "A04:2021", "session", ("javascript","typescript"),
        _rx(r'localStorage\.(?:setItem\s*\(\s*[\'"](?:token|jwt|auth)|set)'),
        "Токен в localStorage доступен XSS. Лучше httpOnly cookie.", 'localStorage.setItem("token",t)', "httpOnly Secure cookie"),
    SecurityRule("MISC-PROTO-POLLUTION-001", "Прототипное загрязнение (__proto__)", "high", "CWE-1321", "A08:2021", "deserialization", ("javascript","typescript"),
        _rx(r'\[[\'"]__proto__[\'"]\]|Object\.assign\s*\([^)]*JSON\.parse'),
        "Слияние недоверенного JSON → prototype pollution.", 'obj[key]=val // key из ввода', "Проверяйте ключи, Object.create(null)"),
    SecurityRule("MISC-GO-SQL-001", "Go: Sprintf в SQL", "critical", "CWE-89", "A03:2021", "sql", ("go",),
        _rx(r'(?:Query|Exec)\s*\(\s*fmt\.Sprintf'),
        "Sprintf в SQL → инъекция.", 'db.Query(fmt.Sprintf("...%s",x))', "db.Query(\"...?\", x)"),
    SecurityRule("MISC-GO-CMD-001", "Go: exec.Command с конкатенацией", "high", "CWE-78", "A03:2021", "command", ("go",),
        _rx(r'exec\.Command\s*\(\s*"(?:sh|bash|cmd)"'),
        "Запуск shell в Go → инъекция.", 'exec.Command("sh","-c",input)', "Прямой бинарь без shell"),
    SecurityRule("MISC-JAVA-DESER-001", "Java ObjectInputStream", "critical", "CWE-502", "A08:2021", "deserialization", ("java",),
        _rx(r'new\s+ObjectInputStream|readObject\s*\('),
        "Java-десериализация недоверенных данных → RCE.", 'in.readObject()', "Безопасный формат (JSON) + allowlist"),
    SecurityRule("MISC-PHP-INCLUDE-001", "PHP include с переменной", "critical", "CWE-98", "A03:2021", "rce", ("php",),
        _rx(r'(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)'),
        "include с пользовательским вводом → RFI/LFI → RCE.", 'include($_GET["page"])', "Whitelist страниц"),
    # ═══ Фреймворк-специфичные правила (40) ═══
    # ── FastAPI / Starlette ──
    SecurityRule("FW-FASTAPI-001", "FastAPI без зависимости аутентификации на mutating-роуте", "low", "CWE-862", "A01:2021", "access", ("python",),
        _rx(r'@(?:app|router)\.(?:post|put|delete|patch)\s*\([^)]*\)(?![^@]*Depends)'),
        "Изменяющий роут без Depends(auth) — проверьте авторизацию.", '@app.post("/x")', "dependencies=[Depends(get_current_user)]"),
    SecurityRule("FW-FASTAPI-002", "FastAPI debug/reload в проде", "medium", "CWE-489", "A05:2021", "config", ("python",),
        _rx(r'uvicorn\.run\s*\([^)]*reload\s*=\s*True'),
        "reload=True не для продакшена.", 'uvicorn.run(app, reload=True)', "reload=False"),
    SecurityRule("FW-FASTAPI-003", "Jinja2Templates без autoescape", "high", "CWE-79", "A03:2021", "xss", ("python",),
        _rx(r'Jinja2Templates\s*\((?![^)]*autoescape)'),
        "Шаблоны FastAPI без autoescape → XSS.", 'Jinja2Templates(directory="t")', "autoescape=True"),
    # ── Django ──
    SecurityRule("FW-DJANGO-001", "Django RawSQL/extra", "high", "CWE-89", "A03:2021", "sql", ("python",),
        _rx(r'RawSQL\s*\(|\.extra\s*\(\s*(?:select|where)\s*='),
        "RawSQL/extra — высокий риск SQLi.", 'RawSQL("...%s"%x)', "ORM или параметры"),
    SecurityRule("FW-DJANGO-002", "Django @csrf_exempt", "medium", "CWE-352", "A01:2021", "config", ("python",),
        _rx(r'@csrf_exempt|csrf_exempt\s*\('),
        "Отключение CSRF на view.", '@csrf_exempt', "Оставьте CSRF включённым"),
    SecurityRule("FW-DJANGO-003", "Django DEBUG=True в settings", "high", "CWE-489", "A05:2021", "config", ("python",),
        _rx(r'^DEBUG\s*=\s*True'),
        "DEBUG=True раскрывает трейсбеки и настройки.", 'DEBUG = True', "DEBUG = os.getenv(...)"),
    SecurityRule("FW-DJANGO-004", "Django HttpResponse с пользовательским HTML", "high", "CWE-79", "A03:2021", "xss", ("python",),
        _rx(r'HttpResponse\s*\([^)]*request\.(?:GET|POST|body)'),
        "Вывод ввода без экранирования → XSS.", 'HttpResponse(request.GET["x"])', "render() с шаблоном"),
    SecurityRule("FW-DJANGO-005", "Django SECURE_SSL_REDIRECT отключён", "low", "CWE-319", "A02:2021", "config", ("python",),
        _rx(r'SECURE_SSL_REDIRECT\s*=\s*False'),
        "Нет принудительного HTTPS.", 'SECURE_SSL_REDIRECT = False', "True в проде"),
    # ── Flask ──
    SecurityRule("FW-FLASK-001", "Flask render_template_string с вводом", "critical", "CWE-1336", "A03:2021", "ssti", ("python",),
        _rx(r'render_template_string\s*\([^)]*(?:request\.|\+|%|\.format|f[\'"])'),
        "SSTI во Flask → RCE.", 'render_template_string("Hi "+name)', "render_template с файлом"),
    SecurityRule("FW-FLASK-002", "Flask send_from_directory с вводом", "high", "CWE-22", "A01:2021", "access", ("python",),
        _rx(r'send_from_directory\s*\([^)]*request\.'),
        "Path traversal при отдаче файлов.", 'send_from_directory(d, request.args["f"])', "Валидируйте имя файла"),
    SecurityRule("FW-FLASK-003", "Flask SECRET_KEY захардкожен", "high", "CWE-798", "A02:2021", "secrets", ("python",),
        _rx(r'app\.secret_key\s*=\s*[\'"][^\'"]+[\'"]'),
        "Секретный ключ в коде ломает безопасность сессий.", 'app.secret_key="abc"', "os.getenv"),
    SecurityRule("FW-FLASK-004", "Flask jsonify с raw SQL результатом", "low", "CWE-200", "A01:2021", "access", ("python",),
        _rx(r'@app\.route\s*\([^)]*\)\s*\n\s*def\s+\w+\(\):[^#]*\.execute\('),
        "Эндпоинт с прямым SQL — проверьте авторизацию и фильтрацию.", '', "Используйте ORM + проверки"),
    # ── Express / Node ──
    SecurityRule("FW-EXPRESS-001", "Express res.send с вводом", "high", "CWE-79", "A03:2021", "xss", ("javascript","typescript"),
        _rx(r'res\.send\s*\([^)]*req\.(?:query|params|body)'),
        "Вывод ввода → reflected XSS.", 'res.send(req.query.q)', "Экранируйте / шаблонизатор с автоэкранированием"),
    SecurityRule("FW-EXPRESS-002", "Express без helmet", "low", "CWE-693", "A05:2021", "config", ("javascript","typescript"),
        _rx(r'express\s*\(\s*\)(?![\s\S]{0,400}helmet)'),
        "Нет helmet — отсутствуют security-заголовки.", 'const app = express()', "app.use(helmet())"),
    SecurityRule("FW-EXPRESS-003", "Express CORS origin:*", "medium", "CWE-942", "A05:2021", "config", ("javascript","typescript"),
        _rx(r'cors\s*\(\s*\{\s*origin\s*:\s*[\'"]\*'),
        "CORS * разрешает любой источник.", "cors({origin:'*'})", "Конкретные домены"),
    SecurityRule("FW-EXPRESS-004", "Express трекинг тела без лимита", "low", "CWE-400", "A05:2021", "dos", ("javascript","typescript"),
        _rx(r'bodyParser\.(?:json|urlencoded)\s*\(\s*\)(?![^)]*limit)'),
        "Парсер без limit → DoS большими телами.", 'bodyParser.json()', "limit: '100kb'"),
    SecurityRule("FW-NODE-001", "Node fs с путём из запроса", "high", "CWE-22", "A01:2021", "access", ("javascript","typescript"),
        _rx(r'fs\.(?:readFile|writeFile|unlink|createReadStream)\s*\([^)]*req\.'),
        "Файловая операция по пользовательскому пути.", 'fs.readFile(req.query.f)', "path.basename + фикс директория"),
    # ── React / фронт ──
    SecurityRule("FW-REACT-001", "React href={userInput}", "medium", "CWE-79", "A03:2021", "xss", ("javascript","typescript"),
        _rx(r'href\s*=\s*\{(?!["\'])[^}]*(?:props|state|data|user)'),
        "javascript:-URL в href → XSS.", 'href={userUrl}', "Проверяйте протокол (http/https)"),
    SecurityRule("FW-VUE-001", "Vue v-html с переменной", "high", "CWE-79", "A03:2021", "xss", ("javascript","typescript"),
        _rx(r'v-html\s*=\s*[\'"]'),
        "v-html вставляет HTML без санитизации.", 'v-html="content"', "DOMPurify или текст"),
    SecurityRule("FW-ANGULAR-001", "Angular bypassSecurityTrust", "high", "CWE-79", "A03:2021", "xss", ("typescript","javascript"),
        _rx(r'bypassSecurityTrust(?:Html|Url|Script|ResourceUrl)\s*\('),
        "Обход санитизации Angular → XSS.", 'bypassSecurityTrustHtml(x)', "Доверяйте только статике"),
    # ── Spring / Java ──
    SecurityRule("FW-SPRING-001", "Spring @CrossOrigin(origins=*)", "medium", "CWE-942", "A05:2021", "config", ("java",),
        _rx(r'@CrossOrigin\s*\([^)]*[\'"]\*[\'"]'),
        "CORS * в Spring.", '@CrossOrigin(origins="*")', "Конкретные домены"),
    SecurityRule("FW-SPRING-002", "Spring SpEL с вводом", "critical", "CWE-94", "A03:2021", "rce", ("java",),
        _rx(r'(?:SpelExpressionParser|parseExpression)\s*\([^)]*(?:request|param|input)'),
        "SpEL-инъекция → RCE.", 'parser.parseExpression(userInput)', "Не парсите ввод как SpEL"),
    SecurityRule("FW-SPRING-003", "Spring @PreAuthorize отсутствует на контроллере", "low", "CWE-862", "A01:2021", "access", ("java",),
        _rx(r'@(?:PostMapping|DeleteMapping|PutMapping)(?![\s\S]{0,200}@PreAuthorize)'),
        "Изменяющий endpoint без @PreAuthorize.", '@PostMapping("/x")', "@PreAuthorize(...)"),
    SecurityRule("FW-JAVA-XXE-001", "Java XML parser без защиты XXE", "high", "CWE-611", "A05:2021", "xxe", ("java",),
        _rx(r'DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature)'),
        "XML-парсер без отключения внешних сущностей → XXE.", 'DocumentBuilderFactory.newInstance()', "setFeature(disallow-doctype, true)"),
    # ── Rails / Ruby ──
    SecurityRule("FW-RAILS-001", "Rails раскрытие через permit!", "high", "CWE-915", "A08:2021", "access", ("ruby",),
        _rx(r'params\.permit!|params\.require\([^)]*\)\.permit!'),
        "permit! разрешает все параметры → mass assignment.", 'params.permit!', "Явный список полей"),
    SecurityRule("FW-RAILS-002", "Rails raw SQL в where", "critical", "CWE-89", "A03:2021", "sql", ("ruby",),
        _rx(r'\.where\s*\(\s*["\'][^"\']*#\{'),
        "Интерполяция в where → SQLi.", 'where("id = #{id}")', "where(id: id) или ?-плейсхолдеры"),
    SecurityRule("FW-RAILS-003", "Rails html_safe/raw с вводом", "high", "CWE-79", "A03:2021", "xss", ("ruby",),
        _rx(r'\.html_safe\b|\braw\s*\(\s*(?:params|@)'),
        "html_safe отключает экранирование.", 'params[:x].html_safe', "Не отключайте экранирование"),
    SecurityRule("FW-RUBY-001", "Ruby Marshal.load", "critical", "CWE-502", "A08:2021", "deserialization", ("ruby",),
        _rx(r'Marshal\.load\s*\('),
        "Marshal.load недоверенных данных → RCE.", 'Marshal.load(data)', "JSON.parse"),
    # ── Laravel / PHP ──
    SecurityRule("FW-LARAVEL-001", "Laravel DB::raw с вводом", "critical", "CWE-89", "A03:2021", "sql", ("php",),
        _rx(r'DB::raw\s*\([^)]*\$'),
        "DB::raw с переменной → SQLi.", 'DB::raw("id=".$id)', "Параметризованные запросы / Eloquent"),
    SecurityRule("FW-LARAVEL-002", "Laravel {!! !!} вывод", "high", "CWE-79", "A03:2021", "xss", ("php",),
        _rx(r'\{!!\s*\$'),
        "{!! !!} выводит без экранирования.", '{!! $userInput !!}', "{{ $userInput }}"),
    SecurityRule("FW-PHP-001", "PHP unserialize", "critical", "CWE-502", "A08:2021", "deserialization", ("php",),
        _rx(r'\bunserialize\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)'),
        "unserialize недоверенных данных → object injection.", 'unserialize($_GET["d"])', "json_decode"),
    SecurityRule("FW-PHP-002", "PHP extract($_REQUEST)", "high", "CWE-915", "A08:2021", "access", ("php",),
        _rx(r'extract\s*\(\s*\$_(?:GET|POST|REQUEST)'),
        "extract() из запроса перезаписывает переменные.", 'extract($_POST)', "Явный доступ к ключам"),
    SecurityRule("FW-PHP-003", "PHP preg_replace /e", "critical", "CWE-95", "A03:2021", "rce", ("php",),
        _rx(r'preg_replace\s*\(\s*[\'"][^\'"]*/e[\'"]'),
        "Модификатор /e выполняет код.", 'preg_replace("/x/e",...)', "preg_replace_callback"),
    # ── GraphQL / API ──
    SecurityRule("FW-GQL-001", "GraphQL без ограничения глубины", "low", "CWE-770", "A05:2021", "dos", ("python","javascript"),
        _rx(r'GraphQLSchema\s*\((?![\s\S]{0,300}depth)|ApolloServer\s*\((?![\s\S]{0,300}depthLimit)'),
        "Нет лимита глубины → DoS вложенными запросами.", 'new ApolloServer({schema})', "depthLimit / костинг"),
    # ── Контейнеры / IaC (в коде/конфигах) ──
    SecurityRule("FW-DOCKER-001", "Dockerfile USER root / нет USER", "low", "CWE-250", "A05:2021", "config", ("*",),
        _rx(r'^USER\s+root\b'),
        "Контейнер под root повышает риск.", 'USER root', "USER приложение"),
    SecurityRule("FW-K8S-001", "K8s privileged: true", "high", "CWE-250", "A05:2021", "config", ("yaml",),
        _rx(r'privileged\s*:\s*true'),
        "Привилегированный контейнер = доступ к хосту.", 'privileged: true', "privileged: false"),
    SecurityRule("FW-K8S-002", "K8s hostNetwork/hostPID true", "high", "CWE-250", "A05:2021", "config", ("yaml",),
        _rx(r'host(?:Network|PID|IPC)\s*:\s*true'),
        "Доступ к хост-неймспейсам.", 'hostNetwork: true', "false"),
    SecurityRule("FW-TERRAFORM-001", "Terraform 0.0.0.0/0 в security group", "high", "CWE-284", "A05:2021", "config", ("*",),
        _rx(r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0'),
        "Открытие порта всему интернету.", 'cidr_blocks = ["0.0.0.0/0"]', "Ограничьте диапазон IP"),
    SecurityRule("FW-ENV-001", "Секрет в .env закоммичен", "medium", "CWE-798", "A07:2021", "secrets", ("*",),
        _rx(r'^(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*\S{6,}'),
        "Реальный секрет в .env-файле.", 'API_KEY=sk-real-value', ".env в .gitignore, пример в .env.example"),
    SecurityRule("FW-NGINX-001", "nginx server_tokens on", "low", "CWE-200", "A05:2021", "config", ("*",),
        _rx(r'server_tokens\s+on'),
        "Раскрытие версии nginx.", 'server_tokens on;', "server_tokens off;"),
]


# ═════════════════════════════════════════════════════════════════════════════
# Aggregate
# ═════════════════════════════════════════════════════════════════════════════

ALL_RULES: List[SecurityRule] = (
    INJECTION_RULES + CRYPTO_RULES + AUTH_RULES
    + DESER_RULES + ACCESS_RULES + SSRF_RULES + CONFIG_RULES
)


@lru_cache(maxsize=32)
def rules_for_language(lang: str) -> List[SecurityRule]:
    """Возвращает правила, применимые к данному языку (кэшируется)."""
    return [r for r in ALL_RULES if "*" in r.languages or lang in r.languages]


def rule_stats() -> dict:
    """Статистика покрытия по правилам."""
    by_sev: dict = {}
    by_owasp: dict = {}
    by_cat: dict = {}
    for r in ALL_RULES:
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
        by_owasp[r.owasp] = by_owasp.get(r.owasp, 0) + 1
        by_cat[r.category] = by_cat.get(r.category, 0) + 1
    return {
        "total": len(ALL_RULES),
        "by_severity": by_sev,
        "by_owasp": by_owasp,
        "by_category": by_cat,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(rule_stats(), indent=2, ensure_ascii=False))
