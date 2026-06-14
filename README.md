# Nexus Core

Бесплатный open-source SAST-сканер (Apache 2.0). Находит уязвимости в исходном коде.

## Возможности (бесплатно)

- **159 правила безопасности** — SQL-инъекции, RCE, секреты, SSRF, XSS и др.
- **OWASP Top 10** — покрытие 9/10 категорий
- **Межпроцедурный taint** — отслеживание данных внутри файла
- **Детект секретов** — AWS, GitHub, приватные ключи
- **Подавление false positives** — `# nosec`, baseline, `.nexusignore`
- **SARIF-экспорт** — интеграция с GitHub/GitLab
- **CLI** — для CI/CD

## Установка

```bash
pip install -r requirements.txt
python3 nexus_core/server.py   # веб-интерфейс на http://localhost:8000
python3 nexus_core/cli.py app.py   # или командная строка
```

## Пример

```bash
$ python3 nexus_core/cli.py vulnerable.py
vulnerable.py: D (38/100), 3 проблем
  [CRITICAL] строка 5: SQL-инъекция [CWE-89]
  [CRITICAL] строка 8: Хардкод секрета [CWE-798]
  [HIGH    ] строка 12: Устаревший хэш MD5 [CWE-327]
```

## Nexus Enterprise

Продвинутые возможности доступны в коммерческой версии:

| Функция | Core (free) | Enterprise |
|---------|:-----------:|:----------:|
| Regex-правила (159) | ✅ | ✅ |
| Taint внутри файла | ✅ | ✅ |
| Детект секретов | ✅ | ✅ |
| SARIF | ✅ | ✅ |
| **Dataflow (CFG, path-sensitive)** | ❌ | ✅ |
| **Кросс-модульный анализ** | ❌ | ✅ |
| **Авто-исправления** | ❌ | ✅ |
| **Compliance (PCI/HIPAA/SOC2/GDPR)** | ❌ | ✅ |
| **Инкрементальный скан (кэш/git-diff)** | ❌ | ✅ |
| **Веб-платформа + командная работа** | ❌ | ✅ |
| **VS Code расширение** | ❌ | ✅ |

→ https://nexus-security.io/enterprise

## Лицензия

Apache License 2.0 — свободное использование с патентной защитой.
