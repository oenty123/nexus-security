# Nexus Core — Инструкция по запуску

Бесплатная версия. Работает на чистом Python 3.8+ без установки зависимостей.

## Вариант 1: Веб-интерфейс (проще всего)

```bash
# 1. Распакуйте архив
tar -xzf nexus-core.tar.gz
cd nexus-core

# 2. Запустите сервер
python3 nexus_core/server.py

# 3. Откройте в браузере:
#    http://localhost:8000
```

Вставьте код в поле → нажмите «Проверить» → увидите список уязвимостей.

Другой порт (если 8000 занят):
```bash
python3 nexus_core/server.py 8080
```

Остановить сервер: `Ctrl+C`

## Вариант 2: Командная строка

```bash
# Анализ одного файла
python3 nexus_core/cli.py путь/к/файлу.py

# В формате JSON (для скриптов/CI)
python3 nexus_core/cli.py файл.py --format json

# Глубина анализа: 1 (быстро), 2 (стандарт), 3 (максимум)
python3 nexus_core/cli.py файл.py --depth 3
```

## Вариант 3: Из своего Python-кода

```python
import sys
sys.path.insert(0, "nexus_core")
from engine import analyze

result = analyze(open("myfile.py").read(), "myfile.py", depth=2)
print(f"Оценка: {result.grade} ({result.score}/100)")
for f in result.findings:
    print(f"  [{f.severity}] строка {f.line}: {f.title}")
```

## Тесты

```bash
python3 tests/test_refactor_basic.py
```

## Что умеет бесплатная версия

- 159 правил безопасности (SQL-инъекции, RCE, секреты, XSS, SSRF и др.)
- Межпроцедурный taint-анализ (Python)
- Детект секретов (AWS, GitHub, приватные ключи)
- Базовый рефакторинг
- Простой веб-интерфейс + CLI
- SARIF-экспорт

## Чего НЕТ в бесплатной версии

Доступно в **Nexus Enterprise**:
- Dataflow-анализ через CFG (path-sensitive)
- Кросс-модульный анализ (taint через файлы)
- Тройной анализ (подтверждение находок)
- Авто-фикс уязвимостей
- Продвинутый рефакторинг
- Compliance-отчёты (PCI DSS / HIPAA / SOC2 / GDPR)
- Пакетный анализ папок и ZIP-архивов
- Инкрементальное сканирование (кэш + git-diff)
- Графики, анимации, современный интерфейс
- VS Code расширение

## Проблемы

**`ModuleNotFoundError`** — запускайте из папки `nexus-core`, либо:
```bash
export PYTHONPATH=$PWD/nexus_core:$PYTHONPATH
```

**Порт занят** — укажите другой: `python3 nexus_core/server.py 8080`

**Python не найден** — проверьте версию: `python3 --version` (нужен 3.8+)
