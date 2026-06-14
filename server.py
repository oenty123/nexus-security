#!/usr/bin/env python3
"""
server.py — простой веб-интерфейс Nexus Core (бесплатная версия).

Работает на стандартной библиотеке Python (без зависимостей).
Базовый функционал: вставил код → получил список уязвимостей.

Продвинутый интерфейс (графики, рефакторинг, авто-фикс, compliance,
пакетный анализ папок/ZIP, dataflow) — в Nexus Enterprise.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).parent))
from engine import analyze

PORT = 8000

# Намеренно простая страница: без графиков, анимаций, вкладок.
PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Nexus Core</title>
<style>
  body { font-family: monospace; max-width: 760px; margin: 30px auto; padding: 0 16px; background: #fff; color: #222; }
  h1 { font-size: 20px; }
  .free { font-size: 12px; color: #888; }
  textarea { width: 100%; height: 240px; font-family: monospace; font-size: 13px; padding: 10px; border: 1px solid #ccc; }
  button { font-family: monospace; font-size: 14px; padding: 8px 18px; margin-top: 8px; background: #2f6f4f; color: #fff; border: none; cursor: pointer; }
  button:hover { background: #255a40; }
  .grade { font-size: 28px; font-weight: bold; margin: 14px 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; }
  th { background: #f4f4f4; }
  .critical { color: #b00; font-weight: bold; }
  .high { color: #c60; }
  .medium { color: #a80; }
  .low { color: #666; }
  .upsell { margin-top: 24px; padding: 12px; background: #f4f8f5; border: 1px solid #cce; font-size: 13px; }
  .upsell b { color: #2f6f4f; }
</style>
</head>
<body>
  <h1>Nexus Core <span class="free">бесплатная версия</span></h1>
  <p class="free">Базовый анализ безопасности кода. Вставьте код и нажмите «Проверить».</p>
  <textarea id="code" placeholder="Вставьте код сюда..."></textarea><br>
  <button onclick="scan()">Проверить</button>
  <div id="out"></div>
  <div class="upsell">
    Это бесплатная версия с базовым функционалом.<br>
    <b>Nexus Enterprise</b> добавляет: dataflow-анализ, кросс-модульный анализ,
    авто-фикс, рефакторинг, compliance-отчёты (PCI/HIPAA/SOC2/GDPR),
    пакетный анализ папок и ZIP, графики, VS Code расширение.<br>
    Связь и приобретение: <a href="https://t.me/Oenty_888" target="_blank">Telegram @Oenty_888</a>
  </div>
<script>
async function scan() {
  const code = document.getElementById('code').value;
  if (!code.trim()) { alert('Вставьте код'); return; }
  const res = await fetch('/scan', { method:'POST', body: code });
  const data = await res.json();
  let html = '<div class="grade">Оценка: ' + data.grade + ' (' + data.score + '/100)</div>';
  if (!data.findings.length) {
    html += '<p>Уязвимостей не найдено.</p>';
  } else {
    html += '<table><tr><th>Уровень</th><th>Строка</th><th>Проблема</th><th>CWE</th></tr>';
    for (const f of data.findings) {
      html += '<tr><td class="'+f.severity+'">'+f.severity+'</td><td>'+(f.line||'?')+
              '</td><td>'+esc(f.title)+'</td><td>'+esc(f.cwe||'')+'</td></tr>';
    }
    html += '</table>';
  }
  document.getElementById('out').innerHTML = html;
}
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # тихий лог

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, "text/html; charset=utf-8", PAGE.encode("utf-8"))
        else:
            self._send(404, "text/plain", b"404")

    def do_POST(self):
        if self.path != "/scan":
            self._send(404, "text/plain", b"404")
            return
        length = int(self.headers.get("Content-Length", 0))
        code = self.rfile.read(length).decode("utf-8", "ignore")
        try:
            result = analyze(code, "snippet.py", 2).to_dict()
        except Exception as e:
            result = {"grade": "?", "score": 0, "findings": [], "error": str(e)}
        self._send(200, "application/json", json.dumps(result).encode("utf-8"))

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    port = PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Nexus Core запущен: http://localhost:{port}")
    print("Остановить: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
        server.shutdown()


if __name__ == "__main__":
    main()
