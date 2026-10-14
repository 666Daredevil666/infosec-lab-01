"""Build a standalone HTML report from this workflow's evidence."""
import argparse
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import tomllib
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


def key(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def table(headers, rows):
    head = ''.join(f'<th>{escape(str(v))}</th>' for v in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{escape(str(v))}</td>' for v in row) + '</tr>' for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def build(evidence, output, project):
    sections, raw, problems = [], [], []

    def read(name, xml=False):
        path = evidence / name
        try:
            text = path.read_text()
            data = ET.fromstring(text) if xml else json.loads(text)
        except (OSError, ValueError, ET.ParseError, DefusedXmlException) as exc:
            problems.append(f'{name}: отчёт отсутствует или повреждён ({exc})')
            return None
        raw.append(f'<details><summary>{escape(name)}</summary><pre>{escape(text)}</pre></details>')
        return data

    inventory = read('packages.json')
    bandit = read('bandit.json')
    audit = read('pip-audit.json')
    snyk = read('snyk.json')
    tests = read('pytest.xml', xml=True)
    runtime = dict(line.strip().split('==', 1) for line in (project / 'requirements.txt').read_text().splitlines() if '==' in line)
    runtime = {key(n): v for n, v in runtime.items()}
    config = tomllib.loads((project / 'pyproject.toml').read_text())
    direct = {key(re.split(r'[<>=!~\[; ]', n)[0]) for n in config['project']['dependencies']}
    installed = {key(p['metadata']['name']): p['metadata'] for p in (inventory or {}).get('installed', [])}
    audited = {key(p['name']): p for p in (audit or {}).get('dependencies', [])}
    roles = {
        'flask': 'Веб-фреймворк: маршруты API, запросы и ответы',
        'pyjwt': 'Создание и проверка JWT для аутентификации',
        'argon2-cffi': 'Хэширование и проверка паролей алгоритмом Argon2',
        'argon2-cffi-bindings': 'Нативные привязки к реализации Argon2',
        'cffi': 'Интерфейс Python к библиотекам на C',
        'pycparser': 'Разбор объявлений C для CFFI',
        'werkzeug': 'HTTP/WSGI-инструменты, используемые Flask',
        'jinja2': 'Шаблонизатор, поставляемый как зависимость Flask',
        'markupsafe': 'Экранирование HTML, в том числе пользовательских данных API',
        'itsdangerous': 'Подпись данных в экосистеме Flask; JWT реализован через PyJWT',
        'click': 'Командная строка Flask',
        'blinker': 'Механизм сигналов Flask',
    }
    rows = []
    for name, pinned in sorted(runtime.items()):
        meta = installed.get(name, {})
        result = audited.get(name)
        status = 'Нет результата'
        if result is not None:
            status = ('Пропущено: ' + result['skip_reason']) if 'skip_reason' in result else f"Находок: {len(result.get('vulns', []))}"
        rows.append((meta.get('name', name), meta.get('version', 'Нет данных'), pinned,
                     'Прямая' if name in direct else 'Транзитивная', roles.get(name, meta.get('summary', '—')), status))
    sections.append('<h2>Библиотеки приложения</h2><p>Все пакеты из requirements.txt. Прямые зависимости заданы в pyproject.toml, остальные нужны этим библиотекам. Версия «установлена» получена из окружения CI.</p>' + table(['Библиотека', 'Установлена', 'Закреплена', 'Тип', 'Назначение', 'pip-audit'], rows))
    rows = []
    for name, meta in sorted(installed.items()):
        license_name = meta.get('license_expression') or meta.get('license') or '; '.join(c for c in meta.get('classifier', []) if c.startswith('License ::')) or 'Не указана'
        rows.append((meta['name'], meta.get('version', '—'), 'Приложение' if name in runtime else 'Инструменты / окружение', meta.get('summary', '—'), license_name, '\n'.join(meta.get('requires_dist', [])) or 'Не заявлены'))
    sections.append('<h2>Полный состав Python-окружения</h2><p>Включает библиотеки приложения, pytest, Bandit, pip-audit и их зависимости. Requires-Dist — объявления из метаданных: условия после «;» и extras могут не быть активны. SCA проверяет requirements.txt, а не все служебные пакеты этой таблицы. Лицензии приведены из метаданных пакетов.</p>' + table(['Пакет', 'Версия', 'Группа', 'Описание', 'Лицензия', 'Requires-Dist'], rows))
    status_rows = []
    if bandit is not None:
        findings = bandit.get('results', [])
        errors = bandit.get('errors', [])
        totals = bandit.get('metrics', {}).get('_totals', {})
        status_rows.append(('Bandit · SAST', f'{len(findings)} находок; ошибок анализа: {len(errors)}', f"Строк кода: {totals.get('loc', '—')}; пропущенных проверок: {totals.get('skipped_tests', '—')}"))
        sections.append('<h2>Статический анализ кода · Bandit</h2><p>Проверяется каталог src. В исходном коде документировано исключение B106 для token_type="Bearer": это тип токена, а не пароль.</p>' + table(['Файл', 'Строка', 'Правило', 'Уровень', 'Описание'], [(f.get('filename'), f.get('line_number'), f.get('test_id'), f.get('issue_severity'), f.get('issue_text')) for f in findings]) + '<pre>' + escape(json.dumps(totals, ensure_ascii=False, indent=2)) + '</pre>')
        if errors:
            problems.append('Bandit сообщил об ошибках анализа; см. исходный JSON.')
    if audit is not None:
        vulns = [(p['name'], p['version'], v.get('id'), v.get('description', ''), ', '.join(v.get('fix_versions', []))) for p in audit.get('dependencies', []) for v in p.get('vulns', [])]
        skipped = [p['name'] for p in audit.get('dependencies', []) if 'skip_reason' in p]
        status_rows.append(('pip-audit · SCA', f'{len(vulns)} находок; пропущено: {len(skipped)}', f"Пакетов в отчёте: {len(audit.get('dependencies', []))}"))
        sections.append('<h2>Уязвимости зависимостей · pip-audit</h2>' + table(['Пакет', 'Версия', 'ID', 'Описание', 'Исправленные версии'], vulns))
    if snyk is not None:
        findings = snyk.get('vulnerabilities', [])
        status_rows.append(('Snyk · SCA', f"ok={snyk.get('ok', 'нет результата')}; находок: {len(findings)}", f"Зависимостей: {snyk.get('dependencyCount', '—')}; порог: {snyk.get('severityThreshold', 'все уровни')}"))
        sections.append('<h2>Уязвимости зависимостей · Snyk</h2><p>' + escape(snyk.get('summary', 'Подробности в исходном JSON.')) + '</p>' + table(['Пакет', 'Версия', 'ID', 'Уровень', 'Описание', 'Путь зависимости'], [(v.get('packageName', v.get('name', '')), v.get('version'), v.get('id'), v.get('severity'), v.get('title'), ' → '.join(v.get('from', []))) for v in findings]))
        if snyk.get('error') or 'ok' not in snyk:
            problems.append('Snyk не вернул корректный результат проверки.')
    if tests is not None:
        cases = list(tests.iter('testcase'))
        rows = []
        for case in cases:
            status = 'Пройден'
            for tag, label in [('skipped', 'Пропущен'), ('failure', 'Ошибка'), ('error', 'Ошибка выполнения')]:
                if case.find(tag) is not None:
                    status = label
            rows.append((case.get('name'), status, case.get('time'), ''.join(case.itertext()).strip()))
        status_rows.append(('pytest', f'Тестов: {len(cases)}', '; '.join(f'{label}: {sum(r[1] == label for r in rows)}' for label in ['Пройден', 'Пропущен', 'Ошибка', 'Ошибка выполнения'])))
        sections.append('<h2>Проверки API</h2>' + table(['Тест', 'Результат', 'Время, с', 'Подробности'], rows))
    missing = ''.join(f'<p class="alert">{escape(p)}</p>' for p in problems)
    repo, run, sha = (os.getenv(k, 'Локальная проверка') for k in ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_SHA'))
    metadata = table(['Параметр', 'Значение'], [('Репозиторий', repo), ('Запуск', run), ('Коммит', sha), ('Сформирован, UTC', datetime.now(timezone.utc).isoformat()), ('Окружение сканирования', json.dumps((inventory or {}).get('environment', {}), ensure_ascii=False))])
    html = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Лабораторная №1 — полный отчёт</title><style>
body{font:15px/1.55 system-ui,sans-serif;color:#182b43;background:#f2f5fa;margin:0}main{max-width:1400px;margin:auto;padding:36px}header{background:#16324f;color:white;padding:28px;border-radius:14px}h1{margin:0;font-size:32px}h2{margin-top:40px}table{width:100%;border-collapse:collapse;background:white}td,th{text-align:left;vertical-align:top;padding:12px;border:1px solid #dce3ed;white-space:pre-wrap;overflow-wrap:anywhere;min-width:80px}th{background:#e5edf6}td{max-width:380px}tr:nth-child(even){background:#f8fafc}.scroll{overflow:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;padding:16px;border:1px solid #dce3ed}summary{cursor:pointer;padding:12px;background:#e5edf6}.alert{background:#ffe2bc;padding:16px}input{padding:12px;width:min(500px,90%);margin:16px 0;border:1px solid #9bacbf;border-radius:6px}@media print{main{padding:0}header{color:black;background:white}.scroll{overflow:visible}input{display:none}td{font-size:10px}}
</style><main><header><p>Информационная безопасность · Лабораторная №1</p><h1>Полный отчёт по проекту</h1><p>Состав библиотек, анализ безопасности и тестирование API</p></header>'''
    html += metadata + '<h2>Результаты проверок</h2>' + missing + table(['Инструмент', 'Результат', 'Область проверки'], status_rows)
    html += '<p>Отсутствие находок означает только результат перечисленных проверок на момент запуска. Пустая таблица уязвимостей сама по себе не подтверждает успешное выполнение: смотрите результаты и сообщения выше.</p><label>Поиск по строкам таблиц библиотек и результатов<br><input id="search" type="search" placeholder="Например: Flask, JWT, pytest"></label>'
    html += ''.join(sections) + '<h2>Исходные отчёты</h2><p>Данные включены в этот HTML; интернет для просмотра не нужен.</p>' + ''.join(raw)
    html += '''</main><script>document.getElementById('search').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>{r.hidden=!r.textContent.toLowerCase().includes(q)})});</script></html>'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding='utf-8')
    return problems


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, default=Path('evidence'))
    parser.add_argument('--output', type=Path, default=Path('full-report/index.html'))
    args = parser.parse_args()
    build(args.evidence, args.output, Path(__file__).resolve().parents[1])
