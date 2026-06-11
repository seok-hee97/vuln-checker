#!/usr/bin/env python3
"""
텍스트 결과 파일 → JSON + HTML 리포트 생성
Usage: python3 generate_report.py <result.txt> <output.json>
       HTML 파일은 output.json 과 같은 경로에 .html 로 생성됨
"""

import sys
import json
import re
from datetime import datetime
from pathlib import Path


# ── 파서 ─────────────────────────────────────────────────────────────────────

LABEL_MAP = {
    "[안전]": "safe",
    "[취약]": "vuln",
    "[권장]": "warn",
    "[정보]": "info",
    "[PASS]": "pass",
}

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def parse_results(txt_path: str) -> dict:
    data = {
        "host": "",
        "scan_time": "",
        "os": "",
        "kernel": "",
        "items": [],
        "stats": {"safe": 0, "vuln": 0, "warn": 0, "info": 0, "pass": 0},
    }
    current_section = ""
    current_check = ""
    current_check_id = ""

    with open(txt_path, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = strip_ansi(raw_line.rstrip())

            # 메타 정보 추출
            if line.startswith("  시작 시각"):
                data["scan_time"] = line.split(":", 1)[-1].strip()
            elif line.startswith("  호스트명"):
                data["host"] = line.split(":", 1)[-1].strip()
            elif line.startswith("  OS"):
                data["os"] = line.split(":", 1)[-1].strip()
            elif line.startswith("  커널"):
                data["kernel"] = line.split(":", 1)[-1].strip()

            # 섹션 헤더 (=== 다음 줄)
            if re.match(r"^={10,}", line):
                continue
            if re.match(r"^  [가-힣A-Z]", line) and not line.strip().startswith("["):
                _stripped = line.strip()
                # 구분선이 아닌 텍스트 헤더
                if not re.match(r"^[-=]+$", _stripped):
                    current_section = _stripped
                continue

            # 점검 항목 헤더: [U-01], [EX-SSH-01], [U-43-extra] 등 모든 ID 패턴
            m = re.match(r"\s+\[([A-Za-z0-9-]+)\]\s+(.+)", line)
            if m:
                current_check_id = m.group(1)
                current_check = m.group(2).strip()
                continue

            # 결과 라인
            for label, kind in LABEL_MAP.items():
                if label in line:
                    msg = re.sub(r".*==>\s*\[[^\]]+\]\s*", "", line).strip()
                    if msg:
                        data["items"].append({
                            "section": current_section,
                            "check_id": current_check_id,
                            "check": current_check,
                            "kind": kind,
                            "message": msg,
                        })
                        if kind in data["stats"]:
                            data["stats"][kind] += 1
                    break

    return data


# ── HTML 생성 ─────────────────────────────────────────────────────────────────

COLOR_MAP = {
    "safe": "#27ae60",
    "vuln": "#e74c3c",
    "warn": "#f39c12",
    "info": "#2980b9",
    "pass": "#95a5a6",
}

LABEL_KR = {
    "safe": "안전",
    "vuln": "취약",
    "warn": "권장",
    "info": "정보",
    "pass": "PASS",
}


def _score_color(score: int) -> str:
    if score >= 80:
        return "#27ae60"
    if score >= 50:
        return "#f39c12"
    return "#e74c3c"


def generate_html(data: dict, out_path: str) -> None:
    stats = data["stats"]
    total = stats["safe"] + stats["vuln"]
    score = round(stats["safe"] / total * 100) if total > 0 else 0
    sc = _score_color(score)

    rows_html = ""
    prev_section = None
    for item in data["items"]:
        if item["kind"] in ("info", "pass"):
            continue  # 정보/PASS 행은 테이블 제외 (상세 집계에만 포함)
        color = COLOR_MAP.get(item["kind"], "#fff")
        label = LABEL_KR.get(item["kind"], "")
        section_cell = ""
        if item["section"] != prev_section:
            # 같은 섹션 그룹핑 — 실제 rowspan 계산이 복잡하므로 단순 출력
            section_cell = f'<td class="section-cell">{item["section"]}</td>'
            prev_section = item["section"]
        else:
            section_cell = '<td class="section-cell"></td>'

        rows_html += f"""
        <tr>
          {section_cell}
          <td class="check-id">{item['check_id']}</td>
          <td>{item['check']}</td>
          <td class="badge" style="background:{color}">[{label}]</td>
          <td class="msg">{item['message']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>취약점 점검 결과 — {data['host']}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Malgun Gothic', 'Noto Sans KR', sans-serif;
            background: #f0f2f5; color: #333; font-size: 14px; }}
    .header {{ background: #2c3e50; color: #fff; padding: 24px 32px; }}
    .header h1 {{ font-size: 1.6em; }}
    .header p  {{ margin-top: 6px; opacity: .8; font-size: .9em; }}
    .summary {{ display: flex; gap: 20px; padding: 20px 32px; flex-wrap: wrap; }}
    .card {{ background: #fff; border-radius: 8px; padding: 20px 28px;
             box-shadow: 0 2px 6px rgba(0,0,0,.08); flex: 1; min-width: 140px; }}
    .card .num  {{ font-size: 2.2em; font-weight: bold; }}
    .card .lbl  {{ font-size: .85em; color: #888; margin-top: 4px; }}
    .score-num  {{ color: {sc}; }}
    .safe-num   {{ color: #27ae60; }}
    .vuln-num   {{ color: #e74c3c; }}
    .warn-num   {{ color: #f39c12; }}
    .table-wrap {{ padding: 0 32px 40px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff;
             border-radius: 8px; overflow: hidden;
             box-shadow: 0 2px 6px rgba(0,0,0,.08); }}
    th {{ background: #2c3e50; color: #fff; padding: 10px 12px;
          text-align: left; font-weight: 600; }}
    td {{ padding: 9px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
    tr:hover td {{ background: #f9f9f9; }}
    .section-cell {{ font-weight: 600; color: #555; white-space: nowrap; }}
    .check-id {{ font-family: monospace; color: #2980b9; white-space: nowrap; }}
    .badge {{ text-align: center; color: #fff; font-weight: bold;
              border-radius: 4px; white-space: nowrap; }}
    .msg {{ max-width: 480px; }}
  </style>
</head>
<body>
<div class="header">
  <h1>Linux 취약점 점검 결과</h1>
  <p>호스트: <b>{data['host']}</b> &nbsp;|&nbsp;
     OS: {data['os']} &nbsp;|&nbsp;
     커널: {data['kernel']} &nbsp;|&nbsp;
     점검 시각: {data['scan_time']} &nbsp;|&nbsp;
     리포트 생성: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>

<div class="summary">
  <div class="card">
    <div class="num score-num">{score}점</div>
    <div class="lbl">보안 점수 (안전 / 전체)</div>
  </div>
  <div class="card">
    <div class="num safe-num">{stats['safe']}</div>
    <div class="lbl">[안전] 항목 수</div>
  </div>
  <div class="card">
    <div class="num vuln-num">{stats['vuln']}</div>
    <div class="lbl">[취약] 항목 수</div>
  </div>
  <div class="card">
    <div class="num warn-num">{stats['warn']}</div>
    <div class="lbl">[권장] 항목 수</div>
  </div>
  <div class="card">
    <div class="num">{total}</div>
    <div class="lbl">전체 판정 항목</div>
  </div>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>영역</th>
        <th>항목 ID</th>
        <th>점검 내용</th>
        <th>판정</th>
        <th>상세</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


# ── 진입점 ─────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: generate_report.py <result.txt> <output.json>", file=sys.stderr)
        sys.exit(1)

    txt_path  = sys.argv[1]
    json_path = sys.argv[2]
    html_path = str(Path(json_path).with_suffix(".html"))

    if not Path(txt_path).exists():
        print(f"[ERROR] 결과 파일을 찾을 수 없습니다: {txt_path}", file=sys.stderr)
        sys.exit(1)

    data = parse_results(txt_path)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[완료] JSON : {json_path}")

    generate_html(data, html_path)
    print(f"[완료] HTML : {html_path}")

    stats = data["stats"]
    total = stats["safe"] + stats["vuln"]
    score = round(stats["safe"] / total * 100) if total > 0 else 0
    print(f"[요약] 안전={stats['safe']}, 취약={stats['vuln']}, 권장={stats['warn']}, 점수={score}/100")


if __name__ == "__main__":
    main()
