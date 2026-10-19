#!/usr/bin/env python3
"""等价清单锚点漂移检测（六仓统一模式，wop-typescript-sdk 实例）。

清单 tests/mutation/EQUIVALENT-MUTANTS.md 的幸存体均已附等价论证
（wop-specs D6），本仓口径为「论证留档、幸存保留在分母」（当前 MSI 93.88%）。
清单行号在源码演进后漂移会使论证失指——本脚本每 PR 校验锚列与当前源码一致
（历史表 08-31 轮锚列由源码自动生成；增量表锚列 2026-10-19 补入）。

用法: python3 scripts/check-equivalent-anchors.py
退出码: 0 = 全部锚点吻合；1 = 存在漂移（更新清单并重新论证后重跑）。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
LEDGER = ROOT / "tests" / "mutation" / "EQUIVALENT-MUTANTS.md"

ROW = re.compile(r"^\|\s*\d+\s*\|\s*`?([A-Za-z0-9_.-]+\.ts):(\d+)`?\s*\|([^|]*)\|([^|]*)\|(.*)$")


def main() -> int:
    if not LEDGER.exists():
        print(f"清单缺失: {LEDGER}", file=sys.stderr)
        return 1
    drifted = []
    no_anchor = 0
    total = 0
    for line in LEDGER.read_text(encoding="utf-8").split("\n"):
        m = ROW.match(line)
        if not m:
            continue
        total += 1
        file, lineno = m.group(1), int(m.group(2))
        anchor = m.group(4).strip().strip("`")
        if not anchor:
            no_anchor += 1
            continue
        path = SRC / file
        if not path.exists():
            # 清单沿用 src 顶层短名（config/ 等子目录重构前生成）：按名唯一解析
            matches = sorted(SRC.rglob(file))
            if len(matches) != 1:
                drifted.append(f"{file}:{lineno} 文件不存在（重命名/删除）")
                continue
            path = matches[0]
        actual = path.read_text(encoding="utf-8").split("\n")[lineno - 1].strip()
        if not actual.startswith(anchor):
            drifted.append(f"{file}:{lineno} 锚失配：清单={anchor!r} 实际={actual[:60]!r}")
    if drifted:
        for d in drifted:
            print(f"ANCHOR DRIFT: {d}", file=sys.stderr)
        return 1
    print(f"anchors ok ({total} 条，其中 {no_anchor} 条待补锚)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
