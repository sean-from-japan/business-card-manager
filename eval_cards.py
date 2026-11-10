"""Compare AI extraction with hand-written expected values for each card image.

Usage: python eval_cards.py <folder>
The folder holds card images and, for each image, <image stem>.expected.json with the 8 fields.
Keep that folder outside the repository (it contains personal data); see README.
"""
import glob
import json
import os
import sys

import db
import extract


def main(folder: str) -> int:
    images = sorted(
        p for p in glob.glob(os.path.join(folder, "*"))
        if os.path.splitext(p)[1].lower() in (".jpg", ".jpeg", ".png", ".webp")
    )
    total_ok = total = 0
    for path in images:
        stem = os.path.splitext(path)[0]
        expected_path = stem + ".expected.json"
        if not os.path.exists(expected_path):
            print(f"{os.path.basename(path)}: no expected file, skipped")
            continue
        with open(expected_path, encoding="utf-8") as f:
            expected = json.load(f)
        try:
            result = extract.extract(path)
        except extract.ExtractionError as e:
            print(f"{os.path.basename(path)}: extraction failed: {e}")
            continue
        ok = 0
        diffs = []
        for k in extract.KEYS:
            same = db.normalize(result["fields"][k]) == db.normalize(expected.get(k, ""))
            ok += same
            if not same:
                diffs.append(k)
        total_ok += ok
        total += len(extract.KEYS)
        u = result["usage"]
        print(f"{os.path.basename(path)}: {ok}/{len(extract.KEYS)} fields match"
              f" | differs: {', '.join(diffs) or 'none'} | unclear: {', '.join(result['unclear']) or 'none'}"
              f" | tokens in={u['input_tokens']} out={u['output_tokens']}")
        for k in diffs:
            print(f"    {k}: expected={expected.get(k, '')!r} got={result['fields'][k]!r}")
    if total:
        print(f"TOTAL {total_ok}/{total} fields match")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "local_check"))
