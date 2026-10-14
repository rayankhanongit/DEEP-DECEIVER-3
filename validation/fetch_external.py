"""
Export a public prompt-injection benchmark to the JSONL format evaluate.py reads
(one object per line: text, attack).

    pip install datasets
    python fetch_external.py deepset/prompt-injections prompt_injections.jsonl
    python evaluate.py --mode agents --pace --resume --external prompt_injections.jsonl

Expected columns: `text` plus a `label` where 1 = injection. Other datasets work
if you pass --text-column / --label-column. Check the dataset card before use:
some benchmarks label differently or include non-English text, and results on
them are only comparable to your own if the label meaning matches.
"""

import argparse
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset")
    parser.add_argument("output")
    parser.add_argument("--split", default="test")
    parser.add_argument("--text-column", default="text")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--attack-value", default="1", help="label value meaning attack")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    from datasets import load_dataset

    data = load_dataset(args.dataset, split=args.split)
    written = attacks = 0

    with open(args.output, "w", encoding="utf-8") as handle:
        for row in data:
            if args.limit and written >= args.limit:
                break

            attack = str(row[args.label_column]).lower() == args.attack_value.lower()
            handle.write(json.dumps({"text": row[args.text_column], "attack": attack}) + "\n")
            written += 1
            attacks += int(attack)

    print(f"Wrote {written} rows ({attacks} attacks, {written - attacks} benign) to {args.output}")


if __name__ == "__main__":
    main()
