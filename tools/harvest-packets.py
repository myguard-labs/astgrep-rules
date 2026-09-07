#!/usr/bin/env python3
"""harvest-packets.py -- stages 2-3 of a rule harvest: model packets and their gates.

Why: the judgement stages of a harvest (which fixes generalise, into which
rule) cost model tokens per diff. This script keeps that spend bounded and
verifiable: it writes one packet file per unit of work, so a cheap subagent
reads the diff and the orchestrator never does; it validates every reply
against a schema and discards what does not conform; and it cross-checks cheap
labels against the deterministic signals from harvest-history.py. Pipeline and
model routing: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  harvest-packets.py label-emit   --corpus candidates.jsonl --work WORK
  harvest-packets.py label-ingest --corpus candidates.jsonl --work WORK
  harvest-packets.py cluster-emit --corpus candidates.jsonl --work WORK [--chunk 12]
  harvest-packets.py cluster-ingest --work WORK
  harvest-packets.py dedupe       --work WORK [--threshold 0.5]
  harvest-packets.py status       --work WORK

Layout under WORK:
  label/packets/<short>.json    one candidate each, for a Haiku-class agent
  label/replies/<short>.json    the agent's reply (schema below)
  label/labels.jsonl            validated labels, one per candidate
  cluster/packets/<key>.json    one (language, class) cluster, for a Sonnet agent
  cluster/replies/<key>.json    proposals for that cluster
  cluster/proposals.jsonl       validated proposals, one per line
  dedupe.tsv                    proposal -> nearest shipped/rejected rule, score

Reply schemas (validated on ingest; anything else is rejected and listed):
  label:    {"id": short, "class": TAXONOMY member, "language": "go"|"c",
             "confidence": "low"|"medium"|"high", "summary": <=160 chars}
  cluster:  {"cluster": key, "proposals": [{"id": kebab-case, "language",
             "claim", "classification": "syntactic"|"taint"|"cross-function"|
             "noise", "positive": source, "near_miss": source,
             "supporting": [shorts], "overlaps": [rule ids], "rationale"}]}
Exit: 0 when every reply present is valid; 1 when any reply was rejected or a
packet has no reply (listed on stderr), so a grind loop can gate on it.
Side effects: writes only under WORK. No network, no model calls: dispatching
the packets is the orchestrator's job (see the pipeline reference).
Limits: dedupe is token overlap on ids, messages and rejected-candidate
entries -- it ranks likely duplicates for a reader, it does not decide.
Extend: TAXONOMY and SIGNAL_FOR_CLASS together; schemas in validate_*().
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Fixed defect taxonomy. The label agent must pick one; "other" is allowed so
# it never has to force a fit. Each class maps to the harvest signal that
# should usually accompany it, which is how label-ingest measures agreement.
TAXONOMY = {
    "nil-deref": "nil-deref",
    "bounds": "bounds",
    "int-cast": "int-cast",
    "pool-reset": "pool-reset",
    "panic-on-input": "panic",
    "unchecked-err": "unchecked-err",
    "concurrency": "concurrency",
    "alloc-free": "alloc",
    "memcpy-len": "memcpy",
    "string-len": "string-len",
    "encoding": "encoding",
    "api-misuse": None,
    "logic": None,
    "other": None,
}
DIFF_LIMIT = 3000  # chars of diff per candidate inside a packet


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def language_of(candidate: dict) -> str:
    return "c" if any(f.endswith((".c", ".h")) for f in candidate["files"]) else "go"


def trimmed_diff(diff: str) -> str:
    return diff if len(diff) <= DIFF_LIMIT else diff[:DIFF_LIMIT] + "\n[...truncated]"


# ---------------------------------------------------------------- label stage

LABEL_PROMPT = """You classify one bug-fix commit into a fixed defect taxonomy.
Read the diff. Reply with exactly one JSON object and nothing else:
{"id": "<the id field>", "class": <one of the classes>, "language": "go"|"c",
 "confidence": "low"|"medium"|"high", "summary": "<=160 chars: what was wrong>"}
Classes: %s
Rules: pick the class that names the defect the fix removes, not the code area.
Use "other" when none fits. Do not judge whether the fix is important or
generalisable; do not propose rules; do not explain outside the JSON."""


def label_emit(args) -> int:
    corpus = read_jsonl(args.corpus)
    out = args.work / "label" / "packets"
    out.mkdir(parents=True, exist_ok=True)
    (args.work / "label" / "replies").mkdir(exist_ok=True)
    (args.work / "label" / "PROMPT.md").write_text(LABEL_PROMPT % ", ".join(TAXONOMY))
    for c in corpus:
        packet = {
            "id": c["short"], "repo": c["repo"], "subject": c["subject"],
            "files": c["files"], "language_hint": language_of(c),
            "diff": trimmed_diff(c["diff"]),
        }
        (out / f"{c['short']}.json").write_text(json.dumps(packet, indent=1))
    print(f"wrote {len(corpus)} label packets to {out}", file=sys.stderr)
    return 0


def validate_label(reply: dict, packet_id: str) -> str | None:
    if not isinstance(reply, dict):
        return "not an object"
    if reply.get("id") != packet_id:
        return f"id mismatch: {reply.get('id')!r}"
    if reply.get("class") not in TAXONOMY:
        return f"class not in taxonomy: {reply.get('class')!r}"
    if reply.get("language") not in ("go", "c"):
        return f"bad language: {reply.get('language')!r}"
    if reply.get("confidence") not in ("low", "medium", "high"):
        return f"bad confidence: {reply.get('confidence')!r}"
    s = reply.get("summary")
    if not isinstance(s, str) or not s.strip() or len(s) > 160:
        return "summary missing or over 160 chars"
    return None


def label_ingest(args) -> int:
    corpus = {c["short"]: c for c in read_jsonl(args.corpus)}
    packets = sorted((args.work / "label" / "packets").glob("*.json"))
    labels, bad, missing, agree = [], [], [], 0
    for p in packets:
        reply_path = args.work / "label" / "replies" / p.name
        if not reply_path.exists():
            missing.append(p.stem)
            continue
        try:
            reply = json.loads(reply_path.read_text())
        except json.JSONDecodeError as e:
            bad.append((p.stem, f"invalid JSON: {e}"))
            continue
        err = validate_label(reply, p.stem)
        if err:
            bad.append((p.stem, err))
            continue
        c = corpus[p.stem]
        expected_signal = TAXONOMY[reply["class"]]
        # Agreement: the class's companion signal was seen by the regex pass.
        # Disagreement is not an error; it routes the candidate to the
        # "unresolved" cluster so a stronger reader sees it.
        agreed = expected_signal is None or expected_signal in c["signals"]
        agree += agreed
        labels.append({**reply, "agreed": agreed, "signals": c["signals"],
                       "density": c["density"], "repo": c["repo"], "url": c["url"]})
    write_jsonl(args.work / "label" / "labels.jsonl", labels)
    hist: dict[str, int] = defaultdict(int)
    for lb in labels:
        hist[lb["class"]] += 1
    print(f"labels: {len(labels)} valid, {len(bad)} rejected, {len(missing)} missing; "
          f"signal agreement {agree}/{len(labels)}", file=sys.stderr)
    for k, n in sorted(hist.items(), key=lambda kv: -kv[1]):
        print(f"  {k:16s} {n}", file=sys.stderr)
    for stem, why in bad:
        print(f"REJECT {stem}: {why}", file=sys.stderr)
    for stem in missing[:20]:
        print(f"MISSING {stem}", file=sys.stderr)
    return 1 if bad or missing else 0


# -------------------------------------------------------------- cluster stage

CLUSTER_PROMPT = """You propose ast-grep rules from a cluster of bug-fix commits
that share one defect class and language. Read every diff. For each *reusable*
defect shape you can state as a single-function syntactic claim, emit one
proposal. Reply with exactly one JSON object and nothing else:
{"cluster": "<the cluster field>", "proposals": [
  {"id": "<lang>-<kebab-case-defect>", "language": "go"|"c",
   "claim": "one sentence: the exact syntax shape that is reported",
   "classification": "syntactic"|"taint"|"cross-function"|"noise",
   "positive": "<minimal inert source that must match>",
   "near_miss": "<minimal inert source differing in one property that must not match>",
   "supporting": ["<commit shorts from this cluster that exhibit it>"],
   "overlaps": ["<ids from shipped_rules that cover the same ground, or empty>"],
   "rationale": "<=300 chars: why this generalises beyond the originating code"}
]}
Rules: a claim that needs types, dataflow, ownership, reachability, or a guard
elsewhere is "taint" or "cross-function" -- still emit it, with the reason, so
it can be recorded as rejected and not re-mined. Do not repeat a shipped or
rejected rule; cite it in overlaps instead. An empty proposals list is a valid
answer. Do not write YAML."""


def shipped_rules(language: str) -> list[dict]:
    rows = []
    for path in sorted((ROOT / "rules" / language).rglob("*.yml")):
        text = path.read_text()
        m = re.search(r"^message:\s*>-?\s*\n((?:\s+.*\n)+)", text, re.MULTILINE)
        msg = " ".join(m.group(1).split()) if m else ""
        rows.append({"id": path.stem, "message": msg[:160]})
    return rows


def rejected_entries(language: str) -> list[str]:
    path = ROOT / "docs" / "rejected-candidates.md"
    if not path.exists():
        return []
    section = re.split(r"^## ", path.read_text(), flags=re.MULTILINE)
    out = []
    for block in section:
        head = block.split("\n", 1)[0]
        if language in head.split() or (language == "c" and "nginx" in head):
            # Two entry spellings exist in the file: "- `id`" and "- **id**".
            out += re.findall(r"^- (?:`([^`]+)`|\*\*([^*]+)\*\*)", block, re.MULTILINE)
    out = [a or b for a, b in out]
    return out


def cluster_emit(args) -> int:
    corpus = {c["short"]: c for c in read_jsonl(args.corpus)}
    labels = read_jsonl(args.work / "label" / "labels.jsonl")
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for lb in labels:
        cls = lb["class"] if lb["agreed"] or lb["class"] in ("other", "logic", "api-misuse") \
            else "unresolved"
        groups[(lb["language"], cls)].append(lb)
    out = args.work / "cluster" / "packets"
    out.mkdir(parents=True, exist_ok=True)
    (args.work / "cluster" / "replies").mkdir(exist_ok=True)
    (args.work / "cluster" / "PROMPT.md").write_text(CLUSTER_PROMPT)
    n = 0
    for (lang, cls), members in sorted(groups.items()):
        if len(members) < args.min_size:
            continue
        members.sort(key=lambda m: -m["density"])
        # A cluster larger than --chunk is split into numbered parts so one
        # packet stays within a single bounded read; each part carries the
        # same shipped/rejected context and is proposed on independently.
        parts = [members[i:i + args.chunk] for i in range(0, len(members), args.chunk)]
        for idx, part in enumerate(parts, 1):
            key = f"{lang}-{cls}" + (f"-{idx}" if len(parts) > 1 else "")
            packet = {
                "cluster": key, "language": lang, "class": cls,
                "part": f"{idx}/{len(parts)}",
                "candidates": [{
                    "short": m["id"], "url": m["url"], "subject": corpus[m["id"]]["subject"],
                    "summary": m["summary"], "diff": trimmed_diff(corpus[m["id"]]["diff"]),
                } for m in part],
                "shipped_rules": shipped_rules(lang),
                "rejected_candidates": rejected_entries(lang),
            }
            (out / f"{key}.json").write_text(json.dumps(packet, indent=1))
            n += 1
            print(f"  {key:28s} {len(part):3d} candidates", file=sys.stderr)
    print(f"wrote {n} cluster packets to {out}", file=sys.stderr)
    return 0


KEBAB = re.compile(r"^(go|c|nginx)-[a-z0-9]+(-[a-z0-9]+)+$")


def validate_cluster(reply: dict, key: str, members: set[str]) -> tuple[str | None, list]:
    if not isinstance(reply, dict) or reply.get("cluster") != key:
        return "cluster key mismatch or not an object", []
    props = reply.get("proposals")
    if not isinstance(props, list):
        return "proposals is not a list", []
    for i, p in enumerate(props):
        req = ("id", "language", "claim", "classification", "positive", "near_miss",
               "supporting", "overlaps", "rationale")
        if not isinstance(p, dict) or any(k not in p for k in req):
            return f"proposal {i}: missing keys", []
        if not KEBAB.match(p["id"]):
            return f"proposal {i}: id {p['id']!r} is not <lang>-kebab-case", []
        if p["classification"] not in ("syntactic", "taint", "cross-function", "noise"):
            return f"proposal {i}: bad classification", []
        if not set(p["supporting"]) <= members:
            return f"proposal {i}: supporting cites commits outside the cluster", []
        if p["positive"].strip() == p["near_miss"].strip():
            return f"proposal {i}: positive equals near_miss", []
        if len(p["rationale"]) > 300:
            return f"proposal {i}: rationale over 300 chars", []
    return None, props


def cluster_ingest(args) -> int:
    packets = sorted((args.work / "cluster" / "packets").glob("*.json"))
    proposals, bad, missing = [], [], []
    for p in packets:
        packet = json.loads(p.read_text())
        members = {c["short"] for c in packet["candidates"]}
        reply_path = args.work / "cluster" / "replies" / p.name
        if not reply_path.exists():
            missing.append(p.stem)
            continue
        try:
            reply = json.loads(reply_path.read_text())
        except json.JSONDecodeError as e:
            bad.append((p.stem, f"invalid JSON: {e}"))
            continue
        err, props = validate_cluster(reply, p.stem, members)
        if err:
            bad.append((p.stem, err))
            continue
        for pr in props:
            proposals.append({**pr, "cluster": p.stem})
    write_jsonl(args.work / "cluster" / "proposals.jsonl", proposals)
    hist: dict[str, int] = defaultdict(int)
    for pr in proposals:
        hist[pr["classification"]] += 1
    print(f"proposals: {len(proposals)} from {len(packets) - len(bad) - len(missing)} clusters; "
          f"{len(bad)} rejected, {len(missing)} missing", file=sys.stderr)
    for k, n in sorted(hist.items()):
        print(f"  {k:16s} {n}", file=sys.stderr)
    for stem, why in bad:
        print(f"REJECT {stem}: {why}", file=sys.stderr)
    for stem in missing:
        print(f"MISSING {stem}", file=sys.stderr)
    return 1 if bad or missing else 0


# --------------------------------------------------------------------- dedupe

STOP = {"the", "a", "an", "of", "in", "on", "to", "and", "or", "is", "for", "with",
        "without", "not", "go", "c", "nginx", "rule", "call", "use", "uses", "used"}


def tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2 and t not in STOP}


def dedupe(args) -> int:
    """Rank each proposal against shipped and rejected rules by token containment.

    Containment (proposal tokens found in the target) rather than Jaccard, so a
    long shipped message cannot dilute a short id that names the same thing.
    The proposal's own `overlaps` list is reported alongside: a self-declared
    overlap is a stronger signal than any string score.
    """
    proposals = read_jsonl(args.work / "cluster" / "proposals.jsonl")
    index: list[tuple[str, str, set[str]]] = []
    for lang in ("go", "c"):
        for r in shipped_rules(lang):
            index.append((r["id"], "shipped", tokens(r["id"] + " " + r["message"])))
        for rid in rejected_entries(lang):
            index.append((rid, "rejected", tokens(rid)))
    rows = ["proposal\tclassification\tnearest\tkind\tscore\tdeclared\tflag"]
    flagged = 0
    for p in proposals:
        mine = tokens(p["id"]) | tokens(p["claim"])
        idt = tokens(p["id"])
        best = ("", "", 0.0)
        for rid, kind, theirs in index:
            # Id-vs-id containment weighs most; claim tokens refine ties.
            score = 0.7 * (len(idt & theirs) / max(len(idt), 1)) \
                + 0.3 * (len(mine & theirs) / max(len(mine), 1))
            if score > best[2]:
                best = (rid, kind, score)
        declared = ",".join(p.get("overlaps") or [])
        flag = "DUP?" if best[2] >= args.threshold or declared else ""
        flagged += bool(flag)
        rows.append(f"{p['id']}\t{p['classification']}\t{best[0]}\t{best[1]}\t"
                    f"{best[2]:.2f}\t{declared}\t{flag}")
    (args.work / "dedupe.tsv").write_text("\n".join(rows) + "\n")
    print(f"dedupe: {len(proposals)} proposals, {flagged} flagged (score >= {args.threshold} "
          f"or declared overlap); see {args.work / 'dedupe.tsv'}", file=sys.stderr)
    return 0


def status(args) -> int:
    def count(rel):
        d = args.work / rel
        return len(list(d.glob("*.json"))) if d.exists() else 0
    lab = args.work / "label" / "labels.jsonl"
    prop = args.work / "cluster" / "proposals.jsonl"
    print(f"label   packets={count('label/packets')} replies={count('label/replies')} "
          f"valid={len(read_jsonl(lab)) if lab.exists() else 0}")
    print(f"cluster packets={count('cluster/packets')} replies={count('cluster/replies')} "
          f"proposals={len(read_jsonl(prop)) if prop.exists() else 0}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, needs_corpus in (
        ("label-emit", label_emit, True), ("label-ingest", label_ingest, True),
        ("cluster-emit", cluster_emit, True), ("cluster-ingest", cluster_ingest, False),
        ("dedupe", dedupe, False), ("status", status, False),
    ):
        sp = sub.add_parser(name)
        sp.add_argument("--work", type=Path, required=True)
        if needs_corpus:
            sp.add_argument("--corpus", type=Path, required=True)
        if name == "cluster-emit":
            sp.add_argument("--min-size", type=int, default=1)
            sp.add_argument("--chunk", type=int, default=12,
                            help="max candidates per packet; larger clusters split")
        if name == "dedupe":
            sp.add_argument("--threshold", type=float, default=0.5)
        sp.set_defaults(fn=fn)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
