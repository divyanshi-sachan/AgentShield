"""AgentShield command line: list, run, experiment, compare."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agents import PROFILES, ScriptedAgent
from .compare import compare_runs
from .dashboard import render_dashboard
from .defenses import ALIASES, get_defense
from .dotenv import load_dotenv
from .env import POSITIONS
from .report import render_comparison_report
from .runner import load_run, plan_episodes, run_benchmark
from .suite import TECHNIQUE_SETS, load_injections, load_tasks, load_techniques


def _select(items, wanted: str | None, key):
    if not wanted:
        return items
    names = set(wanted.split(","))
    chosen = [i for i in items if key(i) in names]
    unknown = names - {key(i) for i in chosen}
    if unknown:
        sys.exit(f"unknown: {', '.join(sorted(unknown))}")
    return chosen


def cmd_list(_: argparse.Namespace) -> None:
    print("Tasks:")
    for t in load_tasks():
        print(f"  {t.id:26} source={t.source:6} {t.prompt}")
    print("\nAttacker goals:")
    for g in {i.goal.id: i.goal for i in load_injections()}.values():
        print(f"  {g.id:26} [{g.category}, {g.severity}] {g.instruction}")
    print("\nTechniques:")
    for t in load_techniques("all"):
        print(f"  {t.id:26} {'(held-out) ' if t.heldout else ''}{t.description}")
    print("\nDefenses: none, D1 isolation, D2 permissions, D3 secrets, D4 approval; combine with '+', e.g. D1+D2+D3+D4")
    print(f"Positions: {', '.join(POSITIONS)}   Scripted profiles: {', '.join(PROFILES)}")


def cmd_run(args: argparse.Namespace) -> None:
    tasks = _select(load_tasks(), args.tasks, lambda t: t.id)
    injections = _select(load_injections(technique_set=args.technique_set), args.goals, lambda i: i.goal.id)
    injections = _select(injections, args.techniques, lambda i: i.technique.id)
    positions = args.positions.split(",")
    if bad := set(positions) - set(POSITIONS):
        sys.exit(f"unknown positions: {', '.join(bad)}")
    try:
        defense = get_defense(args.defense)
    except ValueError as e:
        sys.exit(str(e))
    n = len(plan_episodes(tasks, injections, args.repeats, positions))

    if args.dry_run:
        print(f"{n} episodes, defense {defense.name}")
        return

    from .runner import DirtyTreeError, check_paid_run_allowed

    try:
        check_paid_run_allowed({"agent": args.agent}, allow_dirty=args.allow_dirty)
    except DirtyTreeError as e:
        sys.exit(str(e))
    if args.agent == "scripted":
        agent = ScriptedAgent(profile=args.profile, seed=args.seed)
    else:
        from .agents.claude import ClaudeAgent

        agent = ClaudeAgent(model=args.model, effort=args.effort)
        print(f"Running {n} episodes against {args.model}; each makes several API calls.", file=sys.stderr)

    def progress(i: int, total: int, ep) -> None:
        mark = "ATTACK" if ep.attack_success else ("blocked" if ep.blocked_calls else ("ok" if ep.utility else "fail"))
        print(f"[{i}/{total}] {ep.episode_id}: {mark}", file=sys.stderr)

    run_dir, m = run_benchmark(
        agent,
        defense,
        tasks,
        injections,
        args.seed,
        args.repeats,
        args.out,
        positions,
        progress=None if args.quiet else progress,
        allow_dirty=args.allow_dirty,
    )
    asr, util = m["attack_success_rate"], m["normal_task_success"]
    print(f"\nAttack success rate: {asr['rate']:.1%} ({asr['k']}/{asr['n']})")
    print(f"Normal task success: {util['rate']:.1%} ({util['k']}/{util['n']})")
    print(f"Report: {run_dir / 'report.md'}")


def cmd_experiment(args: argparse.Namespace) -> None:
    from .experiment import check_expected, composition, load_config, run_experiment
    from .runner import DirtyTreeError

    cfg = load_config(args.config)
    comp = composition(cfg)
    print(
        f"{cfg['name']}: {comp['total_episodes']} episodes across {len(cfg['run']['defenses'])} defense "
        f"configurations (agent: {cfg['agent'].get('type')})",
        file=sys.stderr,
    )
    mismatch = check_expected(cfg, comp)
    if args.dry_run:
        print(json.dumps(comp, indent=2))
        for problem in mismatch:
            print(f"MISMATCH: {problem}", file=sys.stderr)
        for bad in comp["incompatible"]:
            print(f"INCOMPATIBLE: {bad['task']} x {bad['goal']}: {'; '.join(bad['problems'])}", file=sys.stderr)
        return
    try:
        exp_dir, cmp = run_experiment(
            args.config, args.out, progress=lambda s: print(s, file=sys.stderr), allow_dirty=args.allow_dirty
        )
    except (DirtyTreeError, ValueError) as e:
        sys.exit(str(e))
    for r in cmp["rows"]:
        print(f"  {r['defense']:14} ASR {r['asr']['rate']:6.1%}   NTSR {r['normal_task_success']['rate']:6.1%}")
    print(f"Comparison: {exp_dir / 'comparison.md'}\nDashboard:  {exp_dir / 'dashboard.html'}")


def cmd_summarize(args: argparse.Namespace) -> None:
    from .runner import resummarize

    for d in args.runs:
        out = Path(args.out) / Path(d).name if args.out else None
        m = resummarize(d, out_dir=out)
        where = out or d
        print(f"{d}: ASR {m['attack_success_rate']['rate']:.1%}, summary written to {where} (no episodes re-run)")


def cmd_merge(args: argparse.Namespace) -> None:
    from .merge import MergeError, merge_runs, repeat_analysis, write_merge

    try:
        merged = merge_runs(args.runs, reference=args.reference)
    except MergeError as e:
        sys.exit(str(e))
    out = write_merge(merged, repeat_analysis(merged), args.out)
    print(f"Merged {len(merged['primary'])} primary + {len(merged['reference'])} reference episodes -> {out}")


def cmd_compare(args: argparse.Namespace) -> None:
    cmp = compare_runs([load_run(d) for d in args.runs])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "comparison.json").write_text(json.dumps(cmp, indent=2))
    (out / "comparison.md").write_text(render_comparison_report(args.name, cmp))
    (out / "dashboard.html").write_text(render_dashboard(args.name, cmp))
    print(f"Comparison: {out / 'comparison.md'}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="agentshield", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list tasks, attacks, defenses").set_defaults(func=cmd_list)

    run = sub.add_parser("run", help="run one agent with one defense pipeline")
    run.add_argument("--agent", choices=["scripted", "claude"], default="scripted")
    run.add_argument("--profile", choices=list(PROFILES), default="medium", help="scripted agent susceptibility")
    run.add_argument("--model", default="claude-opus-5-5")
    run.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default="medium")
    run.add_argument(
        "--defense", default="none", help=f"none, D1..D4 or aliases ({', '.join(ALIASES)}), joined with '+'"
    )
    run.add_argument("--technique-set", choices=TECHNIQUE_SETS, default="baseline")
    run.add_argument("--tasks", help="comma-separated task ids")
    run.add_argument("--goals", help="comma-separated attacker goal ids")
    run.add_argument("--techniques", help="comma-separated technique ids")
    run.add_argument("--positions", default="end", help="comma-separated: start,middle,end")
    run.add_argument("--repeats", type=int, default=1)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--out", default="results")
    run.add_argument("--dry-run", action="store_true", help="print the episode count and exit")
    run.add_argument("--quiet", action="store_true")
    run.add_argument("--allow-dirty", action="store_true", help="allow a paid run from uncommitted code (recorded)")
    run.set_defaults(func=cmd_run)

    exp = sub.add_parser("experiment", help="run a defense matrix from a TOML config")
    exp.add_argument("config")
    exp.add_argument("--out", default="results")
    exp.add_argument("--dry-run", action="store_true", help="print the exact composition and checks, then exit")
    exp.add_argument("--allow-dirty", action="store_true", help="allow a paid run from uncommitted code (recorded)")
    exp.set_defaults(func=cmd_experiment)

    summ = sub.add_parser("summarize", help="recompute summary.json and report.md for finished run directories")
    summ.add_argument("runs", nargs="+")
    summ.add_argument("--out", help="write summaries here instead of into the run directories (keeps them untouched)")
    summ.set_defaults(func=cmd_summarize)

    mrg = sub.add_parser("merge", help="merge repeated runs by case_id and run_id; optional replication reference")
    mrg.add_argument("runs", nargs="+")
    mrg.add_argument("--reference", help="run directory used only as a replication check (e.g. the original baseline)")
    mrg.add_argument("--out", required=True)
    mrg.set_defaults(func=cmd_merge)

    cmp = sub.add_parser("compare", help="compare existing run directories (first 'none' run is the baseline)")
    cmp.add_argument("runs", nargs="+")
    cmp.add_argument("--name", default="comparison")
    cmp.add_argument("--out", default="results/comparison")
    cmp.set_defaults(func=cmd_compare)

    args = parser.parse_args(argv)
    load_dotenv(Path.cwd() / ".env")
    args.func(args)


if __name__ == "__main__":
    main()
