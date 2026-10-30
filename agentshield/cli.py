"""Command-line entry point: `agentshield list` and `agentshield run`."""

from __future__ import annotations

import argparse
import sys

from .agents import PROFILES, ScriptedAgent
from .defenses import DEFENSES, get_defense
from .runner import plan_episodes, run_benchmark
from .suite import load_injections, load_tasks


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
    injections = load_injections()
    print("Tasks:")
    for t in load_tasks():
        print(f"  {t.id:28} slot={t.slot:16} {t.prompt}")
    print("\nAttacker goals:")
    for g in {i.goal.id: i.goal for i in injections}.values():
        print(f"  {g.id:28} [{g.category}] {g.instruction}")
    print("\nTechniques:")
    for t in {i.technique.id: i.technique for i in injections}.values():
        print(f"  {t.id:28} {t.description}")
    print(f"\nDefenses: {', '.join(DEFENSES)}")
    print(f"Scripted profiles: {', '.join(PROFILES)}")


def cmd_run(args: argparse.Namespace) -> None:
    tasks = _select(load_tasks(), args.tasks, lambda t: t.id)
    injections = _select(load_injections(), args.goals, lambda i: i.goal.id)
    injections = _select(injections, args.techniques, lambda i: i.technique.id)
    n = len(plan_episodes(tasks, injections, args.repeats))

    if args.dry_run:
        print(f"{n} episodes ({len(tasks)} tasks x ({len(injections)} injections + 1 benign) x {args.repeats} repeats)")
        return

    if args.agent == "scripted":
        agent = ScriptedAgent(profile=args.profile, seed=args.seed)
    else:
        from .agents.claude import ClaudeAgent

        agent = ClaudeAgent(model=args.model, effort=args.effort)
        print(f"About to run {n} episodes against {args.model}; each makes several API calls.", file=sys.stderr)

    def progress(i: int, total: int, ep) -> None:
        mark = "ATTACK" if ep.attack_success else ("ok" if ep.utility else "fail")
        print(f"[{i}/{total}] {ep.episode_id}: {mark}", file=sys.stderr)

    run_dir, m = run_benchmark(
        agent, get_defense(args.defense), tasks, injections, args.seed, args.repeats, args.out,
        progress=None if args.quiet else progress,
    )
    asr, util = m["attack_success_rate"], m["benign_utility"]
    print(f"\nAttack success rate: {asr['rate']:.1%} ({asr['k']}/{asr['n']})")
    print(f"Benign utility:      {util['rate']:.1%} ({util['k']}/{util['n']})")
    print(f"Report: {run_dir / 'report.md'}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="agentshield", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list tasks, attacks, defenses").set_defaults(func=cmd_list)

    run = sub.add_parser("run", help="run the benchmark")
    run.add_argument("--agent", choices=["scripted", "claude"], default="scripted")
    run.add_argument("--profile", choices=list(PROFILES), default="medium", help="scripted agent susceptibility")
    run.add_argument("--model", default="claude-opus-5-5")
    run.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default="medium")
    run.add_argument("--defense", choices=list(DEFENSES), default="none")
    run.add_argument("--tasks", help="comma-separated task ids")
    run.add_argument("--goals", help="comma-separated attacker goal ids")
    run.add_argument("--techniques", help="comma-separated technique ids")
    run.add_argument("--repeats", type=int, default=1)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--out", default="results")
    run.add_argument("--dry-run", action="store_true", help="print the episode count and exit")
    run.add_argument("--quiet", action="store_true")
    run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
