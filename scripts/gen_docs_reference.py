"""Generate the reference pages of the documentation from the code.

Nothing here is hand-written: the CLI reference walks the click groups, the
file schemas come from the pydantic models, the threat catalogue and the
dismissal rules from ``knowledge/threats``. Run before ``zensical build``
(the docs workflow does; ``make docs`` locally).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "reference"
sys.path.insert(0, str(ROOT / "src"))


def cli_page() -> str:
    from model_wtf.cli import cli

    lines = [
        "# CLI reference",
        "",
        "Generated from the command definitions. Every command takes `--root PATH`"
        " (default: the git top-level of the working directory).",
        "",
    ]
    _walk(cli, ["model-wtf"], lines, depth=1)
    return "\n".join(lines).replace("``", "`") + "\n"


def _walk(cmd: click.Command, path: list[str], lines: list[str], *, depth: int) -> None:
    if isinstance(cmd, click.Group):
        if depth >= 3:
            # `model-wtf compliance <group>`: a section
            lines.append(f"## `{' '.join(path[2:])}`")
            lines.append("")
            if cmd.help:
                lines.append(cmd.help.strip())
                lines.append("")
        for sub_name in sorted(cmd.commands):
            sub = cmd.commands[sub_name]
            if getattr(sub, "hidden", False):
                continue
            _walk(sub, [*path, sub_name], lines, depth=depth + 1)
        return
    lines.append(f"### `{' '.join(path[2:])}`")
    lines.append("")
    if cmd.help:
        lines.append(_dedent_help(cmd.help))
        lines.append("")
    rows = []
    for param in cmd.params:
        if isinstance(param, click.Argument):
            rows.append((f"`{param.name.upper()}`", "argument", ""))
        elif isinstance(param, click.Option):
            if param.hidden or param.name == "help":
                continue
            opts = ", ".join(f"`{o}`" for o in [*param.opts, *param.secondary_opts])
            kind = "flag" if param.is_flag else _type_name(param)
            default = ""
            if param.default not in (None, False, (), []) and not param.is_flag:
                default = f"default `{param.default}`"
            help_text = (param.help or "").replace("\n", " ")
            rows.append((opts, kind, f"{help_text} {default}".strip()))
    if rows:
        lines.append("| Option | Type | Meaning |")
        lines.append("|---|---|---|")
        lines.extend(f"| {a} | {b} | {c} |" for a, b, c in rows)
        lines.append("")


def _type_name(param: click.Option) -> str:
    t = param.type
    if isinstance(t, click.Choice):
        return " \\| ".join(f"`{c}`" for c in t.choices)
    return t.name


def _dedent_help(text: str) -> str:
    import textwrap

    return textwrap.dedent(text).strip()


def schema_page() -> str:
    from model_wtf.compliance import schemas
    from model_wtf.compliance.activities import ActivityFile
    from model_wtf.compliance.data import Override
    from model_wtf.compliance.stamps import Finding, Stamp, StampChallenge
    from model_wtf.compliance.touchpoints import Manifest, Undeclared

    lines = [
        "# File schemas",
        "",
        "Generated from the pydantic models. Unknown keys are declaration errors.",
        "",
    ]
    for title, path, model in (
        ("Application", "`compliance/app.yaml`", schemas.App),
        ("Party", "`compliance/parties/<id>.yaml`", schemas.Party),
        ("Activity", "`compliance/activities/<slug>.yaml`", ActivityFile),
        ("Data override", "`<unit>/compliance/data/<id>.yaml`", Override),
        (
            "Touchpoint manifest",
            "`<unit>/compliance/touchpoints/<slug>.yaml`",
            Manifest,
        ),
        ("Undeclared flow entry", "`undeclared:` items of a manifest", Undeclared),
        ("Threat stamp", "`threats:` entries (mitigated / accepted / n/a)", Stamp),
        ("Stamp challenge", "`challenge:` / `answered:` on a stamp", StampChallenge),
        ("Finding", "`threats:` entries written from a `!missing`", Finding),
    ):
        lines.append(f"## {title}")
        lines.append("")
        lines.append(path)
        lines.append("")
        lines.append("| Field | Type | Required | Description |")
        lines.append("|---|---|---|---|")
        for name, field in model.model_fields.items():
            required = "yes" if field.is_required() else "no"
            desc = (field.description or "").replace("\n", " ").replace("|", "\\|")
            key = field.alias or name
            kind = _annotation(field.annotation)
            lines.append(f"| `{key}` | `{kind}` | {required} | {desc} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def _annotation(annotation: Any) -> str:
    text = str(annotation).replace("typing.", "").replace("model_wtf.compliance.", "")
    for noise in ("schemas.", "yaml_io.", "stamps.", "touchpoints.", "ops."):
        text = text.replace(noise, "")
    text = text.replace("<class '", "").replace("'>", "")
    return text.replace("|", "\\|")


def threats_page() -> str:
    from model_wtf.compliance.threats import load_catalogue, load_topics

    catalogue = load_catalogue()
    topics = load_topics()
    lines = [
        "# Threat catalogue",
        "",
        f"{len(catalogue.threats)} threats from pytm's library, each with how "
        "model-wtf treats it: `never` (impossible in the stacks we generate), "
        "dismissed by a simple rule, or open for a reviewer under a topic.",
        "",
        "## Topics",
        "",
        "| Topic | Question | Threats |",
        "|---|---|---|",
    ]
    for name, topic in topics.items():
        lines.append(
            f"| `{name}` | {topic.title} | {', '.join(f'`{s}`' for s in topic.sids)} |"
        )
    lines.append("")
    lines.append("## Rules")
    lines.append("")
    lines.append("Deterministic facts that close a cell without a reviewer.")
    lines.append("")
    lines.append("| Rule | Applies to | Asserts |")
    lines.append("|---|---|---|")
    for rid, rule in catalogue.rules.items():
        applies = ", ".join(k.value for k in rule.applies)
        lines.append(f"| `{rid}` | {applies} | {rule.description.replace('|', '/')} |")
    lines.append("")
    lines.append("## Threats")
    lines.append("")
    lines.append("| SID | Title | Elements | Treatment | Effect |")
    lines.append("|---|---|---|---|---|")
    for sid, spec in sorted(catalogue.threats.items()):
        treatment = catalogue.mapping.get(sid)
        if treatment is None:
            continue
        if treatment.never:
            how = f"never — {treatment.never}"
        else:
            rules = ", ".join(f"`{r}`" for r in treatment.dismiss) or "—"
            how = f"topic `{treatment.topic_name}`; dismissed by {rules}"
        elements = ", ".join(k.value for k in (treatment.element or spec.elements))
        lines.append(
            f"| `{sid}` | {spec.title.replace('|', '/')} | {elements} | "
            f"{how.replace('|', '/')} | {treatment.effect or '—'} |"
        )
    return "\n".join(lines) + "\n"


def exit_codes_page() -> str:
    from model_wtf.compliance.exit_codes import ExitCode

    lines = ["# Exit codes", "", "| Code | Name | Meaning |", "|---|---|---|"]
    import ast
    import inspect

    docs: dict[str, str] = {}
    tree = ast.parse(inspect.getsource(ExitCode))
    body = tree.body[0].body  # type: ignore[attr-defined]
    for i, node in enumerate(body):
        if (
            isinstance(node, ast.Assign)
            and i + 1 < len(body)
            and isinstance(body[i + 1], ast.Expr)
            and isinstance(body[i + 1].value, ast.Constant)  # type: ignore[attr-defined]
        ):
            docs[node.targets[0].id] = " ".join(  # type: ignore[attr-defined]
                str(body[i + 1].value.value).split()  # type: ignore[attr-defined]
            )
    for code in ExitCode:
        lines.append(f"| {int(code)} | `{code.name}` | {docs.get(code.name, '')} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "cli.md").write_text(cli_page(), encoding="utf-8")
    (OUT / "schemas.md").write_text(schema_page(), encoding="utf-8")
    (OUT / "threats.md").write_text(threats_page(), encoding="utf-8")
    (OUT / "exit-codes.md").write_text(exit_codes_page(), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
