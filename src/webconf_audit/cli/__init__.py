import json
from enum import Enum
from typing import cast

import click
import typer

from webconf_audit.baselines import apply_baseline_diff, load_baseline_file, write_baseline_file
from webconf_audit.external import analyze_external_target
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisIssue, AnalysisResult, Severity, SourceLocation
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter, deduplicate_findings
from webconf_audit.rule_registry import RuleCategory, RuleMeta, StandardReference
from webconf_audit.suppressions import apply_suppressions, load_suppression_file

app = typer.Typer(help="Web server configuration security audit tool")


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


class GroupBy(str, Enum):
    severity = "severity"
    standard = "standard"


class FailOnSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_GROUPING_SEQUENCE_META_KEY = "grouping_sequence"


def _suppressions_option() -> str | None:
    return typer.Option(
        None,
        "--suppressions",
        help="Override the suppression YAML file path.",
    )


def _baseline_option() -> str | None:
    return typer.Option(
        None,
        "--baseline",
        help="Compare current findings against a baseline JSON file.",
    )


def _write_baseline_option() -> str | None:
    return typer.Option(
        None,
        "--write-baseline",
        help="Write the current active findings as a baseline JSON file.",
    )


def _fail_on_new_option() -> FailOnSeverity | None:
    return typer.Option(
        None,
        "--fail-on-new",
        help="Exit 2 when new findings at or above this severity exist.",
    )


def _group_by_option() -> GroupBy:
    return typer.Option(
        GroupBy.severity,
        "--group-by",
        help="Text report grouping: severity or standard.",
        callback=_record_group_by_option,
    )


def _group_repeated_option() -> bool:
    return typer.Option(
        False,
        "--group-repeated/--no-group-repeated",
        help="Group repeated findings in text reports while preserving each location.",
        callback=_record_group_repeated_option,
    )


def _group_by_cause_option() -> bool:
    return typer.Option(
        False,
        "--group-by-cause",
        help="Group findings by shared effective cause in text and JSON reports.",
        callback=_record_group_by_cause_option,
    )


def _output_result(
    result: AnalysisResult,
    fmt: OutputFormat = OutputFormat.text,
    fail_on: FailOnSeverity | None = None,
    suppressions_path: str | None = None,
    baseline_path: str | None = None,
    write_baseline_path: str | None = None,
    fail_on_new: FailOnSeverity | None = None,
    group_by: GroupBy = GroupBy.severity,
    group_repeated: bool = False,
    group_by_cause: bool = False,
    grouping_sequence: list[str] | None = None,
) -> None:
    _ensure_all_rules_loaded()
    if group_by is None:
        group_by = GroupBy.severity
    if grouping_sequence is None:
        ctx = click.get_current_context(silent=True)
        grouping_sequence = list(_grouping_sequence(ctx)) if ctx is not None else []
    group_by, group_repeated, group_by_cause = _resolve_grouping_options(
        group_by=group_by,
        group_repeated=group_repeated,
        group_by_cause=group_by_cause,
        grouping_sequence=grouping_sequence or [],
    )
    suppression_load_failed = _apply_suppressions(
        result,
        suppressions_path,
        load_default=suppressions_path is None,
    )
    report = ReportData(results=[result])
    baseline_operation_failed = _apply_baseline(report, result, baseline_path, fail_on_new)
    if write_baseline_path is not None:
        issue = write_baseline_file(report, write_baseline_path)
        if issue is not None:
            result.issues.append(issue)
            baseline_operation_failed = True
    formatter = (
        TextFormatter(
            group_by=group_by.value,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
        if fmt == OutputFormat.text
        else JsonFormatter(group_by_cause=group_by_cause)
    )
    typer.echo(formatter.format(report))
    exit_code = _ci_exit_code(
        result,
        fail_on,
        fail_on_new,
        report,
        explicit_suppression_error=suppressions_path is not None and suppression_load_failed,
        explicit_baseline_error=baseline_operation_failed,
    )
    if exit_code:
        raise typer.Exit(exit_code)


def _apply_suppressions(
    result: AnalysisResult,
    suppressions_path: str | None,
    *,
    load_default: bool,
) -> bool:
    suppression_set = load_suppression_file(suppressions_path, load_default=load_default)
    result.issues.extend(suppression_set.issues)
    apply_suppressions(result, suppression_set)
    return any(
        issue.level == "error" and issue.code.startswith("suppression_")
        for issue in suppression_set.issues
    )


def _record_group_by_option(
    ctx: click.Context,
    param: click.Parameter,
    value: GroupBy,
) -> GroupBy:
    if _option_came_from_cli(ctx, param):
        _grouping_sequence(ctx).append(value.value)
    return value


def _record_group_repeated_option(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,
) -> bool:
    if _option_came_from_cli(ctx, param):
        _grouping_sequence(ctx).append("repeated" if value else "no-repeated")
    return value


def _record_group_by_cause_option(
    ctx: click.Context,
    param: click.Parameter,
    value: bool,
) -> bool:
    if _option_came_from_cli(ctx, param):
        _grouping_sequence(ctx).append("cause" if value else "no-cause")
    return value


def _option_came_from_cli(ctx: click.Context, param: click.Parameter) -> bool:
    source = ctx.get_parameter_source(param.name) if param.name else None
    return source == click.core.ParameterSource.COMMANDLINE


def _grouping_sequence(ctx: click.Context) -> list[str]:
    sequence = ctx.meta.get(_GROUPING_SEQUENCE_META_KEY)
    if not isinstance(sequence, list):
        sequence = []
        ctx.meta[_GROUPING_SEQUENCE_META_KEY] = sequence
    return sequence


_GROUPING_ACTIVATIONS: frozenset[str] = frozenset({"standard", "repeated", "cause"})


def _resolve_grouping_options(
    *,
    group_by: GroupBy,
    group_repeated: bool,
    group_by_cause: bool,
    grouping_sequence: list[str],
) -> tuple[GroupBy, bool, bool]:
    activations = [token for token in grouping_sequence if token in _GROUPING_ACTIVATIONS]
    if len(activations) > 1:
        typer.echo(
            (
                "Warning: --group-by standard, --group-repeated, and "
                "--group-by-cause are mutually exclusive; using the last one "
                "provided."
            ),
            err=True,
        )

    if not grouping_sequence:
        return group_by, group_repeated, group_by_cause

    winner = grouping_sequence[-1]
    if winner == "standard":
        return GroupBy.standard, False, False
    if winner == "severity":
        return GroupBy.severity, False, False
    if winner == "repeated":
        return GroupBy.severity, True, False
    if winner == "no-repeated":
        return group_by, False, group_by_cause
    if winner == "cause":
        return GroupBy.severity, False, True
    if winner == "no-cause":
        return group_by, group_repeated, False
    return group_by, group_repeated, group_by_cause


def _ci_exit_code(
    result: AnalysisResult,
    fail_on: FailOnSeverity | None,
    fail_on_new: FailOnSeverity | None,
    report: ReportData,
    *,
    explicit_suppression_error: bool = False,
    explicit_baseline_error: bool = False,
) -> int:
    if explicit_suppression_error or explicit_baseline_error:
        return 1
    if fail_on is None and fail_on_new is None:
        return 0
    if any(issue.level == "error" for issue in result.issues):
        return 1
    if _has_blocking_current_findings(result, fail_on):
        return 2
    if _has_blocking_new_findings(report, fail_on_new):
        return 2
    return 0


def _apply_baseline(
    report: ReportData,
    result: AnalysisResult,
    baseline_path: str | None,
    fail_on_new: FailOnSeverity | None,
) -> bool:
    if baseline_path is None:
        if fail_on_new is None:
            return False
        result.issues.append(
            AnalysisIssue(
                code="baseline_required",
                level="error",
                message="--fail-on-new requires --baseline.",
                location=SourceLocation(mode="local", kind="check", details="baseline"),
            )
        )
        return True

    load_result = load_baseline_file(baseline_path)
    result.issues.extend(load_result.issues)
    if load_result.baseline is not None:
        apply_baseline_diff(report, load_result.baseline)
    return load_result.failed


def _has_blocking_current_findings(
    result: AnalysisResult,
    fail_on: FailOnSeverity | None,
) -> bool:
    if fail_on is None:
        return False
    threshold = _SEVERITY_RANK[fail_on.value]
    deduplicated, _ = deduplicate_findings(result.findings)
    return any(_SEVERITY_RANK[finding.severity] >= threshold for finding in deduplicated)


def _has_blocking_new_findings(
    report: ReportData,
    fail_on_new: FailOnSeverity | None,
) -> bool:
    if fail_on_new is None:
        return False
    baseline_diff = report.baseline_diff
    if baseline_diff is None:
        return False
    threshold = _SEVERITY_RANK[fail_on_new.value]
    new_findings = baseline_diff.get("new_findings")
    if not isinstance(new_findings, list):
        return False
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("severity"), str)
        and _SEVERITY_RANK.get(entry["severity"], -1) >= threshold
        for entry in new_findings
    )


@app.command("analyze-nginx")
def analyze_nginx(
    config_path: str = typer.Argument(..., help="Path to nginx config file"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    result = analyze_nginx_config(config_path)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-apache")
def analyze_apache(
    config_path: str = typer.Argument(..., help="Path to Apache config file"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    result = analyze_apache_config(config_path)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-lighttpd")
def analyze_lighttpd(
    config_path: str = typer.Argument(..., help="Path to Lighttpd config file"),
    execute_shell: bool = typer.Option(
        False,
        "--execute-shell/--no-execute-shell",
        help="Execute include_shell directives during analysis.",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        help="Evaluate conditional blocks for a specific host (targeted analysis).",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    result = analyze_lighttpd_config(
        config_path, execute_shell=execute_shell, host=host,
    )
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-iis")
def analyze_iis(
    config_path: str = typer.Argument(
        ...,
        help="Path to IIS config file (web.config or applicationHost.config)",
    ),
    machine_config: str | None = typer.Option(
        None,
        "--machine-config",
        help="Optional path to machine.config for IIS inheritance analysis.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    result = analyze_iis_config(config_path, machine_config_path=machine_config)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


def _parse_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated port string with validation.

    Raises :class:`typer.BadParameter` on invalid tokens, out-of-range
    values (must be 1-65535), or an empty result.
    """
    seen: set[int] = set()
    result: list[int] = []
    for idx, token in enumerate(raw.split(",")):
        token = token.strip()
        if not token:
            raise typer.BadParameter(
                f"empty port value at position {idx + 1} in: {raw!r}"
            )
        try:
            port = int(token)
        except ValueError:
            raise typer.BadParameter(f"invalid port value: {token!r}") from None
        if port < 1 or port > 65535:
            raise typer.BadParameter(
                f"port out of range (1-65535): {port}"
            )
        if port not in seen:
            seen.add(port)
            result.append(port)
    if not result:
        raise typer.BadParameter("--ports requires at least one valid port")
    return tuple(result)


@app.command("analyze-external")
def analyze_external(
    target: str = typer.Argument(..., help="URL, host, or host:port to probe"),
    scan_ports: bool = typer.Option(
        True,
        "--scan-ports/--no-scan-ports",
        help="Enable or disable port discovery for bare-host targets.",
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        help="Comma-separated list of ports to scan (e.g. '80,443,8080').",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    parsed_ports: tuple[int, ...] | None = None
    if ports is not None:
        parsed_ports = _parse_ports(ports)
    result = analyze_external_target(target, scan_ports=scan_ports, ports=parsed_ports)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("list-rules")
def list_rules(
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (local, external, universal).",
    ),
    server_type: str | None = typer.Option(
        None,
        "--server-type",
        "-s",
        help="Filter by server type (nginx, apache, lighttpd, iis).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity (critical, high, medium, low, info).",
    ),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Filter by tag (e.g. tls, headers)."),
    fmt: OutputFormat = typer.Option(
        OutputFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    """List all registered audit rules with optional filtering."""
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    parsed_category = _parse_rule_category(category)
    parsed_server_type = _parse_rule_server_type(server_type)
    parsed_severity = _parse_rule_severity(severity)
    parsed_tag = _parse_rule_tag(tag)

    rules = registry.list_rules(
        category=parsed_category,
        server_type=parsed_server_type,
        severity=parsed_severity,
        tag=parsed_tag,
    )

    if fmt == OutputFormat.json:
        typer.echo(json.dumps([_rule_meta_payload(m) for m in rules], indent=2, ensure_ascii=False))
        return

    if not rules:
        typer.echo("No rules match the given filters.")
        raise typer.Exit()

    typer.echo(f"{'RULE ID':<55} {'SEV':<7} {'CAT':<10} {'SERVER':<10} ORDER")
    typer.echo("-" * 90)
    for m in rules:
        server = m.server_type or ""
        typer.echo(f"{m.rule_id:<55} {m.severity:<7} {m.category:<10} {server:<10} {m.order}")
    typer.echo(f"\nTotal: {len(rules)} rules")


def _rule_meta_payload(meta: RuleMeta) -> dict[str, object]:
    return {
        "rule_id": meta.rule_id,
        "title": meta.title,
        "severity": meta.severity,
        "description": meta.description,
        "recommendation": meta.recommendation,
        "category": meta.category,
        "server_type": meta.server_type,
        "input_kind": meta.input_kind,
        "tags": list(meta.tags),
        "standards": [_rule_standard_ref_payload(ref) for ref in meta.standards],
        "standards_secondary": [
            _rule_standard_ref_payload(ref) for ref in meta.standards_secondary
        ],
        "condition": meta.condition,
        "order": meta.order,
    }


def _rule_standard_ref_payload(ref: StandardReference) -> dict[str, object]:
    fields: dict[str, object | None] = {
        "standard": ref.standard,
        "reference": ref.reference,
        "url": ref.url,
        "coverage": ref.coverage,
        "note": ref.note,
    }
    return {key: value for key, value in fields.items() if value is not None}


def _parse_rule_category(value: str | None) -> RuleCategory | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"local", "external", "universal"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid category {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(RuleCategory, normalized)


def _parse_rule_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"critical", "high", "medium", "low", "info"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid severity {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(Severity, normalized)


def _parse_rule_server_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_server_types()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid server type {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _parse_rule_tag(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_tags()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid tag {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _available_rule_server_types() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        meta.server_type
        for meta in registry.list_rules()
        if meta.server_type is not None
    }


def _available_rule_tags() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        tag
        for meta in registry.list_rules()
        for tag in meta.tags
    }


def _ensure_all_rules_loaded() -> None:
    """Load all rule packages + meta-only registrations into the registry."""
    from webconf_audit.rule_registry import registry
    from webconf_audit.external.rules._runner import register_external_rule_metas

    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    registry.ensure_loaded("webconf_audit.external.rules")
    register_external_rule_metas()


if __name__ == "__main__":
    app()
