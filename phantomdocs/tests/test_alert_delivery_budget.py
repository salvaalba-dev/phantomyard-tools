"""Check cross-file delivery budgets without executing transports or systemd."""

import ast
import configparser
import inspect
import textwrap
from pathlib import Path

import pytest

from phantomdocs import notify_adapter
from phantomdocs import workflow_policy_alert as alert
from phantomdocs import workflow_policy_alert_routes as routes

EXAMPLES = Path(__file__).resolve().parents[1] / "contrib/bridge-policy"


def configured_timeout(function):
    """Read the actual call argument, not another copy of the intended value."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    values = [
        keyword.value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        for keyword in call.keywords
        if keyword.arg == "timeout"
    ]
    assert len(values) == 1, f"Review timeout extraction for {function.__name__}"
    value = ast.literal_eval(values[0])
    assert type(value) in (int, float) and value > 0
    return value


@pytest.mark.parametrize(
    "unit_path",
    [
        EXAMPLES / "example-policy-alert@.service.example",
        EXAMPLES / "disabled-alerts/example-policy-alert@.service.disabled",
    ],
    ids=["regular-unit", "disabled-unit"],
)
def test_real_delivery_limits_enclose_both_sequential_channels(unit_path):
    telegram = configured_timeout(notify_adapter.telegram)
    mail = configured_timeout(notify_adapter.email)
    transport = configured_timeout(routes._deliver)
    lookup = configured_timeout(routes.unit_result)
    handler = configured_timeout(alert.notify)
    unit = configparser.ConfigParser(interpolation=None)
    unit.read_string(unit_path.read_text())
    service = unit.getfloat("Service", "TimeoutStartSec")

    assert max(telegram, mail) < transport, (
        f"Provider limits ({telegram}, {mail}) must fit inside transport {transport}"
    )
    assert transport < handler < service, (
        f"Required timeout order: transport {transport} < handler {handler} "
        f"< unit {service} ({unit_path.name})"
    )
    assert 2 * transport + lookup < handler, (
        f"Both sequential routes and Result lookup need {2 * transport + lookup}s; "
        f"handler {handler}s must leave additional startup/ledger margin"
    )
