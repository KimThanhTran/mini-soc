import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "simulator"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend" / "app"))

import simulate  # noqa: E402


@pytest.mark.parametrize("host", ["127.0.0.1", "10.4.5.6", "192.168.1.20", "172.24.0.2", "localhost"])
def test_private_and_loopback_targets_are_allowed(host):
    simulate.assert_private(host)


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "no-such-host.invalid"])
def test_public_or_unresolvable_targets_are_refused(host):
    with pytest.raises(SystemExit):
        simulate.assert_private(host)
