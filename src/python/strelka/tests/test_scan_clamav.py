from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_clamav import ScanClamav as ScanUnderTest
from strelka.tests import run_test_scan


def _mock_clamd(mocker, reply: bytes):
    """Patches socket.create_connection to return a fake clamd connection."""
    mock_sock = mock.MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = False
    mock_sock.recv.side_effect = [reply, b""]

    return mocker.patch(
        "strelka.scanners.scan_clamav.socket.create_connection",
        return_value=mock_sock,
    )


def test_scan_clamav_clean(mocker):
    """
    Pass: Clean file scan against clamd returns infected=False.
    Failure: Unable to load file or sample event fails to match.
    """
    _mock_clamd(mocker, b"stream: OK\x00")

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "infected": False,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_clamav_infected(mocker):
    """
    Pass: Infected file scan against clamd returns infected=True with a signature name.
    Failure: Unable to load file or sample event fails to match.
    """
    _mock_clamd(mocker, b"stream: Win.Test.EICAR_HDB-1 FOUND\x00")

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "infected": True,
        "signature": "Win.Test.EICAR_HDB-1",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_clamav_connection_error(mocker):
    """
    Pass: An unreachable clamd daemon is flagged instead of raising.
    Failure: Connection error propagates or isn't flagged.
    """
    mocker.patch(
        "strelka.scanners.scan_clamav.socket.create_connection",
        side_effect=ConnectionRefusedError("connection refused"),
    )

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["clamd_connection_error"],
        "error": "connection refused",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
