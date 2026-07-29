import io
from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_url import ScanUrl as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_url_text(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "urls": unordered(
            [
                "http://foobar.example.com",
                "https://barfoo.example.com",
                "ftp://barfoo.example.com",
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.url",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_url_html(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "urls": ["https://example.com/example.js"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.html",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_url_requires_scheme(mocker):
    """
    Pass: Only URLs beginning with a valid scheme and :// are collected.
    Failure: A URL without a scheme is included in the scanner event.
    """

    mocker.patch("strelka.scanners.scan_url.validators.url", return_value=True)
    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "urls": unordered(
            [
                "https://example.com",
                "ftp://files.example.com",
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_fileobj=io.BytesIO(
            b"example.com https://example.com ftp://files.example.com"
        ),
        options={"regex": "test_regex", "test_regex": r"\S+"},
    )

    TestCase().assertDictEqual(test_scan_event, scanner_event)
