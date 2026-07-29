import io
from unittest import TestCase, mock

import pytest

from strelka.scanners.httpx_scanner import (
    HttpxScanner as ScanUnderTest,
)
from strelka.scanners.httpx_scanner import is_valid_http_url, run_httpx
from strelka.tests import run_test_scan


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com",
        "https://example.com/path?q=1",
        "HTTPS://subdomain.example.com:8443/path",
    ],
)
def test_is_valid_http_url_accepts_complete_urls(value):
    assert is_valid_http_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "random words",
        " https://example.com ",
        "example.com",
        "ftp://files.example.com",
        "://example.com",
        "http://",
        "https://has space.example",
    ],
)
def test_is_valid_http_url_rejects_invalid_values(value):
    assert not is_valid_http_url(value)


def test_httpx_scanner_does_not_start_dependencies_for_invalid_input(
    mocker,
):
    kafka_producer = mocker.patch("strelka.scanners.httpx_scanner.KafkaProducer")
    create_run_directory = mocker.patch(
        "strelka.scanners.httpx_scanner.create_run_directory"
    )
    run_httpx_mock = mocker.patch("strelka.scanners.httpx_scanner.run_httpx")

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_fileobj=io.BytesIO(
            b"random words\nexample.com\nftp://files.example.com\n"
        ),
    )

    TestCase().assertDictEqual(
        {
            "elapsed": mock.ANY,
            "flags": ["httpx_invalid_url"],
            "httpx": [],
        },
        scanner_event,
    )
    kafka_producer.assert_not_called()
    create_run_directory.assert_not_called()
    run_httpx_mock.assert_not_called()


def test_httpx_scanner_only_runs_valid_unique_urls(mocker, tmp_path):
    producer = mocker.patch("strelka.scanners.httpx_scanner.KafkaProducer")
    mocker.patch(
        "strelka.scanners.httpx_scanner.create_run_directory",
        return_value=tmp_path,
    )
    run_httpx_mock = mocker.patch("strelka.scanners.httpx_scanner.run_httpx")
    mocker.patch(
        "strelka.scanners.httpx_scanner.read_last_record",
        side_effect=[
            {
                "url": "https://example.com",
                "host": "example.com",
                "content_type": "text/html",
            },
            {
                "url": "http://example.org/path",
                "host": "example.org",
                "content_type": "text/html",
            },
        ],
    )

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_fileobj=io.BytesIO(
            b"random words\n"
            b"https://example.com\n"
            b"example.com\n"
            b"http://example.org/path\n"
            b"https://example.com\n"
        ),
    )

    assert scanner_event["flags"] == ["httpx_invalid_url"]
    assert len(scanner_event["httpx"]) == 2
    assert [call.args[1] for call in run_httpx_mock.call_args_list] == [
        "https://example.com",
        "http://example.org/path",
    ]
    producer.assert_called_once()


def test_run_httpx_rejects_invalid_url_before_subprocess(mocker, tmp_path):
    subprocess_run = mocker.patch("strelka.scanners.httpx_scanner.subprocess.run")

    with pytest.raises(ValueError, match=r"valid HTTP\(S\) URL"):
        run_httpx(
            "httpx_tmp",
            "random words",
            tmp_path / "output.jsonl",
        )

    subprocess_run.assert_not_called()
