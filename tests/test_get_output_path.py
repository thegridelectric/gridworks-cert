"""Test _get_output_path(), which infers output path based (name, suffix, certs_dir) or accepts explicit path."""

from pathlib import Path

from gwcert.key.__main__ import get_output_path  # noqa


def test_get_output_path() -> None:
    """Test _get_output_path()."""
    for name, output in [
        ("a", "/certs/a/a.pem"),
        ("a.pem", "/certs/a/a.pem"),
        ("a.b", "/certs/a.b/a.b.pem"),
        ("a.b.pem", "/certs/a.b/a.b.pem"),
        ("c/a", "./c/a"),
        ("c/a.pem", "./c/a.pem"),
        ("c/a.b", "./c/a.b"),
        ("c/a.b.pem", "./c/a.b.pem"),
        ("/a", "/a"),
        ("/a.b", "/a.b"),
        ("/a.pem", "/a.pem"),
        ("/a.b.pem", "/a.b.pem"),
        ("/c/a", "/c/a"),
        ("/c/a.b", "/c/a.b"),
        ("/c/a.pem", "/c/a.pem"),
        ("/c/a.b.pem", "/c/a.b.pem"),
    ]:
        assert get_output_path(name, ".pem", Path("/certs")) == Path(output)
