import pytest
import os
import sys
import html as html_lib

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from vulnerable_app import init_db, login, render_profile, read_file

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def db_conn():
    """Provide a fresh in-memory DB for each test."""
    conn = init_db()
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def setup_public_dir(tmp_path, monkeypatch):
    """
    Create a controlled public/ directory inside tmp_path and change the
    working directory to tmp_path so all relative path operations in the
    app resolve deterministically within the temp sandbox.
    """
    public_dir = tmp_path / "public"
    public_dir.mkdir()
    (public_dir / "test.txt").write_text("Hello")
    monkeypatch.chdir(tmp_path)
    yield


# ──────────────────────────────────────────────────────────────────────────────
# Functional Tests  (must pass after patching — regression checks)
# ──────────────────────────────────────────────────────────────────────────────

def test_functional_login(db_conn):
    """Valid credentials return True; wrong password returns False."""
    assert login(db_conn, "admin", "secretpass") is True
    assert login(db_conn, "user", "wrongpass") is False


def test_functional_profile():
    """render_profile with a plain username must contain that username."""
    res = render_profile("John")
    assert "John" in res


def test_functional_read_file():
    """read_file with a valid filename inside public/ must return its content."""
    assert read_file("test.txt") == "Hello"


# ──────────────────────────────────────────────────────────────────────────────
# Security Tests  (must pass after patching — exploit checks)
# ──────────────────────────────────────────────────────────────────────────────

def test_security_sqli(db_conn):
    """
    Classic OR-bypass SQLi payload must NOT succeed.
    If login() returns True here, the SQLi vulnerability is still present.
    """
    vuln_exists = login(db_conn, "admin", "' OR '1'='1")
    assert not vuln_exists, "SQL Injection vulnerability still exists"

    # Second payload: comment-based injection
    vuln_exists_2 = login(db_conn, "admin'--", "anything")
    assert not vuln_exists_2, "SQL Injection (comment-based) vulnerability still exists"


def test_security_xss():
    """
    XSS payload must NOT appear unescaped in the rendered output.
    The raw '<script>' tag must not be present in the HTML.
    """
    payload = "<script>alert(1)</script>"
    res = render_profile(payload)

    # The raw, unescaped payload must NOT be in the output
    assert "<script>" not in res, (
        "XSS vulnerability still exists — raw <script> tag found in output"
    )

    # The function must still produce output (not silently break)
    assert res is not None and len(res) > 0, (
        "render_profile returned empty/None — functional regression detected"
    )


def test_security_path_traversal(tmp_path):
    """
    Path traversal attempt (../secret.txt) must NOT return the secret content.
    Uses pytest's tmp_path to place the secret outside the public/ dir cleanly.
    """
    # Create a sensitive file outside public/ but inside the temp sandbox
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("SECRET_DATA")

    # Attempt traversal: public/../secret.txt should be blocked
    res = read_file("../secret.txt")
    assert "SECRET_DATA" not in res, "Path Traversal vulnerability still exists"


def test_security_path_traversal_absolute():
    """
    Absolute path injection must be blocked.
    """
    res = read_file("/etc/passwd")
    # Should return "File not found." or raise — never actual file content
    assert "root:" not in res, "Absolute path injection vulnerability still exists"
