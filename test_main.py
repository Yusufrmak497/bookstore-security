from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_search_books():
    r = client.get("/books", params={"q": "Python"})
    assert r.status_code == 200
    assert any("Python" in b["title"] for b in r.json())


def test_get_book():
    r = client.get("/books/1")
    assert r.status_code == 200
    assert "title" in r.json()


def test_add_and_list_reviews():
    client.post("/reviews", json={"book_id": 1, "text": "Great read"})
    r = client.get("/reviews/1")
    assert r.status_code == 200
    assert "Great read" in r.json()


def test_search_books_sql_injection_regression():
    # Classic injection: on the vulnerable f-string version this closes the
    # LIKE literal and makes the WHERE clause always true -> every book returned.
    r = client.get("/books", params={"q": "' OR 1=1 --"})
    assert r.status_code == 200
    assert r.json() == []


def test_search_books_like_wildcards_are_literal():
    # User-typed % and _ must not act as wildcards (no seeded title contains them).
    for q in ("%", "_", "Python%", "Pyth_n"):
        r = client.get("/books", params={"q": q})
        assert r.status_code == 200
        assert r.json() == [], q

    # Escaping must not break normal matching.
    r = client.get("/books", params={"q": "Clean"})
    assert [b["title"] for b in r.json()] == ["Clean Code"]


def test_secrets_loaded_from_env_not_hardcoded(monkeypatch):
    # CWE-798 regression: on the vulnerable version API_KEY/SECRET_TOKEN were
    # string literals, so they were non-None even with the env vars unset.
    import importlib

    import main

    try:
        monkeypatch.delenv("BOOKSTORE_API_KEY", raising=False)
        monkeypatch.delenv("BOOKSTORE_ADMIN_TOKEN", raising=False)
        importlib.reload(main)
        assert main.API_KEY is None
        assert main.SECRET_TOKEN is None

        monkeypatch.setenv("BOOKSTORE_API_KEY", "test-api-key")
        monkeypatch.setenv("BOOKSTORE_ADMIN_TOKEN", "test-admin-token")
        importlib.reload(main)
        assert main.API_KEY == "test-api-key"
        assert main.SECRET_TOKEN == "test-admin-token"
    finally:
        monkeypatch.undo()
        importlib.reload(main)


def test_cors_restricted_to_allow_list(monkeypatch):
    # CWE-942 regression: the vulnerable version used allow_origins=["*"] with
    # credentials, so Starlette echoed back ANY Origin (incl. attacker sites)
    # and allowed every method/header in preflight.
    import importlib

    import main

    try:
        monkeypatch.delenv("BOOKSTORE_ALLOWED_ORIGINS", raising=False)
        importlib.reload(main)
        c = TestClient(main.app)

        # Untrusted origin: no ACAO header on simple request, preflight rejected.
        r = c.get("/books", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers
        r = c.options(
            "/books",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code == 400
        assert "access-control-allow-origin" not in r.headers

        # Default allowed origin works.
        r = c.get("/books", headers={"Origin": "http://localhost:8000"})
        assert r.headers["access-control-allow-origin"] == "http://localhost:8000"

        # Disallowed method / header rejected even for an allowed origin.
        for method, extra in (("DELETE", None), ("POST", "X-Evil")):
            h = {
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": method,
            }
            if extra:
                h["Access-Control-Request-Headers"] = extra
            assert c.options("/reviews", headers=h).status_code == 400, method

        # Allowed preflight: POST with Content-Type.
        r = c.options(
            "/reviews",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert r.status_code == 200

        # Allow-list is read from the env var (comma-separated, whitespace ok).
        monkeypatch.setenv(
            "BOOKSTORE_ALLOWED_ORIGINS", "https://a.example, https://b.example"
        )
        importlib.reload(main)
        assert main.ALLOWED_ORIGINS == ["https://a.example", "https://b.example"]
        c = TestClient(main.app)
        r = c.get("/books", headers={"Origin": "https://b.example"})
        assert r.headers["access-control-allow-origin"] == "https://b.example"
        r = c.get("/books", headers={"Origin": "http://localhost:8000"})
        assert "access-control-allow-origin" not in r.headers
    finally:
        monkeypatch.undo()
        importlib.reload(main)


def test_reviews_page_renders_text_not_html():
    # CWE-79 regression: the vulnerable page did
    # `box.innerHTML = reviews.map(t => '<p>' + t + '</p>')`, so a stored review
    # like `<img src=x onerror=...>` executed in every visitor's browser.
    import re
    from pathlib import Path

    html = (Path(__file__).parent / "static" / "index.html").read_text()

    # No HTML-parsing sinks for the untrusted review data.
    assert not re.search(r"\.innerHTML\s*\+?=", html)
    assert not re.search(r"\.outerHTML\s*\+?=", html)
    assert "insertAdjacentHTML" not in html
    assert "document.write" not in html

    # Reviews are rendered as text into <p> elements.
    assert re.search(r"\.textContent\s*=", html)
    assert "createElement('p')" in html
