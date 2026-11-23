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
