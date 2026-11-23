[direct] Fixed the SQL injection in `GET /books` and added two regression tests in the `bookstore-security` project → all 5 tests pass. I did this myself because the office agents (`gelistirici`, `test`) aren't available here.

1. **Fix:** `main.py:100-108` now runs a parameterized query, `LIKE ? ESCAPE '\'`. Before binding, it escapes `\`, `%` and `_` in `q`, so typed wildcards match literally. The planted-issues docstring is unchanged.
2. **Tests:** two new tests in `test_main.py`. One checks that `' OR 1=1 --` returns `[]`. The other checks that `%`, `_`, `Python%` and `Pyth_n` return `[]` while `Clean` still finds "Clean Code". Both fail on the vulnerable code: it returns all 3 books.
3. **Results:** `.venv/bin/pytest -q` gives 5 passed. Git commands needed approval, so I checked the old behaviour on a hand-written copy of the vulnerable code in `/tmp/bookstore-vuln/` rather than the committed file. I didn't re-run Semgrep, and nothing was committed.
