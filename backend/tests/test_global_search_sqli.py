"""
Tests for SQL injection remediation in the global_search endpoint (GET /api/v1/search).

The vulnerability (CWE-89) was: user-supplied 'q' parameter interpolated directly
into raw SQL strings passed to db.session.execute(text(...)), allowing arbitrary
SQL injection.

The fix: SQL query strings are now static; the search term is passed as a named
bind parameter (:search_term) so the database driver always treats it as data,
never as SQL syntax.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _search(client, q):
    """Issue a GET /api/v1/search request and return the Response object."""
    return client.get(f"/api/v1/search?q={q}")


# ---------------------------------------------------------------------------
# Positive / functional tests
# ---------------------------------------------------------------------------

class TestGlobalSearchFunctionality:
    """Ensure normal search behaviour is preserved after the fix."""

    def test_missing_query_returns_400(self, client):
        """A request without 'q' must return 400."""
        response = client.get("/api/v1/search")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_empty_query_returns_400(self, client):
        """An empty 'q' value must return 400."""
        response = client.get("/api/v1/search?q=")
        assert response.status_code == 400

    def test_valid_query_returns_200(self, client):
        """A non-empty query must return 200 with the expected keys."""
        response = _search(client, "test")
        assert response.status_code == 200
        data = response.get_json()
        assert "query" in data
        assert "users" in data
        assert "projects" in data
        assert "tasks" in data

    def test_response_echoes_query(self, client):
        """The response body must echo back the exact query string."""
        response = _search(client, "hello")
        data = response.get_json()
        assert data["query"] == "hello"

    def test_no_match_returns_empty_lists(self, client):
        """A query that matches nothing must return empty lists."""
        response = _search(client, "zzz_no_such_thing_zzz")
        data = response.get_json()
        assert data["users"] == []
        assert data["projects"] == []
        assert data["tasks"] == []

    def test_search_finds_existing_user(self, client, sample_user):
        """A query matching an existing username must appear in the users list."""
        response = _search(client, "testuser")
        data = response.get_json()
        assert response.status_code == 200
        usernames = [u.get("username") for u in data["users"]]
        assert "testuser" in usernames

    def test_search_finds_existing_project(self, client, sample_project):
        """A query matching an existing project name must appear in projects."""
        response = _search(client, "Test Project")
        data = response.get_json()
        assert response.status_code == 200
        names = [p.get("name") for p in data["projects"]]
        assert "Test Project" in names

    def test_search_finds_existing_task(self, client, sample_task):
        """A query matching an existing task title must appear in tasks."""
        response = _search(client, "Test Task")
        data = response.get_json()
        assert response.status_code == 200
        titles = [t.get("title") for t in data["tasks"]]
        assert "Test Task" in titles


# ---------------------------------------------------------------------------
# Security / SQL-injection regression tests
# ---------------------------------------------------------------------------

class TestGlobalSearchSQLInjectionPrevention:
    """
    Verify that SQL injection payloads are treated as literal search strings
    (i.e. they produce no results or a harmless 200) rather than being
    executed as SQL.

    With the old code the payloads below would have broken out of the LIKE
    clause.  With parameterized queries the database driver escapes them so
    they are matched literally against the data, which either returns nothing
    or matches only rows that truly contain those characters.
    """

    def _assert_safe_response(self, client, payload):
        """
        A SQL-injection payload must NOT cause a 500 error.
        It must return 200 and carry the standard result structure,
        meaning the injected SQL was NOT executed as SQL.
        """
        response = _search(client, payload)
        # A 500 would indicate the injected SQL was executed and caused an error.
        assert response.status_code == 200, (
            f"Payload {payload!r} caused a server error — possible SQL injection"
        )
        data = response.get_json()
        assert "users" in data
        assert "projects" in data
        assert "tasks" in data

    def test_single_quote_injection(self, client):
        """Classic single-quote break-out attempt."""
        self._assert_safe_response(client, "' OR '1'='1")

    def test_double_quote_injection(self, client):
        """Double-quote variant."""
        self._assert_safe_response(client, '" OR "1"="1')

    def test_comment_injection(self, client):
        """SQL comment stripping attempt."""
        self._assert_safe_response(client, "admin'--")

    def test_union_injection(self, client):
        """UNION-based data-extraction attempt."""
        self._assert_safe_response(client, "' UNION SELECT 1,2,3--")

    def test_stacked_query_injection(self, client):
        """Stacked / batched query attempt."""
        self._assert_safe_response(client, "'; DROP TABLE users;--")

    def test_tautology_injection(self, client):
        """Tautology that would return all rows if not parameterized."""
        self._assert_safe_response(client, "x' OR '1'='1' --")

    def test_wildcard_characters_treated_as_literals(self, client):
        """
        SQL wildcards (%, _) in user input must be treated as literals in
        the result echo and must not cause errors, even though they are valid
        inside a LIKE clause — the driver handles their quoting.
        """
        response = _search(client, "test%user")
        assert response.status_code == 200
        data = response.get_json()
        # The echoed query must be the raw user string, not an expanded one
        assert data["query"] == "test%user"

    def test_null_byte_payload(self, client):
        """A NUL byte in the query must not crash the endpoint."""
        # Use URL-encoding for NUL (%00) so no literal control byte hits the source file
        response = client.get("/api/v1/search?q=test\x00injected")
        # Accept 200 or 400; either is safe. 500 is NOT acceptable.
        assert response.status_code in (200, 400)

    def test_injection_does_not_return_all_users(self, client, sample_user):
        """
        A tautology injection must NOT return rows it shouldn't.
        With the old code  `' OR '1'='1`  would return every user row.
        With parameterized queries the LIKE pattern is literally
        `%' OR '1'='1%`, which won't match 'testuser'.
        """
        payload = "' OR '1'='1"
        response = _search(client, payload)
        assert response.status_code == 200
        data = response.get_json()
        # The tautology must NOT expose the sample user
        usernames = [u.get("username") for u in data["users"]]
        assert "testuser" not in usernames, (
            "SQL injection tautology returned real user rows — fix is ineffective"
        )
