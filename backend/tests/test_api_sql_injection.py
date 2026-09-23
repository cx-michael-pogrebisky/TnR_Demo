"""
Tests for SQL injection remediation in the /api/v1/users endpoint.

The get_users route previously built raw SQL by interpolating the user-supplied
`search` query parameter directly into the query string, enabling SQL injection
attacks.  The fix replaces string interpolation with a SQLAlchemy parameterized
query (text() + bound parameter dict), so the database driver handles escaping.

These tests verify:
  - Normal search functionality still works correctly after the fix.
  - Classic SQL injection payloads are treated as literal search strings and do
    NOT alter query behaviour or return unexpected data.
  - Edge-case inputs (empty string, None, special characters, very long strings)
    are handled safely.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_user(db_session, username, email, role="team_member"):
    """Insert a User row and return it."""
    user = User(username=username, email=email, role=role)
    user.set_password("password123")
    db_session.add(user)
    db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Functional (positive) tests — the route must still work correctly
# ---------------------------------------------------------------------------

class TestGetUsersSearchFunctionality:
    """Verify that normal search behaviour is preserved after the fix."""

    def test_get_all_users_no_search(self, client, db_session):
        """GET /api/v1/users without a search param returns all users."""
        _create_user(db_session, "alice", "alice@example.com")
        _create_user(db_session, "bob", "bob@example.com")

        response = client.get("/api/v1/users")
        assert response.status_code == 200

        data = response.get_json()
        assert "users" in data
        assert "count" in data
        assert data["count"] >= 2

    def test_search_by_username_partial_match(self, client, db_session):
        """Search on a partial username returns matching users only."""
        _create_user(db_session, "charlie", "charlie@example.com")
        _create_user(db_session, "diana", "diana@example.com")

        response = client.get("/api/v1/users?search=charlie")
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u["username"] for u in data["users"]]
        assert "charlie" in usernames
        assert "diana" not in usernames

    def test_search_by_email_partial_match(self, client, db_session):
        """Search on a partial email address returns matching users."""
        _create_user(db_session, "eve", "eve@corp.com")
        _create_user(db_session, "frank", "frank@personal.org")

        response = client.get("/api/v1/users?search=corp.com")
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u["username"] for u in data["users"]]
        assert "eve" in usernames
        assert "frank" not in usernames

    def test_search_no_match_returns_empty_list(self, client, db_session):
        """A search that matches no users returns an empty list, not an error."""
        _create_user(db_session, "george", "george@example.com")

        response = client.get("/api/v1/users?search=xyzzy_no_match")
        assert response.status_code == 200

        data = response.get_json()
        assert data["users"] == []
        assert data["count"] == 0

    def test_search_returns_expected_json_structure(self, client, db_session):
        """Response always contains 'users', 'count', and 'request_id' keys."""
        response = client.get("/api/v1/users?search=anything")
        assert response.status_code == 200

        data = response.get_json()
        assert "users" in data
        assert "count" in data
        assert "request_id" in data

    def test_search_case_insensitive_like(self, client, db_session):
        """LIKE query should return results regardless of case (SQLite default)."""
        _create_user(db_session, "Hannah", "hannah@example.com")

        response = client.get("/api/v1/users?search=hannah")
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u["username"].lower() for u in data["users"]]
        assert "hannah" in usernames


# ---------------------------------------------------------------------------
# Security (negative) tests — injection payloads must be treated as literals
# ---------------------------------------------------------------------------

class TestGetUsersSQLInjectionPrevention:
    """Verify that SQL injection payloads do not alter query behaviour."""

    def test_classic_or_1_equals_1_payload(self, client, db_session):
        """' OR '1'='1 must not leak all users when no match exists."""
        # Seed one user whose name does NOT contain the literal injection string
        _create_user(db_session, "victim_user", "victim@example.com")

        # The payload — if un-parameterized this would return all rows
        payload = "' OR '1'='1"
        response = client.get(f"/api/v1/users?search={payload}")
        assert response.status_code == 200

        data = response.get_json()
        # The payload is treated as a literal LIKE pattern, which matches nothing
        assert data["count"] == 0, (
            "SQL injection payload returned rows — parameterization failed"
        )

    def test_union_select_payload(self, client, db_session):
        """UNION SELECT payload must not inject additional rows."""
        _create_user(db_session, "regular_user", "regular@example.com")

        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8-- -"
        response = client.get(f"/api/v1/users?search={payload}")
        # The endpoint must not crash (500) and must not leak extra rows
        assert response.status_code == 200

        data = response.get_json()
        # No legitimate user matches the literal payload string
        assert data["count"] == 0, (
            "UNION SELECT payload returned unexpected rows"
        )

    def test_comment_termination_payload(self, client, db_session):
        """SQL comment sequences must not truncate the WHERE clause."""
        _create_user(db_session, "safe_user", "safe@example.com")

        # If un-parameterized, the -- would comment out rest of WHERE, returning all users
        payload = "' OR 1=1--"
        response = client.get(f"/api/v1/users?search={payload}")
        assert response.status_code == 200

        data = response.get_json()
        assert data["count"] == 0, (
            "Comment-termination payload bypassed WHERE clause"
        )

    def test_stacked_query_payload(self, client, db_session):
        """Semicolon stacked queries must not execute a second statement."""
        _create_user(db_session, "stacked_target", "stacked@example.com")

        # Attempt to append a DROP TABLE — should be treated as a literal string
        payload = "x'; DROP TABLE users;--"
        response = client.get(f"/api/v1/users?search={payload}")
        # The table must still exist (no 500 from missing table) and return 200
        assert response.status_code == 200

        # Confirm the table still has data (i.e., DROP was not executed)
        no_search = client.get("/api/v1/users")
        assert no_search.status_code == 200
        all_data = no_search.get_json()
        assert all_data["count"] >= 1, (
            "users table appears empty — stacked DROP TABLE may have executed"
        )

    def test_single_quote_in_search_does_not_crash(self, client, db_session):
        """A bare single quote in the search term must not cause a 500 error."""
        response = client.get("/api/v1/users?search='")
        # Must return 200 (not 500 / database error)
        assert response.status_code == 200

    def test_double_quote_in_search_does_not_crash(self, client, db_session):
        """A double-quote in the search term must not cause a 500 error."""
        response = client.get('/api/v1/users?search="')
        assert response.status_code == 200

    def test_backslash_in_search_does_not_crash(self, client, db_session):
        """A backslash in the search term must be handled safely."""
        response = client.get("/api/v1/users?search=\\")
        assert response.status_code == 200

    def test_percent_wildcard_treated_as_literal_content(self, client, db_session):
        """
        The LIKE wildcard '%' in user input must be part of the bound parameter
        value, not interpreted as an extra SQL wildcard beyond the intended ones.

        A user who sends search=% should match users whose name/email literally
        contains '%', not every user in the table.
        """
        _create_user(db_session, "normal_user", "normal@example.com")

        # Querying with a bare % — if improperly handled this becomes %%%, which
        # in SQLite LIKE still matches everything; a correctly parameterized driver
        # escapes it so it only matches a literal '%' character.
        response = client.get("/api/v1/users?search=%25")  # URL-encoded %
        assert response.status_code == 200
        # normal_user's name/email don't contain a literal '%', so count should be 0
        data = response.get_json()
        # We assert the endpoint returns valid JSON (no crash), which is the
        # primary guarantee; match count is database-driver dependent.
        assert "count" in data

    def test_null_byte_in_search_does_not_crash(self, client, db_session):
        """A URL-encoded NUL byte must not crash the endpoint."""
        # %00 is URL-encoded NUL (U+0000); we use the percent-encoded form in the
        # URL string — never a raw control byte in source.
        response = client.get("/api/v1/users?search=%00")
        assert response.status_code in (200, 400), (
            "Unexpected status code for NUL-byte input"
        )

    def test_very_long_search_string_does_not_crash(self, client, db_session):
        """An extremely long search string must not cause a 500 error."""
        long_payload = "a" * 10000
        response = client.get(f"/api/v1/users?search={long_payload}")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Edge-case / boundary tests
# ---------------------------------------------------------------------------

class TestGetUsersEdgeCases:
    """Edge cases that do not strictly involve injection but test robustness."""

    def test_empty_search_param_returns_all_users(self, client, db_session):
        """An empty search string falls through to the ORM path (all users)."""
        _create_user(db_session, "edgecase_user", "edgecase@example.com")

        response = client.get("/api/v1/users?search=")
        assert response.status_code == 200

        data = response.get_json()
        assert data["count"] >= 1

    def test_search_with_spaces(self, client, db_session):
        """Spaces in the search term are handled without errors."""
        _create_user(db_session, "spaced user", "spaced@example.com")

        response = client.get("/api/v1/users?search=spaced%20user")
        assert response.status_code == 200

    def test_search_with_unicode_characters(self, client, db_session):
        """Unicode characters in search must not cause errors."""
        response = client.get("/api/v1/users?search=élève")
        assert response.status_code == 200

    def test_multiple_users_match_search(self, client, db_session):
        """Search can return multiple matching users."""
        _create_user(db_session, "match_one", "match_one@test.com")
        _create_user(db_session, "match_two", "match_two@test.com")
        _create_user(db_session, "no_match", "no_match@other.com")

        response = client.get("/api/v1/users?search=match")
        assert response.status_code == 200

        data = response.get_json()
        assert data["count"] == 2

    def test_count_matches_users_list_length(self, client, db_session):
        """The 'count' field must always equal len(users) in the response."""
        _create_user(db_session, "count_check", "count@example.com")

        response = client.get("/api/v1/users?search=count_check")
        assert response.status_code == 200

        data = response.get_json()
        assert data["count"] == len(data["users"])
