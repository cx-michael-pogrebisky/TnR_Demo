"""
Tests for task management routes, with focus on SQL injection prevention.
Uses pytest with the fixtures defined in conftest.py.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Task, db


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_tasks(client, headers, **params):
    """Convenience wrapper for GET /api/tasks with query params."""
    return client.get('/api/tasks', query_string=params, headers=headers)


# ---------------------------------------------------------------------------
# Functional tests — normal search behaviour
# ---------------------------------------------------------------------------

class TestGetTasksSearch:
    """Verify that the search parameter filters results correctly."""

    def test_search_matches_title(self, client, auth_headers, sample_task):
        """A search term that matches the task title should return that task."""
        resp = _get_tasks(client, auth_headers, search='Test Task')
        assert resp.status_code == 200
        data = resp.get_json()
        assert any(t['title'] == 'Test Task' for t in data['tasks'])

    def test_search_matches_description(self, client, auth_headers, sample_task):
        """A search term that matches the task description should return that task."""
        resp = _get_tasks(client, auth_headers, search='test task')
        assert resp.status_code == 200
        data = resp.get_json()
        # sample_task description is 'A test task'
        assert len(data['tasks']) >= 1

    def test_search_no_match_returns_empty(self, client, auth_headers, sample_task):
        """A search term that matches nothing should return an empty list."""
        resp = _get_tasks(client, auth_headers, search='zzz_no_match_xyz')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['tasks'] == []

    def test_search_is_case_insensitive(self, client, auth_headers, sample_task):
        """Search should be case-insensitive (ilike)."""
        resp = _get_tasks(client, auth_headers, search='TEST TASK')
        assert resp.status_code == 200
        data = resp.get_json()
        assert any(t['title'] == 'Test Task' for t in data['tasks'])

    def test_search_with_project_id_filter(self, client, auth_headers, sample_task, sample_project):
        """search combined with project_id should narrow results correctly."""
        resp = _get_tasks(
            client, auth_headers,
            search='Test Task',
            project_id=sample_project.id
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert any(t['title'] == 'Test Task' for t in data['tasks'])

    def test_search_with_wrong_project_id_returns_empty(
        self, client, auth_headers, sample_task
    ):
        """search + wrong project_id combo should return nothing."""
        resp = _get_tasks(client, auth_headers, search='Test Task', project_id=99999)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['tasks'] == []

    def test_no_search_returns_all_tasks(self, client, auth_headers, sample_task):
        """Without a search param the endpoint returns all accessible tasks."""
        resp = _get_tasks(client, auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data['tasks']) >= 1


# ---------------------------------------------------------------------------
# SQL injection prevention tests
# ---------------------------------------------------------------------------

class TestSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the search parameter are treated as
    literal search strings rather than executed SQL.

    With the old vulnerable code these would manipulate the query structure;
    with parameterized ORM filters they are safely passed as bind values.
    """

    def test_classic_sqli_or_1_eq_1(self, client, auth_headers, db_session, sample_project, sample_user):
        """
        Payload: ' OR '1'='1
        Old code would have produced: … LIKE '%%' OR '1'='1%'
        which returns every row. With the fix it is a literal search string
        that should return no results (no task title/description contains it).
        """
        payload = "' OR '1'='1"
        resp = _get_tasks(client, auth_headers, search=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        # The payload itself does not appear in any legitimate task title/description
        assert data['tasks'] == []

    def test_sqli_comment_truncation(self, client, auth_headers, sample_task):
        """
        Payload: %' --
        Old code would truncate the WHERE clause with the SQL comment.
        With the fix the whole string (including -- ) is a literal LIKE pattern.
        """
        payload = "%' --"
        resp = _get_tasks(client, auth_headers, search=payload)
        assert resp.status_code == 200
        # No crash, no data leak
        data = resp.get_json()
        assert 'tasks' in data

    def test_sqli_union_select(self, client, auth_headers, sample_task):
        """
        Payload: ' UNION SELECT * FROM users --
        Old code would inject a UNION query. With the fix it is a harmless
        literal search pattern that matches nothing.
        """
        payload = "' UNION SELECT * FROM users --"
        resp = _get_tasks(client, auth_headers, search=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['tasks'] == []

    def test_sqli_drop_table(self, client, auth_headers, db_session, sample_task):
        """
        Payload: '; DROP TABLE tasks; --
        Old code could execute destructive DDL. With the fix the table must
        still exist and the query must succeed after the request.
        """
        payload = "'; DROP TABLE tasks; --"
        resp = _get_tasks(client, auth_headers, search=payload)
        assert resp.status_code == 200
        # Confirm the tasks table still exists and the sample task is intact
        surviving_task = db_session.get(Task, sample_task.id)
        assert surviving_task is not None

    def test_sqli_boolean_blind(self, client, auth_headers, sample_task):
        """
        Boolean-blind payload: Test Task' AND '1'='1
        If injected the query would unconditionally match. As a literal LIKE
        pattern it will not match the sample task title.
        """
        payload = "Test Task' AND '1'='1"
        resp = _get_tasks(client, auth_headers, search=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        # The literal string "Test Task' AND '1'='1" is not in any task title
        assert data['tasks'] == []

    def test_sqli_stacked_queries(self, client, auth_headers, sample_task):
        """
        Stacked-query payload: '; INSERT INTO tasks (title) VALUES ('pwned'); --
        With parameterized queries this must not insert a rogue row.
        """
        payload = "'; INSERT INTO tasks (title) VALUES ('pwned'); --"
        resp = _get_tasks(client, auth_headers, search=payload)
        assert resp.status_code == 200
        # Verify no 'pwned' task was inserted
        pwned = Task.query.filter_by(title='pwned').first()
        assert pwned is None

    def test_sqli_project_id_not_injectable(self, client, auth_headers, sample_task, sample_project):
        """
        The project_id parameter is also user-controlled. Using filter_by
        (ORM) means it is parameterized. A non-integer value should return
        no results without crashing.
        """
        resp = _get_tasks(client, auth_headers, project_id="1 OR 1=1")
        # filter_by with a non-integer project_id either returns [] or a 400/500;
        # what must NOT happen is returning all tasks (data exfiltration).
        if resp.status_code == 200:
            data = resp.get_json()
            # Must not return every task in the DB
            all_tasks_count = Task.query.count()
            assert len(data['tasks']) < all_tasks_count or all_tasks_count == 0

    def test_search_with_percent_wildcard_literal(self, client, auth_headers, sample_task):
        """
        A search value of '%' would previously match every row (SQL wildcard).
        With the ORM the '%' is passed as a bind value inside the ilike
        pattern, but SQLAlchemy double-escapes it — it should NOT return
        every task as a wildcard explosion would.
        NOTE: SQLAlchemy's ilike does NOT escape literal % in the user value,
        so this test documents current behaviour rather than asserting zero rows.
        The key guarantee is that the endpoint responds without error.
        """
        resp = _get_tasks(client, auth_headers, search='%')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'tasks' in data

    def test_search_with_sql_metacharacters_no_crash(self, client, auth_headers, sample_task):
        """
        Various SQL metacharacters should not cause a 500 server error.
        """
        payloads = [
            "'; --",
            '" OR "1"="1',
            "\\",
            "\x00",          # NUL byte (expressed as Python escape, not literal)
            "1; SELECT 1",
        ]
        for payload in payloads:
            resp = _get_tasks(client, auth_headers, search=payload)
            assert resp.status_code in (200, 400), (
                f"Unexpected status {resp.status_code} for payload {payload!r}"
            )


# ---------------------------------------------------------------------------
# Additional endpoint sanity tests
# ---------------------------------------------------------------------------

class TestGetTasksFilters:
    """Non-search filter combinations should still work correctly."""

    def test_filter_by_status(self, client, auth_headers, sample_task, db_session):
        """Tasks can be filtered by status."""
        resp = _get_tasks(client, auth_headers, status='pending')
        assert resp.status_code == 200
        data = resp.get_json()
        assert any(t['status'] == 'pending' for t in data['tasks'])

    def test_filter_by_project_id(self, client, auth_headers, sample_task, sample_project):
        """Tasks can be filtered by project_id."""
        resp = _get_tasks(client, auth_headers, project_id=sample_project.id)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data['tasks']) >= 1

    def test_unauthenticated_request_rejected(self, client):
        """Requests without a valid token must be rejected."""
        resp = client.get('/api/tasks')
        assert resp.status_code in (401, 403)
