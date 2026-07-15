"""
Tests for SQL injection prevention in search endpoints.

These tests verify that search parameters are handled via parameterized
ORM queries (SQLAlchemy .like()) rather than raw f-string SQL, so that
SQL injection payloads are treated as literal strings, not SQL syntax.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Fixtures (rely on conftest.py: app, client, db_session, sample_user,
#           sample_project, sample_task, auth_headers)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_message(db_session, sample_user):
    """Create a sample message for search tests."""
    from models import Message
    message = Message(
        sender_id=sample_user.id,
        receiver_id=sample_user.id,
        subject="Hello World",
        content="Test message content",
    )
    db_session.add(message)
    db_session.commit()
    return message


# ---------------------------------------------------------------------------
# Helper: SQL injection payloads that should be treated as literal text
# ---------------------------------------------------------------------------
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "1' OR '1'='1' --",
    "' OR 1=1 --",
    "%' OR '%'='",
    "'; INSERT INTO users (username) VALUES ('hacked'); --",
    "' AND SLEEP(5) --",
    "1 AND 1=1",
    "admin'--",
]


# ===========================================================================
# /api/v1/users  – GET ?search=
# ===========================================================================

class TestUsersSearchSQLInjection:
    """SQL injection tests for GET /api/v1/users?search="""

    def test_search_normal_returns_matching_users(self, client, sample_user):
        """Normal search term returns matching users without error."""
        response = client.get(f"/api/v1/users?search={sample_user.username[:4]}")
        assert response.status_code == 200
        data = response.get_json()
        assert "users" in data

    def test_search_no_results_for_nonexistent_term(self, client, sample_user):
        """A search for a string that no user has returns an empty list."""
        response = client.get("/api/v1/users?search=zzznomatch999")
        assert response.status_code == 200
        data = response.get_json()
        assert data["users"] == []

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, sample_user, payload):
        """SQL injection payloads must not cause a 500 server error."""
        response = client.get(f"/api/v1/users?search={payload}")
        # Must return a valid HTTP response (not a 500 crash)
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_return_all_users(self, client, sample_user, payload):
        """Classic OR-1=1 payloads must NOT return all users from the database.

        If the query were built via string interpolation the payload
        '' OR '1'='1'' would turn the WHERE clause into a tautology
        and return every row. Parameterised ORM queries treat the
        payload as a literal LIKE pattern, so they match only rows
        whose username / email literally contain that string – which
        in this test database is zero rows.
        """
        response = client.get(f"/api/v1/users?search={payload}")
        if response.status_code == 200:
            data = response.get_json()
            users = data.get("users", [])
            # The payload should NOT match any legitimate username/email
            for user in users:
                # Every returned username/email must literally contain the payload
                # (ORM LIKE semantics) – a tautology injection would bypass this
                username_match = payload.lower() in user.get("username", "").lower()
                email_match = payload.lower() in user.get("email", "").lower()
                assert username_match or email_match, (
                    f"Payload '{payload}' returned user '{user.get('username')}' "
                    "without the payload appearing literally in the field. "
                    "This suggests a SQL injection tautology was exploited."
                )


# ===========================================================================
# /api/v1/projects  – GET ?search=
# ===========================================================================

class TestProjectsSearchSQLInjection:
    """SQL injection tests for GET /api/v1/projects?search="""

    def test_search_normal_returns_matching_projects(self, client, sample_project):
        """Normal search term returns matching projects without error."""
        response = client.get(f"/api/v1/projects?search={sample_project.name[:4]}")
        assert response.status_code == 200
        data = response.get_json()
        assert "projects" in data

    def test_search_no_results_for_nonexistent_term(self, client, sample_project):
        """A search for a non-matching string returns an empty list."""
        response = client.get("/api/v1/projects?search=zzznomatch999")
        assert response.status_code == 200
        data = response.get_json()
        assert data["projects"] == []

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, sample_project, payload):
        """Injection payloads must not crash the projects endpoint."""
        response = client.get(f"/api/v1/projects?search={payload}")
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_return_all_projects(self, client, sample_project, payload):
        """Injection payloads must not return projects they don't match literally."""
        response = client.get(f"/api/v1/projects?search={payload}")
        if response.status_code == 200:
            data = response.get_json()
            projects = data.get("projects", [])
            for project in projects:
                name_match = payload.lower() in project.get("name", "").lower()
                desc_match = payload.lower() in (project.get("description") or "").lower()
                assert name_match or desc_match, (
                    f"Payload '{payload}' returned project '{project.get('name')}' "
                    "without the payload appearing literally. Possible SQL injection."
                )


# ===========================================================================
# /api/v1/tasks  – GET ?search=
# ===========================================================================

class TestTasksSearchSQLInjection:
    """SQL injection tests for GET /api/v1/tasks?search="""

    def test_search_normal_returns_matching_tasks(self, client, sample_task):
        """Normal search term returns matching tasks without error."""
        response = client.get(f"/api/v1/tasks?search={sample_task.title[:4]}")
        assert response.status_code == 200
        data = response.get_json()
        assert "tasks" in data

    def test_search_no_results_for_nonexistent_term(self, client, sample_task):
        """A non-matching search returns an empty list."""
        response = client.get("/api/v1/tasks?search=zzznomatch999")
        assert response.status_code == 200
        data = response.get_json()
        assert data["tasks"] == []

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, sample_task, payload):
        """Injection payloads must not crash the tasks endpoint."""
        response = client.get(f"/api/v1/tasks?search={payload}")
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_return_all_tasks(self, client, sample_task, payload):
        """Injection payloads must not return tasks they don't match literally."""
        response = client.get(f"/api/v1/tasks?search={payload}")
        if response.status_code == 200:
            data = response.get_json()
            tasks = data.get("tasks", [])
            for task in tasks:
                title_match = payload.lower() in task.get("title", "").lower()
                desc_match = payload.lower() in (task.get("description") or "").lower()
                assert title_match or desc_match, (
                    f"Payload '{payload}' returned task '{task.get('title')}' "
                    "without literal match. Possible SQL injection."
                )


# ===========================================================================
# /api/v1/projects/<id>/tasks  – GET ?search=
# ===========================================================================

class TestProjectTasksSearchSQLInjection:
    """SQL injection tests for GET /api/v1/projects/<id>/tasks?search="""

    def test_search_normal(self, client, sample_task, sample_project):
        """Normal search term returns results for the given project."""
        response = client.get(
            f"/api/v1/projects/{sample_project.id}/tasks"
            f"?search={sample_task.title[:4]}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "tasks" in data

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, sample_task, sample_project, payload):
        """Injection payloads must not crash the project-tasks endpoint."""
        response = client.get(
            f"/api/v1/projects/{sample_project.id}/tasks?search={payload}"
        )
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_escape_project_scope(
        self, client, sample_task, sample_project, payload
    ):
        """Injection must not return tasks from other projects."""
        response = client.get(
            f"/api/v1/projects/{sample_project.id}/tasks?search={payload}"
        )
        if response.status_code == 200:
            data = response.get_json()
            for task in data.get("tasks", []):
                assert task.get("project_id") == sample_project.id, (
                    "Task from a different project was returned – "
                    "possible SQL injection breaking project_id filter."
                )


# ===========================================================================
# /api/v1/search  – GET ?q=  (global search)
# ===========================================================================

class TestGlobalSearchSQLInjection:
    """SQL injection tests for GET /api/v1/search?q="""

    def test_empty_query_returns_400(self, client):
        """Omitting the query param should return 400."""
        response = client.get("/api/v1/search")
        assert response.status_code == 400

    def test_normal_query_returns_results_structure(self, client, sample_user, sample_project, sample_task):
        """A normal search returns the expected keys."""
        response = client.get("/api/v1/search?q=Test")
        assert response.status_code == 200
        data = response.get_json()
        assert "users" in data
        assert "projects" in data
        assert "tasks" in data

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, sample_user, payload):
        """Injection payloads must not crash the global search endpoint."""
        response = client.get(f"/api/v1/search?q={payload}")
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_return_all_users(self, client, sample_user, payload):
        """Tautology payloads in global search must not dump all users."""
        response = client.get(f"/api/v1/search?q={payload}")
        if response.status_code == 200:
            data = response.get_json()
            for user in data.get("users", []):
                username_match = payload.lower() in user.get("username", "").lower()
                email_match = payload.lower() in user.get("email", "").lower()
                assert username_match or email_match, (
                    f"Global search payload '{payload}' returned user "
                    f"'{user.get('username')}' without literal match."
                )


# ===========================================================================
# /api/messages/search  – GET ?q=  (messages search)
# ===========================================================================

class TestMessagesSearchSQLInjection:
    """SQL injection tests for GET /api/messages/search?q="""

    def test_empty_query_returns_400(self, client, auth_headers):
        """Omitting the query param should return 400."""
        response = client.get("/api/messages/search", headers=auth_headers)
        assert response.status_code == 400

    def test_normal_query_returns_results(self, client, auth_headers, sample_message):
        """A normal search term returns a results list."""
        response = client.get(
            f"/api/messages/search?q={sample_message.subject[:5]}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "results" in data

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, auth_headers, sample_message, payload):
        """Injection payloads must not crash the messages search endpoint."""
        response = client.get(
            f"/api/messages/search?q={payload}", headers=auth_headers
        )
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_return_all_messages(
        self, client, auth_headers, sample_message, payload
    ):
        """Tautology payloads must not dump all messages."""
        response = client.get(
            f"/api/messages/search?q={payload}", headers=auth_headers
        )
        if response.status_code == 200:
            data = response.get_json()
            for msg in data.get("results", []):
                content_match = payload.lower() in (msg.get("content") or "").lower()
                subject_match = payload.lower() in (msg.get("subject") or "").lower()
                assert content_match or subject_match, (
                    f"Message search payload '{payload}' returned a message "
                    "without the payload appearing literally. Possible SQL injection."
                )


# ===========================================================================
# /api/projects  – GET ?search=  (projects blueprint)
# ===========================================================================

class TestProjectsBlueprintSearchSQLInjection:
    """SQL injection tests for the authenticated /api/projects?search= endpoint."""

    def test_search_normal(self, client, auth_headers, sample_project):
        """Authenticated normal search returns matching projects."""
        response = client.get(
            f"/api/projects?search={sample_project.name[:4]}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "projects" in data

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, auth_headers, sample_project, payload):
        """Injection payloads must not crash the authenticated projects endpoint."""
        response = client.get(
            f"/api/projects?search={payload}", headers=auth_headers
        )
        assert response.status_code in (200, 400)


# ===========================================================================
# /api/tasks  – GET ?search=  (tasks blueprint)
# ===========================================================================

class TestTasksBlueprintSearchSQLInjection:
    """SQL injection tests for the authenticated /api/tasks?search= endpoint."""

    def test_search_normal(self, client, auth_headers, sample_task):
        """Authenticated normal search returns matching tasks."""
        response = client.get(
            f"/api/tasks?search={sample_task.title[:4]}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "tasks" in data

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_raise(self, client, auth_headers, sample_task, payload):
        """Injection payloads must not crash the authenticated tasks endpoint."""
        response = client.get(
            f"/api/tasks?search={payload}", headers=auth_headers
        )
        assert response.status_code in (200, 400)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_payload_does_not_return_all_tasks(
        self, client, auth_headers, sample_task, payload
    ):
        """Tautology payloads must not dump all tasks."""
        response = client.get(
            f"/api/tasks?search={payload}", headers=auth_headers
        )
        if response.status_code == 200:
            data = response.get_json()
            for task in data.get("tasks", []):
                title_match = payload.lower() in task.get("title", "").lower()
                desc_match = payload.lower() in (task.get("description") or "").lower()
                assert title_match or desc_match, (
                    f"Payload '{payload}' returned task '{task.get('title')}' "
                    "without literal match. Possible SQL injection."
                )
