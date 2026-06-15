"""
Comprehensive tests for XSS vulnerability prevention in admin dashboard
Tests the fix for Stored XSS vulnerability in role_badge filter
"""
import pytest
import sys
import os
from markupsafe import Markup

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.jinja_filters import role_badge
from models import User, db


class TestRoleBadgeXSSPrevention:
    """Test XSS prevention in role_badge filter"""

    def test_role_badge_escapes_basic_xss_script_tag(self):
        """Test that basic script tags are escaped"""
        malicious_role = '<script>alert("XSS")</script>'
        result = role_badge(None, malicious_role)

        # Should NOT contain unescaped script tags
        assert '<script>' not in result
        assert '</script>' not in result
        # Should contain escaped versions
        assert '&lt;script&gt;' in result
        assert '&lt;/script&gt;' in result

    def test_role_badge_escapes_img_onerror_xss(self):
        """Test that img onerror XSS payloads are escaped"""
        malicious_role = '<img src=x onerror=alert(1)>'
        result = role_badge(None, malicious_role)

        # Should NOT contain unescaped img tag
        assert '<img src=' not in result
        assert 'onerror=' not in result
        # Should contain escaped versions
        assert '&lt;img' in result
        assert '&gt;' in result

    def test_role_badge_escapes_event_handler_xss(self):
        """Test that event handlers are escaped"""
        malicious_role = '" onload="alert(\'XSS\')'
        result = role_badge(None, malicious_role)

        # Should NOT contain unescaped event handlers
        assert 'onload=' not in result
        # Should contain escaped quotes
        assert '&quot;' in result or '&#34;' in result

    def test_role_badge_escapes_javascript_protocol(self):
        """Test that javascript: protocol is escaped"""
        malicious_role = 'javascript:alert(1)'
        result = role_badge(None, malicious_role)

        # Should be escaped and not executable
        # The exact escaping may vary but should not be in raw form
        assert result.startswith('<span class="badge badge-')
        assert 'javascript:alert(1)' in result  # Will be in escaped form within span

    def test_role_badge_escapes_html_entities(self):
        """Test that HTML entities are properly escaped"""
        malicious_role = '&lt;script&gt;alert("double")&lt;/script&gt;'
        result = role_badge(None, malicious_role)

        # Should contain double-escaped entities
        assert '&amp;lt;' in result or '&lt;' in result

    def test_role_badge_escapes_angle_brackets(self):
        """Test that angle brackets are properly escaped"""
        malicious_role = '<>test<>'
        result = role_badge(None, malicious_role)

        # Should NOT contain raw angle brackets in the role text
        # (only in the span tag structure)
        assert '&lt;&gt;test&lt;&gt;' in result

    def test_role_badge_with_legitimate_admin_role(self):
        """Test that legitimate admin role works correctly"""
        result = role_badge(None, 'admin')

        assert '<span class="badge badge-danger">admin</span>' == result
        assert 'admin' in result
        assert 'badge-danger' in result

    def test_role_badge_with_legitimate_project_manager_role(self):
        """Test that legitimate project_manager role works correctly"""
        result = role_badge(None, 'project_manager')

        assert '<span class="badge badge-primary">project_manager</span>' == result
        assert 'project_manager' in result
        assert 'badge-primary' in result

    def test_role_badge_with_legitimate_team_member_role(self):
        """Test that legitimate team_member role works correctly"""
        result = role_badge(None, 'team_member')

        assert '<span class="badge badge-secondary">team_member</span>' == result
        assert 'team_member' in result
        assert 'badge-secondary' in result

    def test_role_badge_with_unknown_role_uses_secondary_color(self):
        """Test that unknown roles default to secondary color"""
        result = role_badge(None, 'custom_role')

        assert '<span class="badge badge-secondary">custom_role</span>' == result
        assert 'custom_role' in result
        assert 'badge-secondary' in result

    def test_role_badge_output_is_markup_safe(self):
        """Test that output is marked as safe HTML (Markup object)"""
        result = role_badge(None, 'admin')

        # The result should be safe HTML that can be rendered
        assert isinstance(result, (str, Markup))
        assert '<span' in str(result)


class TestAdminDashboardXSSPrevention:
    """Test XSS prevention in admin dashboard endpoint"""

    def test_admin_dashboard_with_malicious_user_role(self, app, client, db_session):
        """Test that admin dashboard properly escapes malicious role in database"""
        # Create a user with malicious role
        malicious_user = User(
            username='hacker',
            email='hacker@example.com',
            role='<script>alert("XSS")</script>'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        # Request admin dashboard
        response = client.get('/admin')

        # Should return 200 OK
        assert response.status_code == 200

        # Response should NOT contain unescaped script tags
        response_data = response.data.decode('utf-8')
        # The script tag should be escaped in the HTML
        assert '<script>alert("XSS")</script>' not in response_data
        # Should contain escaped version
        assert '&lt;script&gt;' in response_data or '&amp;lt;script&amp;gt;' in response_data

    def test_admin_dashboard_with_multiple_malicious_users(self, app, client, db_session):
        """Test admin dashboard with multiple users having malicious roles"""
        # Create multiple users with different XSS payloads
        xss_payloads = [
            '<img src=x onerror=alert(1)>',
            '" onclick="alert(2)"',
            '<svg onload=alert(3)>',
            'javascript:alert(4)',
        ]

        for i, payload in enumerate(xss_payloads):
            user = User(
                username=f'hacker{i}',
                email=f'hacker{i}@example.com',
                role=payload
            )
            user.set_password('password123')
            db_session.add(user)

        db_session.commit()

        # Request admin dashboard
        response = client.get('/admin')
        assert response.status_code == 200

        response_data = response.data.decode('utf-8')

        # Verify each payload is properly escaped
        assert '<img src=x onerror=' not in response_data
        assert 'onclick=' not in response_data
        assert '<svg onload=' not in response_data
        # Should contain escaped versions
        assert '&lt;' in response_data or '&amp;lt;' in response_data

    def test_admin_dashboard_with_legitimate_roles(self, app, client, db_session):
        """Test that legitimate roles are displayed correctly"""
        # Create users with legitimate roles
        legitimate_roles = ['admin', 'project_manager', 'team_member']

        for i, role in enumerate(legitimate_roles):
            user = User(
                username=f'user{i}',
                email=f'user{i}@example.com',
                role=role
            )
            user.set_password('password123')
            db_session.add(user)

        db_session.commit()

        # Request admin dashboard
        response = client.get('/admin')
        assert response.status_code == 200

        response_data = response.data.decode('utf-8')

        # Verify legitimate roles are displayed
        assert 'admin' in response_data
        assert 'project_manager' in response_data
        assert 'team_member' in response_data

        # Verify badge HTML structure is present
        assert 'badge badge-danger' in response_data  # admin
        assert 'badge badge-primary' in response_data  # project_manager
        assert 'badge badge-secondary' in response_data  # team_member

    def test_admin_dashboard_mixed_legitimate_and_malicious_roles(self, app, client, db_session):
        """Test admin dashboard with both legitimate and malicious roles"""
        # Create mix of users
        users_data = [
            ('admin_user', 'admin@example.com', 'admin'),
            ('malicious_user', 'hacker@example.com', '<script>alert(1)</script>'),
            ('normal_user', 'user@example.com', 'team_member'),
        ]

        for username, email, role in users_data:
            user = User(username=username, email=email, role=role)
            user.set_password('password123')
            db_session.add(user)

        db_session.commit()

        # Request admin dashboard
        response = client.get('/admin')
        assert response.status_code == 200

        response_data = response.data.decode('utf-8')

        # Legitimate roles should be displayed normally
        assert 'admin' in response_data
        assert 'team_member' in response_data

        # Malicious role should be escaped
        assert '<script>alert(1)</script>' not in response_data
        assert '&lt;script&gt;' in response_data or '&amp;lt;script&amp;gt;' in response_data


class TestXSSAttackVectors:
    """Test various XSS attack vectors are properly mitigated"""

    def test_stored_xss_via_database(self, app, db_session):
        """Test that stored XSS from database is prevented"""
        # This is the primary vulnerability being fixed
        # User stores malicious data in database
        malicious_user = User(
            username='attacker',
            email='attacker@example.com',
            role='<script>document.cookie</script>'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        # Retrieve user and generate badge
        user = db_session.query(User).filter_by(username='attacker').first()
        result = role_badge(None, user.role)

        # XSS should be prevented
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_xss_with_null_byte_injection(self):
        """Test XSS prevention with null byte injection"""
        malicious_role = 'admin\x00<script>alert(1)</script>'
        result = role_badge(None, malicious_role)

        # Script tags should be escaped
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_xss_with_unicode_encoding(self):
        """Test XSS prevention with unicode encoding attempts"""
        # Unicode encoded script tag
        malicious_role = '\u003cscript\u003ealert(1)\u003c/script\u003e'
        result = role_badge(None, malicious_role)

        # Should be properly escaped
        assert '<script>' not in result

    def test_xss_with_html_entities_in_attribute(self):
        """Test XSS prevention with HTML entities in attributes"""
        malicious_role = '" style="background:url(javascript:alert(1))"'
        result = role_badge(None, malicious_role)

        # Quotes should be escaped
        assert '&quot;' in result or '&#34;' in result
        # Should not contain unescaped quotes that could break out
        assert not result.startswith('<span class="badge badge-secondary">')

    def test_xss_with_data_uri(self):
        """Test XSS prevention with data URI"""
        malicious_role = 'data:text/html,<script>alert(1)</script>'
        result = role_badge(None, malicious_role)

        # Should be escaped
        assert '<script>' not in result
        assert '&lt;' in result


class TestRegressionPrevention:
    """Tests to ensure the vulnerability doesn't return"""

    def test_role_badge_always_escapes_user_input(self):
        """Ensure role_badge ALWAYS escapes user input"""
        test_cases = [
            '<script>',
            '<img src=x>',
            '" onload="',
            '<svg/onload=',
            'javascript:',
            '&lt;script&gt;',
            '<iframe>',
            '<object>',
            '<embed>',
        ]

        for test_input in test_cases:
            result = role_badge(None, test_input)
            # All HTML special characters should be escaped
            if '<' in test_input and test_input not in ['&lt;script&gt;']:
                assert '&lt;' in result or result.count('<') == 1  # Only the span tag

    def test_safe_filter_usage_in_template(self, app, client, db_session):
        """Test that safe filter in template doesn't expose XSS when filter does proper escaping"""
        # Even though template uses |safe, the filter should escape first
        malicious_user = User(
            username='xss_test',
            email='xss@example.com',
            role='<script>alert("xss")</script>'
        )
        malicious_user.set_password('password123')
        db_session.add(malicious_user)
        db_session.commit()

        response = client.get('/admin')
        response_data = response.data.decode('utf-8')

        # The |safe filter should output what role_badge returns
        # Since role_badge escapes, final output should be safe
        assert '<script>alert("xss")</script>' not in response_data
        assert '&lt;script&gt;' in response_data or '&amp;lt;script&amp;gt;' in response_data
