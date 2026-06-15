"""Tests for AWS AssumeRole RoleSessionName support."""

from s2iam.aws import (
    DEFAULT_ROLE_SESSION_NAME,
    ROLE_SESSION_NAME_PARAM,
    _role_session_name_from_params,
)


class TestRoleSessionNameFromParams:
    def test_custom_from_additional_params(self):
        name = _role_session_name_from_params(
            {ROLE_SESSION_NAME_PARAM: "my-custom-session"}, None
        )
        assert name == "my-custom-session"

    def test_client_session_name(self):
        name = _role_session_name_from_params(None, "client-session")
        assert name == "client-session"

    def test_additional_params_take_precedence(self):
        name = _role_session_name_from_params(
            {ROLE_SESSION_NAME_PARAM: "param-session"}, "client-session"
        )
        assert name == "param-session"

    def test_default(self):
        name = _role_session_name_from_params(None, None)
        assert name == DEFAULT_ROLE_SESSION_NAME
