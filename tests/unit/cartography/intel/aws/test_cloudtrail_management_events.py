import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from botocore.exceptions import ReadTimeoutError

import cartography.intel.aws.cloudtrail_management_events as cloudtrail_management_events
from cartography.intel.aws.cloudtrail import CloudTrailTransientRegionFailure
from cartography.intel.aws.cloudtrail_management_events import get_assume_role_events
from cartography.intel.aws.cloudtrail_management_events import get_saml_role_events
from cartography.intel.aws.cloudtrail_management_events import (
    get_web_identity_role_events,
)
from cartography.intel.aws.cloudtrail_management_events import sync_assume_role_events
from cartography.intel.aws.cloudtrail_management_events import (
    transform_assume_role_events_to_role_assumptions,
)
from cartography.intel.aws.cloudtrail_management_events import (
    transform_saml_role_events_to_role_assumptions,
)
from cartography.intel.aws.cloudtrail_management_events import (
    transform_web_identity_role_events_to_role_assumptions,
)
from cartography.intel.aws.util.botocore_config import get_botocore_config
from tests.data.aws.cloudtrail_management_events import (
    ACCESS_DENIED_ASSUME_ROLE_CLOUDTRAIL_EVENTS,
)
from tests.data.aws.cloudtrail_management_events import (
    ACCESS_DENIED_SAML_ASSUME_ROLE_CLOUDTRAIL_EVENTS,
)
from tests.data.aws.cloudtrail_management_events import (
    ACCESS_DENIED_WEB_IDENTITY_ASSUME_ROLE_CLOUDTRAIL_EVENTS,
)

# Sample test data for AssumeRole events
SAMPLE_ASSUME_ROLE_EVENT = {
    "EventName": "AssumeRole",
    "EventTime": "2024-01-15T10:30:15.123000",
    "EventId": "test-event-id-123",
    "UserIdentity": {"arn": "arn:aws:iam::123456789012:user/john.doe"},
    "CloudTrailEvent": '{"userIdentity": {"arn": "arn:aws:iam::123456789012:user/john.doe"}, "requestParameters": {"roleArn": "arn:aws:iam::987654321098:role/ApplicationRole"}}',
}

# Sample test data for AssumeRoleWithSAML events
SAMPLE_ASSUME_ROLE_WITH_SAML_EVENT = {
    "EventName": "AssumeRoleWithSAML",
    "EventTime": "2024-01-15T11:45:22.456000",
    "EventId": "test-event-id-456",
    "UserIdentity": {
        "type": "SAMLUser",
        "principalId": "SAML:admin@example.com",
        "userName": "admin@example.com",
    },
    "CloudTrailEvent": '{"userIdentity": {"type": "SAMLUser", "principalId": "SAML:admin@example.com", "userName": "admin@example.com"}, "requestParameters": {"roleArn": "arn:aws:iam::987654321098:role/SAMLApplicationRole", "principalArn": "arn:aws:iam::123456789012:saml-provider/ExampleProvider"}, "responseElements": {"assumedRoleUser": {"arn": "arn:aws:sts::123456789012:assumed-role/SAMLRole/admin@example.com"}}}',
}

# Sample test data for AssumeRoleWithWebIdentity events (GitHub Actions)
SAMPLE_GITHUB_ASSUME_ROLE_WITH_WEB_IDENTITY_EVENT = {
    "EventName": "AssumeRoleWithWebIdentity",
    "EventTime": "2024-01-15T12:15:30.789000",
    "EventId": "test-event-id-789",
    "UserIdentity": {
        "type": "WebIdentityUser",
        "principalId": "repo:example-org/example-repo:ref:refs/heads/main",
        "userName": "repo:example-org/example-repo:ref:refs/heads/main",
        "identityProvider": "token.actions.githubusercontent.com",
    },
    "CloudTrailEvent": '{"userIdentity": {"type": "WebIdentityUser", "principalId": "repo:example-org/example-repo:ref:refs/heads/main", "userName": "repo:example-org/example-repo:ref:refs/heads/main", "identityProvider": "token.actions.githubusercontent.com"}, "requestParameters": {"roleArn": "arn:aws:iam::987654321098:role/GitHubActionsRole", "roleSessionName": "GitHubActions"}}',
}


def test_transform_single_assume_role_event():
    """Test that a single AssumeRole event is correctly transformed."""
    # Arrange
    events = [SAMPLE_ASSUME_ROLE_EVENT]

    # Act
    result = transform_assume_role_events_to_role_assumptions(events=events)

    # Assert
    assert len(result) == 1

    assumption = result[0]
    assert (
        assumption["source_principal_arn"] == "arn:aws:iam::123456789012:user/john.doe"
    )
    assert (
        assumption["destination_principal_arn"]
        == "arn:aws:iam::987654321098:role/ApplicationRole"
    )
    assert assumption["times_used"] == 1
    assert assumption["first_seen_in_time_window"] == "2024-01-15T10:30:15.123000"
    assert assumption["last_used"] == "2024-01-15T10:30:15.123000"


def test_transform_assume_role_event_keeps_govcloud_partition():
    """An assumed-role source ARN is normalized to its role ARN without leaving its partition."""
    # Arrange
    events = [
        {
            "EventName": "AssumeRole",
            "EventTime": "2024-01-15T10:30:15.123000",
            "EventId": "test-event-id-gov",
            "CloudTrailEvent": '{"userIdentity": {"arn": "arn:aws-us-gov:sts::111122223333:assumed-role/ExampleRole/example-session"}, "requestParameters": {"roleArn": "arn:aws-us-gov:iam::444455556666:role/ExampleTargetRole"}}',
        },
    ]

    # Act
    result = transform_assume_role_events_to_role_assumptions(events=events)

    # Assert
    assert [
        (r["source_principal_arn"], r["destination_principal_arn"]) for r in result
    ] == [
        (
            "arn:aws-us-gov:iam::111122223333:role/ExampleRole",
            "arn:aws-us-gov:iam::444455556666:role/ExampleTargetRole",
        ),
    ]


def test_transform_single_saml_role_event():
    """Test that a single AssumeRoleWithSAML event is correctly transformed."""
    # Arrange
    events = [SAMPLE_ASSUME_ROLE_WITH_SAML_EVENT]

    # Act
    result = transform_saml_role_events_to_role_assumptions(events=events)

    # Assert
    assert len(result) == 1

    assumption = result[0]
    assert assumption["source_principal_arn"] == "admin@example.com"
    assert (
        assumption["destination_principal_arn"]
        == "arn:aws:iam::987654321098:role/SAMLApplicationRole"
    )
    assert assumption["times_used"] == 1
    assert assumption["first_seen_in_time_window"] == "2024-01-15T11:45:22.456000"
    assert assumption["last_used"] == "2024-01-15T11:45:22.456000"


def test_transform_single_github_web_identity_role_event():
    """Test that a single GitHub AssumeRoleWithWebIdentity event is correctly transformed."""
    # Arrange
    events = [SAMPLE_GITHUB_ASSUME_ROLE_WITH_WEB_IDENTITY_EVENT]

    # Act
    result = transform_web_identity_role_events_to_role_assumptions(events=events)

    # Assert
    assert len(result) == 1

    assumption = result[0]
    assert assumption["source_repo_fullname"] == "example-org/example-repo"
    assert (
        assumption["destination_principal_arn"]
        == "arn:aws:iam::987654321098:role/GitHubActionsRole"
    )
    assert assumption["times_used"] == 1
    assert assumption["first_seen_in_time_window"] == "2024-01-15T12:15:30.789000"
    assert assumption["last_used"] == "2024-01-15T12:15:30.789000"


@pytest.mark.parametrize(
    "user_name, expected",
    [
        ("repo:octo-org/octo-repo:pull_request", "octo-org/octo-repo"),
        (
            "repo:octo-org@123456/octo-repo@456789:pull_request",
            "octo-org/octo-repo",
        ),
        (
            "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
            "octo-org/octo-repo",
        ),
        (
            "repo:octo-org@123456/octo-repo@456789:environment:production",
            "octo-org/octo-repo",
        ),
        ("repo:octo-org@abc/octo-repo@456789:pull_request", ""),
        ("repo:@123456/octo-repo@456789:pull_request", ""),
        ("repo:octo-org@123456/octo-repo@:pull_request", ""),
        ("repo:octo-org/team/octo-repo:pull_request", ""),
        ("repo:octo-org/octo-repo", ""),
        ("", ""),
    ],
)
def test_extract_github_repo_from_username(user_name, expected):
    """Legacy and immutable GitHub OIDC subjects resolve to the same repository fullname."""
    assert (
        cloudtrail_management_events._extract_github_repo_from_username(user_name)
        == expected
    )


def test_transform_github_web_identity_events_separate_legacy_and_immutable_subjects():
    """Legacy and immutable subjects produce separate aggregated assumptions to avoid unsafe conflation."""
    # Arrange
    immutable_event = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-07-20T09:00:00.000000",
        "EventId": "test-event-id-immutable",
        "CloudTrailEvent": '{"userIdentity": {"type": "WebIdentityUser", "principalId": "repo:example-org@123456/example-repo@456789:ref:refs/heads/main", "userName": "repo:example-org@123456/example-repo@456789:ref:refs/heads/main", "identityProvider": "token.actions.githubusercontent.com"}, "requestParameters": {"roleArn": "arn:aws:iam::987654321098:role/GitHubActionsRole", "roleSessionName": "GitHubActions"}}',
    }
    events = [SAMPLE_GITHUB_ASSUME_ROLE_WITH_WEB_IDENTITY_EVENT, immutable_event]

    # Act
    result = transform_web_identity_role_events_to_role_assumptions(events=events)

    # Assert: distinct records with separate identities
    assert result == [
        {
            "source_repo_fullname": "example-org/example-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": "arn:aws:iam::987654321098:role/GitHubActionsRole",
            "times_used": 1,
            "first_seen_in_time_window": "2024-01-15T12:15:30.789000",
            "last_used": "2024-01-15T12:15:30.789000",
        },
        {
            "source_repo_fullname": "example-org/example-repo",
            "source_repo_database_id": 456789,
            "source_owner_database_ids": [123456],
            "destination_principal_arn": "arn:aws:iam::987654321098:role/GitHubActionsRole",
            "times_used": 1,
            "first_seen_in_time_window": "2026-07-20T09:00:00.000000",
            "last_used": "2026-07-20T09:00:00.000000",
        },
    ]


def test_parse_valid_legacy_subjects():
    """Valid legacy subjects parse to (fullname, None, None)."""
    assert cloudtrail_management_events.parse_github_oidc_subject(
        "repo:octo-org/octo-repo:ref:refs/heads/main"
    ) == ("octo-org/octo-repo", None, None)
    assert cloudtrail_management_events.parse_github_oidc_subject(
        "repo:octo-org/octo-repo:pull_request"
    ) == ("octo-org/octo-repo", None, None)
    assert cloudtrail_management_events.parse_github_oidc_subject(
        "repo:octo-org/octo-repo:environment:production"
    ) == ("octo-org/octo-repo", None, None)


def test_parse_valid_immutable_subjects():
    """Valid immutable subjects parse to (fullname, repo_database_id, owner_database_id)."""
    assert cloudtrail_management_events.parse_github_oidc_subject(
        "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main"
    ) == ("octo-org/octo-repo", 456789, 123456)
    assert cloudtrail_management_events.parse_github_oidc_subject(
        "repo:octo-org@123456/octo-repo@456789:pull_request"
    ) == ("octo-org/octo-repo", 456789, 123456)
    assert cloudtrail_management_events.parse_github_oidc_subject(
        "repo:octo-org@123456/octo-repo@456789:environment:production"
    ) == ("octo-org/octo-repo", 456789, 123456)


def test_parse_invalid_or_malformed_subjects():
    """Malformed subjects and invalid IDs return None."""
    invalid_cases = [
        "repo:octo-org@abc/octo-repo@456789:pull_request",
        "repo:octo-org@123456/octo-repo@xyz:pull_request",
        "repo:@123456/octo-repo@456789:pull_request",
        "repo:octo-org@123456/octo-repo@:pull_request",
        "repo:octo-org@123456/octo-repo:pull_request",
        "repo:octo-org/octo-repo@456789:pull_request",
        "repo:octo-org/team/octo-repo:pull_request",
        "repo:octo-org/octo-repo",
        "invalid:format",
        "",
    ]
    for case in invalid_cases:
        assert cloudtrail_management_events.parse_github_oidc_subject(case) is None


def test_transform_github_web_identity_events_skip_malformed_subjects():
    """Events whose subject does not resolve to a repository are not aggregated."""
    # Arrange
    malformed_event = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-07-20T09:00:00.000000",
        "EventId": "test-event-id-malformed",
        "CloudTrailEvent": '{"userIdentity": {"type": "WebIdentityUser", "principalId": "repo:example-org@abc/example-repo:ref:refs/heads/main", "userName": "repo:example-org@abc/example-repo:ref:refs/heads/main", "identityProvider": "token.actions.githubusercontent.com"}, "requestParameters": {"roleArn": "arn:aws:iam::987654321098:role/GitHubActionsRole", "roleSessionName": "GitHubActions"}}',
    }

    # Act
    result = transform_web_identity_role_events_to_role_assumptions(
        events=[malformed_event]
    )

    # Assert
    assert result == []


def test_transform_different_immutable_ids_do_not_collide():
    """Two events sharing fullname but different immutable IDs produce separate records."""
    event1 = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T10:00:00.000000",
        "EventId": "event-1",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }
    event2 = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-02T11:00:00.000000",
        "EventId": "event-2",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@987654:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@987654:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    result = transform_web_identity_role_events_to_role_assumptions([event1, event2])

    assert len(result) == 2
    ids = {r["source_repo_database_id"] for r in result}
    assert ids == {456789, 987654}
    for r in result:
        assert r["times_used"] == 1
        assert r["source_repo_fullname"] == "octo-org/octo-repo"
        assert r["source_owner_database_ids"] == [123456]


def test_transform_repeated_immutable_events_aggregate_correctly():
    """Repeated events with the same immutable repository ID aggregate correctly."""
    event1 = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T10:00:00.000000",
        "EventId": "event-1",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }
    event2 = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-02T11:00:00.000000",
        "EventId": "event-2",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    result = transform_web_identity_role_events_to_role_assumptions([event1, event2])

    assert len(result) == 1
    assert result[0]["source_repo_database_id"] == 456789
    assert result[0]["source_owner_database_ids"] == [123456]
    assert result[0]["source_repo_fullname"] == "octo-org/octo-repo"
    assert result[0]["times_used"] == 2
    assert result[0]["first_seen_in_time_window"] == "2026-08-01T10:00:00.000000"
    assert result[0]["last_used"] == "2026-08-02T11:00:00.000000"


def test_transform_same_repo_id_different_owner_ids_aggregate_single_record():
    """Same repository ID and same role with different owner IDs produces one aggregate record with total count and both owner IDs."""
    event_org_a = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T10:00:00.000000",
        "EventId": "event-org-a",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:org-a@111111/transferred-repo@456789:ref:refs/heads/main",
                    "userName": "repo:org-a@111111/transferred-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }
    event_org_b = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-02T11:00:00.000000",
        "EventId": "event-org-b",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:org-b@222222/transferred-repo@456789:ref:refs/heads/main",
                    "userName": "repo:org-b@222222/transferred-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    result = transform_web_identity_role_events_to_role_assumptions(
        [event_org_a, event_org_b]
    )

    # Exactly one aggregate record matching the graph relationship identity
    assert len(result) == 1
    record = result[0]
    assert record["source_repo_database_id"] == 456789
    assert (
        record["destination_principal_arn"]
        == "arn:aws:iam::123456789012:role/DeployRole"
    )
    assert record["times_used"] == 2
    assert record["first_seen_in_time_window"] == "2026-08-01T10:00:00.000000"
    assert record["last_used"] == "2026-08-02T11:00:00.000000"
    assert record["source_owner_database_ids"] == [111111, 222222]


def test_transform_same_repo_id_different_destination_roles_produce_separate_records():
    """Same repository ID and different destination roles produce separate records."""
    event_role_a = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T10:00:00.000000",
        "EventId": "event-role-a",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/RoleA",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }
    event_role_b = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-02T11:00:00.000000",
        "EventId": "event-role-b",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/RoleB",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    result = transform_web_identity_role_events_to_role_assumptions(
        [event_role_a, event_role_b]
    )

    assert len(result) == 2
    roles = {r["destination_principal_arn"] for r in result}
    assert roles == {
        "arn:aws:iam::123456789012:role/RoleA",
        "arn:aws:iam::123456789012:role/RoleB",
    }
    for r in result:
        assert r["source_repo_database_id"] == 456789
        assert r["times_used"] == 1
        assert r["source_owner_database_ids"] == [123456]


def test_transform_different_repo_ids_same_fullname_never_combine():
    """Different repository IDs and the same fullname never combine."""
    event1 = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T10:00:00.000000",
        "EventId": "event-1",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }
    event2 = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-02T11:00:00.000000",
        "EventId": "event-2",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@123456/octo-repo@987654:ref:refs/heads/main",
                    "userName": "repo:octo-org@123456/octo-repo@987654:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    result = transform_web_identity_role_events_to_role_assumptions([event1, event2])

    assert len(result) == 2
    ids = {r["source_repo_database_id"] for r in result}
    assert ids == {456789, 987654}
    for r in result:
        assert r["times_used"] == 1
        assert r["source_repo_fullname"] == "octo-org/octo-repo"


def test_matchlink_receives_single_row_preventing_property_overwrites(monkeypatch):
    """The MatchLink receives exactly one row for the same repository/role identity, avoiding relationship-property overwrites."""
    loaded_matchlinks = []

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    event_org_a = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T10:00:00.000000",
        "EventId": "event-1",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:org-a@111111/repo@456789:ref:refs/heads/main",
                    "userName": "repo:org-a@111111/repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }
    event_org_b = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-02T11:00:00.000000",
        "EventId": "event-2",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:org-b@222222/repo@456789:ref:refs/heads/main",
                    "userName": "repo:org-b@222222/repo@456789:ref:refs/heads/main",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    assumptions = transform_web_identity_role_events_to_role_assumptions(
        [event_org_a, event_org_b]
    )
    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=MagicMock(),
        aggregated_role_assumptions=assumptions,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    # Crucial assertion: exactly one row passed to load_matchlinks for this (repo, role) pair
    assert len(data) == 1
    row = data[0]
    assert row["source_repo_database_id"] == 456789
    assert row["destination_principal_arn"] == "arn:aws:iam::123:role/DeployRole"
    assert row["times_used"] == 2
    assert row["source_owner_database_ids"] == [111111, 222222]


def test_immutable_matching_proves_owner_mismatch_cannot_cause_incorrect_attribution():
    """
    Test and document that repository ID alone safely prevents cross-repository misattribution.

    In GitHub's identity model, repository database_id is globally unique across all accounts.
    Even if an event contains a mismatched owner ID (e.g. from an account transfer or spoofed owner ID),
    the MatchLink matches strictly on database_id.
    """
    from cartography.graph.querybuilder import build_matchlink_query
    from cartography.models.aws.cloudtrail.management_events import (
        GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink,
    )

    schema = GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink()
    query = build_matchlink_query(schema)

    # 1. MatchLink matches strictly on database_id
    assert (
        "MATCH (from:GitHubRepository{database_id: item.source_repo_database_id})"
        in query
    )
    # 2. MatchLink does NOT match on owner or fullname
    assert "from.owner" not in query
    assert "item.source_repo_fullname" not in query
    # 3. Only the node with database_id = 456789 can match; no other repo can be linked


def test_transform_rejects_malformed_subjects_without_emitting_empty_records():
    """Malformed subjects are rejected and do not produce empty fullname records."""
    malformed_event = {
        "EventName": "AssumeRoleWithWebIdentity",
        "EventTime": "2026-08-01T12:00:00.000000",
        "EventId": "event-malformed",
        "CloudTrailEvent": json.dumps(
            {
                "userIdentity": {
                    "type": "WebIdentityUser",
                    "principalId": "repo:octo-org@abc/octo-repo@456789:pull_request",
                    "userName": "repo:octo-org@abc/octo-repo@456789:pull_request",
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/DeployRole",
                    "roleSessionName": "GitHubActions",
                },
            }
        ),
    }

    result = transform_web_identity_role_events_to_role_assumptions([malformed_event])
    assert result == []


def test_immutable_matchlink_schema_matches_on_database_id():
    """Immutable MatchLink schema explicitly matches GitHubRepository.database_id and sets relationship properties."""
    from cartography.graph.querybuilder import build_matchlink_query
    from cartography.models.aws.cloudtrail.management_events import (
        GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink,
    )

    schema = GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink()
    query = build_matchlink_query(schema)

    assert (
        "MATCH (from:GitHubRepository{database_id: item.source_repo_database_id})"
        in query
    )
    assert "MATCH (to:AWSRole{arn: item.destination_principal_arn})" in query
    assert "MERGE (from)-[r:ASSUMED_ROLE_WITH_WEB_IDENTITY]->(to)" in query
    assert "r.times_used = item.times_used" in query
    assert "r.first_seen_in_time_window = item.first_seen_in_time_window" in query
    assert "r.last_used = item.last_used" in query
    assert "r.owner_database_ids = item.source_owner_database_ids" in query
    assert "item.source_repo_fullname" not in query


def test_load_web_identity_immutable_does_not_fall_back_to_fullname(monkeypatch):
    """Immutable events are loaded strictly by database_id with no fallback to fullname."""
    loaded_matchlinks = []
    legacy_calls = []

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_legacy_web_identity_role_assumptions",
        lambda session, data, *args, **kwargs: legacy_calls.append(data),
    )

    assumptions = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": 456789,
            "source_owner_database_ids": [123456],
            "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": "2026-08-01T10:00:00",
            "last_used": "2026-08-01T10:00:00",
        }
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=MagicMock(),
        aggregated_role_assumptions=assumptions,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data = loaded_matchlinks[0]
    assert (
        schema.__class__.__name__
        == "GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink"
    )
    assert data[0]["source_repo_database_id"] == 456789
    # No fallback to legacy fullname matching
    assert legacy_calls == []


def test_load_web_identity_unknown_immutable_id_no_fullname_fallback(monkeypatch):
    """Unknown immutable repository ID does not fall back to fullname matching."""
    loaded_matchlinks = []
    legacy_calls = []

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_legacy_web_identity_role_assumptions",
        lambda session, data, *args, **kwargs: legacy_calls.append(data),
    )

    unknown_repo_assumptions = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": 999999999,
            "source_owner_database_ids": [123456],
            "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": "2026-08-01T10:00:00",
            "last_used": "2026-08-01T10:00:00",
        }
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=MagicMock(),
        aggregated_role_assumptions=unknown_repo_assumptions,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data = loaded_matchlinks[0]
    assert (
        schema.__class__.__name__
        == "GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink"
    )
    assert data[0]["source_repo_database_id"] == 999999999
    # Zero fallback to legacy fullname matching
    assert legacy_calls == []


def test_load_legacy_web_identity_rejects_historical_predecessor_event(monkeypatch):
    """Historical event preceding repository creation is rejected (fail-closed lifecycle check)."""
    loaded_matchlinks = []

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {"fullname": "octo-org/octo-repo", "createdat": "2026-08-01T00:00:00Z"}
    ]

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )

    # Event occurred in 2024, but repository was created in 2026
    legacy_assumptions = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": "2024-01-15T12:00:00",
            "last_used": "2024-01-15T12:00:00",
        }
    ]

    cloudtrail_management_events.load_legacy_web_identity_role_assumptions(
        neo4j_session=mock_session,
        legacy_role_assumptions=legacy_assumptions,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    # Rejected: historical event must not link to replacement repository
    assert loaded_matchlinks == []


def test_load_legacy_web_identity_rejects_contaminated_aggregate_spanning_recreation(
    monkeypatch,
):
    """An aggregate containing events spanning repository recreation is rejected."""
    loaded_matchlinks = []

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {"fullname": "octo-org/octo-repo", "createdat": "2026-08-01T00:00:00Z"}
    ]

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )

    # Earliest event in 2024 (predecessor repo), latest in 2026 (replacement repo)
    contaminated_aggregate = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
            "times_used": 2,
            "first_seen_in_time_window": "2024-01-15T12:00:00",
            "last_used": "2026-08-10T12:00:00",
        }
    ]

    cloudtrail_management_events.load_legacy_web_identity_role_assumptions(
        neo4j_session=mock_session,
        legacy_role_assumptions=contaminated_aggregate,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    # Rejected: earliest event occurred before creation, preventing misattribution
    assert loaded_matchlinks == []


def test_load_legacy_web_identity_fails_closed_on_missing_repo_createdat(monkeypatch):
    """Missing repository createdat fails closed."""
    loaded_matchlinks = []

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {"fullname": "octo-org/octo-repo", "createdat": None}
    ]

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )

    legacy_assumptions = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": "2024-01-15T12:00:00",
            "last_used": "2024-01-15T12:00:00",
        }
    ]

    cloudtrail_management_events.load_legacy_web_identity_role_assumptions(
        neo4j_session=mock_session,
        legacy_role_assumptions=legacy_assumptions,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert loaded_matchlinks == []


def test_load_legacy_web_identity_fails_closed_on_missing_event_timestamp(monkeypatch):
    """Missing earliest event timestamp fails closed."""
    loaded_matchlinks = []

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {"fullname": "octo-org/octo-repo", "createdat": "2020-01-01T00:00:00Z"}
    ]

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )

    legacy_assumptions = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": None,
            "last_used": "2024-01-15T12:00:00",
        }
    ]

    cloudtrail_management_events.load_legacy_web_identity_role_assumptions(
        neo4j_session=mock_session,
        legacy_role_assumptions=legacy_assumptions,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert loaded_matchlinks == []


def test_load_legacy_web_identity_succeeds_for_normal_valid_legacy_event(monkeypatch):
    """Normal valid legacy event occurring after repository creation is loaded via MatchLink."""
    loaded_matchlinks = []

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {"fullname": "octo-org/octo-repo", "createdat": "2020-01-01T00:00:00Z"}
    ]

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    valid_assumption = {
        "source_repo_fullname": "octo-org/octo-repo",
        "source_repo_database_id": None,
        "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
        "times_used": 1,
        "first_seen_in_time_window": "2024-01-15T12:00:00",
        "last_used": "2024-01-15T12:00:00",
    }

    cloudtrail_management_events.load_legacy_web_identity_role_assumptions(
        neo4j_session=mock_session,
        legacy_role_assumptions=[valid_assumption],
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    assert schema.__class__.__name__ == "GitHubRepoAssumeRoleWithWebIdentityMatchLink"
    assert data == [valid_assumption]
    assert kwargs["_sub_resource_label"] == "AWSAccount"
    assert kwargs["_sub_resource_id"] == "123456789012"
    assert kwargs["lastupdated"] == 123


def test_load_legacy_web_identity_handles_datetime_and_string_types(monkeypatch):
    """Timestamps formatted as Python datetime objects and ISO strings are normalized and compared safely."""
    from datetime import datetime
    from datetime import timezone

    loaded_matchlinks = []

    mock_session = MagicMock()
    # String from GitHub GraphQL
    mock_session.run.return_value.data.return_value = [
        {"fullname": "octo-org/octo-repo", "createdat": "2020-01-01T00:00:00Z"}
    ]

    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data)
        ),
    )

    # Python datetime from boto3 CloudTrail SDK
    valid_assumption = {
        "source_repo_fullname": "octo-org/octo-repo",
        "source_repo_database_id": None,
        "destination_principal_arn": "arn:aws:iam::123:role/DeployRole",
        "times_used": 1,
        "first_seen_in_time_window": datetime(
            2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc
        ),
        "last_used": datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
    }

    cloudtrail_management_events.load_legacy_web_identity_role_assumptions(
        neo4j_session=mock_session,
        legacy_role_assumptions=[valid_assumption],
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    assert loaded_matchlinks[0][1] == [valid_assumption]


def test_transform_assume_role_events_with_null_request_parameters():
    """Test that AssumeRole events with null requestParameters are gracefully skipped."""
    # Arrange
    events = ACCESS_DENIED_ASSUME_ROLE_CLOUDTRAIL_EVENTS

    # Act - This should no longer crash and should skip events with null requestParameters
    result = transform_assume_role_events_to_role_assumptions(events=events)

    # Assert - Events with null requestParameters should be skipped, resulting in empty list
    assert len(result) == 0


def test_transform_saml_role_events_with_null_request_parameters():
    """Test that AssumeRoleWithSAML events with null requestParameters are gracefully skipped."""
    # Arrange
    events = ACCESS_DENIED_SAML_ASSUME_ROLE_CLOUDTRAIL_EVENTS

    # Act - This should no longer crash and should skip events with null requestParameters
    result = transform_saml_role_events_to_role_assumptions(events=events)

    # Assert - Events with null requestParameters should be skipped, resulting in empty list
    assert len(result) == 0


def test_transform_web_identity_role_events_with_null_request_parameters():
    """Test that AssumeRoleWithWebIdentity events with null requestParameters are gracefully skipped."""
    # Arrange
    events = ACCESS_DENIED_WEB_IDENTITY_ASSUME_ROLE_CLOUDTRAIL_EVENTS

    # Act - This should no longer crash and should skip events with null requestParameters
    result = transform_web_identity_role_events_to_role_assumptions(events=events)

    # Assert - Events with null requestParameters should be skipped, resulting in empty list
    assert len(result) == 0


@pytest.mark.parametrize(
    "getter",
    [
        get_assume_role_events,
        get_saml_role_events,
        get_web_identity_role_events,
    ],
)
def test_get_role_events_raise_transient_region_failure_on_503(getter):
    boto3_session = MagicMock()
    page_iterator = MagicMock()
    page_iterator.__iter__ = MagicMock(
        side_effect=ClientError(
            {
                "Error": {
                    "Code": "ServiceUnavailable",
                    "Message": "Service Unavailable",
                },
                "ResponseMetadata": {"HTTPStatusCode": 503},
            },
            "LookupEvents",
        )
    )
    boto3_session.client.return_value.get_paginator.return_value.paginate.return_value = (
        page_iterator
    )

    with pytest.raises(CloudTrailTransientRegionFailure):
        getter(boto3_session, "me-central-1", 24)

    assert boto3_session.client.call_args.kwargs["config"] == get_botocore_config()


@pytest.mark.parametrize(
    "getter",
    [
        get_assume_role_events,
        get_saml_role_events,
        get_web_identity_role_events,
    ],
)
def test_get_role_events_raise_transient_region_failure_on_read_timeout(getter):
    boto3_session = MagicMock()
    page_iterator = MagicMock()
    page_iterator.__iter__ = MagicMock(
        side_effect=ReadTimeoutError(
            endpoint_url="https://cloudtrail.me-central-1.amazonaws.com/",
            error="timeout",
        )
    )
    boto3_session.client.return_value.get_paginator.return_value.paginate.return_value = (
        page_iterator
    )

    with pytest.raises(CloudTrailTransientRegionFailure):
        getter(boto3_session, "me-central-1", 24)


def test_sync_assume_role_events_skips_cleanup_on_transient_region_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    cleanup_calls = []
    load_calls = []

    def fake_get_assume_role_events(
        boto3_session: MagicMock, region: str, lookback_hours: int
    ):
        if region == "me-central-1":
            raise CloudTrailTransientRegionFailure("transient failure")
        return [{"EventId": f"{region}-event"}]

    def fake_transform_assume_role_events_to_role_assumptions(events):
        return [{"event_count": len(events)}]

    def fake_load_role_assumptions(**kwargs):
        load_calls.append(kwargs["aggregated_role_assumptions"])

    def fake_cleanup(*args, **kwargs):
        cleanup_calls.append((args, kwargs))

    monkeypatch.setattr(
        cloudtrail_management_events,
        "get_assume_role_events",
        fake_get_assume_role_events,
    )
    monkeypatch.setattr(
        cloudtrail_management_events,
        "transform_assume_role_events_to_role_assumptions",
        fake_transform_assume_role_events_to_role_assumptions,
    )
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_role_assumptions",
        fake_load_role_assumptions,
    )
    monkeypatch.setattr(cloudtrail_management_events, "cleanup", fake_cleanup)

    sync_assume_role_events(
        neo4j_session=MagicMock(),
        boto3_session=MagicMock(),
        regions=["us-east-1", "me-central-1"],
        current_aws_account_id="123456789012",
        update_tag=123,
        common_job_parameters={
            "aws_cloudtrail_management_events_lookback_hours": 24,
        },
    )

    assert len(load_calls) == 1
    assert cleanup_calls == []


def test_mixed_legacy_and_immutable_events_coalesce_into_single_immutable_matchlink(
    monkeypatch,
):
    """
    An existing repository created on 2026-01-15 emitted a legacy OIDC event on
    2026-07-14, opted into GitHub's immutable subject claims around July 15, 2026,
    and emitted an immutable event on 2026-07-16. Both events occur in the same
    lookback window for the same destination role.

    Verify that they coalesce into a single immutable MatchLink call with times_used=2,
    earliest first-seen (2026-07-14), latest last-used (2026-07-16), and correct owner-ID union.
    """
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {
            "fullname": "octo-org/octo-repo",
            "createdat": "2026-01-15T00:00:00Z",
            "database_id": 222222,
        }
    ]

    role_arn = "arn:aws:iam::123456789012:role/DeployRole"
    legacy_time = "2026-07-14T10:00:00Z"
    immutable_time = "2026-07-16T14:30:00Z"

    aggregated = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": role_arn,
            "times_used": 1,
            "first_seen_in_time_window": legacy_time,
            "last_used": legacy_time,
        },
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": 222222,
            "source_owner_database_ids": [111111],
            "destination_principal_arn": role_arn,
            "times_used": 1,
            "first_seen_in_time_window": immutable_time,
            "last_used": immutable_time,
        },
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    assert (
        schema.__class__.__name__
        == "GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink"
    )
    assert len(data) == 1
    row = data[0]
    assert row["source_repo_database_id"] == 222222
    assert row["destination_principal_arn"] == role_arn
    assert row["times_used"] == 2
    assert row["first_seen_in_time_window"] == legacy_time
    assert row["last_used"] == immutable_time
    assert row["source_owner_database_ids"] == [111111]


def test_validated_legacy_with_database_id_promoted_to_immutable_matching(monkeypatch):
    """A validated legacy record with a repository database ID but no immutable event is promoted to immutable matching."""
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {
            "fullname": "octo-org/octo-repo",
            "createdat": "2026-01-15T00:00:00Z",
            "database_id": 222222,
        }
    ]

    role_arn = "arn:aws:iam::123456789012:role/DeployRole"
    legacy_time = "2026-07-14T10:00:00Z"

    aggregated = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": role_arn,
            "times_used": 1,
            "first_seen_in_time_window": legacy_time,
            "last_used": legacy_time,
        }
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    assert (
        schema.__class__.__name__
        == "GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink"
    )
    assert len(data) == 1
    row = data[0]
    assert row["source_repo_database_id"] == 222222
    assert row["source_owner_database_ids"] == []
    assert row["times_used"] == 1
    assert row["first_seen_in_time_window"] == legacy_time
    assert row["last_used"] == legacy_time


def test_validated_legacy_without_database_id_retained_on_legacy_path(monkeypatch):
    """A validated legacy record without a database ID in the graph is retained on the legacy fullname matching path."""
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {
            "fullname": "octo-org/legacy-repo",
            "createdat": "2026-01-15T00:00:00Z",
            "database_id": None,
        }
    ]

    role_arn = "arn:aws:iam::123456789012:role/DeployRole"
    legacy_time = "2026-07-14T10:00:00Z"

    aggregated = [
        {
            "source_repo_fullname": "octo-org/legacy-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": role_arn,
            "times_used": 1,
            "first_seen_in_time_window": legacy_time,
            "last_used": legacy_time,
        }
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    assert schema.__class__.__name__ == "GitHubRepoAssumeRoleWithWebIdentityMatchLink"
    assert len(data) == 1
    row = data[0]
    assert row["source_repo_fullname"] == "octo-org/legacy-repo"
    assert row["source_repo_database_id"] is None
    assert row["times_used"] == 1


def test_legacy_event_rejected_by_lifecycle_check_never_promoted(monkeypatch):
    """A legacy event rejected by the lifecycle check is never promoted or loaded."""
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {
            "fullname": "octo-org/recreated-repo",
            "createdat": "2026-01-01T00:00:00Z",
            "database_id": 555555,
        }
    ]

    # Predecessor event timestamp earlier than repository creation timestamp
    predecessor_time = "2024-05-01T12:00:00Z"
    aggregated = [
        {
            "source_repo_fullname": "octo-org/recreated-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": "arn:aws:iam::123456789012:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": predecessor_time,
            "last_used": predecessor_time,
        }
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert loaded_matchlinks == []


def test_ambiguous_repository_resolution_no_attribution(monkeypatch):
    """Ambiguous repository resolution (multiple nodes with same fullname) results in zero attribution."""
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {
            "fullname": "octo-org/ambiguous-repo",
            "createdat": "2024-01-01T00:00:00Z",
            "database_id": 101,
        },
        {
            "fullname": "octo-org/ambiguous-repo",
            "createdat": "2025-06-01T00:00:00Z",
            "database_id": 102,
        },
    ]

    aggregated = [
        {
            "source_repo_fullname": "octo-org/ambiguous-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": "arn:aws:iam::123456789012:role/DeployRole",
            "times_used": 1,
            "first_seen_in_time_window": "2025-08-01T12:00:00Z",
            "last_used": "2025-08-01T12:00:00Z",
        }
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert loaded_matchlinks == []


def test_different_destination_roles_remain_separate(monkeypatch):
    """Events for different destination roles remain separate relationship records."""
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    mock_session.run.return_value.data.return_value = [
        {
            "fullname": "octo-org/octo-repo",
            "createdat": "2026-01-15T00:00:00Z",
            "database_id": 222222,
        }
    ]

    role_a = "arn:aws:iam::123456789012:role/RoleA"
    role_b = "arn:aws:iam::123456789012:role/RoleB"

    aggregated = [
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": None,
            "source_owner_database_ids": [],
            "destination_principal_arn": role_a,
            "times_used": 1,
            "first_seen_in_time_window": "2026-07-14T10:00:00Z",
            "last_used": "2026-07-14T10:00:00Z",
        },
        {
            "source_repo_fullname": "octo-org/octo-repo",
            "source_repo_database_id": 222222,
            "source_owner_database_ids": [111111],
            "destination_principal_arn": role_b,
            "times_used": 1,
            "first_seen_in_time_window": "2026-07-16T14:30:00Z",
            "last_used": "2026-07-16T14:30:00Z",
        },
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    assert (
        schema.__class__.__name__
        == "GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink"
    )
    assert len(data) == 2

    records_by_role = {d["destination_principal_arn"]: d for d in data}
    assert role_a in records_by_role
    assert role_b in records_by_role
    assert records_by_role[role_a]["times_used"] == 1
    assert records_by_role[role_a]["source_owner_database_ids"] == []
    assert records_by_role[role_b]["times_used"] == 1
    assert records_by_role[role_b]["source_owner_database_ids"] == [111111]


def test_different_repo_ids_with_identical_fullnames_never_coalesce(monkeypatch):
    """
    Two immutable assumptions sharing identical fullnames but having different repository
    database IDs (888888 and 999999) never coalesce, retaining separate output
    records, independent counts, and distinct owner-ID provenance.
    """
    loaded_matchlinks = []
    monkeypatch.setattr(
        cloudtrail_management_events,
        "load_matchlinks",
        lambda session, schema, data, **kwargs: loaded_matchlinks.append(
            (schema, data, kwargs)
        ),
    )

    mock_session = MagicMock()
    role_arn = "arn:aws:iam::123456789012:role/DeployRole"

    aggregated = [
        {
            "source_repo_fullname": "octo-org/fork-repo",
            "source_repo_database_id": 888888,
            "source_owner_database_ids": [111111],
            "destination_principal_arn": role_arn,
            "times_used": 1,
            "first_seen_in_time_window": "2026-07-16T10:00:00Z",
            "last_used": "2026-07-16T12:00:00Z",
        },
        {
            "source_repo_fullname": "octo-org/fork-repo",
            "source_repo_database_id": 999999,
            "source_owner_database_ids": [222222],
            "destination_principal_arn": role_arn,
            "times_used": 2,
            "first_seen_in_time_window": "2026-07-16T14:00:00Z",
            "last_used": "2026-07-16T16:00:00Z",
        },
    ]

    cloudtrail_management_events.load_web_identity_role_assumptions(
        neo4j_session=mock_session,
        aggregated_role_assumptions=aggregated,
        current_aws_account_id="123456789012",
        aws_update_tag=123,
    )

    assert len(loaded_matchlinks) == 1
    schema, data, kwargs = loaded_matchlinks[0]
    assert (
        schema.__class__.__name__
        == "GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink"
    )
    assert len(data) == 2

    records_by_db_id = {d["source_repo_database_id"]: d for d in data}
    assert 888888 in records_by_db_id
    assert 999999 in records_by_db_id

    # Independent counts, provenance, and timestamps
    assert records_by_db_id[888888]["times_used"] == 1
    assert records_by_db_id[888888]["source_owner_database_ids"] == [111111]
    assert (
        records_by_db_id[888888]["first_seen_in_time_window"] == "2026-07-16T10:00:00Z"
    )
    assert records_by_db_id[888888]["last_used"] == "2026-07-16T12:00:00Z"

    assert records_by_db_id[999999]["times_used"] == 2
    assert records_by_db_id[999999]["source_owner_database_ids"] == [222222]
    assert (
        records_by_db_id[999999]["first_seen_in_time_window"] == "2026-07-16T14:00:00Z"
    )
    assert records_by_db_id[999999]["last_used"] == "2026-07-16T16:00:00Z"
