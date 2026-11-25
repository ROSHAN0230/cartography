import json
import logging
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import boto3
import dateutil.parser
import neo4j
from botocore.exceptions import ClientError
from botocore.exceptions import ConnectionClosedError
from botocore.exceptions import ConnectTimeoutError
from botocore.exceptions import EndpointConnectionError
from botocore.exceptions import ReadTimeoutError
from botocore.parsers import ResponseParserError

from cartography.client.core.tx import load_matchlinks
from cartography.graph.job import GraphJob
from cartography.intel.aws.cloudtrail import _is_retryable_cloudtrail_error
from cartography.intel.aws.cloudtrail import CloudTrailTransientRegionFailure
from cartography.intel.aws.util.botocore_config import create_boto3_client
from cartography.models.aws.cloudtrail.management_events import AssumedRoleMatchLink
from cartography.models.aws.cloudtrail.management_events import (
    AssumedRoleWithSAMLMatchLink,
)
from cartography.models.aws.cloudtrail.management_events import (
    GitHubRepoAssumeRoleWithWebIdentityMatchLink,
)
from cartography.models.aws.cloudtrail.management_events import (
    GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink,
)
from cartography.util import aws_handle_regions
from cartography.util import timeit

logger = logging.getLogger(__name__)


def _collect_lookup_events(page_iterator: Any) -> List[Dict[str, Any]]:
    all_events: List[Dict[str, Any]] = []
    try:
        for page in page_iterator:
            all_events.extend(page.get("Events", []))
    except ClientError as error:
        if _is_retryable_cloudtrail_error(error):
            raise CloudTrailTransientRegionFailure(
                "AWS SDK retries were exhausted for transient LookupEvents failure"
            ) from error
        raise
    except (
        ConnectionClosedError,
        ConnectTimeoutError,
        EndpointConnectionError,
        ReadTimeoutError,
        ResponseParserError,
    ) as error:
        raise CloudTrailTransientRegionFailure(
            "Encountered a transient regional CloudTrail endpoint failure while calling LookupEvents"
        ) from error

    return all_events


@timeit
@aws_handle_regions
def get_assume_role_events(
    boto3_session: boto3.Session, region: str, lookback_hours: int
) -> List[Dict[str, Any]]:
    """
    Fetch CloudTrail AssumeRole events from the specified time period.

    Focuses specifically on standard AssumeRole events, excluding SAML and WebIdentity variants.

    :type boto3_session: boto3.Session
    :param boto3_session: The boto3 session to use for API calls
    :type region: str
    :param region: The AWS region to fetch events from
    :type lookback_hours: int
    :param lookback_hours: Number of hours back to retrieve events from
    :rtype: List[Dict[str, Any]]
    :return: List of CloudTrail AssumeRole events
    """
    client = create_boto3_client(boto3_session, "cloudtrail", region_name=region)

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)

    logger.debug(
        "Fetching CloudTrail AssumeRole events for region '%s' from %s to %s (%s hours)",
        region,
        start_time,
        end_time,
        lookback_hours,
    )

    paginator = client.get_paginator("lookup_events")

    page_iterator = paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}
        ],
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={
            "MaxItems": 10000,  # Reasonable limit to prevent excessive API calls
            "PageSize": 50,  # CloudTrail API limit per page
        },
    )

    all_events = _collect_lookup_events(page_iterator)

    logger.debug(
        "Retrieved %s AssumeRole events from region '%s'", len(all_events), region
    )

    return all_events


@timeit
@aws_handle_regions
def get_saml_role_events(
    boto3_session: boto3.Session, region: str, lookback_hours: int
) -> List[Dict[str, Any]]:
    """
    Fetch CloudTrail AssumeRoleWithSAML events from the specified time period.

    Focuses specifically on SAML-based role assumption events.

    :type boto3_session: boto3.Session
    :param boto3_session: The boto3 session to use for API calls
    :type region: str
    :param region: The AWS region to fetch events from
    :type lookback_hours: int
    :param lookback_hours: Number of hours back to retrieve events from
    :rtype: List[Dict[str, Any]]
    :return: List of CloudTrail AssumeRoleWithSAML events
    """
    client = create_boto3_client(boto3_session, "cloudtrail", region_name=region)

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)

    logger.debug(
        "Fetching CloudTrail AssumeRoleWithSAML events for region '%s' from %s to %s (%s hours)",
        region,
        start_time,
        end_time,
        lookback_hours,
    )

    paginator = client.get_paginator("lookup_events")

    page_iterator = paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventName", "AttributeValue": "AssumeRoleWithSAML"}
        ],
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={
            "MaxItems": 10000,  # Reasonable limit to prevent excessive API calls
            "PageSize": 50,  # CloudTrail API limit per page
        },
    )

    all_events = _collect_lookup_events(page_iterator)

    logger.debug(
        "Retrieved %s AssumeRoleWithSAML events from region '%s'",
        len(all_events),
        region,
    )

    return all_events


@timeit
@aws_handle_regions
def get_web_identity_role_events(
    boto3_session: boto3.Session, region: str, lookback_hours: int
) -> List[Dict[str, Any]]:
    """
    Fetch CloudTrail AssumeRoleWithWebIdentity events from the specified time period.

    Focuses specifically on WebIdentity-based role assumption events.

    :type boto3_session: boto3.Session
    :param boto3_session: The boto3 session to use for API calls
    :type region: str
    :param region: The AWS region to fetch events from
    :type lookback_hours: int
    :param lookback_hours: Number of hours back to retrieve events from
    :rtype: List[Dict[str, Any]]
    :return: List of CloudTrail AssumeRoleWithWebIdentity events
    """
    client = create_boto3_client(boto3_session, "cloudtrail", region_name=region)

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)

    logger.debug(
        "Fetching CloudTrail AssumeRoleWithWebIdentity events for region '%s' from %s to %s (%s hours)",
        region,
        start_time,
        end_time,
        lookback_hours,
    )

    paginator = client.get_paginator("lookup_events")

    page_iterator = paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventName", "AttributeValue": "AssumeRoleWithWebIdentity"}
        ],
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={
            "MaxItems": 10000,  # Reasonable limit to prevent excessive API calls
            "PageSize": 50,  # CloudTrail API limit per page
        },
    )

    all_events = _collect_lookup_events(page_iterator)

    logger.debug(
        "Retrieved %s AssumeRoleWithWebIdentity events from region '%s'",
        len(all_events),
        region,
    )

    return all_events


@timeit
def transform_assume_role_events_to_role_assumptions(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Transform raw CloudTrail AssumeRole events into aggregated role assumption relationships.

    Focuses specifically on standard AssumeRole events, providing optimized processing
    for the most common role assumption scenario.

    This function performs the complete transformation pipeline:
    1. Extract role assumption events from CloudTrail AssumeRole data
    2. Aggregate events by (source_principal, destination_principal) pairs
    3. Return aggregated relationships ready for loading

    :type events: List[Dict[str, Any]]
    :param events: List of raw CloudTrail AssumeRole events from lookup_events API
    :rtype: List[Dict[str, Any]]
    :return: List of aggregated role assumption relationships ready for loading
    """
    aggregated: Dict[tuple, Dict[str, Any]] = {}
    logger.debug(
        "Transforming %s CloudTrail AssumeRole events to role assumptions", len(events)
    )

    for event in events:

        cloudtrail_event = json.loads(event["CloudTrailEvent"])

        # Skip events with null requestParameters since we can't extract roleArn
        if not cloudtrail_event.get("requestParameters"):
            logger.debug(
                f"Skipping CloudTrail AssumeRole event due to missing requestParameters. Event: {event.get('EventId', 'unknown')}"
            )
            continue

        if cloudtrail_event.get("userIdentity", {}).get("arn"):
            source_principal = cloudtrail_event["userIdentity"]["arn"]
            destination_principal = cloudtrail_event["requestParameters"]["roleArn"]
        else:
            logger.debug(
                f"Skipping CloudTrail AssumeRole event due to missing UserIdentity.arn. Event: {event.get('EventId', 'unknown')}"
            )
            continue

        destination_principal = cloudtrail_event["requestParameters"]["roleArn"]

        normalized_source_principal = _convert_assumed_role_arn_to_role_arn(
            source_principal
        )
        normalized_destination_principal = _convert_assumed_role_arn_to_role_arn(
            destination_principal
        )
        event_time = event.get("EventTime")

        key = (normalized_source_principal, normalized_destination_principal)

        if key in aggregated:
            aggregated[key]["times_used"] += 1
            # Handle None values safely for time comparisons
            if event_time:
                existing_first = aggregated[key]["first_seen_in_time_window"]
                existing_last = aggregated[key]["last_used"]

                if existing_first is None or event_time < existing_first:
                    aggregated[key]["first_seen_in_time_window"] = event_time
                if existing_last is None or event_time > existing_last:
                    aggregated[key]["last_used"] = event_time
        else:
            aggregated[key] = {
                "source_principal_arn": normalized_source_principal,
                "destination_principal_arn": normalized_destination_principal,
                "times_used": 1,
                "first_seen_in_time_window": event_time,
                "last_used": event_time,
            }

    return list(aggregated.values())


@timeit
def transform_saml_role_events_to_role_assumptions(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Transform raw CloudTrail AssumeRoleWithSAML events into aggregated role assumption relationships.

    Focuses specifically on SAML-based role assumption events, providing optimized processing
    for federated identity scenarios.

    This function performs the complete transformation pipeline:
    1. Extract role assumption events from CloudTrail AssumeRoleWithSAML data
    2. Aggregate events by (source_principal, destination_principal) pairs
    3. Return aggregated relationships ready for loading

    :type events: List[Dict[str, Any]]
    :param events: List of raw CloudTrail AssumeRoleWithSAML events from lookup_events API
    :rtype: List[Dict[str, Any]]
    :return: List of aggregated SAML role assumption relationships ready for loading.
             Each dict contains keys: source_principal_arn, destination_principal_arn,
             times_used, first_seen_in_time_window, last_used
    """
    aggregated: Dict[tuple, Dict[str, Any]] = {}
    logger.debug(
        "Transforming %s CloudTrail AssumeRoleWithSAML events to role assumptions",
        len(events),
    )

    for event in events:

        cloudtrail_event = json.loads(event["CloudTrailEvent"])

        # Skip events with null requestParameters since we can't extract roleArn
        if not cloudtrail_event.get("requestParameters"):
            logger.debug(
                f"Skipping CloudTrail AssumeRoleWithSAML event due to missing requestParameters. Event: {event.get('EventId', 'unknown')}"
            )
            continue

        response_elements = cloudtrail_event.get("responseElements", {})
        assumed_role_user = response_elements.get("assumedRoleUser", {})

        if assumed_role_user.get("arn"):
            assumed_role_arn = assumed_role_user["arn"]
            # Extract username from assumed role ARN: arn:aws:sts::account:assumed-role/RoleName/username
            source_principal = assumed_role_arn.split("/")[-1]
            destination_principal = cloudtrail_event["requestParameters"]["roleArn"]
        else:
            logger.debug(
                f"Skipping CloudTrail AssumeRoleWithSAML event due to missing assumedRoleUser.arn. Event: {event.get('EventId', 'unknown')}"
            )
            continue

        event_time = event.get("EventTime")

        key = (source_principal, destination_principal)

        if key in aggregated:
            aggregated[key]["times_used"] += 1
            # Handle None values safely for time comparisons
            if event_time:
                existing_first = aggregated[key]["first_seen_in_time_window"]
                existing_last = aggregated[key]["last_used"]

                if existing_first is None or event_time < existing_first:
                    aggregated[key]["first_seen_in_time_window"] = event_time
                if existing_last is None or event_time > existing_last:
                    aggregated[key]["last_used"] = event_time
        else:
            aggregated[key] = {
                "source_principal_arn": source_principal,
                "destination_principal_arn": destination_principal,
                "times_used": 1,
                "first_seen_in_time_window": event_time,
                "last_used": event_time,
            }

    return list(aggregated.values())


@timeit
def transform_web_identity_role_events_to_role_assumptions(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Transform raw CloudTrail AssumeRoleWithWebIdentity events into aggregated role assumption relationships.

    Focuses specifically on WebIdentity-based role assumption events, providing optimized processing
    for federated web identity scenarios.

    This function performs the complete transformation pipeline:
    1. Extract role assumption events from CloudTrail AssumeRoleWithWebIdentity data
    2. Aggregate events by (source_principal, destination_principal) pairs
    3. Return aggregated relationships ready for loading

    :type events: List[Dict[str, Any]]
    :param events: List of raw CloudTrail AssumeRoleWithWebIdentity events from lookup_events API
    :rtype: List[Dict[str, Any]]
    :return: List of aggregated WebIdentity role assumption relationships ready for loading.
             Each dict contains keys: source_repo_fullname, destination_principal_arn,
             times_used, first_seen_in_time_window, last_used
    """
    github_aggregated: Dict[tuple, Dict[str, Any]] = {}
    logger.debug(
        "Transforming %s CloudTrail AssumeRoleWithWebIdentity events to role assumptions",
        len(events),
    )

    for event in events:

        cloudtrail_event = json.loads(event["CloudTrailEvent"])

        # Skip events with null requestParameters since we can't extract roleArn
        if not cloudtrail_event.get("requestParameters"):
            logger.debug(
                f"Skipping CloudTrail AssumeRoleWithWebIdentity event due to missing requestParameters. Event: {event.get('EventId', 'unknown')}"
            )
            continue

        user_identity = cloudtrail_event.get("userIdentity", {})

        if user_identity.get("type") == "WebIdentityUser" and user_identity.get(
            "userName"
        ):
            identity_provider = user_identity.get("identityProvider", "unknown")
            destination_principal = cloudtrail_event["requestParameters"]["roleArn"]
            event_time = event.get("EventTime")

            # Only process GitHub Actions events
            if "token.actions.githubusercontent.com" in identity_provider:
                user_name = user_identity.get("userName", "")
                if not user_name:
                    logger.debug(
                        f"Missing userName in GitHub WebIdentity event: {event.get('EventId', 'unknown')}"
                    )
                    continue

                parsed_subject = parse_github_oidc_subject(user_name)
                if not parsed_subject:
                    logger.debug(
                        f"Unable to parse GitHub OIDC subject claim from userName '{user_name}' in event: {event.get('EventId', 'unknown')}"
                    )
                    continue

                github_repo, repo_database_id, owner_database_id = parsed_subject

                key: Tuple[Any, ...]
                if repo_database_id is not None:
                    key = (
                        "immutable",
                        str(repo_database_id),
                        destination_principal,
                    )
                else:
                    key = ("legacy", github_repo, destination_principal)

                if key in github_aggregated:
                    github_aggregated[key]["times_used"] += 1
                    # Handle None values safely for time comparisons
                    if event_time:
                        existing_first = github_aggregated[key][
                            "first_seen_in_time_window"
                        ]
                        existing_last = github_aggregated[key]["last_used"]

                        if existing_first is None or event_time < existing_first:
                            github_aggregated[key][
                                "first_seen_in_time_window"
                            ] = event_time
                        if existing_last is None or event_time > existing_last:
                            github_aggregated[key]["last_used"] = event_time

                    if owner_database_id is not None:
                        owner_ids = github_aggregated[key]["source_owner_database_ids"]
                        if owner_database_id not in owner_ids:
                            owner_ids.append(owner_database_id)
                            owner_ids.sort()
                else:
                    initial_owner_ids = (
                        [owner_database_id] if owner_database_id is not None else []
                    )
                    github_aggregated[key] = {
                        "source_repo_fullname": github_repo,
                        "source_repo_database_id": repo_database_id,
                        "source_owner_database_ids": initial_owner_ids,
                        "destination_principal_arn": destination_principal,
                        "times_used": 1,
                        "first_seen_in_time_window": event_time,
                        "last_used": event_time,
                    }
            else:
                # Skip non-GitHub events for now
                continue
        else:
            continue
    # Return aggregated relationships directly
    return list(github_aggregated.values())


@timeit
def load_role_assumptions(
    neo4j_session: neo4j.Session,
    aggregated_role_assumptions: List[Dict[str, Any]],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    """
    Load aggregated role assumption relationships into Neo4j using MatchLink pattern.

    Creates direct ASSUMED_ROLE relationships with aggregated properties:
    (AWSUser|AWSRole|AWSPrincipal)-[:ASSUMED_ROLE {lastupdated, times_used, first_seen_in_time_window, last_used}]->(AWSRole)

    Assumes that both source principals and destination roles already exist in the graph.

    :type neo4j_session: neo4j.Session
    :param neo4j_session: The Neo4j session to use for database operations
    :type aggregated_role_assumptions: List[Dict[str, Any]]
    :param aggregated_role_assumptions: List of aggregated role assumption relationships from transform function
    :type current_aws_account_id: str
    :param current_aws_account_id: The AWS account ID being synced
    :type aws_update_tag: int
    :param aws_update_tag: Timestamp tag for tracking data freshness
    :rtype: None
    """
    # Use MatchLink to create relationships between existing nodes
    matchlink_schema = AssumedRoleMatchLink()

    load_matchlinks(
        neo4j_session,
        matchlink_schema,
        aggregated_role_assumptions,
        lastupdated=aws_update_tag,
        _sub_resource_label="AWSAccount",
        _sub_resource_id=current_aws_account_id,
    )


@timeit
def load_saml_role_assumptions(
    neo4j_session: neo4j.Session,
    aggregated_role_assumptions: List[Dict[str, Any]],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    """
    Load aggregated SAML role assumption relationships into Neo4j using MatchLink pattern.

    Creates direct ASSUMED_ROLE_WITH_SAML relationships with aggregated properties:
    (AWSRole)-[:ASSUMED_ROLE_WITH_SAML {lastupdated, times_used, first_seen_in_time_window, last_used}]->(AWSRole)

    Assumes that both source principals and destination roles already exist in the graph.

    :type neo4j_session: neo4j.Session
    :param neo4j_session: The Neo4j session to use for database operations
    :type aggregated_role_assumptions: List[Dict[str, Any]]
    :param aggregated_role_assumptions: List of aggregated SAML role assumption relationships from transform function
    :type current_aws_account_id: str
    :param current_aws_account_id: The AWS account ID being synced
    :type aws_update_tag: int
    :param aws_update_tag: Timestamp tag for tracking data freshness
    :rtype: None
    """
    # Use MatchLink to create relationships between existing nodes
    matchlink_schema = AssumedRoleWithSAMLMatchLink()

    load_matchlinks(
        neo4j_session,
        matchlink_schema,
        aggregated_role_assumptions,
        lastupdated=aws_update_tag,
        _sub_resource_label="AWSAccount",
        _sub_resource_id=current_aws_account_id,
    )


def _parse_to_utc_datetime(ts: Any) -> Optional[datetime]:
    """
    Parse a timestamp (datetime object or ISO string) into a timezone-aware UTC datetime.
    Returns None if ts is None, empty, or unparseable.
    """
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if isinstance(ts, str):
        cleaned = ts.strip()
        if not cleaned:
            return None
        try:
            parsed = dateutil.parser.parse(cleaned)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (ValueError, TypeError, OverflowError):
            return None
    return None


def _earliest_timestamp(ts1: Any, ts2: Any) -> Any:
    """
    Return the chronologically earlier timestamp between ts1 and ts2,
    handling None, datetime objects, and ISO timestamp strings.
    """
    if ts1 is None:
        return ts2
    if ts2 is None:
        return ts1
    dt1 = _parse_to_utc_datetime(ts1)
    dt2 = _parse_to_utc_datetime(ts2)
    if dt1 is None:
        return ts2
    if dt2 is None:
        return ts1
    return ts1 if dt1 <= dt2 else ts2


def _latest_timestamp(ts1: Any, ts2: Any) -> Any:
    """
    Return the chronologically later timestamp between ts1 and ts2,
    handling None, datetime objects, and ISO timestamp strings.
    """
    if ts1 is None:
        return ts2
    if ts2 is None:
        return ts1
    dt1 = _parse_to_utc_datetime(ts1)
    dt2 = _parse_to_utc_datetime(ts2)
    if dt1 is None:
        return ts2
    if dt2 is None:
        return ts1
    return ts1 if dt1 >= dt2 else ts2


def resolve_and_validate_legacy_web_identity_role_assumptions(
    neo4j_session: neo4j.Session,
    legacy_role_assumptions: List[Dict[str, Any]],
) -> List[Tuple[Dict[str, Any], Optional[int]]]:
    """
    Validate legacy WebIdentity role assumptions against GitHubRepository nodes in Neo4j.

    Fails closed when:
    - Multiple GitHubRepository nodes exist with the same fullname (ambiguous).
    - Repository creation timestamp (createdat) is missing or unparseable.
    - Earliest CloudTrail event timestamp (first_seen_in_time_window) is missing or unparseable.
    - The earliest event occurred before repository creation (createdat > first_seen_in_time_window),
      which indicates historical events from a predecessor deleted repository.

    Returns a list of tuples: (validated_legacy_assumption_dict, resolved_repository_database_id).
    The resolved repository database ID is None if the node has no database_id in the graph.
    """
    if not legacy_role_assumptions:
        return []

    fullnames = list(
        {
            a["source_repo_fullname"]
            for a in legacy_role_assumptions
            if a.get("source_repo_fullname")
        }
    )
    if not fullnames:
        return []

    query = """
    MATCH (from:GitHubRepository)
    WHERE from.fullname IN $fullnames
    RETURN from.fullname AS fullname, from.createdat AS createdat, from.database_id AS database_id
    """
    records = neo4j_session.run(query, fullnames=fullnames).data()

    nodes_by_fullname: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        nodes_by_fullname[r["fullname"]].append(r)

    validated_assumptions: List[Tuple[Dict[str, Any], Optional[int]]] = []
    for item in legacy_role_assumptions:
        fullname = item.get("source_repo_fullname")
        if not fullname:
            continue
        nodes = nodes_by_fullname.get(fullname, [])

        # Uniqueness check: exactly one repository node must exist
        if len(nodes) != 1:
            logger.warning(
                "Legacy GitHub repository match for %s is ambiguous or missing (%d nodes found). Failing closed.",
                fullname,
                len(nodes),
            )
            continue

        node = nodes[0]
        raw_createdat = node.get("createdat")
        raw_first_seen = item.get("first_seen_in_time_window")

        # Critical correction B: Fail-closed when lifecycle evidence is missing
        if raw_createdat is None or raw_first_seen is None:
            logger.warning(
                "Missing lifecycle timestamp evidence for %s (createdat=%s, first_seen=%s). Failing closed.",
                fullname,
                raw_createdat,
                raw_first_seen,
            )
            continue

        # Critical correction C: Normalize both timestamps to timezone-aware UTC datetimes
        repo_created_dt = _parse_to_utc_datetime(raw_createdat)
        event_first_seen_dt = _parse_to_utc_datetime(raw_first_seen)

        if repo_created_dt is None or event_first_seen_dt is None:
            logger.warning(
                "Unable to parse lifecycle timestamps for %s (createdat=%s, first_seen=%s). Failing closed.",
                fullname,
                raw_createdat,
                raw_first_seen,
            )
            continue

        # Critical correction A: Lifecycle protection - earliest event in aggregate must be after repository creation
        if repo_created_dt > event_first_seen_dt:
            logger.warning(
                "Legacy event for %s occurred before repository creation (createdat=%s, first_seen=%s). "
                "Rejecting aggregate to prevent misattribution to replacement repository.",
                fullname,
                raw_createdat,
                raw_first_seen,
            )
            continue

        raw_db_id = node.get("database_id")
        resolved_db_id: Optional[int] = None
        if raw_db_id is not None:
            try:
                resolved_db_id = int(raw_db_id)
            except (ValueError, TypeError):
                resolved_db_id = None

        validated_assumptions.append((dict(item), resolved_db_id))

    return validated_assumptions


def load_legacy_web_identity_role_assumptions(
    neo4j_session: neo4j.Session,
    legacy_role_assumptions: List[Dict[str, Any]],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    """
    Load legacy WebIdentity role assumptions using safe fullname matching.
    """
    validated = resolve_and_validate_legacy_web_identity_role_assumptions(
        neo4j_session,
        legacy_role_assumptions,
    )
    safe_legacy_assumptions = [item for item, _ in validated]
    if safe_legacy_assumptions:
        legacy_matchlink_schema = GitHubRepoAssumeRoleWithWebIdentityMatchLink()
        load_matchlinks(
            neo4j_session,
            legacy_matchlink_schema,
            safe_legacy_assumptions,
            lastupdated=aws_update_tag,
            _sub_resource_label="AWSAccount",
            _sub_resource_id=current_aws_account_id,
        )


@timeit
def load_web_identity_role_assumptions(
    neo4j_session: neo4j.Session,
    aggregated_role_assumptions: List[Dict[str, Any]],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    """
    Load aggregated WebIdentity role assumption relationships into Neo4j.

    Creates direct ASSUMED_ROLE_WITH_WEB_IDENTITY relationships with aggregated properties:
    (GitHubRepository)-[:ASSUMED_ROLE_WITH_WEB_IDENTITY {lastupdated, times_used, first_seen_in_time_window, last_used}]->(AWSRole)

    - Immutable events (with source_repo_database_id) match GitHubRepository nodes by database_id.
    - Legacy events (without source_repo_database_id) are validated against GitHubRepository nodes in Neo4j.
      When a legacy event matches a repository node with a known database_id, it is coalesced into the
      immutable assumption row for (repository_database_id, destination_principal_arn) or promoted to the
      immutable MatchLink path if no immutable event exists.
    - Legacy events whose repository has no database_id in Neo4j remain on the legacy fullname MatchLink path.
    - Ensures each MatchLink schema is loaded at most once per sync, preventing relationship property overwrites.
    """
    immutable_assumptions = [
        a
        for a in aggregated_role_assumptions
        if a.get("source_repo_database_id") is not None
    ]
    legacy_assumptions = [
        a
        for a in aggregated_role_assumptions
        if a.get("source_repo_database_id") is None
    ]

    coalesced_immutable: Dict[Tuple[int, str], Dict[str, Any]] = {}
    for item in immutable_assumptions:
        db_id = int(item["source_repo_database_id"])
        role_arn = item["destination_principal_arn"]
        entry = dict(item)
        if (
            "source_owner_database_ids" not in entry
            or entry["source_owner_database_ids"] is None
        ):
            entry["source_owner_database_ids"] = []
        else:
            entry["source_owner_database_ids"] = list(
                entry["source_owner_database_ids"]
            )
        coalesced_immutable[(db_id, role_arn)] = entry

    remaining_legacy_by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}

    if legacy_assumptions:
        validated_legacy = resolve_and_validate_legacy_web_identity_role_assumptions(
            neo4j_session,
            legacy_assumptions,
        )
        for legacy_item, resolved_db_id in validated_legacy:
            role_arn = legacy_item["destination_principal_arn"]
            if resolved_db_id is not None:
                key = (resolved_db_id, role_arn)
                if key in coalesced_immutable:
                    target = coalesced_immutable[key]
                    target["times_used"] += legacy_item.get("times_used", 1)
                    target["first_seen_in_time_window"] = _earliest_timestamp(
                        target.get("first_seen_in_time_window"),
                        legacy_item.get("first_seen_in_time_window"),
                    )
                    target["last_used"] = _latest_timestamp(
                        target.get("last_used"),
                        legacy_item.get("last_used"),
                    )
                    existing_owners = set(target.get("source_owner_database_ids") or [])
                    legacy_owners = set(
                        legacy_item.get("source_owner_database_ids") or []
                    )
                    target["source_owner_database_ids"] = sorted(
                        list(existing_owners | legacy_owners)
                    )
                else:
                    promoted = dict(legacy_item)
                    promoted["source_repo_database_id"] = resolved_db_id
                    if (
                        "source_owner_database_ids" not in promoted
                        or promoted["source_owner_database_ids"] is None
                    ):
                        promoted["source_owner_database_ids"] = []
                    else:
                        promoted["source_owner_database_ids"] = sorted(
                            list(set(promoted["source_owner_database_ids"]))
                        )
                    coalesced_immutable[key] = promoted
            else:
                fullname = legacy_item["source_repo_fullname"]
                leg_key = (fullname, role_arn)
                if leg_key in remaining_legacy_by_key:
                    target_leg = remaining_legacy_by_key[leg_key]
                    target_leg["times_used"] += legacy_item.get("times_used", 1)
                    target_leg["first_seen_in_time_window"] = _earliest_timestamp(
                        target_leg.get("first_seen_in_time_window"),
                        legacy_item.get("first_seen_in_time_window"),
                    )
                    target_leg["last_used"] = _latest_timestamp(
                        target_leg.get("last_used"),
                        legacy_item.get("last_used"),
                    )
                else:
                    remaining_legacy_by_key[leg_key] = dict(legacy_item)

    final_immutable_assumptions = list(coalesced_immutable.values())
    final_legacy_assumptions = list(remaining_legacy_by_key.values())

    if final_immutable_assumptions:
        matchlink_schema = GitHubRepoImmutableAssumeRoleWithWebIdentityMatchLink()
        load_matchlinks(
            neo4j_session,
            matchlink_schema,
            final_immutable_assumptions,
            lastupdated=aws_update_tag,
            _sub_resource_label="AWSAccount",
            _sub_resource_id=current_aws_account_id,
        )

    if final_legacy_assumptions:
        legacy_matchlink_schema = GitHubRepoAssumeRoleWithWebIdentityMatchLink()
        load_matchlinks(
            neo4j_session,
            legacy_matchlink_schema,
            final_legacy_assumptions,
            lastupdated=aws_update_tag,
            _sub_resource_label="AWSAccount",
            _sub_resource_id=current_aws_account_id,
        )


def _convert_assumed_role_arn_to_role_arn(assumed_role_arn: str) -> str:
    """
    Convert an assumed role ARN to the original role ARN. The partition is kept.

    Example:
    Input:  "arn:aws:sts::123456789012:assumed-role/MyRole/session-name"
    Output: "arn:aws:iam::123456789012:role/MyRole"
    """

    # Split the ARN into parts
    arn_parts = assumed_role_arn.split(":")
    if len(arn_parts) >= 6 and arn_parts[2] == "sts" and "assumed-role" in arn_parts[5]:
        # Extract partition, account ID and role name
        partition = arn_parts[1]
        account_id = arn_parts[4]
        resource_part = arn_parts[5]  # "assumed-role/MyRole/session-name"
        role_name = resource_part.split("/")[1]  # Extract "MyRole"

        # Construct the IAM role ARN
        return f"arn:{partition}:iam::{account_id}:role/{role_name}"

    # Return original ARN if conversion fails
    return assumed_role_arn


def parse_github_oidc_subject(
    user_name: str,
) -> Optional[Tuple[str, Optional[int], Optional[int]]]:
    """
    Parse a GitHub Actions OIDC subject claim from CloudTrail userName.

    GitHub Actions OIDC subjects have two formats:
    - Legacy: "repo:{organization}/{repository}:{context}"
    - Immutable: "repo:{organization}@{organization_id}/{repository}@{repository_id}:{context}"

    Returns:
        (repo_fullname, repo_database_id, owner_database_id) where repo_database_id
        and owner_database_id are ints for immutable subjects, or None for legacy subjects.
        Returns None if user_name is malformed or invalid.
    """
    if not user_name:
        return None

    parts = user_name.split(":")
    if len(parts) < 3 or parts[0] != "repo":
        return None

    repo_path = parts[1]
    if repo_path.count("/") != 1:
        return None

    owner_segment, repo_segment = repo_path.split("/")
    if not owner_segment or not repo_segment:
        return None

    has_owner_at = "@" in owner_segment
    has_repo_at = "@" in repo_segment

    if has_owner_at != has_repo_at:
        return None

    if has_repo_at:
        owner_name, _, owner_id = owner_segment.partition("@")
        repo_name, _, repo_id = repo_segment.partition("@")

        if not owner_name or not owner_id or not owner_id.isdigit():
            return None
        if not repo_name or not repo_id or not repo_id.isdigit():
            return None

        return f"{owner_name}/{repo_name}", int(repo_id), int(owner_id)
    else:
        return f"{owner_segment}/{repo_segment}", None, None


def _extract_github_repo_from_username(user_name: str) -> str:
    """
    Extract GitHub repository fullname from CloudTrail userName field.

    Returns repository fullname "{organization}/{repository}", or empty string if malformed.
    """
    parsed = parse_github_oidc_subject(user_name)
    if not parsed:
        return ""
    return parsed[0]


@timeit
def cleanup(
    neo4j_session: neo4j.Session, current_aws_account_id: str, update_tag: int
) -> None:
    """
    Run CloudTrail management events cleanup job to remove stale ASSUMED_ROLE relationships.

    :type neo4j_session: neo4j.Session
    :param neo4j_session: The Neo4j session to use for database operations
    :type current_aws_account_id: str
    :param current_aws_account_id: The AWS account ID being synced
    :type update_tag: int
    :param update_tag: Timestamp tag for tracking data freshness
    :rtype: None
    """
    logger.info("Running CloudTrail management events cleanup job.")

    matchlink_schema = AssumedRoleMatchLink()
    cleanup_job = GraphJob.from_matchlink(
        matchlink_schema,
        "AWSAccount",
        current_aws_account_id,
        update_tag,
    )
    cleanup_job.run(neo4j_session)


@timeit
def sync_assume_role_events(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync CloudTrail management events to create ASSUMED_ROLE relationships.

    This function orchestrates the complete process:
    1. Fetch CloudTrail management events region by region
    2. Transform events into role assumption records per region
    3. Load role assumption relationships into Neo4j for each region
    4. Run cleanup after processing all regions

    The resulting graph contains direct relationships like:
    (AWSUser|AWSRole|AWSPrincipal)-[:ASSUMED_ROLE {times_used, first_seen_in_time_window, last_used, lastupdated}]->(AWSRole)

    :type neo4j_session: neo4j.Session
    :param neo4j_session: The Neo4j session
    :type boto3_session: boto3.Session
    :param boto3_session: The boto3 session to use for API calls
    :type regions: List[str]
    :param regions: List of AWS regions to sync
    :type current_aws_account_id: str
    :param current_aws_account_id: The AWS account ID being synced
    :type aws_update_tag: int
    :param aws_update_tag: Timestamp tag for tracking data freshness
    :rtype: None
    """
    # Extract lookback hours from common_job_parameters (set by CLI parameter)
    lookback_hours = common_job_parameters.get(
        "aws_cloudtrail_management_events_lookback_hours"
    )

    if not lookback_hours:
        logger.info(
            "CloudTrail management events sync skipped - no lookback period specified"
        )
        return

    logger.info(
        f"Syncing {len(regions)} regions with {lookback_hours} hour lookback period"
    )

    total_role_assumptions = 0
    cleanup_safe = True

    # Process events region by region
    for region in regions:
        logger.debug("Processing CloudTrail events for region %s", region)

        # Process AssumeRole events specifically
        logger.debug("Fetching AssumeRole events specifically for region %s", region)
        try:
            assume_role_events = get_assume_role_events(
                boto3_session=boto3_session,
                region=region,
                lookback_hours=lookback_hours,
            )
        except CloudTrailTransientRegionFailure:
            cleanup_safe = False
            logger.warning(
                "Skipping CloudTrail management events for account %s in region %s after transient failure",
                current_aws_account_id,
                region,
            )
            continue

        # Transform AssumeRole events to role assumptions
        assume_role_assumptions = transform_assume_role_events_to_role_assumptions(
            events=assume_role_events,
        )

        # Load AssumeRole assumptions for this region
        load_role_assumptions(
            neo4j_session=neo4j_session,
            aggregated_role_assumptions=assume_role_assumptions,
            current_aws_account_id=current_aws_account_id,
            aws_update_tag=update_tag,
        )
        total_role_assumptions += len(assume_role_assumptions)
        logger.debug(
            "Loaded %s AssumeRole assumptions for region %s",
            len(assume_role_assumptions),
            region,
        )

    if cleanup_safe:
        cleanup(neo4j_session, current_aws_account_id, update_tag)
    else:
        logger.warning(
            "Skipping CloudTrail management events cleanup for account %s because one or more regions had transient failures. Preserving last-known-good data.",
            current_aws_account_id,
        )

    logger.info(
        f"CloudTrail management events sync completed successfully. "
        f"Processed {total_role_assumptions} total role assumption events across {len(regions)} regions."
    )


@timeit
def sync_saml_role_events(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync CloudTrail SAML management events to create ASSUMED_ROLE_WITH_SAML relationships.

    This function orchestrates the complete process:
    1. Fetch CloudTrail SAML management events region by region
    2. Transform events into role assumption records per region
    3. Load role assumption relationships into Neo4j for each region

    The resulting graph contains direct relationships like:
    (AWSRole)-[:ASSUMED_ROLE_WITH_SAML {times_used, first_seen_in_time_window, last_used, lastupdated}]->(AWSRole)

    :type neo4j_session: neo4j.Session
    :param neo4j_session: The Neo4j session
    :type boto3_session: boto3.Session
    :param boto3_session: The boto3 session to use for API calls
    :type regions: List[str]
    :param regions: List of AWS regions to sync
    :type current_aws_account_id: str
    :param current_aws_account_id: The AWS account ID being synced
    :type update_tag: int
    :param update_tag: Timestamp tag for tracking data freshness
    :rtype: None
    """
    # Extract lookback hours from common_job_parameters (set by CLI parameter)
    lookback_hours = common_job_parameters.get(
        "aws_cloudtrail_management_events_lookback_hours"
    )

    if not lookback_hours:
        logger.info(
            "CloudTrail SAML management events sync skipped - no lookback period specified"
        )
        return

    logger.info(
        f"Syncing SAML events for {len(regions)} regions with {lookback_hours} hour lookback period"
    )

    total_saml_role_assumptions = 0

    # Process events region by region
    for region in regions:
        logger.debug("Processing CloudTrail SAML events for region %s", region)

        # Process AssumeRoleWithSAML events specifically
        logger.debug(
            "Fetching AssumeRoleWithSAML events specifically for region %s", region
        )
        try:
            saml_role_events = get_saml_role_events(
                boto3_session=boto3_session,
                region=region,
                lookback_hours=lookback_hours,
            )
        except CloudTrailTransientRegionFailure:
            logger.warning(
                "Skipping CloudTrail SAML management events for account %s in region %s after transient failure",
                current_aws_account_id,
                region,
            )
            continue

        # Transform AssumeRoleWithSAML events to role assumptions
        saml_role_assumptions = transform_saml_role_events_to_role_assumptions(
            events=saml_role_events,
        )

        # Load SAML role assumptions for this region
        load_saml_role_assumptions(
            neo4j_session=neo4j_session,
            aggregated_role_assumptions=saml_role_assumptions,
            current_aws_account_id=current_aws_account_id,
            aws_update_tag=update_tag,
        )
        total_saml_role_assumptions += len(saml_role_assumptions)
        logger.debug(
            "Loaded %s SAML role assumptions for region %s",
            len(saml_role_assumptions),
            region,
        )

    logger.info(
        f"CloudTrail SAML management events sync completed successfully. "
        f"Processed {total_saml_role_assumptions} total SAML role assumption events across {len(regions)} regions."
    )


@timeit
def sync_web_identity_role_events(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync CloudTrail WebIdentity management events to create ASSUMED_ROLE_WITH_WEB_IDENTITY relationships.

    This function orchestrates the complete process:
    1. Fetch CloudTrail WebIdentity management events region by region
    2. Transform events into role assumption records per region
    3. Load role assumption relationships into Neo4j for each region

    The resulting graph contains direct relationships like:
    (GitHubRepository)-[:ASSUMED_ROLE_WITH_WEB_IDENTITY {times_used, first_seen_in_time_window, last_used, lastupdated}]->(AWSRole)

    :type neo4j_session: neo4j.Session
    :param neo4j_session: The Neo4j session
    :type boto3_session: boto3.Session
    :param boto3_session: The boto3 session to use for API calls
    :type regions: List[str]
    :param regions: List of AWS regions to sync
    :type current_aws_account_id: str
    :param current_aws_account_id: The AWS account ID being synced
    :type update_tag: int
    :param update_tag: Timestamp tag for tracking data freshness
    :rtype: None
    """
    # Extract lookback hours from common_job_parameters (set by CLI parameter)
    lookback_hours = common_job_parameters.get(
        "aws_cloudtrail_management_events_lookback_hours"
    )

    if not lookback_hours:
        logger.info(
            "CloudTrail WebIdentity management events sync skipped - no lookback period specified"
        )
        return

    logger.info(
        f"Syncing WebIdentity events for {len(regions)} regions with {lookback_hours} hour lookback period"
    )

    total_web_identity_role_assumptions = 0

    # Process events region by region
    for region in regions:
        logger.debug("Processing CloudTrail WebIdentity events for region %s", region)

        # Process AssumeRoleWithWebIdentity events specifically
        logger.debug(
            "Fetching AssumeRoleWithWebIdentity events specifically for region %s",
            region,
        )
        try:
            web_identity_role_events = get_web_identity_role_events(
                boto3_session=boto3_session,
                region=region,
                lookback_hours=lookback_hours,
            )
        except CloudTrailTransientRegionFailure:
            logger.warning(
                "Skipping CloudTrail WebIdentity management events for account %s in region %s after transient failure",
                current_aws_account_id,
                region,
            )
            continue

        # Transform AssumeRoleWithWebIdentity events to role assumptions
        web_identity_role_assumptions = (
            transform_web_identity_role_events_to_role_assumptions(
                events=web_identity_role_events,
            )
        )

        # Load WebIdentity role assumptions for this region
        load_web_identity_role_assumptions(
            neo4j_session=neo4j_session,
            aggregated_role_assumptions=web_identity_role_assumptions,
            current_aws_account_id=current_aws_account_id,
            aws_update_tag=update_tag,
        )
        total_web_identity_role_assumptions += len(web_identity_role_assumptions)
        logger.debug(
            "Loaded %s WebIdentity role assumptions for region %s",
            len(web_identity_role_assumptions),
            region,
        )

    logger.info(
        f"CloudTrail WebIdentity management events sync completed successfully. "
        f"Processed {total_web_identity_role_assumptions} total WebIdentity role assumption events across {len(regions)} regions."
    )


# Main sync function for when we decide to add more event types
@timeit
def sync(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Main sync function for CloudTrail management events.

    Syncs AssumeRole, AssumeRoleWithSAML, and AssumeRoleWithWebIdentity events to create separate
    relationship types in the graph for security analysis.
    """
    # Sync regular AssumeRole events
    sync_assume_role_events(
        neo4j_session=neo4j_session,
        boto3_session=boto3_session,
        regions=regions,
        current_aws_account_id=current_aws_account_id,
        update_tag=update_tag,
        common_job_parameters=common_job_parameters,
    )

    # Sync SAML AssumeRoleWithSAML events
    sync_saml_role_events(
        neo4j_session=neo4j_session,
        boto3_session=boto3_session,
        regions=regions,
        current_aws_account_id=current_aws_account_id,
        update_tag=update_tag,
        common_job_parameters=common_job_parameters,
    )

    # Sync WebIdentity AssumeRoleWithWebIdentity events
    sync_web_identity_role_events(
        neo4j_session=neo4j_session,
        boto3_session=boto3_session,
        regions=regions,
        current_aws_account_id=current_aws_account_id,
        update_tag=update_tag,
        common_job_parameters=common_job_parameters,
    )
