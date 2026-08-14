"""The Jira connector (#144).

Issues, comments, attachments and — when an operator opts in — issue history, from
Jira Cloud. The Data Center seams are named where they exist (bearer PATs, wiki
markup, a configurable API prefix), but only Cloud is certified; see
``docs/connectors.md``.
"""

from iceberg_connectors.jira.client import JiraClient
from iceberg_connectors.jira.connector import JIRA_CONNECTOR_TYPE, JiraConnector
from iceberg_connectors.jira.document import adf_to_text, issue_field_text, wiki_to_text

__all__ = [
    "JIRA_CONNECTOR_TYPE",
    "JiraClient",
    "JiraConnector",
    "adf_to_text",
    "issue_field_text",
    "wiki_to_text",
]
