"""
Operation-to-scope mapping for CrowdStrike API operations.

Maps FalconPy operation names to the required CrowdStrike API scopes,
enabling scope-aware error messages on 403 responses.
"""

# Maps FalconPy operation names (or logical groups) to required API scopes.
# Format: "operation_or_group" -> ["scope:permission", ...]
OPERATION_SCOPES = {
    # NGSIEM
    "start_search": ["ngsiem:read"],
    "get_search_status": ["ngsiem:read"],
    "stop_search": ["ngsiem:write"],
    # NGSIEM — read-only introspection (FR 07)
    "list_saved_queries": ["ngsiem:read"],
    "get_saved_query_template": ["ngsiem:read"],
    "list_lookup_files": ["ngsiem:read"],
    "get_lookup_file": ["ngsiem:read"],
    "list_dashboards": ["ngsiem:read"],
    "list_parsers": ["ngsiem:read"],
    "get_parser": ["ngsiem:read"],
    "list_data_connections": ["ngsiem:read"],
    "get_connection_by_id": ["ngsiem:read"],
    "get_provisioning_status": ["ngsiem:read"],
    "list_data_connectors": ["ngsiem:read"],
    "list_connector_configs": ["ngsiem:read"],
    # Alerts
    "query_alerts_v2": ["alerts:read"],
    "get_alerts_v2": ["alerts:read"],
    "update_alerts_v3": ["alerts:write"],
    # Hosts
    "query_devices_by_filter": ["hosts:read"],
    "get_device_details": ["hosts:read"],
    "query_device_login_history": ["hosts:read"],
    "query_network_address_history": ["hosts:read"],
    # Correlation Rules
    "query_rules": ["correlation-rules:read"],
    "get_rules": ["correlation-rules:read"],
    "update_rules": ["correlation-rules:write"],
    # Correlation Rules — Templates (v1.6.1)
    "queries_templates_get_v1Mixin0": ["correlation-rules:read"],
    "entities_templates_get_v1Mixin0": ["correlation-rules:read"],
    # CSPM Registration
    "get_aws_account": ["cspm-registration:read"],
    "get_azure_account": ["cspm-registration:read"],
    "get_policy_settings": ["cspm-registration:read"],
    # Case Management
    "queries_cases_get_v1": ["cases:read"],
    "entities_cases_post_v2": ["cases:read"],
    "entities_cases_put_v2": ["cases:write"],
    "entities_cases_patch_v2": ["cases:write"],
    "entities_alert_evidence_post_v1": ["cases:write"],
    "entities_event_evidence_post_v1": ["cases:write"],
    "entities_case_tags_post_v1": ["cases:write"],
    "entities_case_tags_delete_v1": ["cases:write"],
    "entities_files_upload_post_v1": ["cases:write"],
    "entities_fields_get_v1": ["cases:read"],
    "queries_fields_get_v1": ["cases:read"],
    # Case Management — Access Tags & RTR (v1.6.1)
    "queries_access_tags_get_v1": ["cases:read"],
    "entities_access_tags_get_v1": ["cases:read"],
    "aggregates_access_tags_post_v1": ["cases:read"],
    "entities_get_rtr_file_metadata_post_v1": ["cases:read"],
    "entities_retrieve_rtr_recent_file_post_v1": ["cases:read"],
    # Cloud Security
    "combined_cloud_risks": ["cloud-security:read"],
    "GetCloudRisksEnrichedTimeline": ["cloud-security:read"],
    "query_iom_entities": ["cloud-security-detections:read"],
    "get_iom_entities": ["cloud-security-detections:read"],
    "query_assets": ["cloud-security-assets:read"],
    "get_assets": ["cloud-security-assets:read"],
    "get_combined_compliance_by_account": ["cloud-security-assets:read"],
    # Spotlight Evaluation Logic
    "combinedSupportedEvaluationExt": ["spotlight-vulnerabilities:read"],
    # Spotlight Vulnerabilities
    "query_vulnerabilities": ["spotlight-vulnerabilities:read"],
    "get_vulnerabilities": ["spotlight-vulnerabilities:read"],
    "query_vulnerabilities_combined": ["spotlight-vulnerabilities:read"],
    "get_remediations_v2": ["spotlight-vulnerabilities:read"],
    # Identity Protection
    # NOTE: post_graphql is a read-only query in this module, but CrowdStrike's
    # API surface requires identity-protection-graphql:write for ALL GraphQL
    # calls even when the query is strictly read-only. Tool stays tier="read".
    "post_graphql": [
        "identity-protection-assessment:read",
        "identity-protection-detections:read",
        "identity-protection-entities:read",
        "identity-protection-timeline:read",
        "identity-protection-graphql:write",
    ],
    # CAO Hunting
    "search_queries": ["cao-hunting:read"],
    "get_queries": ["cao-hunting:read"],
    "aggregate_queries": ["cao-hunting:read"],
    "search_guides": ["cao-hunting:read"],
    "get_guides": ["cao-hunting:read"],
    "aggregate_guides": ["cao-hunting:read"],
    "create_export_archive": ["cao-hunting:read"],
    # Real-Time Response (read-only subset — FR03)
    "RTR_InitSession": ["real-time-response:write"],
    "RTR_ListSessions": ["real-time-response:read"],
    "RTR_PulseSession": ["real-time-response:write"],
    "RTR_ExecuteActiveResponderCommand": ["real-time-response:write"],
    "RTR_CheckActiveResponderCommandStatus": ["real-time-response:read"],
    "RTR_GetExtractedFileContents": ["real-time-response:read"],
    "RTR_ListFilesV2": ["real-time-response:read"],
    # Threat Graph
    "entities_vertices_getv2": ["threatgraph:read"],
    "combined_edges_get": ["threatgraph:read"],
    "combined_ran_on_get": ["threatgraph:read"],
    "combined_summary_get": ["threatgraph:read"],
    "queries_edgetypes_get": ["threatgraph:read"],
}


def get_required_scopes(operation: str) -> list[str]:
    """Return the required API scopes for a given operation.

    Args:
        operation: FalconPy operation name or logical group name.

    Returns:
        List of required scope strings, or empty list if unknown.
    """
    return OPERATION_SCOPES.get(operation, [])
