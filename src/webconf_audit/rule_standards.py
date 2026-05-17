"""Rule-specific standards mappings migrated from documentation blocks."""

from __future__ import annotations

from functools import lru_cache
import logging
from pathlib import Path
import re

from webconf_audit.rule_registry import StandardCoverage, StandardReference
from webconf_audit.standards import (
    asvs_5,
    cwe,
    fstec_bdu,
    fstec_mera,
    iso_27002_2022,
    mitre_attack,
    nist_csf_2,
    nist_sp,
    owasp_api_top10_2023,
    owasp_top10_2021,
    pci_dss_4,
)

_LOGGER = logging.getLogger(__name__)

_RULE_ID_PATTERN = re.compile(
    r"`((?:universal|nginx|apache|lighttpd|iis|external)\.[A-Za-z0-9_.]+)`"
)
_SOURCE_RULE_ID_PATTERN = re.compile(
    r"""^\s*RULE_ID\s*=\s*(?P<const_quote>["'])(?P<const_rule_id>(?:universal|nginx|apache|lighttpd|iis|external)\.[A-Za-z0-9_.]+)(?P=const_quote)"""
    r"""|rule_id\s*=\s*(?P<inline_quote>["'])(?P<inline_rule_id>(?:universal|nginx|apache|lighttpd|iis|external)\.[A-Za-z0-9_.]+)(?P=inline_quote)""",
    re.MULTILINE,
)

# Snapshot of the 2026-05 standards migration catch-all mappings. Keeping this
# explicit prevents future rules from silently inheriting legacy broad tags.
_LEGACY_CATCH_ALL_RULES = frozenset(
    {
        "apache.allowoverride_all_in_directory",
        "apache.allowoverride_not_none",
        "apache.backup_temp_files_not_restricted",
        "apache.basic_auth_over_http",
        "apache.content_security_policy_missing_frame_ancestors",
        "apache.content_security_policy_missing_reporting_endpoint",
        "apache.custom_log_missing",
        "apache.default_content_probe",
        "apache.default_tls_vhost_not_rejecting_unknown_hosts",
        "apache.default_vhost_not_rejecting_unknown_hosts",
        "apache.directory_without_allowoverride",
        "apache.error_document_404_missing",
        "apache.error_document_500_missing",
        "apache.error_log_missing",
        "apache.error_log_unsafe_destination",
        "apache.file_etag_inodes",
        "apache.generated_artifacts_not_restricted",
        "apache.hsts_header_unsafe",
        "apache.ht_files_not_restricted",
        "apache.htaccess_auth_without_require",
        "apache.htaccess_contains_security_directive",
        "apache.htaccess_disables_security_headers",
        "apache.htaccess_enables_cgi",
        "apache.htaccess_enables_directory_listing",
        "apache.htaccess_rewrite_without_limit",
        "apache.htaccess_weakens_security",
        "apache.http_method_policy_allows_unapproved",
        "apache.http_protocol_options_unsafe",
        "apache.index_options_fancyindexing_enabled",
        "apache.index_options_scanhtmltitles_enabled",
        "apache.ip_based_requests_allowed",
        "apache.keepalive_disabled",
        "apache.keepalive_timeout_too_high",
        "apache.limit_request_body_missing_or_invalid",
        "apache.limit_request_field_size_too_high",
        "apache.limit_request_fields_missing_or_invalid",
        "apache.limit_request_line_too_high",
        "apache.listen_requires_explicit_address",
        "apache.log_format_missing_fields",
        "apache.log_level_too_restrictive",
        "apache.max_keepalive_requests_too_low",
        "apache.missing_hsts_header",
        "apache.missing_http_method_restrictions",
        "apache.missing_http_to_https_redirect",
        "apache.missing_log_format",
        "apache.missing_permissions_policy_header",
        "apache.missing_referrer_policy_header",
        "apache.missing_x_frame_options_header",
        "apache.modsecurity_crs_not_configured",
        "apache.modsecurity_module_missing",
        "apache.options_execcgi_enabled",
        "apache.options_includes_enabled",
        "apache.options_indexes",
        "apache.options_multiviews_enabled",
        "apache.options_not_none_in_root_directory",
        "apache.permissions_policy_runtime_quality",
        "apache.permissions_policy_unsafe",
        "apache.referrer_policy_unsafe",
        "apache.request_read_timeout_semantics",
        "apache.sensitive_config_files_not_restricted",
        "apache.sensitive_path_environment_policy",
        "apache.server_info_exposed",
        "apache.server_signature_not_off",
        "apache.server_status_exposed",
        "apache.server_tokens_not_prod",
        "apache.sitewide_http_method_policy_missing",
        "apache.ssl_cipher_suite_missing",
        "apache.ssl_cipher_suite_weak",
        "apache.ssl_compression_enabled",
        "apache.ssl_honor_cipher_order_not_on",
        "apache.ssl_insecure_renegotiation_enabled",
        "apache.ssl_protocol_missing_or_weak",
        "apache.ssl_proxy_peer_name_check_disabled",
        "apache.ssl_proxy_verify_not_required",
        "apache.ssl_session_cache_missing",
        "apache.ssl_session_cache_timeout_missing_or_invalid",
        "apache.ssl_stapling_cache_missing",
        "apache.ssl_use_stapling_not_on",
        "apache.timeout_keepalive_default_policy",
        "apache.timeout_too_high",
        "apache.tls_legacy_versions_explicitly_enabled",
        "apache.trace_enable_not_off",
        "apache.vcs_metadata_not_restricted",
        "apache.x_frame_options_unsafe",
        "external.allow_header_dangerous_methods",
        "external.apache.default_welcome_page",
        "external.apache.etag_inode_disclosure",
        "external.apache.mod_status_public",
        "external.apache.version_disclosed_in_server_header",
        "external.backup_archive_exposed",
        "external.backup_file_exposed",
        "external.cert_chain_incomplete",
        "external.cert_chain_length_unusual",
        "external.cert_san_mismatch",
        "external.certificate_expired",
        "external.certificate_expires_soon",
        "external.tls_ct_log_evidence_missing",
        "external.tls_weak_signature_algorithm",
        "external.tls_must_staple_not_observed",
        "external.coep_missing",
        "external.content_security_policy_base_uri_not_restricted",
        "external.content_security_policy_missing",
        "external.content_security_policy_missing_frame_ancestors",
        "external.content_security_policy_missing_reporting_endpoint",
        "external.content_security_policy_nonce_reused",
        "external.content_security_policy_object_src_not_none",
        "external.content_security_policy_unsafe_eval",
        "external.content_security_policy_unsafe_inline",
        "external.script_src_missing_sri",
        "external.cookie_missing_httponly",
        "external.cookie_missing_samesite",
        "external.cookie_missing_secure_on_https",
        "external.cookie_prefix_contract_violated",
        "external.cookie_samesite_none_without_secure",
        "external.coop_missing",
        "external.corp_missing",
        "external.cors_wildcard_origin",
        "external.cors_wildcard_with_credentials",
        "external.dangerous_http_methods_enabled",
        "external.database_dump_exposed",
        "external.dependency_manifest_exposed",
        "external.elmah_axd_exposed",
        "external.env_file_exposed",
        "external.git_metadata_exposed",
        "external.hsts_header_invalid",
        "external.hsts_header_missing",
        "external.hsts_max_age_too_short",
        "external.hsts_missing_include_subdomains",
        "external.htaccess_exposed",
        "external.htpasswd_exposed",
        "external.http_not_redirected_to_https",
        "external.http_redirect_not_permanent",
        "external.https_not_available",
        "external.iis.aspnet_version_header_present",
        "external.iis.default_welcome_page",
        "external.iis.detailed_error_page",
        "external.iis.server_header_removal_not_applied",
        "external.lighttpd.default_welcome_page",
        "external.lighttpd.mod_status_public",
        "external.lighttpd.version_in_server_header",
        "external.nginx.default_index_page_body",
        "external.nginx.default_welcome_page",
        "external.nginx.redirect_target_unexpected",
        "external.nginx.version_disclosed_in_server_header",
        "external.nginx_status_exposed",
        "external.npmrc_exposed",
        "external.ocsp_stapling_not_observed",
        "external.options_method_exposed",
        "external.permissions_policy_missing",
        "external.phpinfo_exposed",
        "external.referrer_policy_missing",
        "external.referrer_policy_unsafe",
        "external.robots_txt_exposed",
        "external.server_info_exposed",
        "external.server_status_exposed",
        "external.server_version_disclosed",
        "external.sitemap_xml_exposed",
        "external.svn_metadata_exposed",
        "external.tls_1_0_supported",
        "external.tls_1_1_supported",
        "external.tls_1_3_not_supported",
        "external.tls_aead_cipher_not_negotiated",
        "external.tls_certificate_self_signed",
        "external.tls_forward_secrecy_not_observed",
        "external.tls_negotiated_compression",
        "external.tls_secure_renegotiation_not_observed",
        "external.tls_server_cipher_preference_not_observed",
        "external.trace_axd_exposed",
        "external.trace_method_allowed",
        "external.trace_method_exposed_via_options",
        "external.weak_cipher_suite",
        "external.web_config_exposed",
        "external.webdav_methods_exposed",
        "external.wordpress_admin_panel_exposed",
        "external.x_aspnet_version_header_present",
        "external.x_content_type_options_invalid",
        "external.x_content_type_options_missing",
        "external.x_frame_options_invalid",
        "external.x_frame_options_missing",
        "external.x_powered_by_header_present",
        "iis.anonymous_auth_enabled",
        "iis.anonymous_auth_uses_specific_user",
        "iis.application_pool_identity_not_application_pool_identity",
        "iis.asp_script_error_sent_to_browser",
        "iis.authorization_allows_anonymous_users",
        "iis.authorization_policy_missing",
        "iis.basic_auth_without_ssl",
        "iis.binding_without_host_header",
        "iis.cgi_handler_enabled",
        "iis.compilation_debug_enabled",
        "iis.content_security_policy_missing_frame_ancestors",
        "iis.content_security_policy_missing_reporting_endpoint",
        "iis.credentials_password_format_clear",
        "iis.credentials_stored_in_config",
        "iis.custom_errors_off",
        "iis.custom_headers_expose_server",
        "iis.deployment_retail_not_enabled",
        "iis.directory_browse_enabled",
        "iis.file_extensions_allow_unlisted",
        "iis.forms_auth_protection_unsafe",
        "iis.forms_auth_require_ssl_missing",
        "iis.handler_write_script_execute_enabled",
        "iis.hsts_header_unsafe",
        "iis.http_cookies_http_only_disabled",
        "iis.http_cookies_require_ssl_missing",
        "iis.http_errors_detailed",
        "iis.http_runtime_version_header_enabled",
        "iis.isapi_cgi_restrictions_allow_unlisted",
        "iis.logging_not_configured",
        "iis.machine_key_legacy_validation_weak",
        "iis.machine_key_validation_weak",
        "iis.max_allowed_content_length_missing",
        "iis.missing_hsts_header",
        "iis.request_filtering_allow_double_escaping",
        "iis.request_filtering_allow_high_bit",
        "iis.request_filtering_max_query_string_missing",
        "iis.request_filtering_max_query_string_too_high",
        "iis.request_filtering_max_url_missing",
        "iis.request_filtering_max_url_too_high",
        "iis.request_filtering_remove_server_header_disabled",
        "iis.schannel_aes128_enabled",
        "iis.schannel_aes256_not_enabled",
        "iis.schannel_cipher_suite_order_not_preferred",
        "iis.schannel_tls12_not_enabled",
        "iis.schannel_weak_protocol_enabled",
        "iis.session_state_cookieless",
        "iis.sites_share_application_pool",
        "iis.ssl_not_required",
        "iis.ssl_weak_cipher_strength",
        "iis.trace_enabled",
        "iis.trust_level_full",
        "iis.webdav_module_enabled",
        "lighttpd.access_log_format_missing_fields",
        "lighttpd.access_log_missing",
        "lighttpd.auth_backend_missing",
        "lighttpd.auth_backend_userfile_missing",
        "lighttpd.backup_temp_files_access_not_denied",
        "lighttpd.basic_auth_over_http",
        "lighttpd.config_data_files_access_not_denied",
        "lighttpd.content_security_policy_missing_frame_ancestors",
        "lighttpd.content_security_policy_missing_reporting_endpoint",
        "lighttpd.content_security_policy_unsafe",
        "lighttpd.dir_listing_enabled",
        "lighttpd.error_log_missing",
        "lighttpd.generated_artifacts_access_not_denied",
        "lighttpd.max_connections_missing",
        "lighttpd.max_keep_alive_idle_too_high",
        "lighttpd.max_keep_alive_requests_unlimited",
        "lighttpd.max_read_idle_too_high",
        "lighttpd.max_request_field_size_too_large",
        "lighttpd.max_request_size_missing",
        "lighttpd.max_request_size_too_large",
        "lighttpd.max_request_size_unlimited",
        "lighttpd.max_write_idle_too_high",
        "lighttpd.missing_content_security_policy",
        "lighttpd.missing_http_method_restrictions",
        "lighttpd.missing_http_to_https_redirect",
        "lighttpd.missing_permissions_policy",
        "lighttpd.missing_referrer_policy",
        "lighttpd.missing_strict_transport_security",
        "lighttpd.missing_x_content_type_options",
        "lighttpd.missing_x_frame_options",
        "lighttpd.mod_cgi_enabled",
        "lighttpd.mod_status_public",
        "lighttpd.mod_webdav_enabled",
        "lighttpd.permissions_policy_unsafe",
        "lighttpd.referrer_policy_unsafe",
        "lighttpd.server_tag_not_blank",
        "lighttpd.ssl_compression_enabled",
        "lighttpd.ssl_engine_not_enabled",
        "lighttpd.ssl_honor_cipher_order_missing",
        "lighttpd.ssl_insecure_renegotiation_enabled",
        "lighttpd.ssl_pemfile_missing",
        "lighttpd.ssl_protocol_policy_missing_or_weak",
        "lighttpd.strict_transport_security_unsafe",
        "lighttpd.tls_legacy_versions_explicitly_enabled",
        "lighttpd.url_access_deny_missing",
        "lighttpd.vcs_metadata_access_not_denied",
        "lighttpd.weak_ssl_cipher_list",
        "lighttpd.webdav_write_access_enabled",
        "lighttpd.x_frame_options_unsafe",
        "nginx.alias_without_trailing_slash",
        "nginx.allow_all_with_deny_all",
        "nginx.auth_basic_over_http",
        "nginx.autoindex_on",
        "nginx.client_body_timeout_too_high",
        "nginx.client_header_buffer_size_too_large",
        "nginx.client_header_timeout_too_high",
        "nginx.client_max_body_size_too_large",
        "nginx.client_max_body_size_unlimited",
        "nginx.content_security_policy_missing_frame_ancestors",
        "nginx.content_security_policy_missing_reporting_endpoint",
        "nginx.content_security_policy_unsafe",
        "nginx.default_server_not_rejecting_unknown_hosts",
        "nginx.default_tls_server_not_rejecting_unknown_hosts",
        "nginx.duplicate_listen",
        "nginx.error_log_too_restrictive",
        "nginx.executable_scripts_allowed_in_uploads",
        "nginx.hsts_header_unsafe",
        "nginx.http_method_policy_allows_unapproved",
        "nginx.if_in_location",
        "nginx.keepalive_timeout_too_high",
        "nginx.large_client_header_buffers_too_large",
        "nginx.large_client_header_buffers_too_restrictive",
        "nginx.limit_conn_invalid_limit",
        "nginx.limit_conn_zone_not_per_ip",
        "nginx.limit_req_unknown_zone",
        "nginx.limit_req_zone_invalid_rate",
        "nginx.limit_req_zone_not_per_ip",
        "nginx.log_format_missing_fields",
        "nginx.merge_slashes_off",
        "nginx.missing_access_log",
        "nginx.missing_access_restrictions_on_sensitive_locations",
        "nginx.missing_allowed_methods_restriction_for_uploads",
        "nginx.missing_auth_basic_user_file",
        "nginx.missing_backup_file_deny",
        "nginx.missing_client_body_timeout",
        "nginx.missing_client_header_timeout",
        "nginx.missing_client_max_body_size",
        "nginx.missing_content_security_policy",
        "nginx.missing_error_log",
        "nginx.missing_generated_artifact_deny",
        "nginx.missing_hidden_files_deny",
        "nginx.missing_hsts_header",
        "nginx.missing_http2_on_tls_listener",
        "nginx.missing_http_method_restrictions",
        "nginx.missing_http_to_https_redirect",
        "nginx.missing_keepalive_timeout",
        "nginx.missing_limit_conn",
        "nginx.missing_limit_conn_zone",
        "nginx.missing_limit_req",
        "nginx.missing_limit_req_zone",
        "nginx.missing_log_format",
        "nginx.missing_permissions_policy",
        "nginx.missing_referrer_policy",
        "nginx.missing_send_timeout",
        "nginx.missing_server_name",
        "nginx.missing_ssl_certificate",
        "nginx.missing_ssl_certificate_key",
        "nginx.missing_ssl_ciphers",
        "nginx.missing_ssl_prefer_server_ciphers",
        "nginx.missing_ssl_protocols",
        "nginx.missing_x_content_type_options",
        "nginx.missing_x_frame_options",
        "nginx.missing_x_xss_protection",
        "nginx.permissions_policy_unsafe",
        "nginx.proxy_missing_source_ip_headers",
        "nginx.public_autoindex_rate_limit_policy_weak",
        "nginx.referrer_policy_unsafe",
        "nginx.send_timeout_too_high",
        "nginx.sensitive_config_files_not_restricted",
        "nginx.sensitive_location_missing_ip_filter",
        "nginx.server_tokens_on",
        "nginx.sitewide_http_method_policy_missing",
        "nginx.ssl_ciphers_weak",
        "nginx.ssl_conf_command_tls_compression_enabled",
        "nginx.ssl_conf_command_unsafe_renegotiation_enabled",
        "nginx.ssl_session_cache_missing",
        "nginx.ssl_session_tickets_disabled",
        "nginx.ssl_session_timeout_missing_or_invalid",
        "nginx.ssl_stapling_disabled",
        "nginx.ssl_stapling_missing_resolver",
        "nginx.ssl_stapling_without_verify",
        "nginx.weak_ssl_protocols",
        "universal.directory_listing_enabled",
        "universal.listen_on_all_interfaces",
        "universal.missing_content_security_policy",
        "universal.missing_hsts",
        "universal.missing_referrer_policy",
        "universal.missing_x_content_type_options",
        "universal.missing_x_frame_options",
        "universal.permissions_policy_unsafe",
        "universal.referrer_policy_unsafe",
        "universal.server_identification_disclosed",
        "universal.tls_intent_without_config",
        "universal.weak_tls_ciphers",
        "universal.weak_tls_protocol",
    }
)

_HSTS_RULES = {
    "universal.missing_hsts",
    "nginx.missing_hsts_header",
    "nginx.hsts_header_unsafe",
    "apache.missing_hsts_header",
    "apache.hsts_header_unsafe",
    "lighttpd.missing_strict_transport_security",
    "lighttpd.strict_transport_security_unsafe",
    "iis.missing_hsts_header",
    "iis.hsts_header_unsafe",
    "external.hsts_header_missing",
    "external.hsts_header_invalid",
    "external.hsts_max_age_too_short",
    "external.hsts_missing_include_subdomains",
}

_TLS_PROTOCOL_RULES = {
    "universal.weak_tls_protocol",
    "nginx.weak_ssl_protocols",
    "nginx.missing_ssl_protocols",
    "apache.tls_legacy_versions_explicitly_enabled",
    "apache.ssl_protocol_missing_or_weak",
    "lighttpd.tls_legacy_versions_explicitly_enabled",
    "lighttpd.ssl_protocol_policy_missing_or_weak",
    "iis.schannel_tls12_not_enabled",
    "iis.schannel_weak_protocol_enabled",
    "external.tls_1_0_supported",
    "external.tls_1_1_supported",
    "external.tls_1_3_not_supported",
}

_TLS_CIPHER_RULES = {
    "universal.weak_tls_ciphers",
    "nginx.missing_ssl_ciphers",
    "nginx.ssl_ciphers_weak",
    "apache.ssl_cipher_suite_missing",
    "apache.ssl_cipher_suite_weak",
    "lighttpd.weak_ssl_cipher_list",
    "iis.schannel_aes128_enabled",
    "iis.schannel_aes256_not_enabled",
    "iis.ssl_weak_cipher_strength",
    "external.weak_cipher_suite",
    "external.tls_forward_secrecy_not_observed",
    "external.tls_aead_cipher_not_negotiated",
}

_TLS_SERVER_PREFERENCE_RULES = {
    "nginx.missing_ssl_prefer_server_ciphers",
    "apache.ssl_honor_cipher_order_not_on",
    "lighttpd.ssl_honor_cipher_order_missing",
    "iis.schannel_cipher_suite_order_not_preferred",
    "external.tls_server_cipher_preference_not_observed",
}

_TLS_CERTIFICATE_RULES = {
    "external.certificate_expired",
    "external.certificate_expires_soon",
    "external.tls_certificate_self_signed",
    "external.cert_chain_incomplete",
    "external.cert_san_mismatch",
    "external.cert_chain_length_unusual",
    "external.tls_ct_log_evidence_missing",
    "external.tls_weak_signature_algorithm",
}

_TLS_RENEGOTIATION_RULES = {
    "apache.ssl_insecure_renegotiation_enabled",
    "nginx.ssl_conf_command_unsafe_renegotiation_enabled",
    "lighttpd.ssl_insecure_renegotiation_enabled",
    "external.tls_secure_renegotiation_not_observed",
}

_TLS_COMPRESSION_RULES = {
    "apache.ssl_compression_enabled",
    "nginx.ssl_conf_command_tls_compression_enabled",
    "lighttpd.ssl_compression_enabled",
    "external.tls_negotiated_compression",
}

_TLS_STAPLING_RULES = {
    "nginx.ssl_stapling_disabled",
    "nginx.ssl_stapling_missing_resolver",
    "nginx.ssl_stapling_without_verify",
    "apache.ssl_use_stapling_not_on",
    "apache.ssl_stapling_cache_missing",
    "external.ocsp_stapling_not_observed",
    "external.tls_must_staple_not_observed",
}

_TLS_NO_PLAINTEXT_RULES = {
    "universal.tls_intent_without_config",
    "nginx.missing_ssl_certificate",
    "nginx.missing_ssl_certificate_key",
    "nginx.missing_http_to_https_redirect",
    "nginx.auth_basic_over_http",
    "apache.missing_http_to_https_redirect",
    "apache.basic_auth_over_http",
    "lighttpd.ssl_engine_not_enabled",
    "lighttpd.ssl_pemfile_missing",
    "lighttpd.basic_auth_over_http",
    "iis.ssl_not_required",
    "iis.basic_auth_without_ssl",
    "iis.forms_auth_require_ssl_missing",
    "external.https_not_available",
    "external.nginx.redirect_target_unexpected",
    "external.http_not_redirected_to_https",
}

_TLS_421_RULES = (
    _TLS_PROTOCOL_RULES
    | _TLS_CIPHER_RULES
    | _TLS_SERVER_PREFERENCE_RULES
    | _TLS_RENEGOTIATION_RULES
    | _TLS_COMPRESSION_RULES
    | _TLS_STAPLING_RULES
    | _TLS_NO_PLAINTEXT_RULES
    | _HSTS_RULES
    | {
        "nginx.missing_http2_on_tls_listener",
        "iis.ssl_weak_cipher_strength",
    }
)

_AUTH_ADMIN_RULES = {
    "nginx.missing_auth_basic_user_file",
    "nginx.auth_basic_over_http",
    "apache.basic_auth_over_http",
    "lighttpd.basic_auth_over_http",
    "iis.basic_auth_without_ssl",
    "iis.anonymous_auth_enabled",
    "iis.anonymous_auth_uses_specific_user",
    "iis.authorization_allows_anonymous_users",
    "iis.forms_auth_require_ssl_missing",
    "external.htpasswd_exposed",
}

_AUTH_TRANSPORT_RULES = {
    "nginx.auth_basic_over_http",
    "apache.basic_auth_over_http",
    "lighttpd.basic_auth_over_http",
    "iis.forms_auth_require_ssl_missing",
    "iis.basic_auth_without_ssl",
    "iis.forms_auth_protection_unsafe",
    "external.cookie_missing_secure_on_https",
    "external.cookie_samesite_none_without_secure",
}

_AUTH_AT_REST_RULES = {
    "iis.credentials_password_format_clear",
    "iis.credentials_stored_in_config",
    "iis.machine_key_validation_weak",
    "iis.machine_key_legacy_validation_weak",
    "external.htpasswd_exposed",
}

_LOG_ENABLE_RULES = {
    "nginx.missing_access_log",
    "nginx.missing_error_log",
    "nginx.error_log_too_restrictive",
    "apache.custom_log_missing",
    "apache.error_log_missing",
    "apache.error_log_unsafe_destination",
    "apache.log_level_too_restrictive",
    "lighttpd.access_log_missing",
    "lighttpd.error_log_missing",
    "iis.logging_not_configured",
}

_LOG_FIELD_RULES = {
    "nginx.missing_log_format",
    "nginx.log_format_missing_fields",
    "nginx.proxy_missing_source_ip_headers",
    "apache.missing_log_format",
    "apache.log_format_missing_fields",
    "lighttpd.access_log_format_missing_fields",
}

_ACCESS_CONTROL_RULES = {
    "nginx.allow_all_with_deny_all",
    "nginx.missing_access_restrictions_on_sensitive_locations",
    "nginx.sensitive_location_missing_ip_filter",
    "nginx.alias_without_trailing_slash",
    "apache.missing_http_method_restrictions",
    "apache.http_method_policy_allows_unapproved",
    "lighttpd.url_access_deny_missing",
    "iis.authorization_allows_anonymous_users",
    "iis.anonymous_auth_enabled",
    "external.wordpress_admin_panel_exposed",
}

_PRIVILEGED_UTILITY_RULES = {
    "apache.options_execcgi_enabled",
    "apache.options_includes_enabled",
    "apache.options_multiviews_enabled",
    "lighttpd.mod_cgi_enabled",
    "iis.webdav_module_enabled",
    "iis.cgi_handler_enabled",
    "iis.handler_write_script_execute_enabled",
}

_NETWORK_SECURITY_RULES = {
    "universal.listen_on_all_interfaces",
    "nginx.default_server_not_rejecting_unknown_hosts",
    "nginx.default_tls_server_not_rejecting_unknown_hosts",
    "apache.listen_requires_explicit_address",
    "apache.ip_based_requests_allowed",
    "apache.default_vhost_not_rejecting_unknown_hosts",
    "apache.default_tls_vhost_not_rejecting_unknown_hosts",
    "iis.binding_without_host_header",
}

_RESPONSE_HEADER_RULES = {
    "universal.missing_hsts",
    "universal.missing_x_content_type_options",
    "universal.missing_x_frame_options",
    "universal.missing_content_security_policy",
    "universal.missing_referrer_policy",
    "nginx.missing_hsts_header",
    "nginx.missing_x_content_type_options",
    "nginx.missing_x_frame_options",
    "nginx.missing_content_security_policy",
    "nginx.content_security_policy_missing_frame_ancestors",
    "nginx.content_security_policy_unsafe",
    "nginx.referrer_policy_unsafe",
    "apache.missing_hsts_header",
    "apache.missing_x_frame_options_header",
    "apache.x_frame_options_unsafe",
    "apache.content_security_policy_missing_frame_ancestors",
    "apache.htaccess_disables_security_headers",
    "apache.hsts_header_unsafe",
    "lighttpd.missing_strict_transport_security",
    "lighttpd.strict_transport_security_unsafe",
    "lighttpd.missing_x_content_type_options",
    "lighttpd.missing_x_frame_options",
    "lighttpd.x_frame_options_unsafe",
    "lighttpd.missing_content_security_policy",
    "lighttpd.content_security_policy_missing_frame_ancestors",
    "lighttpd.content_security_policy_unsafe",
    "lighttpd.missing_referrer_policy",
    "lighttpd.referrer_policy_unsafe",
    "lighttpd.missing_permissions_policy",
    "lighttpd.permissions_policy_unsafe",
    "iis.missing_hsts_header",
    "iis.content_security_policy_missing_frame_ancestors",
    "iis.custom_headers_expose_server",
    "iis.request_filtering_remove_server_header_disabled",
    "external.iis.server_header_removal_not_applied",
    "external.hsts_header_missing",
    "external.hsts_header_invalid",
    "external.hsts_max_age_too_short",
    "external.hsts_missing_include_subdomains",
    "external.x_frame_options_missing",
    "external.x_frame_options_invalid",
    "external.x_content_type_options_missing",
    "external.x_content_type_options_invalid",
    "external.content_security_policy_missing",
    "external.content_security_policy_unsafe_inline",
    "external.content_security_policy_unsafe_eval",
    "external.content_security_policy_missing_frame_ancestors",
    "external.content_security_policy_object_src_not_none",
    "external.content_security_policy_base_uri_not_restricted",
    "external.content_security_policy_missing_reporting_endpoint",
    "external.content_security_policy_nonce_reused",
    "external.coep_missing",
    "external.coop_missing",
    "external.corp_missing",
    "external.permissions_policy_missing",
    "external.referrer_policy_missing",
    "external.referrer_policy_unsafe",
}

_CSP_RULES = {
    "universal.missing_content_security_policy",
    "nginx.missing_content_security_policy",
    "nginx.content_security_policy_unsafe",
    "nginx.content_security_policy_missing_frame_ancestors",
    "apache.content_security_policy_missing_frame_ancestors",
    "apache.htaccess_disables_security_headers",
    "lighttpd.missing_content_security_policy",
    "lighttpd.content_security_policy_missing_frame_ancestors",
    "lighttpd.content_security_policy_unsafe",
    "iis.content_security_policy_missing_frame_ancestors",
    "external.content_security_policy_missing",
    "external.content_security_policy_unsafe_inline",
    "external.content_security_policy_unsafe_eval",
    "external.content_security_policy_missing_frame_ancestors",
    "external.content_security_policy_object_src_not_none",
    "external.content_security_policy_base_uri_not_restricted",
    "external.content_security_policy_nonce_reused",
    "external.script_src_missing_sri",
}

_CLICKJACKING_RULES = {
    "universal.missing_x_frame_options",
    "nginx.missing_x_frame_options",
    "nginx.content_security_policy_missing_frame_ancestors",
    "apache.missing_x_frame_options_header",
    "apache.x_frame_options_unsafe",
    "apache.content_security_policy_missing_frame_ancestors",
    "lighttpd.missing_x_frame_options",
    "lighttpd.x_frame_options_unsafe",
    "lighttpd.content_security_policy_missing_frame_ancestors",
    "iis.content_security_policy_missing_frame_ancestors",
    "external.x_frame_options_missing",
    "external.x_frame_options_invalid",
    "external.content_security_policy_missing_frame_ancestors",
}

_COOKIE_SESSION_RULES = {
    "external.cookie_missing_secure_on_https",
    "external.cookie_missing_httponly",
    "external.cookie_missing_samesite",
    "external.cookie_samesite_none_without_secure",
    "external.cookie_prefix_contract_violated",
}

_SESSION_RULES = _COOKIE_SESSION_RULES | {
    "iis.session_state_cookieless",
    "iis.forms_auth_require_ssl_missing",
    "iis.forms_auth_protection_unsafe",
    "iis.http_cookies_http_only_disabled",
}

_SERVER_DISCLOSURE_RULES = {
    "nginx.server_tokens_on",
    "apache.server_tokens_not_prod",
    "apache.server_signature_not_off",
    "lighttpd.server_tag_not_blank",
    "iis.custom_headers_expose_server",
    "iis.request_filtering_remove_server_header_disabled",
    "iis.http_runtime_version_header_enabled",
    "external.server_version_disclosed",
    "external.x_powered_by_header_present",
    "external.x_aspnet_version_header_present",
    "external.iis.aspnet_version_header_present",
    "external.iis.server_header_removal_not_applied",
    "external.nginx.version_disclosed_in_server_header",
    "external.apache.version_disclosed_in_server_header",
    "external.lighttpd.version_in_server_header",
    "external.apache.etag_inode_disclosure",
}

_WEB_SERVICE_SECURITY_RULES = {
    "nginx.missing_http_method_restrictions",
    "nginx.missing_allowed_methods_restriction_for_uploads",
    "nginx.http_method_policy_allows_unapproved",
    "nginx.sitewide_http_method_policy_missing",
    "nginx.missing_client_max_body_size",
    "nginx.client_max_body_size_unlimited",
    "nginx.executable_scripts_allowed_in_uploads",
    "apache.missing_http_method_restrictions",
    "apache.http_method_policy_allows_unapproved",
    "apache.sitewide_http_method_policy_missing",
    "apache.trace_enable_not_off",
    "apache.limit_request_body_missing_or_invalid",
    "apache.limit_request_field_size_too_high",
    "apache.limit_request_fields_missing_or_invalid",
    "apache.limit_request_line_too_high",
    "iis.request_filtering_allow_double_escaping",
    "iis.request_filtering_allow_high_bit",
    "iis.request_filtering_max_url_too_high",
    "iis.request_filtering_max_query_string_too_high",
    "iis.max_allowed_content_length_missing",
    "iis.webdav_module_enabled",
    "iis.cgi_handler_enabled",
    "iis.handler_write_script_execute_enabled",
    "iis.file_extensions_allow_unlisted",
    "iis.isapi_cgi_restrictions_allow_unlisted",
    "external.trace_method_allowed",
    "external.trace_method_exposed_via_options",
    "external.dangerous_http_methods_enabled",
    "external.webdav_methods_exposed",
    "external.allow_header_dangerous_methods",
}

_FILE_UPLOAD_RULES = {
    "nginx.executable_scripts_allowed_in_uploads",
    "nginx.missing_allowed_methods_restriction_for_uploads",
    "iis.handler_write_script_execute_enabled",
    "iis.cgi_handler_enabled",
    "iis.isapi_cgi_restrictions_allow_unlisted",
}

_ERROR_HANDLING_RULES = {
    "apache.error_document_404_missing",
    "apache.error_document_500_missing",
    "iis.http_errors_detailed",
    "iis.custom_errors_off",
    "iis.asp_script_error_sent_to_browser",
    "iis.compilation_debug_enabled",
    "iis.trace_enabled",
    "iis.deployment_retail_not_enabled",
    "external.iis.detailed_error_page",
    "external.elmah_axd_exposed",
    "external.trace_axd_exposed",
    "external.phpinfo_exposed",
}

_MITRE_T1190_RULES = {
    "external.git_metadata_exposed",
    "external.svn_metadata_exposed",
    "external.env_file_exposed",
    "external.web_config_exposed",
    "external.htaccess_exposed",
    "external.backup_archive_exposed",
    "external.backup_file_exposed",
    "external.database_dump_exposed",
    "external.phpinfo_exposed",
    "external.elmah_axd_exposed",
    "external.trace_axd_exposed",
    "external.wordpress_admin_panel_exposed",
    "external.iis.detailed_error_page",
}

_MITRE_T1592_004_RULES = {
    "external.server_status_exposed",
    "external.server_info_exposed",
    "external.nginx_status_exposed",
    "external.apache.mod_status_public",
    "external.lighttpd.mod_status_public",
    "apache.server_status_exposed",
    "apache.server_info_exposed",
    "lighttpd.mod_status_public",
}

_MITRE_T1213_003_RULES = {
    "external.git_metadata_exposed",
    "external.svn_metadata_exposed",
    "external.dependency_manifest_exposed",
    "nginx.missing_hidden_files_deny",
    "apache.vcs_metadata_not_restricted",
}

_MITRE_T1078_RULES = {
    "external.htpasswd_exposed",
    "external.npmrc_exposed",
    "iis.credentials_password_format_clear",
    "iis.credentials_stored_in_config",
}

_MITRE_T1040_RULES = {
    "external.https_not_available",
    "external.nginx.redirect_target_unexpected",
    "external.http_not_redirected_to_https",
    "iis.basic_auth_without_ssl",
    "iis.forms_auth_require_ssl_missing",
} | _HSTS_RULES

_MITRE_T1505_003_RULES = {
    "nginx.executable_scripts_allowed_in_uploads",
    "iis.handler_write_script_execute_enabled",
    "iis.cgi_handler_enabled",
}

_MITRE_T1557_RULES = (
    {
        "universal.weak_tls_protocol",
        "universal.weak_tls_ciphers",
        "external.tls_1_0_supported",
        "external.tls_1_1_supported",
        "external.weak_cipher_suite",
    }
    | _TLS_PROTOCOL_RULES
    | _TLS_CIPHER_RULES
)

_MITRE_T1574_RULES = {
    "iis.handler_write_script_execute_enabled",
}

# ---------------------------------------------------------------------------
# NIST Cybersecurity Framework 2.0 — secondary alignment.
#
# CSF subcategories are framework-level: a single subcategory typically
# covers many concrete rules. Mappings are intentionally narrow to keep
# CSF tags useful as a high-level cross-reference rather than noisy
# per-rule decoration. Universal rules are the natural anchor because
# they apply across all servers; selected representative external rules
# from PR-3 receive PR.DS-01 alignment to demonstrate the same
# alignment on new safe-probe content. Per-server rules inherit CSF
# alignment through the universal layer.
#
# Source: NIST Cybersecurity Framework version 2.0, "Cybersecurity
# Framework Core" subcategory list (https://www.nist.gov/cyberframework).
# ---------------------------------------------------------------------------

# PR.DS-02 — Data-in-transit is protected.
_NIST_CSF_PR_DS_02_RULES = {
    "universal.tls_intent_without_config",
    "universal.weak_tls_protocol",
    "universal.weak_tls_ciphers",
    "universal.missing_hsts",
}

# PR.DS-01 — Data-at-rest is protected. Applied to the highest-value
# secret-exposure probes introduced by PR-3.
_NIST_CSF_PR_DS_01_RULES = {
    "external.aws_credentials_exposed",
    "external.ssh_private_key_exposed",
    "external.kube_config_exposed",
    "external.gcp_service_account_exposed",
    "external.rails_master_key_exposed",
    "external.springboot_actuator_heapdump_exposed",
}

# PR.AA-03 — Users, services, and hardware are authenticated.
_NIST_CSF_PR_AA_03_RULES = {
    "universal.tls_required_for_authenticated_routes",
}

# PR.AA-05 — Access permissions, entitlements, and authorizations are
# defined, managed, enforced, and reviewed.
_NIST_CSF_PR_AA_05_RULES = {
    "universal.directory_listing_enabled",
}

# PR.PS-01 — Configuration management practices are established and
# applied (response-hardening headers + server identification posture).
_NIST_CSF_PR_PS_01_RULES = {
    "universal.missing_x_content_type_options",
    "universal.missing_x_frame_options",
    "universal.missing_content_security_policy",
    "universal.missing_referrer_policy",
    "universal.referrer_policy_unsafe",
    "universal.permissions_policy_unsafe",
    "universal.server_identification_disclosed",
}

# ---------------------------------------------------------------------------
# OWASP API Security Top 10 (2023) — secondary alignment.
#
# Most API Top 10 entries live at the application layer, but
# API7:2023 (Server-Side Request Forgery) maps directly to the
# `proxy_pass`-with-user-controlled-host check landed in PR-4.
# ---------------------------------------------------------------------------

_OWASP_API7_2023_RULES = {
    "nginx.proxy_pass_user_controlled_destination",
}

_PCI_225_RULES = {
    "apache.trace_enable_not_off",
    "apache.options_execcgi_enabled",
    "apache.options_includes_enabled",
    "apache.options_multiviews_enabled",
    "lighttpd.mod_cgi_enabled",
    "lighttpd.mod_status_public",
    "iis.webdav_module_enabled",
    "iis.cgi_handler_enabled",
    "iis.handler_write_script_execute_enabled",
    "external.trace_method_allowed",
    "external.trace_method_exposed_via_options",
    "external.dangerous_http_methods_enabled",
    "external.webdav_methods_exposed",
    "external.allow_header_dangerous_methods",
    "external.apache.mod_status_public",
    "external.lighttpd.mod_status_public",
    "external.nginx_status_exposed",
    "external.server_status_exposed",
    "external.server_info_exposed",
}

_PCI_226_RULES = {
    "nginx.server_tokens_on",
    "apache.server_tokens_not_prod",
    "apache.server_signature_not_off",
    "apache.server_status_exposed",
    "apache.server_info_exposed",
    "apache.file_etag_inodes",
    "lighttpd.server_tag_not_blank",
    "iis.custom_headers_expose_server",
    "iis.request_filtering_remove_server_header_disabled",
    "iis.http_runtime_version_header_enabled",
    "iis.http_errors_detailed",
    "iis.custom_errors_off",
    "iis.asp_script_error_sent_to_browser",
    "iis.deployment_retail_not_enabled",
    "iis.compilation_debug_enabled",
    "iis.trace_enabled",
    "external.phpinfo_exposed",
    "external.elmah_axd_exposed",
    "external.trace_axd_exposed",
    "external.git_metadata_exposed",
    "external.svn_metadata_exposed",
    "external.web_config_exposed",
    "external.htaccess_exposed",
    "external.env_file_exposed",
    "external.backup_archive_exposed",
    "external.backup_file_exposed",
    "external.database_dump_exposed",
    "external.dependency_manifest_exposed",
    "external.npmrc_exposed",
    "external.iis.detailed_error_page",
    "external.wordpress_admin_panel_exposed",
    "external.x_powered_by_header_present",
    "external.x_aspnet_version_header_present",
    "external.iis.aspnet_version_header_present",
    "external.iis.server_header_removal_not_applied",
    "external.apache.etag_inode_disclosure",
    "external.nginx.version_disclosed_in_server_header",
    "external.apache.version_disclosed_in_server_header",
    "external.lighttpd.version_in_server_header",
    "external.nginx.default_index_page_body",
    "external.nginx.default_welcome_page",
    "external.apache.default_welcome_page",
    "external.iis.default_welcome_page",
    "external.lighttpd.default_welcome_page",
}


def _cheat_sheet(
    title: str,
    url: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return StandardReference(
        standard="OWASP Cheat Sheet Series",
        reference=title,
        url=url,
        coverage=coverage,
        note=note,
    )


def _vendor_reference(
    reference: str,
    url: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return StandardReference(
        standard="Vendor",
        reference=reference,
        url=url,
        coverage=coverage,
        note=note,
    )


def _is_rule_id(rule_id: str) -> bool:
    return rule_id in _known_rule_ids()


@lru_cache(maxsize=1)
def _known_rule_ids() -> frozenset[str]:
    repo_root = Path(__file__).resolve().parents[2]
    source_rule_ids = _known_rule_ids_from_source(repo_root / "src" / "webconf_audit")
    doc_path = repo_root / "docs" / "rule-coverage.md"
    if not doc_path.exists():
        _LOGGER.debug(
            "Cannot load hardening rule IDs from %s; falling back to source-derived rule IDs.",
            doc_path,
        )
        return source_rule_ids
    doc_rule_ids = frozenset(_RULE_ID_PATTERN.findall(doc_path.read_text(encoding="utf-8")))
    return doc_rule_ids | source_rule_ids


def _known_rule_ids_from_source(source_root: Path) -> frozenset[str]:
    rule_ids: set[str] = set()
    for path in source_root.rglob("*.py"):
        for match in _SOURCE_RULE_ID_PATTERN.finditer(path.read_text(encoding="utf-8")):
            rule_id = match.group("const_rule_id") or match.group("inline_rule_id")
            if rule_id is not None:
                rule_ids.add(rule_id)
    return frozenset(rule_ids)


@lru_cache(maxsize=None)
def lookup_rule_standards(
    rule_id: str,
) -> tuple[tuple[StandardReference, ...], tuple[StandardReference, ...]]:
    if not _is_rule_id(rule_id):
        return (), ()
    primary: list[StandardReference] = []
    secondary: list[StandardReference] = []
    primary.extend(_practice_primary_references(rule_id))
    primary.extend(_pci_references(rule_id))
    primary.extend(_nist_references(rule_id))
    primary.extend(_fstec_references(rule_id))
    primary.extend(_iso_references(rule_id))
    primary.extend(_owasp_cheat_sheet_references(rule_id))
    primary.extend(_lighttpd_vendor_references(rule_id))
    secondary.extend(_secondary_references(rule_id))
    return tuple(primary), tuple(secondary)


def _practice_primary_references(rule_id: str) -> list[StandardReference]:
    """Practice-ready CWE/OWASP/ASVS mappings for the legacy rule catalog."""
    if rule_id == "universal.tls_intent_without_config":
        return [
            cwe(319),
            owasp_top10_2021("A02:2021"),
            asvs_5("12.2.1"),
        ]
    if rule_id == "universal.weak_tls_protocol":
        return [
            cwe(327),
            owasp_top10_2021("A02:2021"),
            asvs_5("12.1.1"),
        ]
    if rule_id == "universal.weak_tls_ciphers":
        return [
            cwe(327),
            owasp_top10_2021("A02:2021"),
            asvs_5(
                "12.1.2",
                coverage="partial",
                note="Conservative cipher-string posture checks.",
            ),
        ]
    if rule_id == "universal.missing_hsts":
        return [
            cwe(319),
            owasp_top10_2021("A05:2021"),
            asvs_5("3.4.1"),
        ]
    if rule_id == "universal.missing_x_content_type_options":
        return [
            cwe(693),
            owasp_top10_2021("A05:2021"),
            asvs_5("3.4.4"),
        ]
    if rule_id == "universal.missing_x_frame_options":
        return [
            cwe(1021),
            owasp_top10_2021("A05:2021"),
        ]
    if rule_id == "universal.missing_content_security_policy":
        return [
            cwe(693),
            owasp_top10_2021("A05:2021"),
            asvs_5("3.4.3", coverage="partial", note="Presence only."),
        ]
    if rule_id == "universal.missing_referrer_policy":
        return [
            owasp_top10_2021("A05:2021"),
            asvs_5("3.4.5"),
        ]
    if rule_id == "universal.directory_listing_enabled":
        return [
            cwe(548),
            owasp_top10_2021("A05:2021"),
            asvs_5("13.4.3"),
        ]
    if rule_id == "universal.server_identification_disclosed":
        return [
            cwe(200),
            owasp_top10_2021("A05:2021"),
            asvs_5("13.4.6"),
        ]
    return []


def _pci_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id in _LEGACY_CATCH_ALL_RULES:
        refs.append(pci_dss_4("2.2.1"))
    in_2_2_5 = rule_id in _PCI_225_RULES
    in_2_2_6 = rule_id in _PCI_226_RULES
    if in_2_2_5 or in_2_2_6:
        refs.append(pci_dss_4("2.2.5" if in_2_2_5 else "2.2.6"))
    if rule_id in _TLS_421_RULES:
        refs.append(pci_dss_4("4.2.1"))
    if rule_id in {
        "nginx.executable_scripts_allowed_in_uploads",
        "nginx.missing_allowed_methods_restriction_for_uploads",
        "apache.htaccess_enables_cgi",
        "apache.htaccess_enables_directory_listing",
        "apache.htaccess_disables_security_headers",
        "apache.htaccess_weakens_security",
        "apache.htaccess_contains_security_directive",
        "apache.htaccess_rewrite_without_limit",
        "apache.htaccess_auth_without_require",
        "iis.file_extensions_allow_unlisted",
        "iis.isapi_cgi_restrictions_allow_unlisted",
        "iis.handler_write_script_execute_enabled",
        "iis.cgi_handler_enabled",
        "iis.request_filtering_allow_double_escaping",
        "iis.request_filtering_allow_high_bit",
        "iis.request_filtering_max_url_too_high",
        "iis.request_filtering_max_query_string_too_high",
        "iis.request_filtering_max_url_missing",
        "iis.request_filtering_max_query_string_missing",
    }:
        refs.append(pci_dss_4("6.2.4"))
    if rule_id in _CSP_RULES - {
        "apache.content_security_policy_missing_frame_ancestors",
        "lighttpd.content_security_policy_missing_frame_ancestors",
        "iis.content_security_policy_missing_frame_ancestors",
        "external.script_src_missing_sri",
    }:
        coverage = "partial" if rule_id.startswith("external.") or rule_id.startswith("universal.") else "direct"
        note = (
            "Presence, unsafe-token, and repeated-nonce detection only."
            if rule_id == "external.content_security_policy_nonce_reused"
            else None
        )
        refs.append(pci_dss_4("6.4.3", coverage=coverage, note=note))
    if rule_id in _AUTH_ADMIN_RULES:
        refs.append(pci_dss_4("8.3.1"))
    if rule_id in _AUTH_TRANSPORT_RULES:
        refs.append(pci_dss_4("8.3.2"))
    if rule_id in _AUTH_AT_REST_RULES:
        refs.append(pci_dss_4("8.3.5 / 8.3.6"))
    if rule_id in _LOG_ENABLE_RULES:
        refs.append(pci_dss_4("10.2.1"))
    if rule_id in _LOG_FIELD_RULES:
        refs.append(
            pci_dss_4(
                "10.2.2",
                coverage="partial" if rule_id == "lighttpd.access_log_format_missing_fields" else "direct",
                note=(
                    "Presence and field-coverage validation only."
                    if rule_id == "lighttpd.access_log_format_missing_fields"
                    else None
                ),
            )
        )
    return refs


def _nist_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id in _TLS_PROTOCOL_RULES:
        refs.append(nist_sp("800-52 Rev. 2", "3.1.1 / 3.1.2"))
    if rule_id in _TLS_CIPHER_RULES:
        refs.append(
            nist_sp(
                "800-52 Rev. 2",
                "3.3.1",
                coverage=(
                    "partial"
                    if rule_id in {
                        "external.tls_forward_secrecy_not_observed",
                        "external.tls_aead_cipher_not_negotiated",
                    }
                    else "direct"
                ),
                note=(
                    "Observed negotiated cipher posture only."
                    if rule_id in {
                        "external.tls_forward_secrecy_not_observed",
                        "external.tls_aead_cipher_not_negotiated",
                    }
                    else None
                ),
            )
        )
    if rule_id in _TLS_SERVER_PREFERENCE_RULES:
        refs.append(
            nist_sp(
                "800-52 Rev. 2",
                "3.3.2",
                coverage="partial" if rule_id == "external.tls_server_cipher_preference_not_observed" else "direct",
                note=(
                    "Bounded TLS 1.2 probe only."
                    if rule_id == "external.tls_server_cipher_preference_not_observed"
                    else None
                ),
            )
        )
    if rule_id in _TLS_CERTIFICATE_RULES:
        refs.append(
            nist_sp(
                "800-52 Rev. 2",
                "3.4",
                coverage="related" if rule_id == "external.cert_chain_length_unusual" else "direct",
                note="Advisory certificate-chain depth signal." if rule_id == "external.cert_chain_length_unusual" else None,
            )
        )
    if rule_id in _TLS_RENEGOTIATION_RULES:
        refs.append(
            nist_sp(
                "800-52 Rev. 2",
                "3.5",
                coverage=(
                    "partial"
                    if rule_id.startswith("lighttpd.")
                    or rule_id == "external.tls_secure_renegotiation_not_observed"
                    else "direct"
                ),
                note=(
                    "Explicit local directive signal only."
                    if rule_id.startswith("lighttpd.")
                    else "Initial handshake advertisement only."
                    if rule_id == "external.tls_secure_renegotiation_not_observed"
                    else None
                ),
            )
        )
    if rule_id in _TLS_COMPRESSION_RULES:
        refs.append(
            nist_sp(
                "800-52 Rev. 2",
                "3.6",
                coverage=(
                    "partial"
                    if rule_id.startswith("lighttpd.")
                    or rule_id == "external.tls_negotiated_compression"
                    else "direct"
                ),
                note=(
                    "Explicit local directive signal only."
                    if rule_id.startswith("lighttpd.")
                    else "Initial handshake observation only."
                    if rule_id == "external.tls_negotiated_compression"
                    else None
                ),
            )
        )
    if rule_id in _TLS_STAPLING_RULES:
        refs.append(
            nist_sp(
                "800-52 Rev. 2",
                "4.2" if rule_id == "external.tls_must_staple_not_observed" else "4.2 / 4.3",
                coverage="partial" if rule_id == "external.ocsp_stapling_not_observed" else "direct",
                note="Handshake observation only." if rule_id == "external.ocsp_stapling_not_observed" else None,
            )
        )
    if rule_id in _HSTS_RULES:
        refs.append(nist_sp("800-52 Rev. 2", "4.2.4"))
    if rule_id in _TLS_NO_PLAINTEXT_RULES:
        refs.append(nist_sp("800-52 Rev. 2", "no plaintext fallback"))
    return refs


def _fstec_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id in {
        "nginx.missing_auth_basic_user_file",
        "nginx.auth_basic_over_http",
        "iis.basic_auth_without_ssl",
        "iis.anonymous_auth_enabled",
        "iis.anonymous_auth_uses_specific_user",
        "iis.authorization_allows_anonymous_users",
    }:
        refs.append(
            fstec_mera(
                "ИАФ.1",
                coverage="partial" if rule_id == "nginx.auth_basic_over_http" else "direct",
                note="HTTP Basic transport protection only." if rule_id == "nginx.auth_basic_over_http" else None,
            )
        )
    if rule_id in {
        "nginx.auth_basic_over_http",
        "apache.basic_auth_over_http",
        "lighttpd.basic_auth_over_http",
        "iis.credentials_password_format_clear",
        "iis.credentials_stored_in_config",
        "iis.forms_auth_require_ssl_missing",
        "iis.forms_auth_protection_unsafe",
        "iis.basic_auth_without_ssl",
        "iis.machine_key_validation_weak",
        "iis.machine_key_legacy_validation_weak",
        "external.htpasswd_exposed",
    }:
        refs.append(fstec_mera("ИАФ.6"))
    if rule_id in _ACCESS_CONTROL_RULES or rule_id.startswith("apache.allowoverride_") or rule_id.startswith("apache.htaccess_"):
        refs.append(fstec_mera("УПД.5"))
    if rule_id in _TLS_421_RULES:
        refs.append(fstec_mera("УПД.13"))
    if rule_id == "nginx.proxy_missing_source_ip_headers":
        refs.append(
            fstec_mera(
                "ОПС.3",
                coverage="partial",
                note="Parser-depth follow-up required for full upstream-trust modelling.",
            )
        )
    if rule_id in _LOG_ENABLE_RULES:
        refs.append(fstec_mera("РСБ.1"))
    if rule_id in _LOG_FIELD_RULES:
        refs.append(fstec_mera("РСБ.3"))
    if rule_id in (
        {
            "external.phpinfo_exposed",
            "external.elmah_axd_exposed",
            "external.trace_axd_exposed",
            "external.git_metadata_exposed",
            "external.svn_metadata_exposed",
            "external.web_config_exposed",
            "external.htaccess_exposed",
            "external.env_file_exposed",
            "external.htpasswd_exposed",
            "external.backup_archive_exposed",
            "external.backup_file_exposed",
            "external.database_dump_exposed",
            "external.dependency_manifest_exposed",
            "external.npmrc_exposed",
            "external.iis.detailed_error_page",
            "external.server_status_exposed",
            "external.server_info_exposed",
            "external.nginx_status_exposed",
            "external.apache.mod_status_public",
            "external.lighttpd.mod_status_public",
            "nginx.server_tokens_on",
            "apache.server_tokens_not_prod",
            "apache.server_signature_not_off",
            "lighttpd.server_tag_not_blank",
            "iis.custom_headers_expose_server",
        }
        | {
            "external.server_version_disclosed",
            "external.x_powered_by_header_present",
            "external.x_aspnet_version_header_present",
            "external.iis.aspnet_version_header_present",
            "external.iis.server_header_removal_not_applied",
            "external.apache.etag_inode_disclosure",
            "external.nginx.version_disclosed_in_server_header",
            "external.apache.version_disclosed_in_server_header",
            "external.lighttpd.version_in_server_header",
        }
    ):
        refs.append(fstec_mera("АНЗ.1"))
    if rule_id in _NETWORK_SECURITY_RULES:
        refs.append(fstec_mera("ЗИС.3"))
    if rule_id in _TLS_421_RULES:
        refs.append(fstec_mera("ЗИС.20"))
    # ЗИС.32 is the catch-all web-server hardening control from the legacy mapping.
    if rule_id in _LEGACY_CATCH_ALL_RULES:
        refs.append(fstec_mera("ЗИС.32"))
    return refs


def _iso_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id in _ACCESS_CONTROL_RULES or rule_id.startswith("apache.allowoverride_") or rule_id.startswith("apache.htaccess_"):
        refs.append(iso_27002_2022("5.15"))
    if rule_id in {
        "nginx.missing_auth_basic_user_file",
        "nginx.auth_basic_over_http",
        "apache.basic_auth_over_http",
        "lighttpd.basic_auth_over_http",
        "iis.basic_auth_without_ssl",
        "iis.anonymous_auth_enabled",
        "iis.anonymous_auth_uses_specific_user",
        "iis.authorization_allows_anonymous_users",
        "iis.forms_auth_require_ssl_missing",
        "iis.credentials_password_format_clear",
        "iis.credentials_stored_in_config",
        "iis.forms_auth_protection_unsafe",
        "iis.machine_key_validation_weak",
        "iis.machine_key_legacy_validation_weak",
        "external.htpasswd_exposed",
    }:
        refs.append(iso_27002_2022("8.5"))
    if rule_id in _LOG_ENABLE_RULES | _LOG_FIELD_RULES:
        refs.append(iso_27002_2022("8.15"))
        refs.append(
            iso_27002_2022(
                "8.16",
                coverage="partial",
                note="Full monitoring remains an application and SOC concern.",
            )
        )
    if rule_id in _PRIVILEGED_UTILITY_RULES:
        refs.append(iso_27002_2022("8.18"))
    if rule_id in _NETWORK_SECURITY_RULES:
        refs.append(iso_27002_2022("8.20"))
    if rule_id in _TLS_421_RULES:
        refs.append(iso_27002_2022("8.21"))
    if rule_id in (
        _TLS_PROTOCOL_RULES
        | _TLS_CIPHER_RULES
        | _TLS_SERVER_PREFERENCE_RULES
        | _TLS_CERTIFICATE_RULES
        | _TLS_RENEGOTIATION_RULES
        | _TLS_COMPRESSION_RULES
    ):
        refs.append(iso_27002_2022("8.24"))
    if rule_id in _RESPONSE_HEADER_RULES | _COOKIE_SESSION_RULES:
        refs.append(
            iso_27002_2022(
                "8.26",
                coverage="partial",
                note="Header and cookie posture signal only.",
            )
        )
    # 8.27 was documented as the broad engineering-principles catch-all for mapped rules.
    if rule_id in _LEGACY_CATCH_ALL_RULES:
        refs.append(iso_27002_2022("8.27"))
    return refs


def _owasp_cheat_sheet_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id in _RESPONSE_HEADER_RULES:
        refs.append(
            _cheat_sheet(
                "HTTP Security Response Headers",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            )
        )
    if rule_id in _HSTS_RULES:
        refs.append(
            _cheat_sheet(
                "HTTP Strict Transport Security",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            )
        )
    if rule_id in (_TLS_421_RULES | _TLS_CERTIFICATE_RULES):
        refs.append(
            _cheat_sheet(
                "Transport Layer Security",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            )
        )
    if rule_id in _CSP_RULES:
        refs.append(
            _cheat_sheet(
                "Content Security Policy",
                "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                coverage="partial" if rule_id == "apache.htaccess_disables_security_headers" else "direct",
                note="Partial CSP signal via header weakening." if rule_id == "apache.htaccess_disables_security_headers" else None,
            )
        )
    if rule_id in {
        "external.cookie_missing_samesite",
        "external.cookie_samesite_none_without_secure",
        "external.cookie_prefix_contract_violated",
    }:
        refs.append(
            _cheat_sheet(
                "Cross-Site Request Forgery Prevention",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            )
        )
    if rule_id in _SESSION_RULES:
        refs.append(
            _cheat_sheet(
                "Session Management",
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            )
        )
    if rule_id in _LOG_ENABLE_RULES | _LOG_FIELD_RULES:
        refs.append(
            _cheat_sheet(
                "Logging",
                "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            )
        )
    if rule_id in {
        "nginx.missing_auth_basic_user_file",
        "nginx.auth_basic_over_http",
        "apache.basic_auth_over_http",
        "lighttpd.basic_auth_over_http",
        "iis.basic_auth_without_ssl",
        "iis.anonymous_auth_enabled",
        "iis.anonymous_auth_uses_specific_user",
        "iis.authorization_allows_anonymous_users",
        "external.htpasswd_exposed",
    }:
        refs.append(
            _cheat_sheet(
                "Authentication",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            )
        )
    if rule_id in {
        "iis.credentials_password_format_clear",
        "iis.credentials_stored_in_config",
    }:
        refs.append(
            _cheat_sheet(
                "Credential Stuffing Prevention",
                "https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html",
            )
        )
    if rule_id in _CLICKJACKING_RULES:
        refs.append(
            _cheat_sheet(
                "Clickjacking Defense",
                "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            )
        )
    if rule_id in _SERVER_DISCLOSURE_RULES:
        refs.append(
            _cheat_sheet(
                "Server-Side Headers",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server",
            )
        )
    if rule_id in _WEB_SERVICE_SECURITY_RULES:
        refs.append(
            _cheat_sheet(
                "Web Service Security",
                "https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html",
            )
        )
    if rule_id in _FILE_UPLOAD_RULES:
        refs.append(
            _cheat_sheet(
                "File Upload",
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            )
        )
    if rule_id in _ACCESS_CONTROL_RULES or rule_id.startswith("apache.allowoverride_") or rule_id.startswith("apache.htaccess_"):
        refs.append(
            _cheat_sheet(
                "Access Control",
                "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
            )
        )
    if rule_id in _ERROR_HANDLING_RULES:
        refs.append(
            _cheat_sheet(
                "Error Handling",
                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            )
        )
    return refs


def _lighttpd_vendor_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id == "lighttpd.server_tag_not_blank":
        refs.append(
            _vendor_reference(
                "DevSec lighttpd-baseline lighttpd-01",
                "https://github.com/dev-sec/lighttpd-baseline",
            )
        )
    if rule_id == "lighttpd.dir_listing_enabled":
        refs.append(
            _vendor_reference(
                "DevSec lighttpd-baseline lighttpd-02",
                "https://github.com/dev-sec/lighttpd-baseline",
            )
        )
    if rule_id in {
        "lighttpd.ssl_engine_not_enabled",
        "lighttpd.ssl_pemfile_missing",
        "lighttpd.ssl_protocol_policy_missing_or_weak",
        "lighttpd.weak_ssl_cipher_list",
        "lighttpd.ssl_honor_cipher_order_missing",
    }:
        refs.append(
            _vendor_reference(
                "DevSec lighttpd-baseline lighttpd-03",
                "https://github.com/dev-sec/lighttpd-baseline",
            )
        )
    if rule_id == "lighttpd.missing_http_method_restrictions":
        refs.append(
            _vendor_reference(
                "DevSec lighttpd-baseline lighttpd-05",
                "https://github.com/dev-sec/lighttpd-baseline",
                coverage="partial",
                note="Explicit dangerous-method deny policy signal.",
            )
        )
    if rule_id == "lighttpd.mod_status_public":
        refs.append(
            _vendor_reference(
                "lighttpd Security wiki - mod_status",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id in {
        "lighttpd.mod_cgi_enabled",
        "lighttpd.mod_webdav_enabled",
        "lighttpd.webdav_write_access_enabled",
    }:
        refs.append(
            _vendor_reference(
                "lighttpd Security wiki - mod_cgi / mod_webdav",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id in {
        "lighttpd.url_access_deny_missing",
        "lighttpd.backup_temp_files_access_not_denied",
        "lighttpd.config_data_files_access_not_denied",
        "lighttpd.generated_artifacts_access_not_denied",
        "lighttpd.vcs_metadata_access_not_denied",
    }:
        refs.append(
            _vendor_reference(
                "lighttpd Security wiki - url.access-deny",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id in {"lighttpd.access_log_missing", "lighttpd.access_log_format_missing_fields"}:
        refs.append(
            _vendor_reference(
                "lighttpd mod_accesslog documentation",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id == "lighttpd.error_log_missing":
        refs.append(
            _vendor_reference(
                "lighttpd server.errorlog documentation",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id == "lighttpd.max_connections_missing":
        refs.append(
            _vendor_reference(
                "lighttpd server.max-connections documentation",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id in {
        "lighttpd.max_request_size_missing",
        "lighttpd.max_request_size_unlimited",
        "lighttpd.max_request_size_too_large",
    }:
        refs.append(
            _vendor_reference(
                "lighttpd server.max-request-size documentation",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id == "lighttpd.max_request_field_size_too_large":
        refs.append(
            _vendor_reference(
                "lighttpd server.max-request-field-size documentation",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id in {
        "lighttpd.max_keep_alive_idle_too_high",
        "lighttpd.max_read_idle_too_high",
        "lighttpd.max_write_idle_too_high",
        "lighttpd.max_keep_alive_requests_unlimited",
    }:
        refs.append(
            _vendor_reference(
                "lighttpd idle / keep-alive timeout documentation",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    if rule_id in {
        "lighttpd.missing_strict_transport_security",
        "lighttpd.strict_transport_security_unsafe",
        "lighttpd.missing_x_content_type_options",
        "lighttpd.missing_x_frame_options",
        "lighttpd.x_frame_options_unsafe",
        "lighttpd.missing_content_security_policy",
        "lighttpd.content_security_policy_missing_frame_ancestors",
        "lighttpd.content_security_policy_unsafe",
        "lighttpd.missing_referrer_policy",
        "lighttpd.referrer_policy_unsafe",
        "lighttpd.missing_permissions_policy",
        "lighttpd.permissions_policy_unsafe",
    }:
        refs.append(
            _vendor_reference(
                "lighttpd Security wiki - security response headers via mod_setenv",
                "https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security",
            )
        )
    return refs


def _secondary_references(rule_id: str) -> list[StandardReference]:
    refs: list[StandardReference] = []
    if rule_id in _MITRE_T1190_RULES:
        refs.append(mitre_attack("T1190"))
    if rule_id in _SERVER_DISCLOSURE_RULES:
        refs.append(mitre_attack("T1592.002"))
    if rule_id in _MITRE_T1592_004_RULES:
        refs.append(mitre_attack("T1592.004"))
    if rule_id in _MITRE_T1213_003_RULES:
        refs.append(mitre_attack("T1213.003"))
    if rule_id in _MITRE_T1078_RULES:
        refs.append(mitre_attack("T1078"))
    if rule_id in _MITRE_T1040_RULES:
        refs.append(mitre_attack("T1040"))
        refs.append(fstec_bdu("УБИ.044"))
    if rule_id in _MITRE_T1505_003_RULES:
        refs.append(mitre_attack("T1505.003"))
    if rule_id in _MITRE_T1557_RULES:
        refs.append(mitre_attack("T1557"))
    if rule_id in _MITRE_T1574_RULES:
        refs.append(mitre_attack("T1574"))
    if rule_id in _MITRE_T1190_RULES | {
        "external.dependency_manifest_exposed",
    }:
        refs.append(fstec_bdu("УБИ.067"))
    if rule_id in _MITRE_T1557_RULES:
        refs.append(fstec_bdu("УБИ.072"))
    if rule_id in {
        "universal.missing_content_security_policy",
        "universal.missing_x_frame_options",
        "universal.missing_x_content_type_options",
        "external.content_security_policy_missing",
        "external.content_security_policy_unsafe_inline",
        "external.content_security_policy_unsafe_eval",
        "external.content_security_policy_missing_frame_ancestors",
        "external.content_security_policy_object_src_not_none",
        "external.content_security_policy_base_uri_not_restricted",
        "external.content_security_policy_missing_reporting_endpoint",
        "external.content_security_policy_nonce_reused",
        "external.script_src_missing_sri",
        "external.x_frame_options_missing",
        "external.x_frame_options_invalid",
        "external.x_content_type_options_missing",
        "external.x_content_type_options_invalid",
    }:
        refs.append(fstec_bdu("УБИ.121"))
    if rule_id in {
        "external.htpasswd_exposed",
        "external.npmrc_exposed",
        "iis.credentials_password_format_clear",
        "iis.credentials_stored_in_config",
        "iis.basic_auth_without_ssl",
    }:
        refs.append(fstec_bdu("УБИ.184"))
    # NIST CSF 2.0 — alignment-level secondary references.
    if rule_id in _NIST_CSF_PR_DS_02_RULES:
        refs.append(nist_csf_2("PR.DS-02"))
    if rule_id in _NIST_CSF_PR_DS_01_RULES:
        refs.append(nist_csf_2("PR.DS-01"))
    if rule_id in _NIST_CSF_PR_AA_03_RULES:
        refs.append(nist_csf_2("PR.AA-03"))
    if rule_id in _NIST_CSF_PR_AA_05_RULES:
        refs.append(nist_csf_2("PR.AA-05"))
    if rule_id in _NIST_CSF_PR_PS_01_RULES:
        refs.append(nist_csf_2("PR.PS-01"))
    # OWASP API Security Top 10 (2023) — application-layer alignment.
    if rule_id in _OWASP_API7_2023_RULES:
        refs.append(owasp_api_top10_2023("API7:2023"))
    return refs
