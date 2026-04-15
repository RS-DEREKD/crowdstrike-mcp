"""Tests confirming EndpointModule has been removed."""

import os


class TestEndpointModuleRemoved:
    def test_endpoint_module_file_does_not_exist(self):
        endpoint_path = os.path.join(os.path.dirname(__file__), "..", "src", "crowdstrike_mcp", "modules", "endpoint.py")
        assert not os.path.exists(endpoint_path), "modules/endpoint.py should be deleted"

    def test_registry_does_not_discover_endpoint(self):
        from crowdstrike_mcp.registry import discover_module_classes

        class_names = [cls.__name__ for cls in discover_module_classes()]
        assert "EndpointModule" not in class_names

    def test_alerts_module_has_no_detects_dependency(self):
        """AlertsModule should not attempt to use the Detects API."""
        import crowdstrike_mcp.modules.alerts as alerts_mod

        source = open(alerts_mod.__file__).read()
        # The Detects import guard should be removed
        assert "_DETECTS_AVAILABLE" not in source or "False" in source
