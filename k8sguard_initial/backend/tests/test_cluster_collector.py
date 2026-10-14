"""Verify collector resource identity without requiring a live Kubernetes cluster."""
import pytest
from app.cluster_collect import RESOURCE_TYPES, normalize_resource

@pytest.mark.parametrize('collection,kind,api_version', [
    (key, *value) for key, value in RESOURCE_TYPES.items()
])
def test_resource_api_identity(collection, kind, api_version):
    item = {'metadata': {'name': 'sample'}}
    result = normalize_resource(item, collection)
    assert result['kind'] == kind
    assert result['apiVersion'] == api_version
    assert 'kind' not in item  # no mutation of input


def test_existing_resource_type_is_preserved():
    item = {'kind': 'Custom', 'apiVersion': 'example.io/v1', 'metadata': {'name': 'sample'}}
    result = normalize_resource(item, 'pods')
    assert result['kind'] == 'Custom'
    assert result['apiVersion'] == 'example.io/v1'
