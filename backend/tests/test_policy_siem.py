from routes.siem_routes import _matches, _validate_conditions


def test_siem_rule_matches_nested_payload_and_all_conditions():
    conditions = _validate_conditions({"all": [
        {"field": "event_type", "operator": "equals", "value": "authentication"},
        {"field": "outcome", "operator": "equals", "value": "failure"},
        {"field": "payload.failed_attempts", "operator": "gte", "value": 5},
    ]})
    assert _matches({"event_type": "authentication", "outcome": "failure", "payload": {"failed_attempts": 7}}, conditions)
    assert not _matches({"event_type": "authentication", "outcome": "success", "payload": {"failed_attempts": 7}}, conditions)


def test_siem_rule_validation_rejects_unsupported_fields():
    try:
        _validate_conditions({"all": [{"field": "command", "operator": "equals", "value": "rm"}]})
    except Exception as error:
        assert "Condição" in str(error.detail)
    else:
        raise AssertionError("unsupported SIEM condition was accepted")
