# Readiness: the only request qa-api retries. Keep it a GET with no side effect.
GET {{base_url}}{{api_ready_path}}
HTTP 200
