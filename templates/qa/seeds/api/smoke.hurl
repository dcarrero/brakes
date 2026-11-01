# First smoke test. Add one file per endpoint family beside this one; never a host here.
# The same file runs on pull requests (qa-api), after deploy (delivery) and on a schedule (observability),
# each passing its own base_url.
# It starts on the path the API answered as ready (api_ready_path); point it at a real endpoint.
GET {{base_url}}{{api_ready_path}}
HTTP 200
[Asserts]
duration < 2000
