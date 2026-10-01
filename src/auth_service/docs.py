from pathlib import Path

from flask import Blueprint, Response, render_template_string, send_file

docs_bp = Blueprint("docs", __name__)

SWAGGER_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Auth Service Lab API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.25.3/swagger-ui.css"
    integrity="sha384-S+iZGxcLHU1ByODKehPIOcS0UkxgKTWKdT/VtKStv2S430eyGsmjt/NeSxrQq6Ke"
    crossorigin="anonymous">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.25.3/swagger-ui-bundle.js"
    integrity="sha384-ke66V3QlTNSSOUUUixP5CLJKMU65oy88MNXUJ0eKNJOn0G4I7HOn1aOdd3Kii6xE"
    crossorigin="anonymous"></script>
  <script>
    SwaggerUIBundle({
      url: {{ url_for('docs.openapi') | tojson }},
      dom_id: '#swagger-ui',
      deepLinking: true,
      persistAuthorization: false,
      validatorUrl: null
    });
  </script>
</body>
</html>
"""


@docs_bp.get("/docs")
def swagger_ui() -> str:
    return render_template_string(SWAGGER_HTML)


@docs_bp.get("/openapi.json")
def openapi() -> Response:
    return send_file(Path("docs/openapi.json").resolve(), mimetype="application/json")
