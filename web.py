from os import environ



google_web = dict(
    client_id=environ.get("google_client_id", "google_client_id_here"),
    project_id=environ.get("google_project_id", "google_project_id_here"),
    auth_uri=environ.get(
        "google_auth_uri",
        "https://accounts.google.com/o/oauth2/auth"
    ),
    token_uri=environ.get(
        "google_token_uri",
        "https://accounts.google.com/o/oauth2/token"
    ),
    auth_provider_x509_cert_url=environ.get(
        "google_x509",
        "https://www.googleapis.com/oauth2/v1/certs"
    ),
    client_secret=environ.get(
        "google_client_secret",
        "google_client_secret_here"
    ),
    javascript_origins=[
        "http://localhost:5000"
    ],
    scope='',
    redirect_uris=[
        "https://localhost:5000/callback",
        "http://localhost:5000/callback"
    ]
)