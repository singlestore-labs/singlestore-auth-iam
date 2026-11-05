"""GCP impersonation URLs must match Go's url.PathEscape."""

from s2iam.gcp import impersonation_url


def test_impersonation_url_encodes_the_service_account_as_one_segment():
    email = "service-account@project-id.iam.gserviceaccount.com"
    assert impersonation_url(email) == (
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + email + ":generateIdToken"
    )
    encoded = impersonation_url("evil/other:generateAccessToken")
    assert "/evil/other" not in encoded
    assert "evil%2Fother:generateAccessToken" in encoded
