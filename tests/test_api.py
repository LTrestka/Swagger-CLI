import pytest
import subprocess
import time
from typing import Dict, Any
import json
import os
from urllib.parse import urlencode

from ferry_cli.helpers.api import FerryAPI
from ferry_cli.helpers.auth import AuthToken
import ferry_cli.helpers.api as _api

TokenGetCommand = "htgettoken"
tokenDestroyCommand = "htdestroytoken"
tokenDecodeCommand = "httokendecode"

tokenHost = "htvaultprod.fnal.gov"  # "-a arg"
tokenUser = "fermilab"  # "-i arg"
ferryName = "hypotana"
ferryPort = 8445
FERRY_DEV_SERVER = "https://ferrydev.fnal.gov"
FERRY_DEV_PORT = 8447


# --- fixtures


@pytest.fixture
def get_token(monkeypatch, tmp_path):
    # Set up temporary area for token to live
    token_file = tmp_path / "tokenfile"
    token_file.touch()
    old_bearer_token_file = os.getenv("BEARER_TOKEN_FILE", None)
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(token_file.absolute()))

    # Get our token
    proc = subprocess.run([TokenGetCommand, "-a", tokenHost, "-i", tokenUser])
    if proc.returncode != 0:
        raise ValueError(
            f"{TokenGetCommand} failed.  Please try running it manually for more details"
        )

    # Decode and validate the token
    tokenObject = {}
    tokenDecoding = subprocess.getoutput([tokenDecodeCommand])

    try:
        tokenObject = json.loads(tokenDecoding)
    except ValueError as ve:
        print(" *** Token Failure: Didn't get valid JWT")
        raise ve

    tokenValidCheck(tokenObject)
    yield tokenObject

    # Set the environment back
    if old_bearer_token_file:
        os.environ["BEARER_TOKEN_FILE"] = old_bearer_token_file


@pytest.fixture
def get_token_path():
    uid = os.getuid()
    token_path = f"/run/user/{uid}/bt_u{uid}"
    return token_path


@pytest.fixture
def getEncodedToken(get_token, get_token_path):
    with open(get_token_path) as file:
        return file.read().strip()


@pytest.fixture(scope="function")
def sendToEndpoint(get_token):
    token_auth = AuthToken()

    def _sendToEndpoint(
        token,
        endPoint,
        method: str = "get",
        data: Dict[Any, Any] = {},
        headers: Dict[str, Any] = {},
        params: Dict[Any, Any] = {},
    ):
        api = FerryAPI(f"{FERRY_DEV_SERVER}:{FERRY_DEV_PORT}/", token_auth)
        try:
            apiResult = api.call_endpoint(
                endpoint=endPoint,
                method=method,
                data=data,
                headers=headers,
                params=params,
            )
        except Exception as e:
            print(" *** API Failure: Didn't get valid endpoint response")
            raise
        return apiResult

    return _sendToEndpoint


# --- tests below ----


@pytest.mark.integration
def test_token_aquisition(get_token):
    assert get_token is not False


@pytest.mark.integration
def test_get_capability_set(getEncodedToken, sendToEndpoint):
    result = sendToEndpoint(getEncodedToken, "getCapabilitySet")
    assert (result["ferry_status"]) == "success"


@pytest.mark.integration
def test_getAllGroups(getEncodedToken, sendToEndpoint):
    result = sendToEndpoint(getEncodedToken, "getAllGroups")
    assert (result["ferry_status"]) == "success"
    assert result["ferry_output"]  # Make sure we got non-empty result


@pytest.mark.unit
def test_call_endpoint_uses_auth_header_provider_for_each_request(monkeypatch):
    seen_headers = []

    class DummyAuthorizer:
        token_string = "stale-token"

        def __call__(self, session):
            return session

    class FakeResponse:
        def __init__(self, request_url):
            self.ok = True
            self.request = type("Request", (), {"url": request_url})

        def json(self):
            return {"ferry_status": "success"}

    class FakeSession:
        def get(self, url, headers=None, params=None):
            seen_headers.append(dict(headers or {}))
            return FakeResponse(url)

    monkeypatch.setattr(_api.requests, "Session", lambda: FakeSession())

    call_count = {"value": 0}
    expected_tokens = ["token-one", "token-two"]

    def header_provider():
        token_value = expected_tokens[call_count["value"]]
        call_count["value"] += 1
        return {"Authorization": f"Bearer {token_value}"}

    api = FerryAPI(
        base_url="https://example.com/",
        authorizer=DummyAuthorizer(),
        auth_header_provider=header_provider,
    )

    api.call_endpoint("ping")
    api.call_endpoint("ping")

    assert seen_headers[0]["Authorization"] == "Bearer token-one"
    assert seen_headers[1]["Authorization"] == "Bearer token-two"
    assert seen_headers[0]["accept"] == "application/json"
    assert seen_headers[1]["accept"] == "application/json"


@pytest.mark.unit
def test_call_endpoint_disables_tls_verification_when_insecure(monkeypatch):
    seen_verify = []

    class DummyAuthorizer:
        def __call__(self, session):
            return session

    class FakeResponse:
        ok = True
        request = type("Request", (), {"url": "https://example.com/ping"})

        def json(self):
            return {"ferry_status": "success"}

    class FakeSession:
        def __init__(self):
            self.verify = True

        def get(self, url, headers=None, params=None):
            seen_verify.append(self.verify)
            return FakeResponse()

    monkeypatch.setattr(_api.requests, "Session", lambda: FakeSession())

    api = FerryAPI(
        base_url="https://example.com/",
        authorizer=DummyAuthorizer(),
        insecure=True,
    )

    api.call_endpoint("ping")

    assert seen_verify == [False]


@pytest.mark.unit
def test_call_endpoint_substitutes_path_parameters_and_omits_from_query(monkeypatch):
    seen_request = {}

    class DummyAuthorizer:
        def __call__(self, session):
            return session

    class FakeResponse:
        def __init__(self, request_url):
            self.ok = True
            self.request = type("Request", (), {"url": request_url})

        def json(self):
            return {"ferry_status": "success"}

    class FakeSession:
        def get(self, url, headers=None, params=None):
            seen_request["url"] = url
            seen_request["params"] = dict(params or {})
            request_url = url
            if params:
                request_url = f"{url}?{urlencode(params)}"
            return FakeResponse(request_url)

    monkeypatch.setattr(_api.requests, "Session", lambda: FakeSession())

    api = FerryAPI(
        base_url="https://example.com/",
        authorizer=DummyAuthorizer(),
    )

    task_id = "39406b65-c133-4bb9-ab49-8a0f39ea8cf9"
    response = api.call_endpoint(
        "tasks/{taskID}",
        params={"taskID": task_id, "include": "details"},
    )

    assert seen_request["url"] == f"https://example.com/tasks/{task_id}"
    assert seen_request["params"] == {"include": "details"}
    assert response["request_url"] == f"https://example.com/tasks/{task_id}?include=details"


@pytest.mark.unit
def test_call_endpoint_raises_when_path_parameter_is_missing(monkeypatch):
    class DummyAuthorizer:
        def __call__(self, session):
            return session

    class FakeSession:
        def get(self, url, headers=None, params=None):  # pragma: no cover
            raise AssertionError("Session.get should not be called")

    monkeypatch.setattr(_api.requests, "Session", lambda: FakeSession())

    api = FerryAPI(
        base_url="https://example.com/",
        authorizer=DummyAuthorizer(),
    )

    with pytest.raises(ValueError) as exc:
        api.call_endpoint("tasks/{taskID}")

    assert "taskID" in str(exc.value)


# --- test helper functions


def tokenValidCheck(passedToken):
    if "exp" in passedToken:
        if int(time.time()) < passedToken["exp"]:
            return
    raise ValueError(" *** Token Failure: Expired")


def tokenDestroy():
    subprocess.run([tokenDestroyCommand])
