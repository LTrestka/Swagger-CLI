from collections import namedtuple
import io
import json
import os
import subprocess
import sys
import time
import pytest

from ferry_cli.__main__ import (
    FerryCLI,
    handle_show_configfile,
    get_config_info_from_user,
    help_called,
    normalize_endpoint,
)
import ferry_cli.__main__ as _main
import ferry_cli.config.config as _config
from ferry_cli.helpers.customs import FerryParser


class DummyTokenAuthorizer:
    def __init__(self):
        self.token_string = ""

    def __call__(self, session):
        return session


def write_auth_config(
    tmp_path,
    token_path,
    authentication_file,
    authenticate_url,
    token_format="json",
):
    config_text = f"""
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/

[authorization]
enabled = True
auth_method = "token"
authentication_file = "{authentication_file}"
authenticate_url = "{authenticate_url}"

[token-auth]
token_path = "{token_path}"
token_format = "{token_format}"
token_header = "Bearer {{token}}"
"""
    config_file = tmp_path / "config.ini"
    config_file.write_text(config_text)
    return config_file


@pytest.fixture
def inject_fake_stdin(monkeypatch):
    def inner(fake_input):
        monkeypatch.setattr("sys.stdin", io.StringIO(fake_input))

    return inner


@pytest.fixture
def mock_write_config_file_with_user_values(monkeypatch):
    def _func():
        print("Mocked write_config_file")

    monkeypatch.setattr(
        _main,
        "write_config_file_with_user_values",
        _func,
    )


@pytest.fixture
def write_and_set_fake_config_file(monkeypatch, tmp_path):
    # Fake config file
    p = tmp_path
    config_dir = p / "ferry_cli"
    config_dir.mkdir()
    config_file = config_dir / "config.ini"
    config_file.write_text("This is a fake config file")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(p.absolute()))
    return config_file


@pytest.fixture
def configfile_doesnt_exist(monkeypatch):
    monkeypatch.setattr(_config, "get_configfile_path", lambda: None)


@pytest.mark.unit
def test_sanitize_base_url():
    cases = ["http://hostname.domain:1234/", "http://hostname.domain:1234"]
    expected = "http://hostname.domain:1234/"
    for case in cases:
        assert FerryCLI._sanitize_base_url(case) == expected

    complex_case = "http://hostname.domain:1234/apiEndpoint?key1=val1"
    assert FerryCLI._sanitize_base_url(complex_case) == complex_case


@pytest.mark.unit
def test_handle_show_configfile_configfile_exists(
    capsys, monkeypatch, write_and_set_fake_config_file
):
    # If we have a config file, we should print out the path to the config file and return
    config_file = write_and_set_fake_config_file

    test_case = namedtuple("TestCase", ["args", "expected_stdout_substr"])
    args_cases = (
        test_case(
            ["--show-config-file", "--foo", "bar", "--baz"],  # Arg passed
            f"Configuration file: {str(config_file.absolute())}",
        ),
        test_case(["--foo", "bar", "--baz"], ""),  # Arg not passed
    )

    for case in args_cases:
        handle_show_configfile(case.args)
        captured = capsys.readouterr()
        assert captured.out.strip() == case.expected_stdout_substr


@pytest.mark.unit
def test_handle_show_configfile_configfile_does_not_exist(
    capsys, monkeypatch, tmp_path, mock_write_config_file_with_user_values
):
    # If we can't find the configfile, we should print out the right message and enter interactive mode
    p = tmp_path
    config_dir = p / "ferry_cli"
    config_dir.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(p.absolute()))

    args = ["--show-config-file", "--foo", "bar", "--baz"]  # Arg passed

    handle_show_configfile(args)
    captured = capsys.readouterr()
    assert (
        f"Based on the environment, would use configuration file: {str((config_dir / 'config.ini').absolute())}.  However, that path does not exist. Will now enter interactive mode to generate it."
        in captured.out
    )
    assert "Mocked write_config_file" in captured.out


@pytest.mark.unit
def test_handle_show_configfile_envs_not_found(
    capsys,
    monkeypatch,
    configfile_doesnt_exist,
    mock_write_config_file_with_user_values,
):
    args = ["--show-config-file", "--foo", "bar", "--baz"]  # Arg passed

    handle_show_configfile(args)
    captured = capsys.readouterr()
    assert (
        "No configuration file found.  Will attempt to create configuration file at $HOME/.config/ferry_cli/config.ini"
        in captured.out
    )
    assert "Mocked write_config_file" in captured.out


@pytest.mark.parametrize(
    "args, expected_out_substr",
    [
        (
            ["-h"],
            "--show-config-file",
        ),  # If we pass -h, make sure --show-config-file shows up
        (
            ["-h", "--show-config-file", "-e", "getAllGroups"],
            "--show-config-file",
        ),  # If we pass -h and --show-config-file, -h should win
        (
            ["--show-config-file"],
            "Configuration file",
        ),  # Print out config file if we only pass --show-config-file
        (
            ["--show-config-file", "-e", "getAllGroups"],
            "Configuration file",
        ),  # If we pass --show-config-file with other args, --show-config-file should print out the config file
    ],
)
@pytest.mark.unit
def test_show_configfile_flag_with_other_args(
    tmp_path, monkeypatch, write_and_set_fake_config_file, args, expected_out_substr
):
    # Since we have to handle --show-config-file outside of argparse, make sure we get the correct behavior given different combinations of args
    bindir = f"{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}/bin"
    exe = f"{bindir}/ferry-cli"

    exe_args = [sys.executable, exe]
    exe_args.extend(args)

    try:
        proc = subprocess.run(exe_args, capture_output=True)
    except SystemExit:
        pass
    assert expected_out_substr in str(proc.stdout)


@pytest.mark.unit
def test_get_config_info_from_user(monkeypatch, capsys):
    # test good
    monkeypatch.setattr("builtins.input", lambda _: "https://wwww.google.com")
    correct_dict = {"base_url": "https://wwww.google.com"}
    generated_dict = get_config_info_from_user()
    assert correct_dict == generated_dict

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        monkeypatch.setattr("builtins.input", lambda _: "badurl")
        get_config_info_from_user()
        assert pytest_wrapped_e.from_e == 1

    captured = capsys.readouterr()
    assert (
        "\nThis doesn't look like a valid URL, you need to specify the https:// part. Try again."
        in captured.out
    )
    assert "\nMultiple failures in specifying base URL, exiting..." in captured.out


@pytest.mark.unit
def test_help_called():
    # Test when "--help" is present in the arguments
    args = ["command", "--help", "arg1", "-h", "arg2"]
    assert help_called(args) == True

    # Test when "-h" is present in the arguments
    args = ["command", "arg1", "-h", "arg2", "--help"]
    assert help_called(args) == True

    # Test when neither "--help" nor "-h" is present in the arguments
    args = ["command", "arg1", "arg2"]
    assert help_called(args) == False


@pytest.mark.parametrize(
    "expected_stdout_before_prompt, user_input, expected_stdout_after_prompt",
    [
        (
            "Configuration file already exists at",
            "n",
            ["usage:", "Exiting without writing configuration file."],
        ),
        (
            "Configuration file already exists at",
            "\n",
            ["usage:", "Exiting without writing configuration file."],
        ),
        (
            "Configuration file already exists at",
            "y",
            ["usage:", "Exiting without writing configuration file."],
        ),
        (
            "Configuration file already exists at",
            "Y",
            [
                "Will launch interactive mode to write configuration file.  If this was a mistake, just press Ctrl+C to exit",
                "Mocked write_config_file",
            ],
        ),
    ],
)
@pytest.mark.unit
def test_handle_no_args_configfile_exists(
    monkeypatch,
    tmp_path,
    mock_write_config_file_with_user_values,
    capsys,
    inject_fake_stdin,
    write_and_set_fake_config_file,
    expected_stdout_before_prompt,
    user_input,
    expected_stdout_after_prompt,
):
    inject_fake_stdin(user_input)
    config_file = write_and_set_fake_config_file

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        _main.handle_no_args(config_file)

    captured = capsys.readouterr()
    assert expected_stdout_before_prompt in captured.out
    for elt in expected_stdout_after_prompt:
        assert elt in captured.out

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0


@pytest.mark.parametrize(
    "expected_stdout_before_prompt, user_input, expected_stdout_after_prompt",
    [
        (
            "Would you like to enter interactive mode to write the configuration file for ferry-cli to use in the future (Y/[n])? ",
            "n",
            ["usage:"],
        ),
        (
            "Would you like to enter interactive mode to write the configuration file for ferry-cli to use in the future (Y/[n])? ",
            "\n",
            ["usage:"],
        ),
        (
            "Would you like to enter interactive mode to write the configuration file for ferry-cli to use in the future (Y/[n])? ",
            "y",
            ["usage:"],
        ),
        (
            "Would you like to enter interactive mode to write the configuration file for ferry-cli to use in the future (Y/[n])? ",
            "Y",
            [
                "Will launch interactive mode to write configuration file.  If this was a mistake, just press Ctrl+C to exit",
                "Mocked write_config_file",
            ],
        ),
    ],
)
@pytest.mark.unit
def test_handle_no_args_configfile_does_not_exist(
    monkeypatch,
    tmp_path,
    configfile_doesnt_exist,
    capsys,
    inject_fake_stdin,
    mock_write_config_file_with_user_values,
    expected_stdout_before_prompt,
    user_input,
    expected_stdout_after_prompt,
):
    inject_fake_stdin(user_input)

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        _main.handle_no_args(None)

    captured = capsys.readouterr()
    assert expected_stdout_before_prompt in captured.out
    for elt in expected_stdout_after_prompt:
        assert elt in captured.out

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 0


@pytest.mark.unit
def test_snakecase_and_underscore_conversion():
    test_endpoints = {"getUserInfo": object()}

    # test to make sure function does matching irrespective of capitalization
    assert normalize_endpoint(test_endpoints, "Get_USeriNFo") == "getUserInfo"

    # test to make sure function never stops working for correct syntax
    assert normalize_endpoint(test_endpoints, "getUserInfo") == "getUserInfo"

    # test that non-endpoint values are left untouched when no match is found
    assert (
        normalize_endpoint(test_endpoints, "SomeOtherEndpoint") == "SomeOtherEndpoint"
    )


@pytest.mark.unit
def test_leading_underscore_preserved():
    test_endpoints = {"_internalEndpoint": object()}

    assert (
        normalize_endpoint(test_endpoints, "_Internal_endpoint") == "_internalEndpoint"
    )


@pytest.mark.unit
def test_resolve_endpoint_maps_concrete_path_to_template(tmp_path):
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/
"""
    )
    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())
    cli.endpoints = {"tasks/{taskID}": object()}

    task_id = "39406b65-c133-4bb9-ab49-8a0f39ea8cf9"
    resolved_endpoint, path_params = cli.resolve_endpoint(f"tasks/{task_id}")

    assert resolved_endpoint == "tasks/{taskID}"
    assert path_params == {"taskID": task_id}


@pytest.mark.unit
def test_run_accepts_concrete_path_for_templated_endpoint(tmp_path):
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/
"""
    )
    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())

    endpoint_parser = FerryParser.create_subparser(
        "tasks/{taskID}",
        description="Get a task",
        method="GET",
    )
    endpoint_parser.set_arguments(
        [
            {
                "name": "taskID",
                "description": "Task ID",
                "type": "string",
                "required": True,
            },
            {
                "name": "view",
                "description": "Task view",
                "type": "string",
                "required": False,
            },
        ]
    )
    cli.endpoints = {"tasks/{taskID}": endpoint_parser}

    seen = {}

    class FakeAPI:
        def call_endpoint(self, endpoint, params):
            seen["endpoint"] = endpoint
            seen["params"] = params
            return {"ferry_status": "success"}

    cli.ferry_api = FakeAPI()

    task_id = "39406b65-c133-4bb9-ab49-8a0f39ea8cf9"
    cli.run(
        debug_level=_main.DebugLevel.QUIET,
        dryrun=False,
        extra_args=["-e", f"tasks/{task_id}", "--view", "summary"],
    )

    assert seen["endpoint"] == "tasks/{taskID}"
    assert seen["params"]["taskID"] == task_id
    assert seen["params"]["view"] == "summary"


@pytest.mark.parametrize(
    "base_url, expected_base_url",
    [
        (None, "https://example.com:12345/"),  # Get base_url from config
        (
            "https://override_example.com:54321/",
            "https://override_example.com:54321/",
        ),  # Get base_url from override
    ],
)
@pytest.mark.unit
def test_override_base_url_FerryCLI(tmp_path, base_url, expected_base_url):
    # Set up fake config
    fake_config_text = """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/

"""
    fake_config = tmp_path / "config.ini"
    fake_config.write_text(fake_config_text)

    cli = FerryCLI(config_path=fake_config, base_url=base_url)
    assert cli.base_url == expected_base_url


@pytest.mark.parametrize(
    "args, expected_out_url",
    [
        ([], "https://example.com:12345/"),  # Get base_url from config
        (
            ["--server", "https://override_example.com:54321/"],
            "https://override_example.com:54321/",
        ),  # Get base_url from override
    ],
)
@pytest.mark.test
def test_server_flag_main(tmp_path, monkeypatch, args, expected_out_url):
    # Run ferry-cli with overridden base_url in dryrun mode to endpoint ping. Then see if we see the correct server in output
    override_url = "https://override_example.com:54321/"
    # Set up fake config
    fake_config_text = """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/

"""
    # Fake config file
    p = tmp_path
    config_dir = p / "ferry_cli"
    config_dir.mkdir()
    config_file = config_dir / "config.ini"
    config_file.write_text(fake_config_text)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(p.absolute()))

    bindir = f"{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}/bin"
    exe = f"{bindir}/ferry-cli"

    exe_args = [sys.executable, exe]
    exe_args.extend(args + ["--dryrun", "-e", "ping"])

    proc = subprocess.run(exe_args, capture_output=True)
    assert f"Would call endpoint: {expected_out_url}ping with params" in str(
        proc.stdout
    )


@pytest.mark.unit
def test_build_ferry_api_supports_legacy_constructor(tmp_path, monkeypatch):
    fake_config_text = """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/

"""
    config_path = tmp_path / "config.ini"
    config_path.write_text(fake_config_text)

    seen_args = {}

    class LegacyFerryAPI:
        def __init__(
            self,
            base_url,
            authorizer,
            debug_level=_main.DebugLevel.NORMAL,
            dryrun=False,
        ):
            seen_args["base_url"] = base_url
            seen_args["authorizer"] = authorizer
            seen_args["debug_level"] = debug_level
            seen_args["dryrun"] = dryrun

    monkeypatch.setattr(_main, "FerryAPI", LegacyFerryAPI)

    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())
    api = cli._build_ferry_api(debug_level=_main.DebugLevel.DEBUG, dryrun=True)

    assert isinstance(api, LegacyFerryAPI)
    assert seen_args["base_url"] == "https://example.com:12345/"
    assert seen_args["authorizer"] is cli.authorizer
    assert seen_args["debug_level"] == _main.DebugLevel.DEBUG
    assert seen_args["dryrun"] is True


@pytest.mark.unit
def test_build_ferry_api_passes_insecure_when_supported(tmp_path, monkeypatch):
    fake_config_text = """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/

"""
    config_path = tmp_path / "config.ini"
    config_path.write_text(fake_config_text)

    seen_args = {}

    class CurrentFerryAPI:
        def __init__(
            self,
            base_url,
            authorizer,
            debug_level=_main.DebugLevel.NORMAL,
            dryrun=False,
            insecure=False,
        ):
            seen_args["base_url"] = base_url
            seen_args["authorizer"] = authorizer
            seen_args["debug_level"] = debug_level
            seen_args["dryrun"] = dryrun
            seen_args["insecure"] = insecure

    monkeypatch.setattr(_main, "FerryAPI", CurrentFerryAPI)

    cli = FerryCLI(
        config_path=config_path,
        authorizer=DummyTokenAuthorizer(),
        insecure=True,
    )
    api = cli._build_ferry_api(debug_level=_main.DebugLevel.DEBUG, dryrun=True)

    assert isinstance(api, CurrentFerryAPI)
    assert seen_args["base_url"] == "https://example.com:12345/"
    assert seen_args["authorizer"] is cli.authorizer
    assert seen_args["debug_level"] == _main.DebugLevel.DEBUG
    assert seen_args["dryrun"] is True
    assert seen_args["insecure"] is True


@pytest.mark.unit
def test_get_authorization_header_uses_existing_valid_token(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text(
        json.dumps(
            {
                "access_token": "existing-token",
                "tokenExpiresAt": int(time.time()) + 3600,
            }
        )
    )
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"username": "user", "password": "pass"}))
    config_path = write_auth_config(
        tmp_path, token_path, auth_file, "https://example.com/api/auth/login"
    )

    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())
    auth_header = cli._get_authorization_header()

    assert auth_header == {"Authorization": "Bearer existing-token"}
    assert cli.authorizer.token_string == "existing-token"


@pytest.mark.unit
def test_get_authorization_header_refreshes_expired_token(tmp_path, monkeypatch):
    token_path = tmp_path / "token.json"
    token_path.write_text(
        json.dumps(
            {
                "access_token": "expired-token",
                "tokenExpiresAt": int(time.time()) - 60,
            }
        )
    )
    auth_file = tmp_path / "auth.json"
    auth_payload = {"username": "user", "password": "pass"}
    auth_file.write_text(json.dumps(auth_payload))
    auth_url = "https://example.com/api/auth/login"
    config_path = write_auth_config(tmp_path, token_path, auth_file, auth_url)

    refreshed_token_data = {
        "access_token": "fresh-token",
        "tokenExpiresAt": int(time.time()) + 3600,
    }

    called = {}

    class FakeResponse:
        ok = True
        status_code = 200
        text = ""

        def json(self):
            return refreshed_token_data

    def fake_post(url, json, headers, verify, timeout):
        called["url"] = url
        called["json"] = json
        called["headers"] = headers
        called["verify"] = verify
        called["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(_main.requests, "post", fake_post)

    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())
    auth_header = cli._get_authorization_header()

    assert called["url"] == auth_url
    assert called["json"] == auth_payload
    assert called["verify"] is True
    assert auth_header == {"Authorization": "Bearer fresh-token"}
    assert cli.authorizer.token_string == "fresh-token"

    persisted_token_data = json.loads(token_path.read_text())
    assert persisted_token_data["access_token"] == "fresh-token"


@pytest.mark.unit
def test_get_authorization_header_expired_token_without_refresh_config_raises(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text(
        json.dumps(
            {
                "access_token": "expired-token",
                "tokenExpiresAt": int(time.time()) - 60,
            }
        )
    )

    config_text = f"""
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/

[authorization]
enabled = True
auth_method = "token"

[token-auth]
token_path = "{token_path}"
token_format = "json"
"""
    config_path = tmp_path / "config.ini"
    config_path.write_text(config_text)

    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())

    with pytest.raises(RuntimeError) as exc:
        cli._get_authorization_header()

    assert "authorization.authentication_file" in str(exc.value)


@pytest.mark.unit
def test_generate_endpoints_openapi3_resolves_parameter_and_requestbody_refs(
    tmp_path, monkeypatch
):
    swagger = {
        "openapi": "3.0.0",
        "paths": {
            "/auth/login": {
                "parameters": [{"$ref": "#/components/parameters/tenant"}],
                "post": {
                    "summary": "Login request",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginRequest"}
                            }
                        },
                    },
                },
            }
        },
        "components": {
            "parameters": {
                "tenant": {
                    "name": "tenant",
                    "in": "query",
                    "description": "Tenant name",
                    "required": True,
                    "schema": {"type": "string"},
                }
            },
            "schemas": {
                "LoginRequest": {
                    "type": "object",
                    "required": ["username"],
                    "properties": {
                        "username": {
                            "type": "string",
                            "description": "Username for authentication",
                        },
                        "password": {"type": "string"},
                    },
                }
            },
        },
    }
    (tmp_path / "swagger.json").write_text(json.dumps(swagger))

    config_path = tmp_path / "config.ini"
    config_path.write_text(
        """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/
"""
    )

    monkeypatch.setattr(_main, "CONFIG_DIR", str(tmp_path))
    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())
    endpoints = cli.generate_endpoints()

    parser = endpoints["auth/login"]
    options = {
        action.dest: action for action in parser._actions if action.dest != "help"
    }

    assert "tenant" in options
    assert "username" in options
    assert "password" in options
    assert options["tenant"].required is True
    assert options["username"].required is True
    assert options["password"].required is False
    assert "Tenant name" in options["tenant"].help
    assert "Username for authentication" in options["username"].help
    assert "password field" in options["password"].help


@pytest.mark.unit
def test_generate_endpoints_swagger2_resolves_parameter_and_body_schema_refs(
    tmp_path, monkeypatch
):
    swagger = {
        "swagger": "2.0",
        "paths": {
            "/widgets": {
                "post": {
                    "description": "Create widget",
                    "parameters": [
                        {"$ref": "#/parameters/limitParam"},
                        {
                            "name": "payload",
                            "in": "body",
                            "required": True,
                            "schema": {"$ref": "#/definitions/CreateWidgetRequest"},
                        },
                    ],
                }
            }
        },
        "parameters": {
            "limitParam": {
                "name": "limit",
                "in": "query",
                "description": "Result limit",
                "required": False,
                "type": "integer",
            }
        },
        "definitions": {
            "CreateWidgetRequest": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "description": "Widget name"},
                    "count": {"type": "integer"},
                },
            }
        },
    }
    (tmp_path / "swagger.json").write_text(json.dumps(swagger))

    config_path = tmp_path / "config.ini"
    config_path.write_text(
        """
[api]
base_url = https://example.com:12345/
dev_url = https://example.com:12345/
"""
    )

    monkeypatch.setattr(_main, "CONFIG_DIR", str(tmp_path))
    cli = FerryCLI(config_path=config_path, authorizer=DummyTokenAuthorizer())
    endpoints = cli.generate_endpoints()

    parser = endpoints["widgets"]
    options = {
        action.dest: action for action in parser._actions if action.dest != "help"
    }

    assert "limit" in options
    assert "name" in options
    assert "count" in options
    assert options["limit"].required is False
    assert options["name"].required is True
    assert options["count"].required is False
    assert "Result limit" in options["limit"].help
    assert "Widget name" in options["name"].help
    assert "count field" in options["count"].help
