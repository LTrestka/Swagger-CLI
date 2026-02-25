import json
import re
import sys
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote

import requests  # pylint: disable=import-error

try:
    from ferry_cli.helpers.auth import Auth, DebugLevel
    from ferry_cli.config import CONFIG_DIR
except ImportError:
    from helpers.auth import Auth, DebugLevel  # type: ignore
    from config import CONFIG_DIR  # type: ignore


# pylint: disable=unused-argument,pointless-statement,too-many-arguments
class FerryAPI:
    # pylint: disable=too-many-arguments
    def __init__(
        self: "FerryAPI",
        base_url: str,
        authorizer: Auth = Auth(),
        auth_header_provider: Optional[Callable[[], Dict[str, str]]] = None,
        debug_level: DebugLevel = DebugLevel.NORMAL,
        dryrun: bool = False,
        insecure: bool = False,
    ):
        """
        Parameters:
            base_url (str):  The root URL from which all FERRY API URLs are constructed
            authorizer (Callable[[requests.Session, requests.Session]): A function that prepares the requests session by adding any necessary auth data
            debug_level (DebugLevel): Level of debugging.  Can be DebugLevel.QUIET, DebugLevel.NORMAL, or DebugLevel.DEBUG
            dryrun (bool): Whether or not this is a test run.  If True, the intended URL will be printed, but the HTTP request will not be made
        """
        self.base_url = base_url
        self.authorizer = authorizer
        self.auth_header_provider = auth_header_provider
        self.debug_level = debug_level
        self.dryrun = dryrun
        self.insecure = insecure

    # pylint: disable=too-many-arguments
    @staticmethod
    def _substitute_path_parameters(
        endpoint: str, request_params: Dict[Any, Any]
    ) -> str:
        path_parameter_names = list(dict.fromkeys(re.findall(r"{([^{}]+)}", endpoint)))
        if not path_parameter_names:
            return endpoint

        missing_parameters = []
        resolved_endpoint = endpoint
        for parameter_name in path_parameter_names:
            parameter_value = request_params.get(parameter_name)
            if parameter_value is None:
                missing_parameters.append(parameter_name)
                continue

            encoded_value = quote(str(parameter_value), safe="")
            resolved_endpoint = resolved_endpoint.replace(
                f"{{{parameter_name}}}", encoded_value
            )
            request_params.pop(parameter_name, None)

        if missing_parameters:
            missing_string = ", ".join(missing_parameters)
            raise ValueError(
                f"Missing required path parameter(s): {missing_string} for endpoint '{endpoint}'."
            )

        return resolved_endpoint

    # pylint: disable=too-many-arguments
    def call_endpoint(
        self: "FerryAPI",
        endpoint: str,
        method: str = "get",
        data: Optional[Dict[Any, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[Any, Any]] = None,
        extra: Optional[Dict[Any, Any]] = None,
    ) -> Any:
        request_headers: Dict[str, Any] = dict(headers or {})
        request_params: Dict[Any, Any] = dict(params or {})
        extra_params: Dict[Any, Any] = dict(extra or {})

        if extra_params:
            for attribute_name, attribute_value in extra_params.items():
                if attribute_name not in request_params:
                    request_params[attribute_name] = attribute_value

        resolved_endpoint = self._substitute_path_parameters(endpoint, request_params)

        # Create a session object to persist certain parameters across requests
        if self.dryrun:
            print(
                f"\nWould call endpoint: {self.base_url}{resolved_endpoint} with params\n{request_params}"
            )
            return None

        debug = self.debug_level == DebugLevel.DEBUG

        if debug:
            print(f"\nCalling Endpoint: {self.base_url}{resolved_endpoint}")

        _session = requests.Session()
        session = self.authorizer(_session)  # Handles auth for session
        if self.insecure:
            session.verify = False

        if self.auth_header_provider:
            request_headers.update(self.auth_header_provider())
        elif "Authorization" not in request_headers:
            token_string = getattr(self.authorizer, "token_string", None)
            if token_string:
                request_headers["Authorization"] = f"Bearer {token_string}"

        request_headers.setdefault("accept", "application/json")

        # I believe they are all actually "GET" calls
        try:
            if method.lower() == "get":
                response = session.get(
                    f"{self.base_url}{resolved_endpoint}",
                    headers=request_headers,
                    params=request_params,
                )
            elif method.lower() == "post":
                response = session.post(
                    f"{self.base_url}{resolved_endpoint}",
                    params=request_params,
                    headers=request_headers,
                )
            elif method.lower() == "put":
                response = session.put(
                    f"{self.base_url}{resolved_endpoint}",
                    params=request_params,
                    headers=request_headers,
                )
            else:
                raise ValueError("Unsupported HTTP method.")
            if debug:
                print(f"Called Endpoint: {response.request.url}")
            if not response.ok:
                print(response.text)
                raise RuntimeError(
                    f" *** API Failure: Status code {response.status_code} returned from endpoint /{endpoint}"
                )

            output = response.json()
            if isinstance(output, list):
                output = {"response": output}
            elif not isinstance(output, dict):
                output = {"response": output}
            output["request_url"] = response.request.url
            return output
        except BaseException as e:
            # How do we want to handle errors?
            raise e

    def get_latest_swagger_file(self: "FerryAPI") -> None:
        last_exception: Optional[BaseException] = None
        for endpoint in ("spec", "docs/swagger.json"):
            try:
                response = self.call_endpoint(endpoint)
                if response:
                    with open(f"{CONFIG_DIR}/swagger.json", "w") as file:
                        file.write(json.dumps(response, indent=4))
                    return
            except BaseException as e:  # pylint: disable=broad-except
                last_exception = e

        if last_exception:
            raise last_exception

        print("Failed to fetch swagger.json file")
        sys.exit(1)
