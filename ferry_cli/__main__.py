#!/usr/bin/env python3

import argparse
import copy
import configparser
import inspect
import json
import os
import pathlib
import re
import sys
import textwrap
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Type
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

import requests  # pylint: disable=import-error
import validators  # pylint: disable=import-error

# pylint: disable=unused-import
try:
    # Try package import
    from ferry_cli.helpers.api import FerryAPI
    from ferry_cli.helpers.auth import (
        Auth,
        DebugLevel,
        get_auth_args,
        set_auth_from_args,
        get_auth_parser,
    )
    from ferry_cli.helpers.customs import FerryParser
    from ferry_cli.helpers.supported_workflows import SUPPORTED_WORKFLOWS
    from ferry_cli.safeguards.dcs import SafeguardsDCS
    from ferry_cli.config import CONFIG_DIR, config
except ImportError:
    # Fallback to direct import
    from helpers.api import FerryAPI  # type: ignore
    from helpers.auth import (  # type: ignore
        Auth,
        DebugLevel,
        get_auth_args,
        set_auth_from_args,
        get_auth_parser,
    )
    from helpers.customs import FerryParser  # type: ignore
    from helpers.supported_workflows import SUPPORTED_WORKFLOWS  # type: ignore
    from safeguards.dcs import SafeguardsDCS  # type: ignore
    from config import CONFIG_DIR, config  # type: ignore


class FerryCLI:
    # pylint: disable=too-many-instance-attributes
    def __init__(
        self: "FerryCLI",
        base_url: Optional[str] = None,
        config_path: Optional[pathlib.Path] = None,
        authorizer: Auth = Auth(),
        insecure: bool = False,
        print_help: bool = False,
    ) -> None:
        """
        Initializes the FerryCLI instance.

        Args:
            base_url (Optional[str]): The base URL for the Ferry API, if that should not come from the file specified by config_path.
            config_path (Optional[pathlib.Path]): The path to the configuration file. If None,
                a message will be printed indicating that a configuration file is required.
            authorizer (Auth): An instance of the Auth class used for authorization. Defaults to a dummy Auth instance.
            insecure (bool): If True, disable SSL certificate verification for outbound API calls.
            print_help (bool): If True, prints the help message for the CLI and does not run any setup of the FerryCLI class. Defaults to False.

        Class Attributes:
            base_url (str): The base URL for the Ferry API.
            dev_url (str): The development URL for the Ferry API.
            safeguards (SafeguardsDCS): An instance of SafeguardsDCS for managing safeguards.
            endpoints (Dict[str, Any]): A dictionary to store API endpoints.
            ferry_api (Optional[FerryAPI]): An instance of the FerryAPI class, initialized later.
            parser (Optional[FerryParser]): An instance of the FerryParser class, initialized later.
            config_path (pathlib.Path): The path to the configuration file.
            configs (dict): Parsed configuration data from the configuration file.
            authorizer (Auth): The authorizer instance used for API authentication.

        Raises:
            ValueError: If the configuration file does not have a base_url specified.
        """
        self.base_url: str
        self.dev_url: str
        self.safeguards = SafeguardsDCS()
        self.endpoints: Dict[str, Any] = {}
        self.ferry_api: Optional["FerryAPI"] = None
        self.parser: Optional["FerryParser"] = None
        if print_help:
            self.get_arg_parser().print_help()
            return
        if config_path is None:
            print(
                'A configuration file is required to run the Ferry CLI. Please run "ferry-cli" to generate one interactively if one does not already exist.'
            )
            return

        self.config_path = config_path
        self.configs = self.__parse_config_file()
        self.authorizer = authorizer
        self.insecure = insecure
        self.base_url = (
            self._sanitize_base_url(self.base_url)
            if base_url is None
            else self._sanitize_base_url(base_url)
        )
        self.dev_url = self._sanitize_base_url(self.dev_url)

    @staticmethod
    def _clean_config_value(value: str) -> str:
        return value.strip().strip('"').strip("'")

    @staticmethod
    def _parse_expiration_epoch(value: Any) -> Optional[float]:
        if value is None:
            return None

        parsed_epoch: Optional[float]
        if isinstance(value, (int, float)):
            parsed_epoch = float(value)
        elif isinstance(value, str):
            stripped_value = value.strip()
            if not stripped_value:
                return None
            if stripped_value.isdigit():
                parsed_epoch = float(stripped_value)
            else:
                try:
                    parsed_datetime = datetime.fromisoformat(
                        stripped_value.replace("Z", "+00:00")
                    )
                    if parsed_datetime.tzinfo is None:
                        parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)
                    parsed_epoch = parsed_datetime.timestamp()
                except ValueError:
                    return None
        else:
            return None

        # Some providers use milliseconds.
        if parsed_epoch > 1_000_000_000_000:
            parsed_epoch /= 1_000.0
        return parsed_epoch

    def _is_authorization_enabled(self: "FerryCLI") -> bool:
        enabled_value = self._clean_config_value(
            self.configs.get("authorization", "enabled", fallback="True")
        ).lower()
        return enabled_value not in {"0", "false", "no", "off"}

    def _is_token_auth_method(self: "FerryCLI") -> bool:
        if not hasattr(self.authorizer, "token_string"):
            return False

        auth_method = self._clean_config_value(
            self.configs.get("authorization", "auth_method", fallback="token")
        ).lower()
        return auth_method == "token"

    def _token_file_path(self: "FerryCLI") -> str:
        return self._clean_config_value(
            self.configs.get("token-auth", "token_path", fallback="")
        )

    def _token_format(self: "FerryCLI") -> str:
        return self._clean_config_value(
            self.configs.get("token-auth", "token_format", fallback="raw")
        ).lower()

    def _token_is_expired(self: "FerryCLI", token_data: Dict[str, Any]) -> bool:
        if token_data.get("passwordHasExpired") is True:
            return True

        for expiration_key in ("tokenExpiresAt", "expires_at", "exp"):
            expires_at_epoch = self._parse_expiration_epoch(token_data.get(expiration_key))
            if expires_at_epoch is not None:
                return expires_at_epoch <= time.time()

        return False

    def _read_token_data_from_file(self: "FerryCLI") -> Dict[str, Any]:
        token_path = self._token_file_path()
        if not token_path:
            raise RuntimeError(
                "token-auth.token_path must be configured when using token auth."
            )
        if not os.path.exists(token_path):
            raise FileNotFoundError(
                f"Token file {token_path} was not found. Please authenticate or fix token-auth.token_path."
            )

        if self._token_format() == "json":
            with open(token_path, "r", encoding="utf-8") as token_file:
                token_data = json.load(token_file)
            if not isinstance(token_data, dict):
                raise RuntimeError(
                    f"Token file {token_path} must contain a JSON object."
                )
            return token_data

        with open(token_path, "r", encoding="utf-8") as token_file:
            raw_token = token_file.read().strip()
        if not raw_token:
            raise RuntimeError(f"Token file {token_path} is empty.")
        return {"access_token": raw_token}

    def _try_authenticate_with_file(self: "FerryCLI") -> Dict[str, Any]:
        auth_file_path = self._clean_config_value(
            self.configs.get("authorization", "authentication_file", fallback="")
        )
        authenticate_url = self._clean_config_value(
            self.configs.get("authorization", "authenticate_url", fallback="")
        )
        if not auth_file_path or not authenticate_url:
            raise RuntimeError(
                "Both authorization.authentication_file and authorization.authenticate_url must be set to refresh an expired token."
            )

        with open(auth_file_path, "r", encoding="utf-8") as auth_file:
            auth_payload = json.load(auth_file)

        response = requests.post(
            authenticate_url,
            json=auth_payload,
            headers={"Content-Type": "application/json", "accept": "application/json"},
            verify=not self.insecure,
            timeout=30,
        )
        if not response.ok:
            raise RuntimeError(
                f"Authentication request failed with status {response.status_code} while calling {authenticate_url}."
            )

        try:
            refreshed_token_data = response.json()
        except ValueError:
            refreshed_token_data = {"access_token": response.text.strip()}

        if not isinstance(refreshed_token_data, dict):
            raise RuntimeError(
                "Authentication response must be a JSON object or plain access token."
            )

        access_token = refreshed_token_data.get("access_token") or refreshed_token_data.get(
            "token"
        )
        if not access_token:
            raise RuntimeError(
                "Authentication response did not contain 'access_token' or 'token'."
            )
        refreshed_token_data["access_token"] = access_token

        token_path = self._token_file_path()
        if token_path:
            token_directory = os.path.dirname(token_path)
            if token_directory:
                os.makedirs(token_directory, exist_ok=True)
            with open(token_path, "w", encoding="utf-8") as token_file:
                if self._token_format() == "json":
                    json.dump(refreshed_token_data, token_file)
                else:
                    token_file.write(access_token)

        if hasattr(self.authorizer, "token_string"):
            self.authorizer.token_string = access_token

        return refreshed_token_data

    def _get_authorization_header(self: "FerryCLI") -> Dict[str, str]:
        if (not self._is_authorization_enabled()) or (not self._is_token_auth_method()):
            return {}

        token_data = self._read_token_data_from_file()
        if self._token_is_expired(token_data):
            token_data = self._try_authenticate_with_file()
            if self._token_is_expired(token_data):
                raise RuntimeError("Token is still expired after refresh.")

        access_token = token_data.get("access_token") or token_data.get("token")
        if not access_token:
            raise RuntimeError(
                "Token file is missing access token data ('access_token' or 'token')."
            )

        if hasattr(self.authorizer, "token_string"):
            self.authorizer.token_string = access_token

        header_template = self._clean_config_value(
            self.configs.get("token-auth", "token_header", fallback="Bearer {token}")
        )
        try:
            authorization_value = header_template.format(token=access_token)
        except (KeyError, ValueError):
            authorization_value = f"Bearer {access_token}"

        # Keep output consistent with expected Bearer token semantics.
        if not authorization_value.startswith("Bearer "):
            authorization_value = f"Bearer {access_token}"

        return {"Authorization": authorization_value}

    def _build_ferry_api(
        self: "FerryCLI",
        debug_level: DebugLevel,
        dryrun: bool = False,
    ) -> "FerryAPI":
        api_kwargs: Dict[str, Any] = {
            "base_url": self.base_url,
            "authorizer": self.authorizer,
            "debug_level": debug_level,
            "dryrun": dryrun,
        }

        try:
            init_parameters = inspect.signature(FerryAPI.__init__).parameters
        except (TypeError, ValueError):
            init_parameters = {}

        if "auth_header_provider" in init_parameters:
            api_kwargs["auth_header_provider"] = self._get_authorization_header
        if "insecure" in init_parameters:
            api_kwargs["insecure"] = self.insecure

        return FerryAPI(**api_kwargs)

    def get_arg_parser(self: "FerryCLI") -> FerryParser:
        parser = FerryParser.create(
            description="CLI for Ferry API endpoints", parents=[get_auth_parser()]
        )
        parser.add_argument(
            "--output",
            default=None,
            help="(string) Specifies the path to a file where the output will be stored in JSON format. If a file already exists in the specified path, it will be overritten.",
        )
        parser.add_argument(
            "--filter",
            default=None,
            help="(string) Use to filter results on -le and -lw flags",
        )
        parser.add_argument(
            "-le",
            "--list_endpoints",
            "--list-endpoints",
            action=self.list_available_endpoints_action(),
            nargs=0,
            help="List all available endpoints",
        )
        parser.add_argument(
            "-lw",
            "--list_workflows",
            "--list-workflows",
            action=self.list_workflows_action(),  # type: ignore
            nargs=0,
            help="List all supported custom workflows",
        )
        parser.add_argument(
            "-ep",
            "--endpoint_params",
            "--endpoint-params",
            action=self.get_endpoint_params_action(),  # type: ignore
            help="List parameters for the selected endpoint",
        )
        parser.add_argument(
            "-wp",
            "--workflow_params",
            "--workflow-params",
            action=self.workflow_params_action(),  # type: ignore
            help="List parameters for the supported workflow",
        )
        parser.add_argument("-e", "--endpoint", help="API endpoint and parameters")
        parser.add_argument("-w", "--workflow", help="Execute supported workflows")
        parser.add_argument(
            "--show-config-file",
            action="store_true",
            help="Locate and print configuration file, if it exists, then exit.",
        )

        return parser

    def list_available_endpoints_action(self: "FerryCLI"):  # type: ignore
        endpoints = self.endpoints

        class _ListEndpoints(argparse.Action):
            def __call__(  # type: ignore
                self: "_ListEndpoints", parser, args, values, option_string=None
            ) -> None:
                filter_args = FerryCLI.get_filter_args()
                filter_str = (
                    f' (filtering for "{filter_args.filter}")'
                    if filter_args.filter
                    else ""
                )
                print(
                    f"""
                    Listing all supported endpoints{filter_str}':
                    """
                )
                for ep, subparser in endpoints.items():
                    if filter_args.filter:
                        if filter_args.filter.lower() in ep.lower():
                            print(subparser.description)
                    else:
                        print(subparser.description)
                sys.exit(0)

        return _ListEndpoints

    @staticmethod
    def get_filter_args() -> argparse.Namespace:
        filter_parser = FerryParser()
        filter_parser.set_arguments(
            [
                {
                    "name": "filter",
                    "description": "Filter by workflow title (contains)",
                    "type": "string",
                    "required": False,
                }
            ]
        )
        filter_args, _ = filter_parser.parse_known_args()
        return filter_args

    def list_workflows_action(self):  # type: ignore
        class _ListWorkflows(argparse.Action):
            def __call__(  # type: ignore
                self: "_ListWorkflows", parser, args, values, option_string=None
            ) -> None:
                filter_args = FerryCLI.get_filter_args()
                filter_str = (
                    f' (filtering for "{filter_args.filter}")'
                    if filter_args.filter
                    else ""
                )
                print(
                    f"""
                    Listing all supported workflows{filter_str}':
                    """
                )
                for name, workflow in SUPPORTED_WORKFLOWS.items():
                    if filter_args.filter:
                        if filter_args.filter.lower() in name.lower():
                            workflow().get_description()
                    else:
                        workflow().get_description()

                sys.exit(0)

        return _ListWorkflows

    def get_endpoint_params_action(self):  # type: ignore
        safeguards = self.safeguards
        ferrycli = self
        ferrycli_get_endpoint_params = self.get_endpoint_params

        class _GetEndpointParams(argparse.Action):
            def __call__(  # type: ignore
                self: "_GetEndpointParams", parser, args, values, option_string=None
            ) -> None:
                # Prevent DCS from running this endpoint if necessary, and print proper steps to take instead.
                ep, _ = ferrycli.resolve_endpoint(values)
                safeguards.verify(ep)
                ferrycli_get_endpoint_params(ep)
                sys.exit(0)

        return _GetEndpointParams

    def workflow_params_action(self):  # type: ignore
        class _WorkflowParams(argparse.Action):
            def __call__(  # type: ignore
                self: "_WorkflowParams", parser, args, values, option_string=None
            ) -> None:
                try:
                    # Finds workflow inherited class in dictionary if exists, and initializes it.
                    workflow = SUPPORTED_WORKFLOWS[values]()
                    workflow.init_parser()
                    workflow.get_info()
                    sys.exit(0)
                except KeyError:
                    # pylint: disable=raise-missing-from
                    raise KeyError(f"Error: '{values}' is not a supported workflow.")

        return _WorkflowParams

    def get_endpoint_params(self: "FerryCLI", endpoint: str) -> None:
        # pylint: disable=consider-using-f-string
        print(
            """
              Listing parameters for endpoint: %s%s"
              """
            % (self.base_url, endpoint)
        )
        subparser = self.endpoints.get(endpoint, None)
        if not subparser:
            print(
                # pylint: disable=consider-using-f-string
                """
                  Error: '%s' is not a valid endpoint. Run 'ferry -l' for a full list of available endpoints.
                  """
                % endpoint
            )
        else:
            print(subparser.format_help())
            print()

    @staticmethod
    def _build_template_match_pattern(
        endpoint_template: str,
    ) -> Optional[Tuple[re.Pattern, List[str]]]:
        pattern_parts: List[str] = []
        parameter_names: List[str] = []
        cursor = 0
        for match in re.finditer(r"{([^{}]+)}", endpoint_template):
            parameter_name = match.group(1).strip()
            if not parameter_name:
                return None

            pattern_parts.append(re.escape(endpoint_template[cursor : match.start()]))
            pattern_parts.append(r"([^/]+)")
            parameter_names.append(parameter_name)
            cursor = match.end()

        if not parameter_names:
            return None

        pattern_parts.append(re.escape(endpoint_template[cursor:]))
        return re.compile("^" + "".join(pattern_parts) + "$"), parameter_names

    def resolve_endpoint(self: "FerryCLI", raw_endpoint: str) -> Tuple[str, Dict[str, str]]:
        normalized_endpoint = normalize_endpoint(self.endpoints, raw_endpoint)
        if normalized_endpoint in self.endpoints:
            return normalized_endpoint, {}

        for endpoint_template in self.endpoints:
            template_pattern = self._build_template_match_pattern(endpoint_template)
            if not template_pattern:
                continue

            pattern, parameter_names = template_pattern
            match = pattern.match(raw_endpoint)
            if not match:
                continue

            extracted_path_params = {
                parameter_name: unquote(parameter_value)
                for parameter_name, parameter_value in zip(
                    parameter_names, match.groups()
                )
            }
            return endpoint_template, extracted_path_params

        return raw_endpoint, {}

    def execute_endpoint(
        self: "FerryCLI",
        endpoint: str,
        params: List[str],
        path_params: Optional[Dict[str, str]] = None,
    ) -> Any:
        request_path_params: Dict[str, str] = dict(path_params or {})
        try:
            subparser = self.endpoints[endpoint]
        except KeyError:
            raise ValueError(  # pylint: disable=raise-missing-from
                f"Error: '{endpoint}' is not a valid endpoint. Run 'ferry -l' for a full list of available endpoints."
            )
        else:
            parse_params = list(params)
            for parameter_name, parameter_value in request_path_params.items():
                param_flag = f"--{parameter_name}"
                if param_flag not in parse_params:
                    parse_params.extend([param_flag, str(parameter_value)])

            params_args, _ = subparser.parse_known_args(parse_params)
            request_params = vars(params_args)
            request_params.update(request_path_params)
            return self.ferry_api.call_endpoint(endpoint, params=request_params)  # type: ignore

    @staticmethod
    def _merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        merged = copy.deepcopy(base)
        for key, value in override.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = FerryCLI._merge_dicts(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

    @staticmethod
    def _resolve_ref_path(api_data: Dict[str, Any], ref_path: str) -> Dict[str, Any]:
        if not isinstance(ref_path, str) or not ref_path.startswith("#/"):
            return {}
        ref_obj: Any = api_data
        for part in ref_path[2:].split("/"):
            if not isinstance(ref_obj, dict):
                return {}
            ref_obj = ref_obj.get(part)
            if ref_obj is None:
                return {}
        return copy.deepcopy(ref_obj) if isinstance(ref_obj, dict) else {}

    def _resolve_refs_in_object(
        self: "FerryCLI",
        api_data: Dict[str, Any],
        obj: Dict[str, Any],
        seen_refs: Optional[set] = None,
    ) -> Dict[str, Any]:
        seen = set() if seen_refs is None else set(seen_refs)
        resolved_obj = copy.deepcopy(obj)
        ref_path = resolved_obj.get("$ref")
        if isinstance(ref_path, str) and ref_path not in seen:
            base_obj = self._resolve_ref_path(api_data, ref_path)
            if base_obj:
                seen.add(ref_path)
                base_obj = self._resolve_refs_in_object(api_data, base_obj, seen)
                resolved_obj.pop("$ref", None)
                resolved_obj = self._merge_dicts(base_obj, resolved_obj)

        for key, value in list(resolved_obj.items()):
            if isinstance(value, dict):
                resolved_obj[key] = self._resolve_refs_in_object(api_data, value, seen)
            elif isinstance(value, list):
                resolved_list: List[Any] = []
                for item in value:
                    if isinstance(item, dict):
                        resolved_list.append(
                            self._resolve_refs_in_object(api_data, item, seen)
                        )
                    else:
                        resolved_list.append(item)
                resolved_obj[key] = resolved_list

        return resolved_obj

    def _normalize_schema(
        self: "FerryCLI", api_data: Dict[str, Any], schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        normalized = self._resolve_refs_in_object(api_data, schema)

        if isinstance(normalized.get("allOf"), list):
            merged_schema: Dict[str, Any] = {}
            required_keys: List[str] = []
            for part in normalized["allOf"]:
                if isinstance(part, dict):
                    part_schema = self._normalize_schema(api_data, part)
                    merged_schema = self._merge_dicts(merged_schema, part_schema)
                    if isinstance(part_schema.get("required"), list):
                        required_keys.extend(
                            [k for k in part_schema["required"] if isinstance(k, str)]
                        )
            normalized = self._merge_dicts(
                merged_schema,
                {k: v for k, v in normalized.items() if k != "allOf"},
            )
            if required_keys:
                normalized["required"] = sorted(set(required_keys))

        for selector in ("oneOf", "anyOf"):
            selected = normalized.get(selector)
            if isinstance(selected, list) and selected:
                first_schema = selected[0]
                if isinstance(first_schema, dict):
                    resolved_first = self._normalize_schema(api_data, first_schema)
                    normalized = self._merge_dicts(
                        resolved_first,
                        {k: v for k, v in normalized.items() if k != selector},
                    )
                break

        properties = normalized.get("properties")
        if isinstance(properties, dict):
            normalized["properties"] = {
                k: self._normalize_schema(api_data, v)
                if isinstance(v, dict)
                else v
                for k, v in properties.items()
            }

        items = normalized.get("items")
        if isinstance(items, dict):
            normalized["items"] = self._normalize_schema(api_data, items)

        return normalized

    @staticmethod
    def _schema_type(schema: Optional[Dict[str, Any]]) -> str:
        if not isinstance(schema, dict):
            return "string"
        schema_type = schema.get("type")
        if isinstance(schema_type, str) and schema_type:
            return schema_type
        if isinstance(schema.get("enum"), list):
            return "string"
        if isinstance(schema.get("properties"), dict):
            return "object"
        if isinstance(schema.get("items"), dict):
            return "array"
        return "string"

    def _normalize_parameter(
        self: "FerryCLI",
        api_data: Dict[str, Any],
        raw_parameter: Dict[str, Any],
        fallback_name: Optional[str] = None,
        inherited_required: bool = False,
        default_description: str = "",
    ) -> Optional[Dict[str, Any]]:
        parameter = self._resolve_refs_in_object(api_data, raw_parameter)
        schema: Optional[Dict[str, Any]] = None
        if isinstance(parameter.get("schema"), dict):
            schema = self._normalize_schema(api_data, parameter["schema"])

        name = parameter.get("name") or fallback_name
        if not isinstance(name, str) or not name.strip():
            return None
        name = name.strip()

        param_type = parameter.get("type")
        if not isinstance(param_type, str) or not param_type:
            param_type = self._schema_type(schema)

        description = parameter.get("description")
        if (not isinstance(description, str)) or (not description.strip()):
            if schema and isinstance(schema.get("description"), str):
                description = schema["description"]
            elif default_description:
                description = default_description
            else:
                description = f"{name} parameter"

        required = bool(parameter.get("required", inherited_required))
        return {
            "name": name,
            "description": description,
            "type": param_type,
            "required": required,
        }

    def _extract_body_schema_parameters(
        self: "FerryCLI",
        api_data: Dict[str, Any],
        schema: Dict[str, Any],
        required: bool = False,
        default_description: str = "",
        fallback_name: str = "body",
    ) -> List[Dict[str, Any]]:
        normalized_schema = self._normalize_schema(api_data, schema)
        properties = normalized_schema.get("properties")
        required_properties = normalized_schema.get("required", [])

        if isinstance(properties, dict) and properties:
            property_required = (
                {k for k in required_properties if isinstance(k, str)}
                if isinstance(required_properties, list)
                else set()
            )
            out_parameters: List[Dict[str, Any]] = []
            for prop_name, prop_schema in properties.items():
                if not isinstance(prop_schema, dict):
                    continue
                param = self._normalize_parameter(
                    api_data=api_data,
                    raw_parameter={
                        "name": prop_name,
                        "schema": prop_schema,
                        "required": prop_name in property_required,
                    },
                    default_description=f"{prop_name} field",
                )
                if param:
                    out_parameters.append(param)
            if out_parameters:
                return out_parameters

        fallback_param = self._normalize_parameter(
            api_data=api_data,
            raw_parameter={"schema": normalized_schema, "required": required},
            fallback_name=fallback_name,
            inherited_required=required,
            default_description=default_description or f"{fallback_name} parameter",
        )
        return [fallback_param] if fallback_param else []

    def _extract_operation_parameters(
        self: "FerryCLI",
        api_data: Dict[str, Any],
        path_data: Dict[str, Any],
        operation_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        normalized_by_name: Dict[str, Dict[str, Any]] = {}

        path_parameters = path_data.get("parameters", [])
        op_parameters = operation_data.get("parameters", [])
        all_parameters = []
        if isinstance(path_parameters, list):
            all_parameters.extend(path_parameters)
        if isinstance(op_parameters, list):
            all_parameters.extend(op_parameters)

        for raw_param in all_parameters:
            if not isinstance(raw_param, dict):
                continue

            resolved_param = self._resolve_refs_in_object(api_data, raw_param)
            if (
                resolved_param.get("in") == "body"
                and isinstance(resolved_param.get("schema"), dict)
            ):
                body_params = self._extract_body_schema_parameters(
                    api_data=api_data,
                    schema=resolved_param["schema"],
                    required=bool(resolved_param.get("required", False)),
                    default_description=resolved_param.get("description", ""),
                    fallback_name=resolved_param.get("name", "body"),
                )
                for body_param in body_params:
                    normalized_by_name[body_param["name"]] = body_param
                continue

            normalized = self._normalize_parameter(
                api_data=api_data,
                raw_parameter=resolved_param,
            )
            if normalized:
                normalized_by_name[normalized["name"]] = normalized

        request_body = operation_data.get("requestBody")
        if isinstance(request_body, dict):
            resolved_request_body = self._resolve_refs_in_object(api_data, request_body)
            request_body_required = bool(resolved_request_body.get("required", False))
            request_body_description = resolved_request_body.get("description", "")
            content = resolved_request_body.get("content", {})
            if isinstance(content, dict):
                schema: Optional[Dict[str, Any]] = None
                for content_type in ("application/json", "application/*+json", "*/*"):
                    media_type_obj = content.get(content_type)
                    if isinstance(media_type_obj, dict) and isinstance(
                        media_type_obj.get("schema"), dict
                    ):
                        schema = media_type_obj["schema"]
                        break
                if schema is None:
                    for media_type_obj in content.values():
                        if isinstance(media_type_obj, dict) and isinstance(
                            media_type_obj.get("schema"), dict
                        ):
                            schema = media_type_obj["schema"]
                            break

                if schema:
                    body_params = self._extract_body_schema_parameters(
                        api_data=api_data,
                        schema=schema,
                        required=request_body_required,
                        default_description=request_body_description,
                    )
                    for body_param in body_params:
                        normalized_by_name[body_param["name"]] = body_param

        return list(normalized_by_name.values())

    def generate_endpoints(self: "FerryCLI") -> Dict[str, FerryParser]:
        endpoints = {}
        with open(f"{CONFIG_DIR}/swagger.json", "r") as json_file:
            api_data = json.load(json_file)
            for path, data in api_data["paths"].items():
                if not isinstance(data, dict):
                    continue
                endpoint = path[1:] if path.startswith("/") else path
                method = None
                if "get" in data:
                    method = "get"
                elif "post" in data:
                    method = "post"
                elif "put" in data:
                    method = "put"
                elif "delete" in data:
                    method = "delete"
                if not method:
                    continue

                operation_data = data.get(method, {})
                if not isinstance(operation_data, dict):
                    continue

                endpoint_description = (
                    operation_data.get("description")
                    or operation_data.get("summary")
                    or f"{method.upper()} {endpoint}"
                )
                endpoint_parser = FerryParser.create_subparser(
                    endpoint,
                    method=method.upper(),
                    description=endpoint_description,
                )

                params = self._extract_operation_parameters(
                    api_data=api_data,
                    path_data=data,
                    operation_data=operation_data,
                )
                if params:
                    endpoint_parser.set_arguments(params)
                endpoints[endpoint] = endpoint_parser

        return endpoints

    def parse_description(
        self: "FerryCLI", name: str, desc: str, method: Optional[str] = None
    ) -> str:
        description_lines = textwrap.wrap(desc, width=60)
        first_line = description_lines[0]
        rest_lines = description_lines[1:]
        endpoint_description = name
        method_char_count = 49 - len(f"({method})")
        endpoint_description = (
            f"{endpoint_description:<{method_char_count}} ({method}) | {first_line}\n"
        )
        for line in rest_lines:
            endpoint_description += f"{'':<50} | {line}\n"
        return endpoint_description

    def run(
        self: "FerryCLI",
        debug_level: DebugLevel,
        dryrun: bool,
        extra_args: Any,
    ) -> None:
        self.parser = self.get_arg_parser()
        args, endpoint_args = self.parser.parse_known_args(extra_args)

        debug = debug_level == DebugLevel.DEBUG
        if debug:
            print(f"Debug level: {debug_level}\nDryrun: {dryrun}")
            print_args = {
                f"{k}: {v}"
                for k, v in vars(args).items()
                if k not in ["debug_level", "dryrun"]  # We're passing these into run()
            }
            print(f"Args: {print_args} \n" f"Endpoint Args:  {endpoint_args}")
            print(f"Using FERRY base url: {self.base_url}")

        if not self.ferry_api:
            self.ferry_api = self._build_ferry_api(
                debug_level=debug_level,
                dryrun=dryrun,
            )

        if args.endpoint:
            # Prevent DCS from running this endpoint if necessary, and print proper steps to take instead.
            ep, path_params = self.resolve_endpoint(args.endpoint)
            self.safeguards.verify(ep)
            try:
                json_result = self.execute_endpoint(
                    ep, endpoint_args, path_params=path_params
                )
            except Exception as e:
                raise Exception(f"{e}")
            if not dryrun:
                self.handle_output(
                    json.dumps(json_result, indent=4), args.output, debug_level
                )

        elif args.workflow:
            try:
                # Finds workflow inherited class in dictionary if exists, and initializes it.
                workflow = SUPPORTED_WORKFLOWS[args.workflow]()
                workflow.init_parser()
                workflow_params, _ = workflow.parser.parse_known_args(endpoint_args)
                json_result = workflow.run(self.ferry_api, vars(workflow_params))  # type: ignore
                if (not dryrun) and json_result:
                    self.handle_output(
                        json.dumps(json_result, indent=4), args.output, debug_level
                    )
            except KeyError:
                raise KeyError(f"Error: '{args.workflow}' is not a supported workflow.")

        else:
            self.parser.print_help()

    def handle_output(
        self: "FerryCLI",
        output: str,
        output_file: str = "",
        debug_level: DebugLevel = DebugLevel.NORMAL,
    ) -> None:
        def error_raised(
            exception_type: Type[BaseException],
            message: str,
        ) -> None:
            message = f"{exception_type.__name__}\n" f"{message}"
            if debug_level != DebugLevel.QUIET:
                message += f"\nPrinting response instead: {output}"
            raise exception_type(message)

        if not output_file:
            if debug_level == DebugLevel.QUIET:
                return

            print_string = (
                f"Response: {output}" if (debug_level == DebugLevel.DEBUG) else output
            )
            print(print_string)
            return

        directory = os.path.dirname(output_file)
        if directory:
            try:
                os.makedirs(directory, exist_ok=True)
            except PermissionError:
                error_raised(
                    PermissionError,
                    f"Permission denied: Unable to create directory: {directory}",
                )
            except OSError as e:
                error_raised(OSError, f"Error creating directory: {e}")
        try:
            with open(output_file, "w") as file:
                file.write(output)
            if debug_level == DebugLevel.DEBUG:
                print(f"Output file: {output_file}")
            return
        except PermissionError:
            error_raised(
                PermissionError,
                f"Permission denied: Unable to write to file: {output_file}",
            )
        except IOError as e:
            error_raised(IOError, f"Error writing to file: {e}")
        except Exception as e:  # pylint: disable=broad-except
            error_raised(Exception, f"Error: {e}")

    @staticmethod
    def _sanitize_path(raw_path: str) -> str:
        """
        Normalizes a URL path:
        - Collapses multiple internal slashes
        - Ensures exactly one leading slash
        - Ensures exactly one trailing slash
        """
        cleaned = re.sub(r"/+", "/", raw_path.strip())
        return "/" + cleaned.strip("/") + "/" if cleaned else "/"

    @staticmethod
    def _sanitize_base_url(raw_base_url: str) -> str:
        """
        Ensures the base URL has a trailing slash **only if**:
        - It does not already have one
        - It does not include query or fragment parts

        Leaves URLs with query or fragment untouched.
        """
        parts = urlsplit(raw_base_url)

        # If query or fragment is present, return as-is
        if parts.query or parts.fragment:
            return raw_base_url

        # Normalize the path (ensure trailing slash)
        path = parts.path or "/"
        if not path.endswith("/"):
            path += "/"

        # Collapse multiple slashes in path
        path = re.sub(r"/+", "/", path)

        # Rebuild the URL with sanitized path
        sanitized_parts = SplitResult(
            scheme=parts.scheme, netloc=parts.netloc, path=path, query="", fragment=""
        )

        return urlunsplit(sanitized_parts)

    def __parse_config_file(self: "FerryCLI") -> configparser.ConfigParser:
        configs = configparser.ConfigParser()
        with open(self.config_path, "r") as f:
            configs.read_file(f)

        _base_url = configs.get("api", "base_url", fallback=None)
        if _base_url is None:
            raise ValueError(
                f"api.base_url must be specified in the config file at {self.config_path}. "
                "Please set that value and try again."
            )
        self.base_url = _base_url.strip().strip('"')

        _dev_url = configs.get("api", "dev_url", fallback=None)
        if _dev_url is not None:
            self.dev_url = _dev_url.strip().strip('"')

        return configs


def get_config_info_from_user() -> Dict[str, str]:
    print(
        "\nLaunching interactive mode to generate config file with user supplied values..."
    )

    # if we had a list of what all the keys should be I'd load that and we'd ask for each

    base_url = ""
    counter = 0

    while not validators.url(base_url):
        try:
            base_url = input("Enter the base url for Ferry/API endpoint: ")
        except KeyboardInterrupt:
            print(
                "\nKeyboardInterrupt.  Exiting without writing configuration file...\n"
            )
            sys.exit(1)

        if validators.url(base_url):
            break

        if counter >= 2:
            print("\nMultiple failures in specifying base URL, exiting...")
            sys.exit(1)

        print(
            "\nThis doesn't look like a valid URL, you need to specify the https:// part. Try again."
        )
        counter += 1

    return {"base_url": base_url}


def write_config_file_with_user_values() -> pathlib.Path:
    """
    Writes a configuration file with user-provided values.

    This function prompts the user to provide configuration values using the
    get_config_info_from_user function. It then writes out the configuration
    file using the provided values.

    Returns:
        pathlib.Path: The path to the written configuration file.
    """
    config_values = get_config_info_from_user()
    return config.write_out_configfile(config_values)

def handle_show_configfile(args: List[str]) -> None:
    """
    Handles the logic for displaying the configuration file path or generating it interactively.
    Otherwise, if the configfile exists, print it.  If not, try to create the configuration file from user input.
    """
    if not "--show-config-file" in args:
        return

    config_path = config.get_configfile_path()
    if config_path is None:
        # this is the case where path variable isn't set OR the file isn't found but the directory exists
        print(
            "No configuration file found.  Will attempt to create configuration file at $HOME/.config/ferry_cli/config.ini"
        )
        write_config_file_with_user_values()
        return

    if not config_path.exists():
        # Our config path is set, but the config file doesn't exist
        print(
            f"Based on the environment, would use configuration file: {str(config_path.absolute())}.  However, that path does not exist. Will now enter interactive mode to generate it."
        )
        write_config_file_with_user_values()
        return

    print(f"Configuration file: {str(config_path.absolute())}")
    return


def help_called(args: List[str]) -> bool:
    return "--help" in args or "-h" in args


def handle_no_args(_config_path: Optional[pathlib.Path]) -> bool:
    """
    Handles the case when no arguments are provided to the CLI.
    """
    write_configfile_prompt = "Would you like to enter interactive mode to write the configuration file for ferry-cli to use in the future (Y/[n])? "
    if (_config_path is not None) and (_config_path.exists()):
        write_configfile_prompt = f"Configuration file already exists at {_config_path}. Are you sure you want to overwrite it (Y/[n])?  "

    write_config_file = input(write_configfile_prompt)

    if write_config_file != "Y":
        FerryCLI(print_help=True)
        print("Exiting without writing configuration file.")
        sys.exit(0)

    print(
        "Will launch interactive mode to write configuration file.  If this was a mistake, just press Ctrl+C to exit."
    )
    write_config_file_with_user_values()
    sys.exit(0)


def normalize_endpoint(endpoints: Dict[str, Any], raw: str) -> str:
    # Extract and preserve a single leading underscore, if any
    leading_underscore = "_" if raw.startswith("_") else ""
    # Remove all leading underscores before processing
    stripped = raw.lstrip("_")
    # Convert to lowerCamelCase from snake_case or kebab-case
    parts = re.split(r"[_-]+", stripped)
    camel = parts[0].lower() + "".join(part.capitalize() for part in parts[1:])
    normalized = leading_underscore + camel
    # Match endpoint case-insensitively and replace original argument if found
    return next((ep for ep in endpoints if ep.lower() == normalized.lower()), raw)


# pylint: disable=too-many-branches
def main() -> None:
    _config_path = config.get_configfile_path()
    if len(sys.argv) == 1:
        # User just called python3 ferry-cli or ferry-cli with no arguments
        handle_no_args(_config_path)

    _help_called_flag = help_called(sys.argv)
    if not _help_called_flag:
        handle_show_configfile(sys.argv)

    # Set our config_path to use in FerryCLI instance
    config_path: Optional[pathlib.Path]
    if _help_called_flag:
        config_path = None
    elif (_config_path is not None) and (_config_path.exists()):
        config_path = _config_path
    else:
        config_path = write_config_file_with_user_values()
        print("\nConfiguration file set.\n")

    if config_path is None and not _help_called_flag:
        raise TypeError(
            "Config path could not be found.  Please check to make sure that the "
            "configuration file is located at $XDG_CONFIG_HOME/ferry_cli/config.ini "
            'or $HOME/.config/ferry_cli/config.ini. You can run "ferry-cli" with no '
            "arguments to generate a new configuration file interactively."
        )

    if _help_called_flag:
        FerryCLI(print_help=True)
        sys.exit(0)

    try:
        auth_args, other_args = get_auth_args()

        ferry_cli = FerryCLI(
            config_path=config_path,
            authorizer=set_auth_from_args(auth_args),
            base_url=auth_args.server,
            insecure=auth_args.insecure,
        )
        if auth_args.update or not os.path.exists(f"{CONFIG_DIR}/swagger.json"):
            if auth_args.debug_level != DebugLevel.QUIET:
                print("Fetching latest swagger file...")
            ferry_cli.ferry_api = ferry_cli._build_ferry_api(
                debug_level=auth_args.debug_level,
            )
            ferry_cli.ferry_api.get_latest_swagger_file()
            if auth_args.debug_level != DebugLevel.QUIET:
                print("Successfully stored latest swagger file.\n")
            if not other_args:
                if auth_args.debug_level != DebugLevel.QUIET:
                    print("No more arguments provided. Exiting.")
                sys.exit(0)

        if not other_args:
            ferry_cli.get_arg_parser().print_help()
            sys.exit(1)

        ferry_cli.endpoints = ferry_cli.generate_endpoints()
        ferry_cli.run(
            auth_args.debug_level,
            auth_args.dryrun,
            other_args,
        )
    except (
        Exception  # pylint: disable=broad-except
    ) as e:  # TODO Eventually we want to handle a certain set of exceptions, but this will do for now # pylint: disable=fixme
        print(f"An error occurred while using the FERRY CLI: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
