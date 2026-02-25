# pylint: disable=invalid-name,arguments-differ,unused-import
import os
from re import sub
import re
import sys
import subprocess
from typing import Any, Dict, Optional
import json
try:
    from ferry_cli.helpers.api import FerryAPI
    from ferry_cli.helpers.auth import DebugLevel
    from ferry_cli.helpers.workflows import Workflow
except ImportError:
    from helpers.api import FerryAPI  # type: ignore
    from helpers.auth import DebugLevel  # type: ignore
    from helpers.workflows import Workflow  # type: ignore


class GetDriveConfigurations(Workflow):
    def __init__(self: "GetDriveConfigurations") -> None:
        self.name = "getDriveConfigurations"
        self.method = "GET"
        self.description = "Retrieves the configurations of drives based on the specified parameters."
        self.params = [
            {
                "name": "prefix",
                "description": "The library prefix for drive names, e.g., 'F1_', 'G3_'",
                "type": "string",
                "required": True,
            },
            {
                "name": "partition",
                "description": "The partition the drives belong to",
                "type": "string",
                "required": True,
            },
            {
                "name": "suffix",
                "description": "The suffix for drive names, e.g., '_DEV', '_ITB'",
                "type": "string",
                "required": False
            },
            {
                "name": "drivesPerNode",
                "description": "The number of drives per node",
                "type": "integer",
                "required": False,
            }
        ]
        super().__init__()
        self.nodes = self._fetch_nodes()
        self.api: "FerryAPI" = None
    
    def _fetch_nodes(self) -> list[str]:
        if os.path.exists("/root/.config/nodes.json"):
            with open(os.path.expanduser("~/.config/nodes.json"), "r") as f:
                self.nodes = json.load(f).get("nodes", [])
                return self.nodes
        # This is a placeholder function. The actual implementation would depend on how the nodes are retrieved from the API.
        self.nodes = []
        return self.nodes

    def _set_drive_name(self, base:str, args: Any) -> Dict[str, str]:
        parts = base.replace("Drive:", "").split(":")
        drive_name = args.get("prefix", "")
        if len(parts) > 0:
            drive_name += f"F{parts[0]}"
        if len(parts) > 1:
            drive_name += f"B{parts[1]}"
        if len(parts) > 2:
            drive_name += f"D{parts[2]}"
        return {"DriveName": drive_name}
    
    def _set_library_name(self, generation:str, args: Any) -> Dict[str, str]:
        return {
            "DriveDevice": '',
            "DriveLogicalLibrary": f"{args['prefix']}{generation.replace('-', '')}{args.get('suffix', '')}"
        }
    
    def _set_calculated_fields(self, element_address: int, sn:str) -> Dict[str, str]:
        return {
            "DriveDevice": '',
            "SN": str(sn),
            "DriveControlPath": (
                f"echo $(cta-smc -q D | awk '$2 == {element_address} {{ print \"smc\"$1 }}')"
            ),
            "DriveDevice_v5.11": (
                f"ls /dev/tape/by-id/scsi-* | grep -i '{sn}-nst'"
            )
        }
    
    def _set_drive_position(self, position) -> Dict[str, str]:
        # This is a placeholder function. The actual implementation would depend on how the position is determined from the drive information.
        return {"Position": f"T{position}"}
    
    def _generate_base_config(self, drive: Dict[str, Any], args: Any) -> Dict[str, str]:
        config = {}
        config.update(self._set_drive_name(drive['name'], args))
        config.update(self._set_library_name(drive['generation'], args))
        if "physicalDrive" in drive:
            config.update(self._set_calculated_fields(
                drive.get('address', 0),
                drive['physicalDrive'].get('serialNumber', ''),
            ))
        return config
    
    def _run_calculations_on_node(self, node, data) -> list[Dict[str, str]]:
        retval = []
        try:
            items = data["all"]
            for item in items:
                success = True
                print(f"Running calculations on node {node} for item with SN {item.get('SN', 'N/A')}")
                for field in ["DriveControlPath", "DriveDevice_v5.11"]:
                    try:
                        cmd = item.get(field)
                        if cmd:
                            result = subprocess.run(
                                ["ssh", f"root@{node}", cmd],
                                capture_output=True,
                                text=True,
                                check=True,
                            )
                            item[field] = result.stdout.strip()
                    except subprocess.CalledProcessError as e:
                        success = False
                        continue
                if success:
                    if self.api.debug_level != DebugLevel.QUIET:
                        print(f"\tPassed")
                    retval.append(item)
                else:
                    if self.api.debug_level != DebugLevel.QUIET:
                        print(f"\tFailed")
        except Exception as e:
            if self.api.debug_level != DebugLevel.QUIET:
                print(f"An error occurred while running calculations on node {node}: {e}")
            raise

        return retval
            
        
    def run(self: "GetDriveConfigurations", api: "FerryAPI", args: Any) -> Any:  # type: ignore # pylint: disable=arguments-differ,too-many-branches
        # Get all drive configurations and filter based on the provided parameters
        self.api = api
        if api.dryrun:
            print(
                "WARNING:  This workflow is being run with the --dryrun flag.  The exact steps shown here may differ since "
                "some of the workflow steps depend on the output of API calls."
            )
        try:
            if args.get("suffix") in [None, 'None']:
                args['suffix'] = ''
            if args.get('drivesPerNode') in [None, 'None']:
                args['drivesPerNode'] = 4
            drives = {}
            data = self.verify_output(
                api, api.call_endpoint("partitions", method="GET")
            )
            if isinstance(data, dict):
                drives = {
                    drive['name']: drive 
                    for drive in data.get("drives", [])
                    if "partition" in drive 
                    and drive["partition"] == args["partition"]
            }
            elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
                for item in data:
                    if "drives" in item and isinstance(item["drives"], list):
                        drives = {
                            drive['name']: drive 
                            for drive in item["drives"]
                            if "partition" in drive 
                            and drive["partition"] == args["partition"]
                        }
            else:
                print("Unexpected data format received from API:")
                print(json.dumps(data, indent=2))
                raise RuntimeError("API response did not contain expected drive information")
            
            retval = {
                "all": []
            }
            
            # create base config for each drive and distribute them across nodes based on the drivesPerNode parameter
            for drive in drives.values():
                config = self._generate_base_config(drive, args)
                retval["all"].append(config)
            
            # process calculated fields on each node and filter out any configs that are missing fields after processing
            if self.nodes and len(self.nodes) > 0:
                node = self.nodes[0]
                retval['all'] = self._run_calculations_on_node(node, retval)
            
            position = 0
            current_node_index = 0
            drives_per_node = int(args.get("drivesPerNode", 4))
            
            # Distribute configs across nodes based on the drivesPerNode parameter
            for config in retval["all"]:
                if drives_per_node and self.nodes:
                    if current_node_index < len(self.nodes):
                        node = self.nodes[current_node_index]
                        if node not in retval:
                            retval[node] = []
                        config.update(self._set_drive_position(position))
                        retval[node].append(config)
                        position += 1
                        if position >= drives_per_node:
                            current_node_index += 1
                            position = 0
                    else:
                        break
                        
            print(json.dumps(retval, indent=2))
            if api.debug_level != DebugLevel.QUIET:
                print(
                    f"Retrieved configurations for {len(retval)} drives in partition {args['partition']} with prefix {args['prefix']} and suffix {args.get('suffix', '')}"
                )
            sys.exit(0)
        except Exception as e:
            print(f"An error occurred while executing the workflow: {e}")
            raise e
