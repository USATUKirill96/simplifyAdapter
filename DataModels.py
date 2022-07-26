import dataclasses
from typing import Any, Dict


@dataclasses.dataclass
class ConnectorParams(object):
    source_folder_path: str = None  # file path for entity list files
    iteration_entities_count: int = (
        None  # how many entities to process each interval (ignore the rest)
    )


@dataclasses.dataclass
class ConnectorSettings(object):
    run_interval_seconds: int = (
        None  # iterations interval in seconds for current connector
    )
    script_file_path: str = None  # the file path to the connector script
    connector_name: str = None  # connector name
    params: ConnectorParams = None  # see below
    output_folder_path: str = None  # file path for connector output


@dataclasses.dataclass
class ConnectorResult(object):
    alerts: Dict[
        str, Any
    ] = None  # connector output with data per entity. Key = Entity, value = entity data
