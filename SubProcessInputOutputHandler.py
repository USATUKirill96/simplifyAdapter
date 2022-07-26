import argparse
from typing import Dict

from DataModels import ConnectorParams


class InputError(Exception):
    pass


class SubProcessInputOutputHandler(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("source_folder_path", metavar="sf", type=str)
        self.parser.add_argument("iteration_entities_count", metavar="i", type=int)

    @property
    def connector_params(self) -> ConnectorParams:
        args = self.parser.parse_args()
        result = ConnectorParams(
            source_folder_path=args.source_folder_path,
            iteration_entities_count=args.iteration_entities_count,
        )
        if not isinstance(result.source_folder_path, str):
            raise InputError("Source path must be a string")

        if not isinstance(result.iteration_entities_count, int):
            raise InputError("Iteration count must be an integer")

        if result.iteration_entities_count <= 0:
            raise InputError("Iteration count must be greater than 0")

        return result

    @staticmethod
    def end(connector_result: Dict[str, dict]):
        """connector_result is of type ConnectorResult"""
        for k in connector_result:
            print(k, connector_result[k])
        exit()
