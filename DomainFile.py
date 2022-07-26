import json
import os
from os import listdir
from os.path import isfile, join
from typing import List


class NoFilesFound(Exception):
    pass


class IncorrectInput(Exception):
    pass


class DomainFile:
    path: str

    def __init__(self, path: str) -> None:
        self.path = path

    def read(self) -> [str]:
        """Reads the file and returns list of domains inside it"""

        with open(self.path) as f:
            file_input: dict = json.load(f)
        self.validate(file_input)

        return file_input["urls"]

    @staticmethod
    def validate(j: dict) -> None:
        """Validates if the input structure follows the expected contract"""

        urls: [str] = j.get("urls", None)
        if not urls:
            raise IncorrectInput("Key 'urls' must be provided")

        if not isinstance(urls, list):
            raise IncorrectInput("Value of 'urls' must be a list of strings")

        domain: str
        for domain in urls:
            if not isinstance(domain, str):
                raise IncorrectInput("Value of 'urls' must be a list of strings")

    def mark_checked(self) -> None:
        idx = self.path.index(".json")
        new_path = self.path[:idx] + ".done" + self.path[idx:]
        os.rename(self.path, new_path)


class DomainFileList:
    path: str

    def __init__(self, path: str) -> None:
        self.path = path

    def first(self) -> DomainFile:
        """Return the first unchecked file"""

        file_name = self.unchecked_files()[0]
        return DomainFile(join(self.path, file_name))

    def unchecked_files(self) -> [str]:
        """Reads all files in `self.path` and returns list of not checked. Raises `NoFilesFound` if none found"""

        files: filter[str] = filter(
            lambda f: isfile(join(self.path, f)), listdir(self.path)
        )
        unchecked_files: List[str] = list(
            filter(lambda f: not f.endswith(".done.json"), files)
        )
        if not unchecked_files:
            raise NoFilesFound("No unchecked files found")
        return unchecked_files
