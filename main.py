import dataclasses
import logging
import os

from dotenv import load_dotenv

from DomainFile import DomainFileList, NoFilesFound
from SubProcessInputOutputHandler import SubProcessInputOutputHandler
from VirusTotalAdapter import VirusTotalAdapter

load_dotenv()

logger = logging.getLogger(__name__)


def main():

    api_key = os.getenv("API_KEY")
    if not api_key:
        # https://developers.virustotal.com/v3.0/reference#overview
        logger.error("environment variable API_KEY must be provided")
        exit(1)

    io_mgr = SubProcessInputOutputHandler()
    try:
        params = io_mgr.connector_params
        first_file = DomainFileList(params.source_folder_path).first()
        domains = first_file.read()
        adapter = VirusTotalAdapter(api_key)

        result = {}

        for i in range(min(len(domains), params.iteration_entities_count)):
            res = adapter.scan(domains[i])
            result[domains[i]] = dataclasses.asdict(res)

        first_file.mark_checked()
        io_mgr.end(result)

    except NoFilesFound:
        logger.info("No files to check")
        io_mgr.end({})

    except Exception as e:
        logger.error(e)
        exit(1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s [%(levelname)s] - "
            "(%(filename)s).%(funcName)s:%(lineno)d - %(message)s"
        ),
    )
    main()
