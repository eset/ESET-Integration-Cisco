import asyncio
import logging
import time

from integration.main import ServiceClient
from integration.models import Config, DataSource

from models_cisco import EnvVariablesCisco
from utils_cisco import LastDataTimeHandlerCisco, RequestSenderCisco, TransformerDataCisco


class ServiceClientCisco(ServiceClient):
    def __init__(self) -> None:
        super().__init__()

    def _get_config(self) -> Config:
        return Config("Cisco", "1.0.0")

    def _get_env_vars(self) -> EnvVariablesCisco:
        return EnvVariablesCisco()

    def _get_request_sender(self) -> RequestSenderCisco:
        return RequestSenderCisco(self.config, self.env_vars)

    def _get_transformer_data(self) -> TransformerDataCisco:
        return TransformerDataCisco(self.env_vars, self.request_sender)

    def _get_last_data_time_handler(self, data_source: DataSource) -> LastDataTimeHandlerCisco:
        return LastDataTimeHandlerCisco(data_source, self.env_vars.interval)


async def main() -> None:
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S"
    )
    service_client = ServiceClientCisco()
    while True:
        try:
            await asyncio.gather(service_client.run(), asyncio.sleep(service_client.env_vars.interval * 60))
        except Exception:
            await asyncio.sleep(3 * service_client.env_vars.interval * 60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Process interrupted by user. Exiting...")
