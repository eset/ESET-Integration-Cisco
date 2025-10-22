import os
import typing as t

from integration.models import EnvVariables


class EnvVariablesCisco(EnvVariables):
    def __init__(self) -> None:
        super().__init__()
        self.__cisco_xdr_api_client_id: str = os.getenv("CISCO_XDR_API_CLIENT_ID", "")
        self.__cisco_xdr_api_client_password: str = os.getenv("CISCO_XDR_API_CLIENT_PASSWORD", "")

        self.cisco_region_map = {"us": "", "eu": "eu", "apjc": "apjc"}
        cisco_xdr_region: str = self.map_region(os.getenv("CISCO_XDR_API_REGION", ""))

        self.cisco_xdr_oauth_url: str = (
            f"https://visibility.{cisco_xdr_region}.amp.cisco.com/iroh/oauth2/token".replace("..", ".")
        )
        self.cisco_xdr_api_url: str = f"https://private.intel.{cisco_xdr_region}.amp.cisco.com/ctia/".replace("..", ".")

    def map_region(self, region_value: str) -> str:
        region_key = region_value.lower()
        try:
            return self.cisco_region_map[region_key]
        except KeyError:
            raise ValueError(
                f"Invalid Cisco XDR region value: {region_value} Allowed values {list(self.cisco_region_map.keys())}"
            )

    @property
    def cisco_xdr_api_client_id(self) -> t.Optional[str]:
        return self.__cisco_xdr_api_client_id

    @property
    def cisco_xdr_api_client_password(self) -> t.Optional[str]:
        return self.__cisco_xdr_api_client_password
