import asyncio
import logging
import typing as t
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from aiohttp import ClientSession
from integration.exceptions import AuthenticationException
from integration.models import Config, DataSource, EnvVariables
from integration.utils import LastDataTimeHandler, RequestSender, TransformerData
from pydantic import ValidationError

from models_cisco import EnvVariablesCisco
from models_data_cisco import IncidentCisco, IncidentsCisco, Sighting, Sightings, create_judgements_from_sighting


class RequestSenderCisco(RequestSender):
    def __init__(self, config: Config, env_vars: EnvVariablesCisco) -> None:
        super().__init__(config, env_vars)

    async def get_cisco_token(self, session: ClientSession, header: dict[str, str], *args: t.Any) -> tuple[t.Any, str]:
        assert isinstance(self.env_vars, EnvVariablesCisco)
        async with session.post(
            url=self.env_vars.cisco_xdr_oauth_url,
            headers=header,
            data={
                "grant_type": "client_credentials",
                "client_id": self.env_vars.cisco_xdr_api_client_id,
                "client_secret": self.env_vars.cisco_xdr_api_client_password,
            },
            timeout=self.config.requests_timeout,
        ) as response:
            response_json = await response.json()
            if response.status >= 400:
                logging.info(f"Response status: {response.status} Response text: {response.text}")
                response.raise_for_status()
            return response_json, response.headers["Date"]

    async def send_cisco_request_post_data(
        self, session: ClientSession, header: dict[str, str], endp: str, data_to_send: dict[str, t.Any]
    ) -> t.Union[bool, None]:
        assert isinstance(self.env_vars, EnvVariablesCisco)

        async with session.post(
            url=f"{self.env_vars.cisco_xdr_api_url}bundle/import",
            headers=header,
            json=data_to_send,
            params={"wait_for": "true"},
            timeout=self.config.requests_timeout,
        ) as response:
            response_json = await response.json()
            if response.status in [200, 201]:
                count_created = (
                    sum(1 for k in response_json["results"] if k.get("result") == "created")
                    if response_json and response_json.get("results")
                    else 0
                )
                logging.info(f"Data {endp} sent successfully to Cisco. Created: {count_created}.")
                return True
            if response.status >= 400:
                logging.warning(
                    f"Sending data do Cisco failed. Response status: {response.status} Response text: {response.text}. Response json: {response_json}"
                )
                response.raise_for_status()
                return False
            return None


class TransformerDataCisco(TransformerData):
    def __init__(self, env_vars: EnvVariables, req_sender: RequestSenderCisco) -> None:
        super().__init__(env_vars)
        self.req_sender = req_sender
        self.cisco_api_token: str = ""
        self.cisco_token_expiry: datetime = datetime.utcnow()

    async def _send_data_to_destination(
        self,
        validated_data: t.List[dict[str, t.Any]],
        last_data: str | None,
        endp: str = "",
        lock: t.Optional[asyncio.Lock] = None,
        session: t.Optional[ClientSession] = None,
    ) -> tuple[str | None, bool]:

        if "incidents" in endp:
            last_data = max(validated_data, key=lambda data: data.get("createTime") or "").get("createTime")

        cisco_data = await self.map_data_to_cisco_format(validated_data, endp)

        assert session and lock
        async with lock:
            await self.get_cisco_token_if_needed(session, endp)

        if not self.cisco_api_token or datetime.utcnow() > self.cisco_token_expiry or not cisco_data:
            return last_data, False

        data_bundle = self.prepare_data_bundle(cisco_data, endp)

        try:
            response = await self.req_sender.send_request(
                self.req_sender.send_cisco_request_post_data,
                session,
                {"Authorization": f"Bearer {self.cisco_api_token}", "Content-Type": "application/json"},
                endp,
                data_bundle,
            )
            if not response:
                return last_data, False
        except AuthenticationException:
            logging.error("Sending data to Cisco failed.")
            return last_data, False
        except Exception as e:
            logging.error(f"Sending data to Cisco failed from unexpected reason: {e}.")
            return last_data, False

        if "incidents" in endp:
            last_data = max(cisco_data.incidents, key=lambda data: data.incident_time.opened or "").incident_time.opened
        return last_data, True

    async def get_cisco_token_if_needed(self, session: ClientSession, endp: str) -> None:
        if not self.cisco_api_token or datetime.utcnow() > self.cisco_token_expiry:
            response: t.Any = await self.req_sender.send_request(
                self.req_sender.get_cisco_token,
                session,
                {"Content-Type": "application/x-www-form-urlencoded"},
                endp,
            )
            if response:
                response_json, exp_date = response
                self.cisco_api_token = response_json.get("access_token", "")
                self.cisco_token_expiry = datetime.strptime(exp_date, "%a, %d %b %Y %H:%M:%S GMT") + timedelta(
                    seconds=response_json.get("expires_in") - 15
                )
            else:
                logging.error("Failed to obtain Cisco API token.")

    async def map_data_to_cisco_format(
        self, validated_data: t.List[dict[str, t.Any]], endp: str
    ) -> t.Union[IncidentsCisco, Sightings, None]:
        data_key, data_model = ("incidents", IncidentsCisco) if "incidents" in endp else ("sightings", Sightings)
        try:
            return data_model.model_validate({data_key: validated_data})
        except ValidationError as e:
            logging.error(e)

            validated_data_list = []
            single_data_model: type[t.Union[Sighting, IncidentCisco]] = (
                Sighting if data_model == Sightings else IncidentCisco
            )

            for data in validated_data:
                try:
                    validated_data_list.append(single_data_model.model_validate(data))
                except ValidationError as e:
                    logging.error(e)

            return None if not validated_data_list else data_model.model_validate({data_key: validated_data_list})

    def prepare_data_bundle(self, cisco_data: t.Union[IncidentsCisco, Sightings], endp: str) -> dict[str, t.Any]:
        bundle: dict[str, t.Any] = {"source": "ESET"}

        if "incidents" in endp:
            bundle.update(cisco_data.model_dump())
        else:
            seen_ids: list[str] = []
            judgements_all_dumped = []
            for sighting in cisco_data.sightings:
                jfs = create_judgements_from_sighting(sighting, seen_ids)
                if jfs:
                    judgements_all_dumped.extend(jfs.model_dump().get("judgements"))

            if judgements_all_dumped:
                bundle.update({"judgements": judgements_all_dumped})
            bundle.update({"sightings": cisco_data.model_dump().get("sightings")})

        return bundle


class LastDataTimeHandlerCisco(LastDataTimeHandler):
    def __init__(self, data_source: DataSource, interval: int) -> None:
        self.file_name = "last_detection_time.yml"
        super().__init__(data_source, interval)

    def get_last_data_time(self, data_source: DataSource, interval: int = 5) -> tuple[str, str]:
        try:
            self.ldt = yaml.safe_load(Path(__file__).absolute().parent.joinpath(self.file_name).read_bytes())
        except FileNotFoundError as e:
            logging.error(e)
            raise FileNotFoundError(f"The {self.file_name} file is not found.")

        self.verify_last_data_time_from_file(data_source)

        if data_source == DataSource.INCIDENTS and self.ldt.get(data_source.name) == "":
            return (datetime.now(timezone.utc) - timedelta(minutes=10 * interval)).strftime("%Y-%m-%dT%H:%M:%SZ"), ""

        return self.ldt.get(data_source.name), self.ldt.get(f"{data_source.name}_NPT", "")

    def verify_last_data_time_from_file(self, data_source: DataSource) -> None:
        if not self.ldt:
            logging.info("The last detection time file is empty.")
            self.ldt = {"EP": "", "EI_ECOS": "", "EP_NPT": "", "EI_ECOS_NPT": "", "INCIDENTS": ""}
        if self.ldt.get(data_source.name) == None:
            self.ldt[data_source.name] = ""

    async def update_last_data_time(
        self, cur_ld_time: t.Optional[str], next_page_token: t.Optional[str], data_source: DataSource
    ) -> None:
        self.get_last_data_time(data_source)
        updates: dict[str, t.Any] = {}

        if data_source == DataSource.INCIDENTS:
            if cur_ld_time and cur_ld_time != self.last_data_time:
                updates[data_source.name] = self.prepare_date_plus_timedelta(cur_ld_time)
        else:
            if next_page_token and next_page_token != self.next_page_token:
                updates[f"{data_source.name}_NPT"] = next_page_token
            elif cur_ld_time and cur_ld_time != self.last_data_time:
                updates.update({data_source.name: cur_ld_time, f"{data_source.name}_NPT": next_page_token})

        if updates:
            self.ldt.update(updates)
            with open(Path(__file__).absolute().parent.joinpath(self.file_name), "w") as file:
                yaml.safe_dump(self.ldt, file, default_flow_style=False, sort_keys=False)
            logging.info(f"Updated {self.file_name} file for {data_source}.")
