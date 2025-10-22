import hashlib
import typing as t
from datetime import datetime, timedelta

from integration.models_data import NetworkCommunication
from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

SEVERITY_MAPPING = {
    "SEVERITY_LEVEL_UNSPECIFIED": "Unknown",
    "SEVERITY_LEVEL_DIAGNOSTIC": "Info",
    "SEVERITY_LEVEL_INFORMATIONAL": "Info",
    "SEVERITY_LEVEL_LOW": "Low",
    "SEVERITY_LEVEL_MEDIUM": "Medium",
    "SEVERITY_LEVEL_HIGH": "High",
}

CISCO_SEVERITY_TO_DISPOSITION = {
    "Unknown": "Unknown",
    "Info": "Clean",
    "Low": "Common",
    "Medium": "Suspicious",
    "High": "Malicious",
}


class Observable(BaseModel):
    type: str
    value: str


class ObservedTime(BaseModel):
    start_time: str


class Targets(BaseModel):
    type: str = "endpoint"
    observables: list[Observable]
    observed_time: ObservedTime


class Sighting(BaseModel):
    source: str = Field(alias="providerName")
    sensor: str = Field(alias="category")
    title: str = Field(alias="displayName")
    short_description: str = Field(alias="typeName")
    count: int = Field(alias="groupSize")
    description: t.Optional[str] = Field(default="", alias="note")
    timestamp: str = Field(alias="TimeGenerated")
    occurTime: str = Field(default="", exclude=True)
    responses: t.Optional[list[t.Any]] = Field(default=None, exclude=True)
    severityLevel: str = Field(default="", exclude=True)
    networkCommunication: t.Optional[NetworkCommunication] = Field(default=None, exclude=True)
    deviceDisplayName: t.Optional[str] = Field(default=None, exclude=True)  # observable
    deviceUuid: t.Optional[str] = Field(default=None, exclude=True)  # observable
    objectHashSha1: str = Field(default="", exclude=True)  # observable
    objectName: str = Field(default="", exclude=True)  # observable
    objectUrl: str = Field(default="", exclude=True)  # observable
    processCommandline: t.Optional[str] = Field(default=None, exclude=True)  # observable
    processPath: t.Optional[str] = Field(default=None, exclude=True)  # observable
    userNameBase: t.Optional[str] = Field(default=None, exclude=True)  # observable
    detectionUuid: str = Field(default="", exclude=True)

    @staticmethod
    def adjust_lenght(value: str, max_length: int) -> str:
        return value[:max_length] if isinstance(value, str) else ""

    @field_validator("title", mode="before")
    def limit_title_length(cls, v: str) -> str:
        return cls.adjust_lenght(v, 1024)

    @field_validator("short_description", mode="before")
    def limit_short_description_length(cls, v: str) -> str:
        return cls.adjust_lenght(v, 2048)

    @field_validator("description", mode="before")
    def limit_description_length(cls, v: str) -> str:
        return cls.adjust_lenght(v, 5000)

    @staticmethod
    def create_observable(o_type: str, o_value: t.Optional[str]) -> t.Optional[Observable]:
        if o_value is None:
            return None
        val = str(o_value).strip()
        if not val:
            return None
        return Observable(type=o_type, value=val)

    @computed_field(return_type=list)
    def targets(self) -> list[Targets]:
        refs = []
        data = {
            "device": self.deviceUuid,
            "hostname": self.deviceDisplayName,
            "ip": (
                f"{self.networkCommunication.localIpAddress}:{self.networkCommunication.localPort}"
                if self.networkCommunication
                else ""
            ),
        }
        for observable_type, observable_value in data.items():
            observable_obj = self.create_observable(observable_type, observable_value)
            if observable_obj:
                refs.append(observable_obj)
        return (
            []
            if not refs
            else [Targets(type="endpoint", observables=refs, observed_time=ObservedTime(start_time=self.occurTime))]
        )

    @computed_field(return_type=list)
    def observables(self) -> list[Observable]:
        refs = []
        data = {
            "user": self.userNameBase,
            "sha1": self.objectHashSha1,
            "file_name": self.objectName,
            "file_path": self.processPath,
            "process_args": self.processCommandline,
            "url": self.objectUrl,
            "ip": (
                f"{self.networkCommunication.remoteIpAddress}:{self.networkCommunication.remotePort}"
                if self.networkCommunication
                else ""
            ),
        }
        for observable_type, observable_value in data.items():
            observable_obj = self.create_observable(observable_type, observable_value)
            if observable_obj:
                refs.append(observable_obj)
        return refs

    @computed_field(return_type=ObservedTime)
    def observed_time(self) -> ObservedTime:
        return ObservedTime(start_time=self.occurTime)

    @computed_field(return_type=str)
    def resolution(self) -> str:
        return str(self.responses or "")

    @computed_field(return_type=str)
    def severity(self) -> str:
        return SEVERITY_MAPPING.get(self.severityLevel, "Unknown")

    @computed_field(return_type=list)
    def external_references(
        self,
    ) -> list[dict[str, t.Any]]:
        refs = []
        for field in ["detectionUuid"]:
            if getattr(self, field):
                refs.append({"source_name": f"{field}", "description": getattr(self, field)})
        return refs


class Judgement(BaseModel):  # based on Sighting
    observable: Observable
    severity: str
    source: str
    timestamp: t.Optional[str]
    valid_time: dict[str, str]
    priority: int = 90
    confidence: str = "High"
    external_ids: list[str]

    @computed_field(return_type=str)
    def disposition_name(self) -> str:
        return CISCO_SEVERITY_TO_DISPOSITION.get(self.severity, "Unknown")


class Sightings(BaseModel):
    sightings: list[Sighting]


class Judgements(BaseModel):
    judgements: list[Judgement]


def current_date_plus_one_year() -> str:
    current_date = datetime.utcnow()
    try:
        new_date = current_date.replace(year=current_date.year + 1)
    except ValueError:
        new_date = current_date + timedelta(days=366)

    return new_date.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_string(input_string: str) -> str:
    sha256_hash = hashlib.sha256(input_string.encode("utf-8"))
    return sha256_hash.hexdigest()


def generate_external_id_judgement(observed_value: dict[str, t.Any]) -> str:
    return f"eset-judgement-{hash_string(f'|{observed_value}')}"


def create_valid_time(observable: Observable, observed_time: ObservedTime) -> dict[str, str]:
    valid_time = {"start_time": observed_time.start_time}
    return valid_time if observable.type == "sha1" else valid_time | {"end_time": current_date_plus_one_year()}


def create_judgements_from_sighting(sighting: Sighting, seen_ids: list[str]) -> t.Optional[Judgements]:
    observables: list[Observable] = t.cast(list[Observable], sighting.observables)

    if not observables:
        return None

    judgements = []
    for o in observables:
        external_id = generate_external_id_judgement(o.model_dump())
        if external_id not in seen_ids:
            seen_ids.append(external_id)
            j = Judgement(
                observable=o,
                severity=t.cast(str, sighting.severity),
                source=sighting.source,
                timestamp=sighting.timestamp,
                valid_time=create_valid_time(o, t.cast(ObservedTime, sighting.observed_time)),
                external_ids=[external_id],
            )
            judgements.append(j)

    return Judgements(judgements=judgements)


class IncidentTime(BaseModel):
    opened: str


class IncidentCisco(BaseModel):
    source: str = Field(alias="providerName")
    title: str = Field(alias="displayName")
    timestamp: str = Field(alias="TimeGenerated")
    severity: str
    status: str
    incident_time: IncidentTime
    confidence: str = "High"
    categories: list[str] = Field(alias="tags")
    source_description: str = Field(alias="description", exclude=True)
    metrics: t.Optional[dict[str, int]] = Field(default=None, exclude=True)
    assigneeUuid: t.Optional[str] = Field(default=None, exclude=True)
    triageDuration: t.Optional[str] = Field(default=None, exclude=True)
    detectionUuids: t.Optional[list[str]] = Field(default=None, exclude=True)
    deviceUuids: t.Optional[list[str]] = Field(default=None, exclude=True)
    resolveReason: t.Optional[str] = Field(default=None, exclude=True)
    uuid: t.Optional[str] = Field(default=None, exclude=True)

    @computed_field
    def scores(self) -> dict[str, int]:
        map_severity_to_global = {
            "Unknown": 0,
            "Low": 200,
            "Medium": 400,
            "High": 800,
        }
        return {"asset": 0, "ttp": 0, "probability": 0, "global": map_severity_to_global[getattr(self, "severity")]}

    @computed_field
    def description(self) -> str:
        extra_description = []
        for field in [
            "severity",
            "categories",
            "uuid",
            "assigneeUuid",
            "detectionUuids",
            "deviceUuids",
            "metrics",
            "triageDuration",
            "resolveReason",
        ]:
            if getattr(self, field):
                extra_description.append({f"{field}": getattr(self, field)})

        return self.adjust_lenght(f"{self.source_description}\n{extra_description}", 5000)

    @staticmethod
    def adjust_lenght(value: str, max_length: int) -> str:
        return value[:max_length] if isinstance(value, str) else ""

    @field_validator("title", mode="before")
    def limit_title_length(cls, v: str) -> str:
        return cls.adjust_lenght(v, 1024)

    @model_validator(mode="before")
    @classmethod
    def move_createTime(cls, data: dict[str, t.Any]) -> dict[str, t.Any]:
        if ct := data.pop("createTime", ""):
            data.setdefault("incident_time", {})["opened"] = ct
        return data

    @field_validator("severity", mode="before")
    @classmethod
    def map_severity(cls, v: str) -> str:
        severity_mapping = {
            "INCIDENT_SEVERITY_LEVEL_UNSPECIFIED": "Unknown",
            "INCIDENT_SEVERITY_LEVEL_LOW": "Low",
            "INCIDENT_SEVERITY_LEVEL_MEDIUM": "Medium",
            "INCIDENT_SEVERITY_LEVEL_HIGH": "High",
        }
        return severity_mapping.get(v, v)

    @field_validator("status", mode="before")
    @classmethod
    def map_status(cls, v: str) -> str:
        status_mapping = {
            "INCIDENT_STATUS_UNSPECIFIED": "New",
            "INCIDENT_STATUS_OPEN": "Open",
            "INCIDENT_STATUS_IN_PROGRESS": "Open: Investigating",
            "INCIDENT_STATUS_CLOSED": "Closed",
            "INCIDENT_STATUS_WAITING_FOR_INPUT": "Hold",
        }
        return status_mapping.get(v, v)

    @staticmethod
    def _prep_description(field_value: t.Any, description: str = "") -> t.Optional[str]:
        if isinstance(field_value, str):
            description = field_value
        elif isinstance(field_value, list):
            description = ", ".join(map(str, field_value))
        elif isinstance(field_value, dict):
            description = "; ".join(f"{k}={v}" for k, v in field_value.items())
        return description

    @computed_field(return_type=list)
    def external_references(self) -> list[dict[str, t.Any]]:
        refs = []
        for field in [
            "uuid",
            "assigneeUuid",
            "detectionUuids",
            "deviceUuids",
            "metrics",
            "triageDuration",
            "resolveReason",
        ]:
            if getattr(self, field):
                refs.append({"source_name": f"{field}", "description": self._prep_description(getattr(self, field))})
        return refs


class IncidentsCisco(BaseModel):
    incidents: list[IncidentCisco]
