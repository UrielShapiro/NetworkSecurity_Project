from enum import Enum


class AbnormalityType(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    FLAGS_VIOLATION = "FLAGS_VIOLATION"
    HEADER_VIOLATION = "HEADER_VIOLATION"
    PAYLOAD_VIOLATION = "PAYLOAD_VIOLATION"
    ALERT = "ALERT"
    PORT_VIOLATION = "PORT_VIOLATION"
    TRANSACTION_VIOLATION = "TRANSACTION_VIOLATION"

    @property
    def __str__(self):
        if "_" in self.name:
            return self.name.replace("_", " ").title()
        return self.name

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.name)


class FlowAbnormality:
    def __init__(self, abnormality_type, description, level: AbnormalityType):
        self.abnormality_type = abnormality_type
        self.description = description
        self.level = level

    def get_level(self):
        return self.level.name

    def __str__(self):
        return f"{self.abnormality_type}: {self.description}"

    def __eq__(self, other):
        return self.abnormality_type == other.abnormality_type and self.description == other.description

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.abnormality_type, self.description, self.level))
