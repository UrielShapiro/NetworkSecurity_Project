from enum import Enum


class AbnormalityType(Enum):
    INFO = 1
    WARNING = 2
    FLAGS_VIOLATION = 3
    HEADER_VIOLATION = 4
    PAYLOAD_VIOLATION = 5
    ALERT = 6
    PORT_VIOLATION = 7
    TRANSACTION_VIOLATION = 8

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

    def __str__(self):
        return f"{self.abnormality_type}: {self.description}"

    def __eq__(self, other):
        return self.abnormality_type == other.abnormality_type and self.description == other.description

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.abnormality_type, self.description, self.level))
