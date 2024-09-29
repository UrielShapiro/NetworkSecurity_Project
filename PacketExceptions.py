class TCPFlagsException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"TCPFlagsException: {self.message}"

class UDPPortException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"UDPPortException: {self.message}"

class MacAddressException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"MacAddressException: {self.message}"