"""Expected, operator-facing Toolbox failures."""


class ToolboxError(Exception):
    """Base class for failures that may be safely shown to an operator."""


class InputError(ToolboxError):
    pass


class CapabilityError(ToolboxError):
    pass


class TransportError(ToolboxError):
    pass


class DependencyError(ToolboxError):
    """A required local runtime dependency is unavailable."""

    pass


class PanoramaResponseError(TransportError):
    pass


class OutcomeUnknownError(TransportError):
    """A mutating request timed out after dispatch and must not be replayed."""

    pass


class SessionError(ToolboxError):
    pass


class IntegrityError(SessionError):
    pass


class ConflictError(ToolboxError):
    pass


class ValidationError(ToolboxError):
    pass
