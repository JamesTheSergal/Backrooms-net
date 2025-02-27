import dataclasses

@dataclasses.dataclass(frozen=True, order=True)
class BaseAddonHeader:
    addonName = str
    addonVersion = str
    author = str
    website = str
    internalModule = bool