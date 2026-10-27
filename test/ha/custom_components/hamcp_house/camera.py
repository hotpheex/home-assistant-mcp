from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    async_add_entities([Porch()])


class Porch(Camera):
    _attr_name = "E2E Camera"
    _attr_unique_id = "camera"

    async def async_camera_image(self, width: int | None = None, height: int | None = None) -> bytes | None:
        return None
