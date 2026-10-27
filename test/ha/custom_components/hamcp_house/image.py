from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    async_add_entities([Snapshot(hass)])


class Snapshot(ImageEntity):
    _attr_name = "E2E Image"
    _attr_unique_id = "image"
    _attr_content_type = "image/png"

    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__(hass)
        self._attr_image_last_updated = dt_util.utcnow()

    async def async_image(self) -> bytes | None:
        return None
