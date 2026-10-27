from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import PLUG


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    async_add_entities([Restart()])


class Restart(ButtonEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_name = "Restart"
    _attr_unique_id = "plug_restart"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_device_info = PLUG

    async def async_press(self) -> None:
        pass
