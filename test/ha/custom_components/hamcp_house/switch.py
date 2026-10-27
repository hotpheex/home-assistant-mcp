from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import ChildDeviceInfo, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import DOMAIN, PLUG


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    def outlet(key: str, name: str) -> ChildDeviceInfo:
        return ChildDeviceInfo(identifiers={(DOMAIN, key)}, name=name, parent_device_id=entry.runtime_data)

    async_add_entities(
        [
            Switch("outlet_a", outlet("outlet_a", "Outlet A")),
            Switch("outlet_b", outlet("outlet_b", "Outlet B")),
            Switch("plug", PLUG),
            Switch("plug_led", PLUG, "LED", visible=False),
            Switch("plug_child_lock", PLUG, "Child lock", category=EntityCategory.CONFIG),
        ]
    )


class Switch(SwitchEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_is_on = False

    def __init__(
        self,
        unique_id: str,
        device: DeviceInfo | ChildDeviceInfo,
        name: str | None = None,
        visible: bool = True,
        category: EntityCategory | None = None,
    ) -> None:
        self._attr_unique_id = unique_id
        self._attr_device_info = device
        self._attr_name = name
        self._attr_entity_registry_visible_default = visible
        self._attr_entity_category = category

    async def async_turn_on(self, **kwargs: Any) -> None:
        self._attr_is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        self._attr_is_on = False
        self.async_write_ha_state()
