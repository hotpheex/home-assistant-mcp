"""The e2e's fixed house, since no built-in integration makes config entities and child devices without hardware.

A hub with two child devices, a plug whose hidden and config entities share its area, and a camera and an image
whose entity_picture carries a bearer token.
"""

from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.typing import ConfigType

DOMAIN = "hamcp_house"
PLATFORMS = [Platform.BUTTON, Platform.CAMERA, Platform.IMAGE, Platform.SWITCH]
CONFIG_SCHEMA = cv.empty_config_schema(DOMAIN)
PLUG = DeviceInfo(identifiers={(DOMAIN, "plug")}, name="E2E Plug")


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    hass.async_create_task(
        hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_IMPORT}, data={})
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    # A child device's parent must already be registered by the same config entry.
    hub = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={(DOMAIN, "hub")}, name="E2E Hub"
    )
    entry.runtime_data = hub.id
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True
