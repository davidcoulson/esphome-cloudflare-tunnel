import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_PATH
from esphome.components.esp32 import (
    add_idf_component,
    add_idf_sdkconfig_option,
    include_builtin_idf_component,
)

CODEOWNERS = []
DEPENDENCIES = ["network"]
AUTO_LOAD = []

cloudflare_tunnel_ns = cg.esphome_ns.namespace("cloudflare_tunnel")
CloudflareTunnel = cloudflare_tunnel_ns.class_("CloudflareTunnel", cg.Component)

CONF_TOKEN = "token"
CONF_HOSTNAME = "hostname"
CONF_STREAMS = "application_streams"
CONF_UPSTREAM_PORT = "upstream_port"
CONF_PAGES = "pages"
CONF_CONTENT = "content"
CONF_CONTENT_TYPE = "content_type"

PAGE_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_PATH): cv.string_strict,
        cv.Required(CONF_CONTENT): cv.string_strict,
        cv.Optional(CONF_CONTENT_TYPE, default="text/plain; charset=utf-8"): cv.string_strict,
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(CloudflareTunnel),
            cv.Required(CONF_TOKEN): cv.string_strict,
            cv.Required(CONF_HOSTNAME): cv.domain,
            cv.Optional(CONF_STREAMS, default=4): cv.one_of(2, 4, int=True),
            cv.Optional(CONF_UPSTREAM_PORT, default=80): cv.int_range(min=0, max=65535),
            cv.Optional(CONF_PAGES, default=[]): cv.ensure_list(PAGE_SCHEMA),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_token(config[CONF_TOKEN]))
    cg.add(var.set_hostname(config[CONF_HOSTNAME]))
    cg.add(var.set_streams(config[CONF_STREAMS]))
    cg.add(var.set_upstream_port(config[CONF_UPSTREAM_PORT]))
    for page in config[CONF_PAGES]:
        cg.add(var.add_page(page[CONF_PATH], page[CONF_CONTENT_TYPE], page[CONF_CONTENT]))

    include_builtin_idf_component("esp-tls")
    include_builtin_idf_component("json")
    add_idf_component(name="espressif/nghttp", ref="1.68.1")
    # The edge requires TLS 1.3.
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_SSL_PROTO_TLS1_3", True)
