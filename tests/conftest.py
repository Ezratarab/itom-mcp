import pytest

from itom_mcp.config import load_settings

INSTANCE = "https://dev1.service-now.com"
API = f"{INSTANCE}/api/now"


def make_settings(**overrides):
    env = {
        "SERVICENOW_INSTANCE_URL": INSTANCE,
        "SERVICENOW_USERNAME": "itom.user",
        "SERVICENOW_PASSWORD": "S3cr3t-P@ss",
        "RATE_LIMIT_PER_MINUTE": "1000",
    }
    env.update({k: str(v) for k, v in overrides.items()})
    return load_settings(env)


@pytest.fixture
def settings():
    return make_settings()


async def call(mcp, name, args=None):
    """Call a tool through FastMCP's tool manager (validates args like a real client call)."""
    return await mcp._tool_manager.call_tool(name, args or {}, convert_result=False)
