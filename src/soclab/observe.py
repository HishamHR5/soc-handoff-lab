"""Optional: send traces to Arize Phoenix (http://localhost:6006).

Install:  pip install -r requirements-phoenix.txt
Start  :  phoenix serve
Then set phoenix.enabled: true in config/settings.yaml.
"""


def setup_phoenix(settings: dict) -> None:
    if not settings.get("phoenix", {}).get("enabled"):
        return
    from phoenix.otel import register
    register(project_name="soc-handoff-lab", auto_instrument=True)
