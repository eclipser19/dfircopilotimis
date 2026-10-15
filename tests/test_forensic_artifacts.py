"""ForensicArtifacts locations: conversion to globs for an image, search, and the agent's tool."""
import json

from copilot import forensic_artifacts as fa

DEFINITIONS = [
    {"name": "WindowsThing", "doc": "Something Windows keeps.  Second sentence. Third sentence.",
     "sources": [{"type": "FILE", "attributes": {"paths": [
         r"%%environ_systemroot%%\Logs\**10\*.log", r"\Boot\BCD", r"%%users.localappdata%%\App\data.db"]}}],
     "supported_os": ["Windows"], "urls": ["https://example.org/thing"]},
    {"name": "BrowserHistoryFile", "doc": "History of a browser on three systems.",
     "sources": [{"type": "FILE", "attributes": {"paths": [
         "%%users.homedir%%/Library/Application Support/Browser/History",
         "%%users.homedir%%/.config/browser/History",
         r"%%users.localappdata%%\Browser\User Data\*\History"]}}],
     "supported_os": ["Darwin", "Linux", "Windows"]},
    {"name": "WindowsSettingKeys", "doc": "Machine and user settings.",
     "sources": [{"type": "REGISTRY_KEY", "attributes": {"keys": [
         r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\*",
         r"HKEY_USERS\%%users.sid%%\Software\Vendor\Recent\*",
         r"HKEY_USERS\%%users.sid%%_Classes\Local Settings\*",
         r"HKEY_CLASSES_ROOT\CLSID\{0000}\*"]}},
                 {"type": "REGISTRY_VALUE", "attributes": {"key_value_pairs": [
                     {"key": r"HKEY_LOCAL_MACHINE\Software\Vendor", "value": "InstallDate"},
                     {"key": r"HKEY_CURRENT_USER\Software\Vendor", "value": ""}]}}],
     "supported_os": ["Windows"]},
    {"name": "WindowsLiveOnly", "doc": "Only a WMI query.",
     "sources": [{"type": "WMI", "attributes": {"query": "SELECT * FROM Win32_Thing"}}], "supported_os": ["Windows"]},
    {"name": "LinuxOnly", "doc": "Linux file.", "sources": [{"type": "FILE", "attributes": {"paths": ["/etc/thing"]}}],
     "supported_os": ["Linux"]},
    {"name": "WindowsGroup", "doc": "A group.", "sources": [{"type": "ARTIFACT_GROUP",
                                                           "attributes": {"names": ["WindowsThing"]}}],
     "supported_os": ["Windows"]},
]


def test_conversion_gives_globs_for_an_image_mounted_as_c():
    out = {e["name"]: e for e in fa.convert(DEFINITIONS)}
    assert set(out) == {"WindowsThing", "BrowserHistoryFile", "WindowsSettingKeys", "WindowsGroup"}
    assert out["WindowsThing"]["files"] == [r"C:\Windows\Logs\**\*.log", r"C:\Boot\BCD",
                                            r"C:\Users\*\AppData\Local\App\data.db"]
    assert out["WindowsThing"]["doc"] == "Something Windows keeps. Second sentence."
    assert out["WindowsThing"]["url"] == "https://example.org/thing"
    assert out["BrowserHistoryFile"]["files"] == [r"C:\Users\*\AppData\Local\Browser\User Data\*\History"]
    keys = out["WindowsSettingKeys"]
    assert keys["registry"] == [r"HKEY_LOCAL_MACHINE\System\ControlSet001\Services\*",
                                r"HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{0000}\*",
                                r"HKEY_LOCAL_MACHINE\Software\Vendor\InstallDate"]
    assert keys["user_registry"] == [r"Software\Vendor\Recent\*", r"Software\Vendor\@"]
    assert out["WindowsGroup"]["includes"] == ["WindowsThing"]


def test_search_returns_ready_collections(monkeypatch):
    monkeypatch.setattr(fa, "entries", lambda: fa.convert(DEFINITIONS))
    best = fa.search("vendor settings")[0]
    assert best["name"] == "WindowsSettingKeys"
    assert {"artifact": "Windows.Search.FileFinder",
            "parameters": {"SearchFilesGlobTable": [r"HKEY_LOCAL_MACHINE\System\ControlSet001\Services\*",
                                                    r"HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{0000}\*",
                                                    r"HKEY_LOCAL_MACHINE\Software\Vendor\InstallDate"],
                           "Accessor": "registry"}} in best["collect"]
    assert {"artifact": "Windows.Registry.NTUser", "parameters": {"KeyGlob": r"Software\Vendor\Recent\*"}} \
        in best["collect"]
    assert fa.search("browser history")[0]["collect"] == [
        {"artifact": "Windows.Search.FileFinder",
         "parameters": {"SearchFilesGlobTable": [r"C:\Users\*\AppData\Local\Browser\User Data\*\History"]}}]
    assert fa.search("nothing like this") == []


def test_shipped_reference_and_tool():
    from copilot import tools
    assert len(fa.entries()) > 300
    found = json.loads(tools.find_data_location.invoke({"keyword": "time zone"}))["matches"]
    assert found[0]["name"] == "WindowsTimezone"
    assert found[0]["collect"][0]["parameters"]["Accessor"] == "registry"
    assert "ControlSet001" in found[0]["collect"][0]["parameters"]["SearchFilesGlobTable"][0]
    assert "No location known" in tools.find_data_location.invoke({"keyword": "zzqx"})


def test_shipped_reference_has_no_unconverted_placeholders():
    globs = [g for e in fa.entries() for k in ("files", "registry", "user_registry") for g in e.get(k, [])]
    assert globs and not [g for g in globs if "%%" in g]
    assert not [g for e in fa.entries() for g in e.get("registry", []) if "CurrentControlSet" in g]
