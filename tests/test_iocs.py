from langchain_core.messages import AIMessage

from copilot.iocs import clean, extract_iocs, llm_extract_iocs, merge, refang

TEXT = r"""Recipe sold on dark web. Attacker 194[.]61[.]24[.]102 brute-forced RDP on CITADEL-DC01 (10.42.85.10).
Payload coreupdater.exe from hxxp://194.61.24.102/coreupdater.exe, C2 203.78.103.109 and happydoghappycat-th[.]com.
Account C137\Administrator, user ricksanchez. SHA256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
Archive loot.zip; not an IP: 999.1.1.1, e.g. examples."""


def test_pattern_extraction_handles_defanged_iocs():
    iocs = extract_iocs(TEXT)
    assert iocs["ips"] == ["194.61.24.102", "10.42.85.10", "203.78.103.109"]
    assert iocs["domains"] == ["happydoghappycat-th.com"]
    assert iocs["hashes"] == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    assert iocs["filenames"] == ["coreupdater.exe", "loot.zip"]
    assert iocs["users"] == ["C137\\Administrator", "ricksanchez"]


def test_refang_and_clean():
    assert refang("evil[dot]com hxxps://x") == "evil.com https://x"
    assert clean({"ips": ["1.2.3.4", "1.2.3.4", "300.1.1.1"], "hashes": ["xyz"], "domains": ["A.COM."]}) == {
        "ips": ["1.2.3.4"], "domains": ["a.com"], "hashes": [], "filenames": [], "users": []}
    assert merge({"ips": ["1.1.1.1"]}, {"ips": ["1.1.1.1", "2.2.2.2"]})["ips"] == ["1.1.1.1", "2.2.2.2"]


def test_llm_extraction_cannot_invent_values():
    class LLM:
        def invoke(self, prompt):
            return AIMessage(content='Sure: {"users": ["jsmith", "invented_user"], "ips": ["8.8.8.8"], '
                                     '"filenames": ["invoice.pdf"]}')
    out = llm_extract_iocs(LLM(), "The account of jsmith opened invoice.pdf yesterday.")
    assert out["users"] == ["jsmith"] and out["filenames"] == ["invoice.pdf"] and out["ips"] == []
