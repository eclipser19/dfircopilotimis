"""
Volatility 3 plugin used by the DFIR copilot (loaded with Volatility's -p option; see copilot/memory.py).

Searches each running process's memory for a text (ASCII and UTF-16, case-insensitive), or with
a YARA rule file, and says which process holds it. Unlike windows.vadyarascan it
- needs no YARA for a text search,
- keeps going when one process or memory region can't be read,
- returns readable text (the match with the text before and after it) instead of raw bytes, so
  rendering never has to read the memory again,
- reads large regions in pieces.
One row per process and distinct match, with how often it was found.
"""
import logging

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

CHUNK = 16 * 1024 * 1024        # bytes read at a time
MAX_REGION = 1024 ** 3          # regions above this are skipped (like windows.vadyarascan)
BEFORE, AFTER = 60, 100         # characters of context kept around a text match
MAX_HITS = 5000                 # stop after this many hits in all


def _printable(data: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)


def _context(data: bytes, start: int, end: int, step: int):
    """Printable text before start, and from start on (the match and up to AFTER more characters)."""
    def printable(i):
        return 0x20 <= data[i] <= 0x7E and (step == 1 or data[i + 1] == 0)

    i = start
    while i - step >= 0 and (start - i) // step < BEFORE and printable(i - step):
        i -= step
    j = end
    while j + step <= len(data) and (j - end) // step < AFTER and printable(j):
        j += step
    return data[i:start][::step].decode("latin-1"), data[start:j][::step].decode("latin-1")


class MemSearch(interfaces.plugins.PluginInterface):
    """Searches process memory for a text or with YARA rules, one row per process and match."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel",
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.ListRequirement(name="pid", element_type=int, optional=True,
                                         description="Process IDs to include (all other processes are excluded)"),
            requirements.StringRequirement(name="text", optional=True,
                                           description="Text to find (ASCII and UTF-16, case-insensitive)"),
            requirements.URIRequirement(name="yara_file", optional=True, description="YARA rules file"),
        ]

    def _scanner(self):
        """(kind, matcher): matcher(data, base) yields (offset, rule, before, match, encoding)."""
        text = self.config.get("text")
        if text:
            needle = text.lower().encode("latin-1", "replace")
            needles = [(needle, 1, "ASCII"), (b"".join(bytes([c]) + b"\0" for c in needle), 2, "UTF-16")]

            def find(data, base):
                lowered = data.lower()
                for pattern, step, encoding in needles:
                    at = lowered.find(pattern)
                    while at != -1:
                        before, match = _context(data, at, at + len(pattern), step)
                        yield base + at, "", before, match, encoding
                        at = lowered.find(pattern, at + 1)
            return len(needles[1][0]) + (BEFORE + AFTER) * 2, find
        if not self.config.get("yara_file"):
            raise ValueError("Give --text or --yara-file.")
        try:
            from volatility3.plugins import yarascan
        except ImportError:
            raise ValueError("YARA rules need YARA for Python: pip install yara-x (or yara-python).")
        scanner = yarascan.YaraScanner(rules=yarascan.YaraScanner.from_file(self.config["yara_file"]))

        def scan(data, base):
            for offset, rule, _, value in scanner(data, base):
                yield offset, rule, "", _printable(value[:200]), ""
        return 1024 * 1024, scan

    def _generator(self):
        margin, matcher = self._scanner()
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        total = 0
        for task in pslist.PsList.list_processes(context=self.context, kernel_module_name=self.config["kernel"],
                                                 filter_func=filter_func):
            try:
                pid, ppid = int(task.UniqueProcessId), int(task.InheritedFromUniqueProcessId)
                name = task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count, errors="replace")
                layer = self.context.layers[task.add_process_layer()]
                regions = [(vad.get_start(), vad.get_size()) for vad in task.get_vad_root().traverse()]
            except Exception as e:      # an unreadable process must not stop the search of the others
                vollog.info(f"Process at {task.vol.offset:#x} skipped: {e}")
                continue
            hits = {}
            for start, size in regions:
                if size > MAX_REGION or total >= MAX_HITS:
                    continue
                for offset in range(0, size, CHUNK):
                    head = min(offset, margin)
                    try:
                        data = layer.read(start + offset - head, min(head + CHUNK + margin, size - offset + head),
                                          pad=True)
                    except Exception as e:
                        vollog.info(f"PID {pid}: region {start:#x} skipped: {e}")
                        break
                    for at, rule, before, match, encoding in matcher(data, start + offset - head):
                        if not start + offset <= at < start + offset + CHUNK:
                            continue           # in the overlap: counted with the neighbouring piece
                        key = (rule, encoding, before, match)
                        if key in hits:
                            hits[key][0] += 1
                        else:
                            hits[key] = [1, at]
                        total += 1
            for (rule, encoding, before, match), (count, first) in hits.items():
                yield 0, (pid, ppid, name, rule, encoding, before, match, count, format_hints.Hex(first))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("PPID", int), ("Process", str), ("Rule", str), ("Encoding", str), ("Before", str),
             ("Match", str), ("Hits", int), ("FirstOffset", format_hints.Hex)],
            self._generator(),
        )
