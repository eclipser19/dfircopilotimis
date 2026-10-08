"""
Who is working on which case.

Each investigator session has its own active case: its settings (CaseConfig) and its own
database connection (CaseDatabase). The CLI has one session for the whole process. The
Streamlit app gives every browser session its own, so several signed-in investigators can
work on different cases at the same time.

`copilot.case_config.case_config` and `copilot.database.case_db` are views of the current
session's case, so the rest of the code uses them exactly as before.
"""
import os
import threading


class NoCase(Exception):
    """No case is open in this session (the user has none yet, or lost access)."""


class Session:
    def __init__(self, user: str = None):
        self.user = user                # None: no sign-in (CLI, or the app without accounts)
        self.config = None              # CaseConfig of the active case
        self.db = None                  # CaseDatabase of the active case (this session's connection)
        self.switched = False           # the active case changed: the conversation must restart
        self.settings_changed = False   # the active case's settings changed: refresh the system prompt
        self.report_formats = None      # chosen in the Streamlit sidebar; None = the case file decides
        self._mtime = None

    @property
    def has_case(self) -> bool:
        return self.config is not None

    def open(self, case_file: str):
        """Makes case_file this session's active case (reusing the objects, so views stay valid)."""
        from copilot.case_config import CaseConfig
        from copilot.database import CaseDatabase, data_dir_for
        if self.config is None:
            config, db = CaseConfig(case_file), CaseDatabase(data_dir_for(case_file))
            self.config, self.db = config, db
        else:
            self.config.switch(case_file)
            self.db.open(data_dir_for(case_file))
        self._mtime = _mtime(case_file)

    def close(self):
        if self.db is not None and self.db.conn is not None:
            self.db.conn.close()
        self.config = self.db = None

    def reload_if_changed(self) -> bool:
        """Reloads the case file if it changed on disk (another session or a manual edit)."""
        if self.config is None:
            return False
        mtime = _mtime(self.config.path)
        if mtime == self._mtime:
            return False
        self.config.switch(self.config.path)
        self._mtime = mtime
        self.settings_changed = True
        return True

    def touch(self):
        """This session wrote the case file itself: no need to reload it."""
        if self.config is not None:
            self._mtime = _mtime(self.config.path)


def _mtime(path: str):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


# Set by the Streamlit app: returns the Session of the browser session running the code,
# or None when the code isn't running for a browser session (then the process session is
# used; the app runs all case work in its browser sessions' script threads).
PROVIDER = None

_default = None
_lock = threading.Lock()


def default() -> Session:
    """The process-wide session (CLI, scripts, tests), opened on the initial case."""
    global _default
    with _lock:
        if _default is None:
            from copilot.case_config import initial_case_file
            session = Session()
            session.open(initial_case_file())
            _default = session
        return _default


def current() -> Session:
    if PROVIDER is not None:
        session = PROVIDER()
        if session is not None:
            return session
    return default()


def current_user():
    return current().user


class CaseView:
    """Forwards attribute access to the current session's config or database."""

    def __init__(self, part: str):
        object.__setattr__(self, "_part", part)

    def _target(self):
        target = getattr(current(), self._part)
        if target is None:
            raise NoCase("No case is open. Create one, or ask an admin for access to one.")
        return target

    def __getattr__(self, name):
        return getattr(self._target(), name)

    def __setattr__(self, name, value):
        setattr(self._target(), name, value)

    def __repr__(self):
        return f"<current session's {self._part}>"
