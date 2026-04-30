import sys
import threading
import queue as _queue

# ─── Colors ───────────────────────────────────────────────────────────────────
RED   = "\033[91m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RESET = "\033[0m"

# ─── Queue and internal state ─────────────────────────────────────────────
_q = _queue.Queue()
_last_was_spinner = False
_stopped = False


def _run():
    global _last_was_spinner
    while True:
        try:
            kind, text = _q.get(timeout=0.05)
        except _queue.Empty:
            continue

        if kind == "_STOP":
            break

        if kind == "SPIN":
            # Overwrite the same line without a newline
            sys.stdout.write(f"\r\033[K{text}")
            sys.stdout.flush()
            _last_was_spinner = True

        else:  # "LOG" - block message with newline
            if _last_was_spinner:
                sys.stdout.write("\r\033[K")  # clear spinner before printing
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            _last_was_spinner = False


_thread = threading.Thread(target=_run, daemon=True)
_thread.start()


# ─── Public API ────────────────────────────────────────────────────────
def spin(msg: str):
    """Update the progress line (overwrites in place)."""
    _q.put(("SPIN", msg))


def log(msg: str):
    """Print a normal line (clears the spinner first if active)."""
    _q.put(("LOG", msg))


def clear_spin():
    """Clear the spinner line without printing anything."""
    _q.put(("LOG", ""))


def stop():
    """Stop the printer thread. Call when exiting."""
    _q.put(("_STOP", ""))
    _thread.join(timeout=1)
