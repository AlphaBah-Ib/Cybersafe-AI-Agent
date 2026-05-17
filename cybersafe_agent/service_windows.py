"""
Windows Service wrapper for the Cybersafe Agent.

This module implements the Windows SCM (Service Control Manager)
integration via pywin32. It's only imported when the agent is invoked
with `--service` (i.e. by the MSI-installed Windows service).

Without this wrapper, the binary runs as a console process and the SCM
times out after 30s with Event ID 1053/7000/7009 ("service did not
respond to the start or control request"), because nothing ever calls
SetServiceStatus(SERVICE_RUNNING).

With this wrapper:
    1. SCM launches cybersafe-agent.exe --service
    2. main.py detects --service and calls run_as_service()
    3. ServiceFramework.SvcDoRun() reports SERVICE_RUNNING immediately
    4. The actual agent loop runs in a worker thread
    5. On SvcStop(), a threading.Event is set to gracefully stop the loop

References:
    - https://learn.microsoft.com/en-us/windows/win32/services/service-functions
    - https://timgolden.me.uk/pywin32-docs/win32service.html
    - https://github.com/mhammond/pywin32/blob/main/win32/Demos/service/pipeTestService.py
"""
import logging
import sys
import threading
from typing import Callable, Optional


# Stop event shared with the agent loop. Set by SvcStop, polled by run().
# Initialized lazily because importing this module on Linux must not fail.
_stop_event: Optional[threading.Event] = None


def get_stop_event() -> threading.Event:
    """
    Return the global stop event (lazy-initialized).

    Called by main.run() to receive the SCM stop signal in a cross-OS way:
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    """
    global _stop_event
    if _stop_event is None:
        _stop_event = threading.Event()
    return _stop_event


def run_as_service():
    """
    Entry point when the binary is launched with --service.

    This is only callable on Windows. On Linux/macOS it will raise
    a clear error if mistakenly invoked.
    """
    import platform
    if platform.system() != "Windows":
        raise RuntimeError(
            "run_as_service() can only be called on Windows. "
            "On Linux/macOS, run the agent in console mode (no --service flag)."
        )

    # Lazy imports: pywin32 modules are only loaded on Windows
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class CybersafeAgentService(win32serviceutil.ServiceFramework):
        """
        SCM-aware wrapper around the agent's run() function.

        SCM lifecycle:
            __init__   -> service object created
            SvcDoRun   -> SCM start request, must report RUNNING quickly
            SvcStop    -> SCM stop request, must finish in ~30s
        """
        _svc_name_ = "CybersafeAgent"
        _svc_display_name_ = "Cybersafe-AI Agent"
        _svc_description_ = (
            "Collects Windows Event Log security events and forwards them "
            "to the Cybersafe-AI SOC platform."
        )

        def __init__(self, args):
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._worker_thread: Optional[threading.Thread] = None

        def SvcStop(self):
            """Called by SCM when the service is asked to stop."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            # 1) Tell the cross-OS stop event (read by main.run() loop)
            get_stop_event().set()
            # 2) Tell the pywin32 wait handle (in case anything waits on it)
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            """Called by SCM at service start. Must report RUNNING quickly."""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ''),
            )
            # Mark RUNNING immediately so SCM doesn't time us out (1053 fix).
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            try:
                # Import here so a syntax/import error in main.py doesn't
                # crash the SCM dispatch before we can log it.
                from cybersafe_agent.main import run

                # Run the agent in this thread (SvcDoRun blocks until stop).
                # The stop event will be set by SvcStop() and is polled
                # inside run() to exit cleanly.
                run(stop_event=get_stop_event())
            except Exception as exc:  # pragma: no cover
                # Last-resort logging to Windows Event Log so we never
                # silently die without leaving a trace.
                servicemanager.LogErrorMsg(
                    f"Cybersafe Agent fatal error: {exc!r}"
                )
                raise
            finally:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STOPPED,
                    (self._svc_name_, ''),
                )

    # Dispatch control to the SCM. This call blocks until the service stops.
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(CybersafeAgentService)
    servicemanager.StartServiceCtrlDispatcher()
