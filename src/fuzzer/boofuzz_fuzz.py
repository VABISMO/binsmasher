"""Boofuzz network fuzzing methods for Fuzzer."""
import os
import time
import subprocess
import logging

log = logging.getLogger("binsmasher")


class BoofuzzMixin:
    """Methods: fuzz_target."""

    def fuzz_target(self, file_input, protocol, binary_args):
        log.info(f"Boofuzz ({protocol}) @ {self.host}:{self.port}…")
        try:
            from boofuzz import (Session, Target, TCPSocketConnection,
                                  s_initialize, s_static, s_string, s_get)
        except ImportError:
            log.error("boofuzz not installed: pip install boofuzz")
            return False

        srv_proc = None
        if os.path.isfile(self.binary):
            try:
                srv_proc = subprocess.Popen([self.binary] + binary_args,
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
                time.sleep(1.5)
            except Exception as e:
                log.warning(f"Could not start server: {e}")
        try:
            try:
                conn = TCPSocketConnection(self.host, self.port, timeout=5)
            except TypeError:
                conn = TCPSocketConnection(self.host, self.port)

            session = Session(target=Target(connection=conn), sleep_time=0.05,
                              crash_threshold_request=3, crash_threshold_element=3)
            if file_input == "mp3":
                s_initialize("mp3")
                s_static(b"\xFF\xFB")
                s_string(b"ID3", fuzzable=False)
                s_string(b"\x03\x00\x00\x00\x00\x00", fuzzable=True, name="hdr")
                s_string(b"A" * 512, fuzzable=True, name="body")
            elif protocol == "http":
                s_initialize("http")
                s_static(b"GET /")
                s_string(b"index.html", fuzzable=True, name="path")
                s_static(b" HTTP/1.1\r\nHost: ")
                s_string(b"localhost", fuzzable=True, name="host")
                s_static(b"\r\n\r\n")
                s_string(b"", fuzzable=True, name="body")
            else:
                s_initialize("raw")
                s_string(b"A" * 128, fuzzable=True, name="payload")
            name = "mp3" if file_input == "mp3" else ("http" if protocol == "http" else "raw")
            session.connect(s_get(name))
            session.fuzz(max_depth=500)
            log.info("Boofuzz completed — check boofuzz-results/ for crashes")
            return True
        except Exception as e:
            log.error(f"Boofuzz error: {e}")
            return False
        finally:
            if srv_proc:
                srv_proc.terminate()
