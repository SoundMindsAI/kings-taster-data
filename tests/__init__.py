"""Tests run with no network: any socket connect raises."""
import socket


def _blocked(*a, **k):
    raise OSError("network disabled in tests")


socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.create_connection = _blocked
