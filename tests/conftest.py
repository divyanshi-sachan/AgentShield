import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """The sandbox must never make real network requests; fail loudly if anything tries."""

    def guard(*args, **kwargs):
        raise RuntimeError("network access attempted during tests")

    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)
