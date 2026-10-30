import os

from agentshield.dotenv import load_dotenv


def test_load_dotenv(tmp_path, monkeypatch):
    for k in ("AS_A", "AS_B", "AS_C", "AS_D", "AS_KEEP"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AS_KEEP", "original")
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n\nAS_A=plain\nexport AS_B='quoted value'\nAS_C=\"dq\"\nAS_D=val # trailing\nAS_KEEP=override\nnot a line\n"
    )
    loaded = load_dotenv(env)
    assert set(loaded) == {"AS_A", "AS_B", "AS_C", "AS_D"}
    assert (os.environ["AS_A"], os.environ["AS_B"], os.environ["AS_C"], os.environ["AS_D"]) == (
        "plain",
        "quoted value",
        "dq",
        "val",
    )
    assert os.environ["AS_KEEP"] == "original"  # real environment wins
    for k in loaded:
        monkeypatch.delenv(k)


def test_missing_file_is_fine(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == []
