"""Provider calls with httpx replaced: request shape, response parsing, and HTTP error messages."""
import json

import httpx
import pytest

import extract

FIELDS = {"name": "Test Taro", "company": "Example Co.", "department": "", "title": "", "email": "t@example.test",
          "phone": "", "address": "", "website": "", "unclear_fields": []}


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def fake_post(status, body, seen):
    def post(url, json=None, headers=None, timeout=None):
        seen.update(url=url, body=json, headers=headers)
        return FakeResponse(status, body)
    return post


def test_openai_tool_call_is_parsed(monkeypatch):
    seen = {}
    body = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": json.dumps(FIELDS)}}]}}],
            "usage": {"prompt_tokens": 900, "completion_tokens": 80}}
    monkeypatch.setattr(httpx, "post", fake_post(200, body, seen))
    raw, tin, tout = extract._call_openai("sk-proj-test", "gpt-5", "AAAA")
    assert raw["name"] == "Test Taro" and (tin, tout) == (900, 80)
    assert seen["headers"]["Authorization"] == "Bearer sk-proj-test"
    content = seen["body"]["messages"][1]["content"]
    assert content[0]["image_url"]["url"].startswith("data:image/jpeg;base64,")
    assert seen["body"]["tool_choice"]["function"]["name"] == "record_card"


def test_gemini_json_text_is_parsed(monkeypatch):
    seen = {}
    body = {"candidates": [{"content": {"parts": [{"text": "```json\n" + json.dumps(FIELDS) + "\n```"}]}}],
            "usageMetadata": {"promptTokenCount": 700, "candidatesTokenCount": 60}}
    monkeypatch.setattr(httpx, "post", fake_post(200, body, seen))
    raw, tin, tout = extract._call_gemini("AIzaTest", "gemini-2.5-flash", "AAAA")
    assert raw["company"] == "Example Co." and (tin, tout) == (700, 60)
    assert seen["headers"]["x-goog-api-key"] == "AIzaTest"


@pytest.mark.parametrize("status,phrase", [(401, "HTTP 401"), (429, "上限"), (503, "サービス側")])
def test_http_errors_become_clear_messages(monkeypatch, status, phrase):
    monkeypatch.setattr(httpx, "post", fake_post(status, {"error": {"message": "x"}}, {}))
    with pytest.raises(extract.ExtractionError) as e:
        extract._call_openai("sk-proj-test", "gpt-5", "AAAA")
    assert phrase in str(e.value) and "手で入力" in str(e.value)


def test_full_extract_through_openai_path(monkeypatch, tmp_path):
    from PIL import Image
    img = tmp_path / "c.png"
    Image.new("RGB", (3000, 2000), "white").save(img)
    seen = {}
    body = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": json.dumps(FIELDS)}}]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
    monkeypatch.setenv("LLM_API_KEY", "sk-proj-test")
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.setattr(httpx, "post", fake_post(200, body, seen))
    result = extract.extract(str(img))
    assert result["fields"]["name"] == "Test Taro" and result["usage"]["model"] == "openai/gpt-5"
    import base64, io
    sent = Image.open(io.BytesIO(base64.b64decode(seen["body"]["messages"][1]["content"][0]["image_url"]["url"].split(",", 1)[1])))
    assert max(sent.size) == extract.LLM_IMAGE_MAX_SIDE  # large photos are shrunk before sending
