import json
import logging
import httpx
from typing import List, AsyncGenerator, Dict, Any
from app.core.config import settings
from app.schemas.openai import Message

logger = logging.getLogger(__name__)

class ZaiAuthError(Exception):
    pass

class ZaiAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Zai API returned {status_code}: {message}")

class ZaiClient:
    _client: httpx.AsyncClient = None

    @classmethod
    def get_client(cls) -> httpx.AsyncClient:
        if cls._client is None or cls._client.is_closed:
            cls._client = httpx.AsyncClient(timeout=120.0)
        return cls._client

    @classmethod
    async def close_client(cls):
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Zai-Gateway/1.0", 
        }

    async def get_models(self) -> List[Dict[str, Any]]:
        # 使用标准 OpenAI 模型接口
        url = f"{settings.ZAI_BASE_URL}/api/v1/models" 
        if "/v1" not in url: 
             url = f"{settings.ZAI_BASE_URL}/api/models"

        client = self.get_client()
        try:
            response = await client.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    return data.get("data", [])
                return data
            return []
        except Exception as e:
            logger.error(f"Error fetching models: {e}")
            return []

    async def stream_chat(self, messages: List[Message], model: str) -> AsyncGenerator[str, None]:
        # 使用OpenAI 接口路径
        url = f"{settings.ZAI_BASE_URL}/api/v1/chat/completions"
        
        # 构造标准 OpenAI Payload
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": True
        }

        client = self.get_client()
        try:
            # 发起标准 POST 请求
            async with client.stream("POST", url, json=payload, headers=self.headers) as response:
                if response.status_code != 200:
                    error_bytes = await response.aread()
                    error_text = error_bytes.decode('utf-8', errors='ignore')
                    logger.error(f"Zai API Error: {response.status_code} - {error_text}")
                    if response.status_code == 401:
                        raise ZaiAuthError("401 Unauthorized")
                    raise ZaiAPIError(response.status_code, error_text)

                async for line in response.aiter_lines():
                    if not line: continue
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]": break
                        try:
                            data = json.loads(data_str)
                            # 解析 OpenAI 响应结构
                            if "choices" in data and len(data["choices"]) > 0:
                                delta = data["choices"][0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield content
                            # 兼容
                            elif "content" in data:
                                yield data["content"]
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.error(f"Stream error: {e}")
            raise e
