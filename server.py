import seclib
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from masker import Masker
from llm_client import call_llm

app = FastAPI()

# Master key: generata la pornire, impartita 3-din-5, cheia intreaga nu se pastreaza
_master = seclib.generate_key()
SHARES = seclib.split_secret(_master, 3, 5)
del _master


class Msg(BaseModel):
    text: str


@app.get("/")
def index():
    return FileResponse("web/index.html")


@app.get("/logo.svg")
def logo():
    return FileResponse("web/logo.svg", media_type="image/svg+xml")


@app.post("/api/chat")
def chat(msg: Msg):
    key = bytearray(seclib.combine_shares(SHARES[:3]))
    try:
        m = Masker()
        masked = m.mask(msg.text)
        answer = call_llm(masked)
        final = m.unmask(answer)
        blob = m.export_encrypted(bytes(key))
        return {
            "real": msg.text,
            "masked": masked,
            "final": final,
            "mapping_bytes": len(blob),
            "mapping_hex": blob.hex()[:48],
        }
    finally:
        for i in range(len(key)):
            key[i] = 0


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
