from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from cryptography.hazmat.primitives import serialization

app = FastAPI()

PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-rzszbkex.apps.exam.local"

public_key = serialization.load_pem_public_key(PUBLIC_KEY)


class TokenRequest(BaseModel):
    token: str


@app.get("/")
def home():
    return {"message": "OAuth Verification Service"}


@app.post("/verify")
def verify(req: TokenRequest):
    try:
        payload = jwt.decode(
            req.token,
            key=public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )

        return {
            "valid": True,
            "email": payload["email"],
            "sub": payload["sub"],
            "aud": payload["aud"],
        }

    except jwt.PyJWTError:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )