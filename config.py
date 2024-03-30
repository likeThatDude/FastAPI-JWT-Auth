from pathlib import Path

BASE_DIR = Path(__file__).parent


class AuthJWTKeys:
    jwy_public_key: Path = (BASE_DIR / 'certs' / 'jwt-public.pem').read_text()
    jwt_private_key: Path = (BASE_DIR / 'certs' / 'jwt-private.pem').read_text()
    jwt_expiration: int = 900
    jwt_algorithm: str = 'RS256'
