import jwt
from datetime import datetime, timedelta
from config import Config


class JWTManager:

    def create_token(self, device_id):

        payload = {
            "device_id": device_id,
            "exp": datetime.utcnow() + timedelta(minutes=Config.TOKEN_VALIDITY_MINUTES),
            "iat": datetime.utcnow()
        }

        return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)

    def verify_token(self, token):

        try:

            decoded = jwt.decode(
                token,
                Config.JWT_SECRET,
                algorithms=[Config.JWT_ALGORITHM]
            )

            return True, decoded

        except jwt.ExpiredSignatureError:
            return False, "Token expired"

        except jwt.InvalidTokenError:
            return False, "Invalid token"