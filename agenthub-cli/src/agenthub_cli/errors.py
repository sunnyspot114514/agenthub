class CliError(Exception):
    def __init__(self, message: str, code: int, payload: dict | None = None):
        super().__init__(message)
        self.exit_code = code
        self.payload = payload or {"error": {"message": message, "code": str(code)}}


def map_http(status: int, body: dict) -> int:
    err = (body or {}).get("error") or {}
    code = str(err.get("code") or "")
    if status in (401,):
        return 3
    if status in (403,):
        return 4
    if status in (404,):
        return 5
    if status in (409, 412):
        return 6
    if status in (413, 422):
        return 7
    if status in (429, 502, 503, 504) or err.get("retryable"):
        return 8
    if status >= 500:
        return 8
    if code == "incompatible":
        return 10
    return 2 if status >= 400 else 0
