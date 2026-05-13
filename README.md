# PassGuard API

Password strength analysis and breach detection using HaveIBeenPwned. Built with FastAPI.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/password/check` | GET | Full check — strength + breach detection |
| `/password/strength` | GET | Strength analysis only, instant response |
| `/password/breach` | GET | Breach check via HaveIBeenPwned |
| `/password/bulk-check` | POST | Check up to 20 passwords at once |

## Privacy

Uses k-anonymity — only the first 5 characters of the SHA1 hash are sent to HaveIBeenPwned. Your full password is never transmitted anywhere.

## Quick Start

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

API docs at `http://localhost:8000/docs`
