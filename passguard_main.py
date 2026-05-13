from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import hashlib
import re
import math
from typing import List, Optional
from datetime import datetime

app = FastAPI(
    title="PassGuard API",
    description="Check password strength, detect breaches via HaveIBeenPwned, and generate secure passwords.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Common weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "admin", "welcome",
    "login", "hello", "charlie", "donald", "password2", "qwerty123", "admin123",
    "1234", "12345", "123456789", "1234567890", "000000", "111111", "222222",
    "333333", "444444", "555555", "666666", "777777", "888888", "999999",
    "1q2w3e", "1q2w3e4r", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234qwer",
    "pass", "test", "guest", "root", "toor", "changeme", "default", "secret",
    "access", "batman", "summer", "flower", "princess", "michael", "jessica",
    "thomas", "jordan", "hunter", "ranger", "harley", "robert", "andrew",
    "andrea", "joshua", "george", "amanda", "andrea", "jessica", "nicole"
}

HIBP_API = "https://api.pwnedpasswords.com/range/{prefix}"


def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset += 32
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)


def analyze_strength(password: str) -> dict:
    issues = []
    score = 100

    # Length checks
    if len(password) < 8:
        score -= 40
        issues.append("Too short — minimum 8 characters")
    elif len(password) < 12:
        score -= 15
        issues.append("Short — 12+ characters recommended")
    elif len(password) >= 16:
        score += 10

    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    if not has_lower:
        score -= 15
        issues.append("Add lowercase letters")
    if not has_upper:
        score -= 15
        issues.append("Add uppercase letters")
    if not has_digit:
        score -= 15
        issues.append("Add numbers")
    if not has_special:
        score -= 10
        issues.append("Add special characters (!@#$%^&*)")

    # Common patterns
    if password.lower() in COMMON_PASSWORDS:
        score -= 50
        issues.append("This is one of the most common passwords")

    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("Avoid repeating characters (aaa, 111)")

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg)', password.lower()):
        score -= 10
        issues.append("Avoid sequential characters (123, abc)")

    if re.search(r'(qwerty|asdf|zxcv)', password.lower()):
        score -= 10
        issues.append("Avoid keyboard patterns (qwerty, asdf)")

    score = max(0, min(100, score))
    entropy = calculate_entropy(password)

    if score >= 80:
        strength = "strong"
    elif score >= 60:
        strength = "moderate"
    elif score >= 40:
        strength = "weak"
    else:
        strength = "very weak"

    # Crack time estimate
    if entropy >= 60:
        crack_time = "centuries"
    elif entropy >= 50:
        crack_time = "years"
    elif entropy >= 40:
        crack_time = "months"
    elif entropy >= 30:
        crack_time = "days"
    elif entropy >= 20:
        crack_time = "hours"
    else:
        crack_time = "minutes or less"

    return {
        "score": score,
        "strength": strength,
        "entropy_bits": round(entropy, 2),
        "estimated_crack_time": crack_time,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_numbers": has_digit,
        "has_special": has_special,
        "is_common_password": password.lower() in COMMON_PASSWORDS,
        "issues": issues,
        "suggestions": issues
    }


async def check_hibp(password: str) -> dict:
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(
                HIBP_API.format(prefix=prefix),
                headers={"Add-Padding": "true"}
            )
            if r.status_code == 200:
                hashes = r.text.splitlines()
                for line in hashes:
                    parts = line.split(":")
                    if len(parts) == 2 and parts[0].upper() == suffix:
                        count = int(parts[1].strip())
                        return {
                            "breached": True,
                            "breach_count": count,
                            "message": f"This password appeared {count:,} times in data breaches. Do not use it.",
                            "hibp_available": True
                        }
                return {
                    "breached": False,
                    "breach_count": 0,
                    "message": "This password has not been found in known data breaches.",
                    "hibp_available": True
                }
            else:
                return {
                    "breached": None,
                    "breach_count": None,
                    "message": "Could not check breach database at this time.",
                    "hibp_available": False
                }
        except Exception:
            return {
                "breached": None,
                "breach_count": None,
                "message": "Could not reach breach database — try again.",
                "hibp_available": False
            }


@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "name": "PassGuard API",
        "version": "1.0.0",
        "status": "live",
        "endpoints": [
            "/password/check",
            "/password/strength",
            "/password/breach",
            "/password/bulk-check"
        ],
        "docs": "/docs"
    }


@app.get("/password/check")
async def full_check(
    password: str = Query(..., description="Password to check"),
    check_breach: bool = Query(True, description="Also check against HaveIBeenPwned breach database")
):
    """
    Full password analysis. Checks strength, entropy, common patterns,
    and optionally verifies against the HaveIBeenPwned breach database.
    Uses k-anonymity — your full password is never sent anywhere.
    """
    strength = analyze_strength(password)
    result = {
        "strength_score": strength["score"],
        "strength_level": strength["strength"],
        "entropy_bits": strength["entropy_bits"],
        "estimated_crack_time": strength["estimated_crack_time"],
        "character_checks": {
            "has_lowercase": strength["has_lowercase"],
            "has_uppercase": strength["has_uppercase"],
            "has_numbers": strength["has_numbers"],
            "has_special": strength["has_special"]
        },
        "is_common_password": strength["is_common_password"],
        "issues": strength["issues"],
        "breach_checked": False,
        "breached": None,
        "breach_count": None,
        "breach_message": None,
        "safe_to_use": strength["score"] >= 60,
        "checked_at": datetime.utcnow().isoformat()
    }

    if check_breach:
        breach = await check_hibp(password)
        result["breach_checked"] = True
        result["breached"] = breach["breached"]
        result["breach_count"] = breach["breach_count"]
        result["breach_message"] = breach["message"]
        result["hibp_available"] = breach["hibp_available"]
        if breach["breached"]:
            result["safe_to_use"] = False

    return result


@app.get("/password/strength")
def strength_only(
    password: str = Query(..., description="Password to analyze")
):
    """
    Analyze password strength only — no breach check.
    Returns score, entropy, crack time estimate, and improvement suggestions.
    Instant response, no external API calls.
    """
    strength = analyze_strength(password)
    return {
        "password_length": len(password),
        "strength_score": strength["score"],
        "strength_level": strength["strength"],
        "entropy_bits": strength["entropy_bits"],
        "estimated_crack_time": strength["estimated_crack_time"],
        "character_checks": {
            "has_lowercase": strength["has_lowercase"],
            "has_uppercase": strength["has_uppercase"],
            "has_numbers": strength["has_numbers"],
            "has_special": strength["has_special"]
        },
        "is_common_password": strength["is_common_password"],
        "issues": strength["issues"]
    }


@app.get("/password/breach")
async def breach_only(
    password: str = Query(..., description="Password to check against breach database")
):
    """
    Check if a password has appeared in known data breaches using HaveIBeenPwned.
    Uses k-anonymity model — only first 5 chars of SHA1 hash are sent, never the full password.
    """
    breach = await check_hibp(password)
    return {
        "breached": breach["breached"],
        "breach_count": breach["breach_count"],
        "message": breach["message"],
        "hibp_available": breach["hibp_available"],
        "privacy_note": "Only the first 5 characters of the SHA1 hash are sent to HaveIBeenPwned. Your password is never transmitted.",
        "checked_at": datetime.utcnow().isoformat()
    }


@app.post("/password/bulk-check")
async def bulk_check(
    passwords: List[str],
    check_breach: bool = Query(False, description="Check each password against breach database (slower)")
):
    """
    Check up to 20 passwords in one request.
    Returns strength analysis for each with an overall summary.
    """
    if len(passwords) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 passwords per bulk request")

    results = []
    strong_count = 0
    weak_count = 0
    breached_count = 0

    for pwd in passwords:
        strength = analyze_strength(pwd)
        item = {
            "password_length": len(pwd),
            "strength_score": strength["score"],
            "strength_level": strength["strength"],
            "estimated_crack_time": strength["estimated_crack_time"],
            "is_common_password": strength["is_common_password"],
            "issues": strength["issues"],
            "safe_to_use": strength["score"] >= 60
        }

        if check_breach:
            breach = await check_hibp(pwd)
            item["breached"] = breach["breached"]
            item["breach_count"] = breach["breach_count"]
            if breach["breached"]:
                item["safe_to_use"] = False
                breached_count += 1

        if strength["score"] >= 60:
            strong_count += 1
        else:
            weak_count += 1

        results.append(item)

    return {
        "total_processed": len(results),
        "summary": {
            "strong": strong_count,
            "weak": weak_count,
            "breached": breached_count if check_breach else "not checked"
        },
        "results": results
    }
