"""Small utilities useful during OSINT work: JWT decode, hashing, EXIF."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

from .common import clip, guarded, jsonable, request, utcnow


def _b64url(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


@guarded
async def jwt_decode(token: str) -> dict:
    """Decode a JWT header and payload without verifying the signature.

    Flags alg=none, shows exp/iat/nbf as human dates and whether it is expired.
    """
    value = (token or "").strip()
    if value.lower().startswith("bearer "):
        value = value.split(None, 1)[1]
    parts = value.split(".")
    if len(parts) < 2:
        return {"ok": False, "error": "not a JWT (need at least header.payload)"}
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"decode failed: {exc}"}

    now = utcnow().timestamp()
    times = {}
    for claim in ("iat", "nbf", "exp"):
        if isinstance(payload.get(claim), (int, float)):
            times[claim] = {
                "timestamp": payload[claim],
                "utc": utcnow().fromtimestamp(payload[claim], utcnow().tzinfo).isoformat(timespec="seconds"),
            }
    expired = None
    if isinstance(payload.get("exp"), (int, float)):
        expired = payload["exp"] < now

    return {
        "ok": True,
        "header": header,
        "payload": payload,
        "signature_present": len(parts) > 2 and bool(parts[2]),
        "times": times,
        "expired": expired,
        "warnings": [warning for warning in [
            "alg=none - unsigned token" if str(header.get("alg", "")).lower() == "none" else None,
            "expired token" if expired else None,
        ] if warning],
    }


@guarded
async def hash_text(text: str, algorithms: str = "md5,sha1,sha256,sha512") -> dict:
    """Hash a string with one or more algorithms (md5, sha1, sha256, sha512, sha3_256...)."""
    requested = [item.strip().lower() for item in algorithms.split(",") if item.strip()]
    available = set(hashlib.algorithms_available)
    unknown = [item for item in requested if item not in available]
    if unknown:
        return {"ok": False, "error": f"unknown algorithms: {unknown}", "available": sorted(available)}
    data = (text or "").encode()
    return {
        "ok": True,
        "length": len(data),
        "hashes": {name: hashlib.new(name, data).hexdigest() for name in requested},
    }


def _to_decimal(values, ref: str) -> float | None:
    if not values or len(values) != 3:
        return None
    try:
        degrees, minutes, seconds = (float(item) for item in values)
        result = degrees + minutes / 60 + seconds / 3600
        if str(ref).upper() in ("S", "W"):
            result = -result
        return round(result, 8)
    except Exception:  # noqa: BLE001
        return None


@guarded
async def image_exif(source: str) -> dict:
    """Extract EXIF metadata (camera, timestamps, GPS) from a local image or image URL.

    GPS coordinates are converted to decimal degrees when present. Useful for
    geolocating photos and checking whether metadata was stripped.
    """
    from PIL import ExifTags, Image as PILImage

    path = None
    temporary = False
    if source.lower().startswith(("http://", "https://")):
        response = await request(source, timeout=30.0)
        suffix = Path(source.split("?")[0]).suffix or ".jpg"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
            handle.write(response.content)
            path = handle.name
            temporary = True
    else:
        path = os.path.expanduser(source)
        if not os.path.isfile(path):
            return {"ok": False, "error": f"file not found: {path}"}

    try:
        image = PILImage.open(path)
        exif = image.getexif()
        named = {}
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            named[name] = jsonable(value)

        gps = {}
        try:
            gps_ifd = exif.get_ifd(0x8825)
            for key, value in gps_ifd.items():
                gps[ExifTags.GPSTAGS.get(key, str(key))] = jsonable(value)
            lat = _to_decimal(gps_ifd.get(2), gps_ifd.get(1, ""))
            lon = _to_decimal(gps_ifd.get(4), gps_ifd.get(3, ""))
            if lat is not None and lon is not None:
                gps["decimal"] = {"lat": lat, "lon": lon, "maps": f"https://maps.google.com/?q={lat},{lon}"}
        except Exception:  # noqa: BLE001
            pass

        exif_ifd = {}
        try:
            for key, value in exif.get_ifd(0x8769).items():
                exif_ifd[ExifTags.TAGS.get(key, str(key))] = jsonable(value)
        except Exception:  # noqa: BLE001
            pass

        return {
            "ok": True,
            "source": source,
            "format": image.format,
            "size": image.size,
            "mode": image.mode,
            "exif": named,
            "exif_ifd": exif_ifd,
            "gps": gps or None,
            "has_exif": bool(named or exif_ifd or gps),
        }
    finally:
        if temporary and path:
            try:
                os.unlink(path)
            except OSError:
                pass
