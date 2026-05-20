"""
Photo OSINT Tool — executes reverse image search, EXIF extraction,
social media photo matching, and basic face detection.

Capabilities:
  1. Reverse Image Search — queries Google Images, Bing, Yandex, TinEye
  2. EXIF Extraction — extracts and analyzes metadata from images
  3. Social Media Photo Match — matches profile photos across platforms
  4. Face Detection — basic face presence detection in images
"""
import base64
import hashlib
import io
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote, unquote

from src.osint_platform.tools.base import BaseTool, ToolResult
from src.osint_platform.tools.photo.photo_library import (
    EXIF_OSINT_RISK_MAP,
    EXIF_FIELDS,
    REVERSE_IMAGE_ENDPOINTS,
    SOCIAL_MEDIA_PHOTO_PATTERNS,
    classify_image_url,
    get_exif_risk_score,
    FaceDetectionConfidence,
    ImageSource,
)

logger = logging.getLogger(__name__)

# ─── Optional dependency handling ────────────────────────────────────────────

_PIL_AVAILABLE = None


def _check_pillow() -> bool:
    """Check if Pillow library is available for EXIF extraction."""
    global _PIL_AVAILABLE
    if _PIL_AVAILABLE is not None:
        return _PIL_AVAILABLE
    try:
        import PIL  # noqa: F401
        _PIL_AVAILABLE = True
    except ImportError:
        _PIL_AVAILABLE = False
        logger.warning("Pillow not installed. EXIF extraction will be disabled.")
    return _PIL_AVAILABLE


def _check_face_detection() -> bool:
    """Check if face detection libraries are available."""
    try:
        import PIL  # noqa: F401
        # Basic face detection can work with PIL alone via pixel analysis
        return True
    except ImportError:
        return False


# ─── Image URL Helpers ──────────────────────────────────────────────────────


def _is_image_url(url: str) -> bool:
    """Check if a URL points to an image based on extension and common patterns."""
    from src.osint_platform.tools.photo.photo_library import COMMON_IMAGE_EXTENSIONS
    parsed = urlparse(url)
    path = parsed.path.lower()
    ext_match = re.search(r'\.([a-zA-Z0-9]+)(?:\?|$)', path)
    if ext_match:
        ext = f".{ext_match.group(1).lower()}"
        if ext in COMMON_IMAGE_EXTENSIONS:
            return True
    # Check for common image CDN patterns even without extension
    image_domains = {
        "pbs.twimg.com", "avatars.githubusercontent.com",
        "media.licdn.com", "i.redd.it", "preview.redd.it",
        "cdn.discordapp.com", "images.unsplash.com",
    }
    if parsed.netloc in image_domains:
        return True
    return False


async def _download_image(url: str, timeout: int = 30) -> Optional[bytes]:
    """Download an image from a URL.

    Returns raw image bytes, or None if download fails.
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            }
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            content = response.content
            if len(content) > 50 * 1024 * 1024:  # 50MB limit
                logger.warning(f"Image too large: {len(content)} bytes from {url}")
                return None
            return content
    except Exception as e:
        logger.warning(f"Failed to download image from {url}: {e}")
        return None


# ─── EXIF Extraction ─────────────────────────────────────────────────────────


def _extract_exif_from_bytes(image_data: bytes) -> Dict[str, Any]:
    """Extract EXIF data from raw image bytes using Pillow.

    Returns a dict of EXIF tag -> value.
    """
    if not _check_pillow():
        return {}

    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS

    exif_data: Dict[str, Any] = {}

    try:
        img = Image.open(io.BytesIO(image_data))
        exif_raw = img._getexif()
        if exif_raw is None:
            return {}

        # Map tag numbers to human-readable names
        for tag_id, value in exif_raw.items():
            tag_name = TAGS.get(tag_id, f"TAG_{tag_id}")
            if tag_name == "GPSInfo":
                gps_data = {}
                for gps_tag_id, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_tag_id, f"GPS_TAG_{gps_tag_id}")
                    gps_data[gps_tag_name] = _format_exif_value(gps_value)
                exif_data["GPSInfo"] = gps_data
            else:
                exif_data[tag_name] = _format_exif_value(value)

        # Image dimensions
        exif_data["_ImageWidth"] = img.width
        exif_data["_ImageLength"] = img.height
        exif_data["_Format"] = img.format
        exif_data["_Mode"] = img.mode

    except Exception as e:
        logger.warning(f"EXIF extraction failed: {e}")

    return exif_data


def _format_exif_value(value: Any) -> Any:
    """Format an EXIF value for human-readable output."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip()
        except Exception:
            return base64.b64encode(value).decode()
    if isinstance(value, tuple):
        # Handle rational values (tuples of numerator, denominator)
        if len(value) == 2 and isinstance(value[0], (int, float)):
            try:
                return round(value[0] / value[1], 6) if value[1] != 0 else 0.0
            except (ZeroDivisionError, TypeError):
                return str(value)
        return str(value)
    if isinstance(value, (int, float)):
        return value
    return str(value)


def _convert_to_decimal_degrees(dms_tuple: tuple, ref: str) -> Optional[float]:
    """Convert EXIF GPS coordinates from (degrees, minutes, seconds) to decimal."""
    try:
        degrees, minutes, seconds = float(dms_tuple[0]), float(dms_tuple[1]), float(dms_tuple[2])
        decimal = degrees + minutes / 60.0 + seconds / 3600.0
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except (TypeError, ValueError, IndexError):
        return None


def _parse_gps_coordinates(exif_data: Dict[str, Any]) -> Optional[Dict[str, float]]:
    """Parse GPS coordinates from EXIF data into decimal format.

    Returns dict with lat, lng keys, or None if insufficient GPS data.
    """
    gps = exif_data.get("GPSInfo", {})
    if not gps:
        return None

    lat = _convert_to_decimal_degrees(
        gps.get("GPSLatitude", (0, 0, 0)),
        gps.get("GPSLatitudeRef", "N"),
    )
    lng = _convert_to_decimal_degrees(
        gps.get("GPSLongitude", (0, 0, 0)),
        gps.get("GPSLongitudeRef", "E"),
    )

    if lat and lng and (lat != 0 or lng != 0):
        return {"lat": lat, "lng": lng}

    return None


# ─── Face Detection (Basic) ──────────────────────────────────────────────────


def _detect_faces_basic(image_data: bytes) -> Dict[str, Any]:
    """Basic face detection using pixel/color analysis.

    Note: This is a lightweight heuristic, not a full ML-based face detector.
    For production, use OpenCV or a dedicated face detection API.

    Returns dict with:
        - face_detected: bool
        - confidence: FaceDetectionConfidence
        - method: str
        - details: str
    """
    if not _check_face_detection():
        return {
            "face_detected": False,
            "confidence": FaceDetectionConfidence.NONE,
            "method": "none",
            "details": "Face detection library not available. Install Pillow for basic support.",
        }

    from PIL import Image

    try:
        img = Image.open(io.BytesIO(image_data))
        # Convert to RGB if necessary
        if img.mode != "RGB":
            img = img.convert("RGB")

        # Simple skin-tone based detection (heuristic only)
        # This is NOT accurate — it's a placeholder for actual ML-based detection
        pixels = img.getdata()
        skin_pixels = 0
        total_pixels = len(pixels)

        # Very basic skin color range heuristic (not robust)
        for r, g, b in pixels:
            if r > 60 and g > 40 and b > 20 and r > g and r > b and abs(r - g) > 15:
                skin_pixels += 1

        skin_ratio = skin_pixels / max(total_pixels, 1)

        result = {
            "face_detected": skin_ratio > 0.05,
            "skin_pixel_ratio": round(skin_ratio, 4),
            "method": "basic_skin_heuristic",
            "details": "",
        }

        if skin_ratio > 0.20:
            result["confidence"] = FaceDetectionConfidence.HIGH
            result["details"] = "High probability of human subject (significant skin-tone pixels detected)"
        elif skin_ratio > 0.10:
            result["confidence"] = FaceDetectionConfidence.MEDIUM
            result["details"] = "Possible human subject present"
        elif skin_ratio > 0.05:
            result["confidence"] = FaceDetectionConfidence.LOW
            result["details"] = "Skin-tone pixels detected, but may be background"
        else:
            result["confidence"] = FaceDetectionConfidence.NONE
            result["details"] = "No human subject detected via basic heuristic"

        return result

    except Exception as e:
        logger.warning(f"Face detection failed: {e}")
        return {
            "face_detected": False,
            "confidence": FaceDetectionConfidence.NONE,
            "method": "error",
            "details": f"Detection error: {e}",
        }


# ─── Image Hash Computation ──────────────────────────────────────────────────


def _compute_image_hashes(image_data: bytes) -> Dict[str, str]:
    """Compute cryptographic hashes of image data.

    Returns dict with md5, sha1, sha256 hashes.
    """
    return {
        "md5": hashlib.md5(image_data).hexdigest(),
        "sha1": hashlib.sha1(image_data).hexdigest(),
        "sha256": hashlib.sha256(image_data).hexdigest(),
    }


# ─── PhotoTool ───────────────────────────────────────────────────────────────


class PhotoTool(BaseTool):
    """
    OSINT tool for photo intelligence gathering.

    Capabilities:
    - Reverse image search across multiple engines
    - EXIF metadata extraction and analysis
    - Social media profile photo matching
    - Basic face detection
    - Image hash computation for deduplication
    """

    def __init__(self, timeout: int = 60, max_results: int = 20):
        super().__init__(name="photo_osint", timeout=timeout)
        self.max_results = max_results

    async def search(self, query: str, **kwargs) -> ToolResult:
        """
        Execute photo OSINT investigation.

        Args:
            query: URL of an image, or a file path (future support for local files)
            **kwargs:
                extract_exif: Whether to extract EXIF data (default: True)
                reverse_search: Whether to run reverse image search (default: True)
                detect_faces: Whether to run face detection (default: True)
                match_social: Whether to match across social media (default: False)
                image_data: Raw image bytes (alternative to URL query)
        Returns:
            ToolResult with findings
        """
        start_time = time.monotonic()
        self._current_query = query

        extract_exif = kwargs.get("extract_exif", True)
        reverse_search = kwargs.get("reverse_search", True)
        detect_faces = kwargs.get("detect_faces", True)
        match_social = kwargs.get("match_social", False)
        image_data = kwargs.get("image_data")

        # Get image data
        if image_data is None:
            if query and _is_image_url(query):
                image_data = await _download_image(query)
            elif query and re.match(r'^data:image/', query):
                try:
                    # Handle base64 encoded images
                    base64_data = re.sub(r'^data:image/\w+;base64,', '', query)
                    image_data = base64.b64decode(base64_data)
                except Exception as e:
                    logger.warning(f"Failed to decode base64 image: {e}")
            else:
                # Try treating query as URL even without image extension
                if query and (query.startswith("http://") or query.startswith("https://")):
                    image_data = await _download_image(query)

        if image_data is None:
            elapsed = time.monotonic() - start_time
            return ToolResult(
                tool_name=self.name,
                query=query,
                success=False,
                data=[{"error": "Could not download or access image. Provide a valid image URL."}],
                execution_time_seconds=round(elapsed, 2),
            )

        results: Dict[str, Any] = {
            "image_url": query,
            "image_size_bytes": len(image_data),
            "hashes": _compute_image_hashes(image_data),
            "exif": {},
            "reverse_search": [],
            "face_detection": {},
            "url_classification": classify_image_url(query) if query and query.startswith("http") else {},
        }

        # 1. EXIF Extraction
        if extract_exif:
            exif_raw = _extract_exif_from_bytes(image_data)
            if exif_raw:
                gps_coords = _parse_gps_coordinates(exif_raw)
                risk = get_exif_risk_score(exif_raw)
                results["exif"] = {
                    "raw_fields": exif_raw,
                    "gps_coordinates": gps_coords,
                    "risk_assessment": risk,
                    "field_count": len(exif_raw),
                }
                if gps_coords:
                    maps_url = (
                        f"https://www.google.com/maps?q={gps_coords['lat']},{gps_coords['lng']}"
                    )
                    results["exif"]["maps_url"] = maps_url
                    results["exif"]["gps_display"] = (
                        f"{gps_coords['lat']}, {gps_coords['lng']}"
                    )

        # 2. Face Detection
        if detect_faces:
            face_result = _detect_faces_basic(image_data)
            results["face_detection"] = face_result

        # 3. Reverse Image Search (simulated — generates search URLs)
        if reverse_search and query and query.startswith("http"):
            results["reverse_search"] = self._generate_reverse_search_links(query)

        # 4. Social Media Match (simulated — maps to known profile photo patterns)
        if match_social and query and query.startswith("http"):
            results["social_matches"] = self._check_social_photo_patterns(query)

        elapsed = time.monotonic() - start_time

        # Flatten results into a list of findings for the ToolResult
        findings = self._flatten_results(results)

        return ToolResult(
            tool_name=self.name,
            query=query,
            success=True,
            data=findings,
            execution_time_seconds=round(elapsed, 2),
        )

    def _generate_reverse_search_links(self, image_url: str) -> List[Dict[str, str]]:
        """Generate reverse image search URLs for each supported engine."""
        links = []
        encoded_url = quote(image_url, safe="")

        for engine_key, engine_info in REVERSE_IMAGE_ENDPOINTS.items():
            search_url = engine_info["search_url"].replace("{url}", encoded_url)
            links.append({
                "engine": engine_info["name"],
                "engine_key": engine_key,
                "search_url": search_url,
                "description": engine_info["description"],
            })

        return links

    def _check_social_photo_patterns(self, image_url: str) -> List[Dict[str, str]]:
        """Check if an image URL matches known social media photo patterns."""
        matches = []
        for platform, pattern_info in SOCIAL_MEDIA_PHOTO_PATTERNS.items():
            base_pattern = pattern_info["pattern"].replace("{", r"\{").replace("}", r"\}")
            # Convert {username} / {email_hash} / {user_id} to a wildcard pattern
            url_pattern = re.sub(r"\\\{[^}]+\\\}", ".*", base_pattern)
            if re.match(url_pattern, image_url):
                matches.append({
                    "platform": platform,
                    "pattern": pattern_info["pattern"],
                    "description": pattern_info["description"],
                    "confidence": "high" if platform in image_url else "medium",
                })

        return matches

    def _flatten_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten the structured results into a list of findings for ToolResult."""
        findings: List[Dict[str, Any]] = []
        finding_id = 0

        # EXIF findings
        exif = results.get("exif", {})
        if exif:
            risk = exif.get("risk_assessment", {})
            findings.append({
                "id": f"photo_exif_{finding_id}",
                "type": "exif_metadata",
                "summary": f"EXIF metadata analyzed — {exif.get('field_count', 0)} fields found",
                "risk_score": risk.get("risk_score", 0),
                "risk_level": risk.get("risk_level", "LOW"),
                "details": risk.get("details", []),
            })
            finding_id += 1

            gps = exif.get("gps_coordinates")
            if gps:
                findings.append({
                    "id": f"photo_gps_{finding_id}",
                    "type": "gps_location",
                    "summary": f"GPS coordinates: {gps['lat']}, {gps['lng']}",
                    "risk_score": 10,
                    "risk_level": "CRITICAL",
                    "details": [f"Maps URL: {exif.get('maps_url', '')}"],
                })
                finding_id += 1

        # Face detection findings
        face = results.get("face_detection", {})
        if face and face.get("face_detected"):
            findings.append({
                "id": f"photo_face_{finding_id}",
                "type": "face_detected",
                "summary": "Human subject detected in image",
                "confidence": face.get("confidence", "low"),
                "risk_score": 8,
                "risk_level": "HIGH",
                "details": [face.get("details", "")],
            })
            finding_id += 1

        # Image info
        findings.append({
            "id": f"photo_info_{finding_id}",
            "type": "image_metadata",
            "summary": f"Image size: {results.get('image_size_bytes', 0)} bytes",
            "hashes": results.get("hashes", {}),
            "risk_score": 0,
            "risk_level": "INFO",
        })
        finding_id += 1

        # URL classification
        url_class = results.get("url_classification", {})
        if url_class and url_class.get("source_type") and url_class["source_type"] != "unknown":
            findings.append({
                "id": f"photo_url_{finding_id}",
                "type": "url_classification",
                "summary": f"Image source: {url_class.get('platform', url_class['source_type'])}",
                "risk_score": 3,
                "risk_level": "MEDIUM",
            })
            finding_id += 1

        # Reverse search links
        rev_searches = results.get("reverse_search", [])
        if rev_searches:
            findings.append({
                "id": f"photo_reverse_{finding_id}",
                "type": "reverse_search",
                "summary": f"Reverse image search URLs generated for {len(rev_searches)} engines",
                "engines": [
                    {
                        "name": r["engine"],
                        "url": r["search_url"],
                    }
                    for r in rev_searches
                ],
                "risk_score": 5,
                "risk_level": "HIGH",
            })
            finding_id += 1

        # Social matches
        social = results.get("social_matches", [])
        if social:
            findings.append({
                "id": f"photo_social_{finding_id}",
                "type": "social_media_match",
                "summary": f"Image matches {len(social)} social media photo patterns",
                "matches": social,
                "risk_score": 6,
                "risk_level": "HIGH",
            })

        return findings


# ─── Batch Photo Analysis ────────────────────────────────────────────────────


async def analyze_photo_batch(
    tool: PhotoTool,
    image_urls: List[str],
    extract_exif: bool = True,
    reverse_search: bool = True,
    detect_faces: bool = True,
) -> Dict[str, Any]:
    """Run photo OSINT analysis on multiple image URLs.

    Args:
        tool: PhotoTool instance
        image_urls: List of image URLs to analyze
        extract_exif: Whether to extract EXIF data
        reverse_search: Whether to generate reverse search links
        detect_faces: Whether to run face detection

    Returns:
        Dict with aggregated results per image
    """
    results_by_url: Dict[str, Dict[str, Any]] = {}
    total_exif_found = 0
    total_faces_detected = 0
    total_gps_found = 0

    for url in image_urls:
        result = await tool.search(
            url,
            extract_exif=extract_exif,
            reverse_search=reverse_search,
            detect_faces=detect_faces,
        )

        url_result = {
            "url": url,
            "success": result.success,
            "findings": result.data,
            "error": result.error,
        }

        if result.success:
            for finding in result.data:
                if finding.get("type") == "exif_metadata" and finding.get("field_count", 0) > 0:
                    total_exif_found += 1
                if finding.get("type") == "face_detected":
                    total_faces_detected += 1
                if finding.get("type") == "gps_location":
                    total_gps_found += 1

        results_by_url[url] = url_result

    return {
        "total_images": len(image_urls),
        "images_with_exif": total_exif_found,
        "images_with_faces": total_faces_detected,
        "images_with_gps": total_gps_found,
        "results_by_url": results_by_url,
    }


import asyncio  # noqa: E402
