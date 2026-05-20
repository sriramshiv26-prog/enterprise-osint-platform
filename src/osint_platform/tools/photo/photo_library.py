"""
Photo OSINT Library — platform definitions, search endpoints, and image analysis utilities.

Defines:
- Reverse image search platforms (Google Images, TinEye, Bing Images, Yandex)
- EXIF analysis field descriptions
- Social media platforms with profile photo patterns
- Face detection confidence levels
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ImageSource(str, Enum):
    """Sources for reverse image search."""
    GOOGLE_IMAGES = "google_images"
    BING_IMAGES = "bing_images"
    YANDEX_IMAGES = "yandex_images"
    TINEYE = "tineye"


class SearchPlatform(str, Enum):
    """Social media / web platforms that host profile photos and images."""
    GITHUB = "github"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    REDDIT = "reddit"
    TIKTOK = "tiktok"
    MEDIUM = "medium"
    PINTEREST = "pinterest"
    FLICKR = "flickr"
    DEVIANTART = "deviantart"
    TELEGRAM = "telegram"
    WHATSAPP = "whatsapp"
    DISCOURSE = "discourse"
    GRAVATAR = "gravatar"
    KEYBASE = "keybase"
    ABOUT_ME = "about_me"
    WORDPRESS = "wordpress"
    TUMBLR = "tumblr"
    SOUNDCLOUD = "soundcloud"
    SPOTIFY = "spotify"
    YOUTUBE = "youtube"
    VIMEO = "vimeo"
    BEHANCE = "behance"
    DRIBBBLE = "dribbble"
    SLACK = "slack"
    GOOGLE_SCHOLAR = "google_scholar"
    RESEARCHGATE = "researchgate"
    ACADEMIA = "academia"


class FaceDetectionConfidence(str, Enum):
    """Confidence levels for face detection results."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class EXIFCategory(str, Enum):
    """Categories of EXIF data fields."""
    CAMERA_INFO = "camera_info"
    GPS = "gps_location"
    TIMESTAMP = "timestamp"
    SOFTWARE = "software"
    IMAGE_DETAILS = "image_details"
    THUMBNAIL = "thumbnail"
    MAKER_NOTES = "maker_notes"


@dataclass
class EXIFField:
    """Describes a single EXIF field and its OSINT significance."""
    tag: str
    label: str
    category: EXIFCategory
    description: str
    osint_value: str  # Why this matters for OSINT


EXIF_FIELDS: List[EXIFField] = [
    # Camera Info
    EXIFField("Make", "Camera Make", EXIFCategory.CAMERA_INFO,
              "Manufacturer of the camera/phone", "Identifies device brand (e.g., Apple, Canon, Samsung)"),
    EXIFField("Model", "Camera Model", EXIFCategory.CAMERA_INFO,
              "Specific model of the camera/phone", "Pinpoints exact device model"),
    EXIFField("LensModel", "Lens Model", EXIFCategory.CAMERA_INFO,
              "Lens used to capture image", "Identifies photographer's equipment"),
    EXIFField("FocalLength", "Focal Length", EXIFCategory.CAMERA_INFO,
              "Focal length in mm", "Helps determine distance from subject"),
    EXIFField("FNumber", "Aperture", EXIFCategory.CAMERA_INFO,
              "F-stop value", "Indicates lighting conditions and depth of field"),
    EXIFField("ISOSpeedRatings", "ISO Speed", EXIFCategory.CAMERA_INFO,
              "ISO sensitivity", "Indicates shooting conditions (low light = high ISO)"),
    EXIFField("ExposureTime", "Exposure Time", EXIFCategory.CAMERA_INFO,
              "Shutter speed in seconds", "Can indicate tripod use (slow shutter) or handheld"),
    EXIFField("Flash", "Flash", EXIFCategory.CAMERA_INFO,
              "Whether flash was fired", "Indicates indoor/studio vs natural light"),

    # GPS / Location
    EXIFField("GPSLatitudeRef", "GPS Latitude Ref", EXIFCategory.GPS,
              "N/S latitude reference", "Confirms hemisphere (crucial for accurate coordinates)"),
    EXIFField("GPSLatitude", "GPS Latitude", EXIFCategory.GPS,
              "Latitude coordinates", "Exact location where photo was taken"),
    EXIFField("GPSLongitudeRef", "GPS Longitude Ref", EXIFCategory.GPS,
              "E/W longitude reference", "Confirms hemisphere for coordinates"),
    EXIFField("GPSLongitude", "GPS Longitude", EXIFCategory.GPS,
              "Longitude coordinates", "Exact location where photo was taken"),
    EXIFField("GPSAltitude", "GPS Altitude", EXIFCategory.GPS,
              "Altitude in meters", "Geographic altitude of capture location"),
    EXIFField("GPSMapDatum", "GPS Map Datum", EXIFCategory.GPS,
              "Geodetic survey data", "Coordinate system used (usually WGS-84)"),
    EXIFField("GPSTimeStamp", "GPS Timestamp", EXIFCategory.GPS,
              "GPS time in UTC", "UTC time of capture from GPS satellites"),
    EXIFField("GPSImgDirection", "GPS Direction", EXIFCategory.GPS,
              "Direction camera was facing", "Direction the photographer was facing"),
    EXIFField("GPSProcessingMethod", "GPS Processing Method", EXIFCategory.GPS,
              "GPS data processing method", "How GPS coordinates were determined"),

    # Timestamp
    EXIFField("DateTimeOriginal", "Original Date", EXIFCategory.TIMESTAMP,
              "Original capture date/time", "When the photo was originally taken"),
    EXIFField("DateTimeDigitized", "Digitized Date", EXIFCategory.TIMESTAMP,
              "Date/time digitized", "When photo was scanned/digitized (for scanned images)"),
    EXIFField("DateTime", "Last Modified", EXIFCategory.TIMESTAMP,
              "Last file modification date", "When the image file was last saved"),

    # Software
    EXIFField("Software", "Software Used", EXIFCategory.SOFTWARE,
              "Software that processed the image", "Identifies editing software (Photoshop, Lightroom, GIMP)"),
    EXIFField("ProcessingSoftware", "Processing Software", EXIFCategory.SOFTWARE,
              "Software that processed the RAW file", "High-end photography workflow indicator"),
    EXIFField("Artist", "Artist/Creator", EXIFCategory.SOFTWARE,
              "Creator name embedded by software", "Can contain real name or pseudonym"),
    EXIFField("Copyright", "Copyright Holder", EXIFCategory.SOFTWARE,
              "Copyright notice", "Legal owner of the image"),

    # Image Details
    EXIFField("ImageWidth", "Image Width", EXIFCategory.IMAGE_DETAILS,
              "Width in pixels", "Original resolution indicator"),
    EXIFField("ImageLength", "Image Height", EXIFCategory.IMAGE_DETAILS,
              "Height in pixels", "Original resolution indicator"),
    EXIFField("Orientation", "Orientation", EXIFCategory.IMAGE_DETAILS,
              "Rotation of image", "How the camera was held (landscape/portrait)"),
    EXIFField("XResolution", "X Resolution", EXIFCategory.IMAGE_DETAILS,
              "Horizontal DPI", "Print resolution indicator"),
    EXIFField("YResolution", "Y Resolution", EXIFCategory.IMAGE_DETAILS,
              "Vertical DPI", "Print resolution indicator"),
    EXIFField("ColorSpace", "Color Space", EXIFCategory.IMAGE_DETAILS,
              "Color profile (sRGB, Adobe RGB)", "Expertise level of photographer"),
    EXIFField("WhiteBalance", "White Balance", EXIFCategory.IMAGE_DETAILS,
              "White balance mode", "Auto vs manual — indicates photographer skill"),

    # Thumbnail
    EXIFField("ThumbnailOffset", "Thumbnail Offset", EXIFCategory.THUMBNAIL,
              "Offset of thumbnail data in file", "Indicates if an embedded preview exists"),
    EXIFField("ThumbnailLength", "Thumbnail Length", EXIFCategory.THUMBNAIL,
              "Length of thumbnail data in bytes", "Size of embedded preview image"),
    EXIFField("ThumbnailCompression", "Thumbnail Compression", EXIFCategory.THUMBNAIL,
              "Compression method for thumbnail", "JPEG vs uncompressed thumbnail type"),

    # Maker Notes
    EXIFField("MakerNote", "Maker Note", EXIFCategory.MAKER_NOTES,
              "Camera manufacturer-specific metadata", "Contains proprietary camera settings and serial numbers"),
    EXIFField("UserComment", "User Comment", EXIFCategory.MAKER_NOTES,
              "User-embedded comment text", "Can contain tags, locations, or personal info"),
    EXIFField("ImageDescription", "Image Description", EXIFCategory.MAKER_NOTES,
              "Description or caption of the image", "Often contains auto-generated or user-added descriptions"),
]


# ─── Reverse Image Search Endpoints ──────────────────────────────────────────

REVERSE_IMAGE_ENDPOINTS: Dict[str, Dict[str, str]] = {
    "google_images": {
        "name": "Google Images",
        "upload_url": "https://lens.google.com/uploadbyurl",
        "search_url": "https://www.google.com/searchbyimage?image_url={url}",
        "description": "Google Lens reverse image search. Best general-purpose coverage.",
    },
    "bing_images": {
        "name": "Bing Visual Search",
        "upload_url": "https://www.bing.com/images/searchbyimage",
        "search_url": "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{url}",
        "description": "Microsoft Bing reverse image search. Good for web-scale matching.",
    },
    "yandex_images": {
        "name": "Yandex Images",
        "upload_url": "https://yandex.com/images/search",
        "search_url": "https://yandex.com/images/search?rpt=imageview&url={url}",
        "description": "Yandex reverse image search. Strong on Eastern European and Russian sources.",
    },
    "tineye": {
        "name": "TinEye",
        "upload_url": "https://tineye.com/",
        "search_url": "https://tineye.com/search?url={url}",
        "description": "TinEye reverse image search. Best for finding exact matches and modified versions.",
    },
}


# ─── Social Media Photo URL Patterns ─────────────────────────────────────────

SOCIAL_MEDIA_PHOTO_PATTERNS: Dict[str, Dict[str, str]] = {
    "github": {
        "pattern": "https://avatars.githubusercontent.com/{username}",
        "description": "GitHub profile avatar",
        "size_param": "?s={size}",
    },
    "twitter": {
        "pattern": "https://pbs.twimg.com/profile_images/{user_id}",
        "description": "Twitter/X profile photo",
        "note": "Requires user_id, not username. Can be obtained from API.",
    },
    "gravatar": {
        "pattern": "https://www.gravatar.com/avatar/{email_hash}",
        "description": "Gravatar globally recognized avatar",
        "size_param": "?s={size}&d=404",
    },
    "keybase": {
        "pattern": "https://keybase.io/{username}/picture",
        "description": "Keybase profile picture",
    },
}


# ─── Image Analysis Utilities ────────────────────────────────────────────────

COMMON_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".svg"}
SOCIAL_MEDIA_IMAGE_DOMAINS = {
    "pbs.twimg.com", "avatars.githubusercontent.com",
    "media.licdn.com", "scontent.*.fbcdn.net",
    "instagram.*.fna.fbcdn.net", "i.redd.it",
    "preview.redd.it", "cdn.discordapp.com",
}

# ─── Threat Assessment Helpers ───────────────────────────────────────────────

EXIF_OSINT_RISK_MAP: Dict[str, int] = {
    "gps": 10,       # GPS coordinates are highest risk for privacy
    "timestamp": 7,  # Accurate timestamps reveal patterns of life
    "device": 5,     # Device info identifies the photographer
    "software": 3,   # Software used indicates sophistication
    "face": 8,       # Face detection enables cross-platform matching
}


def get_exif_risk_score(exif_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate OSINT risk score from extracted EXIF data.

    Returns:
        Dict with risk_score, risk_level, and details of what was found.
    """
    score = 0
    details = []

    has_gps = any(k.startswith("GPS") for k in exif_data)
    has_timestamp = any(k in exif_data for k in ["DateTimeOriginal", "DateTimeDigitized"])
    has_device = any(k in exif_data for k in ["Make", "Model", "LensModel"])
    has_software = any(k in exif_data for k in ["Software", "ProcessingSoftware"])
    has_artist = any(k in exif_data for k in ["Artist", "Copyright"])

    if has_gps:
        score += EXIF_OSINT_RISK_MAP["gps"]
        details.append(f"GPS coordinates present ({sum(1 for k in exif_data if 'GPS' in k)} fields)")

    if has_timestamp:
        score += EXIF_OSINT_RISK_MAP["timestamp"]
        details.append("Timestamps present (capture date/time)")

    if has_device:
        score += EXIF_OSINT_RISK_MAP["device"]
        device_parts = []
        if exif_data.get("Make"):
            device_parts.append(exif_data["Make"])
        if exif_data.get("Model"):
            device_parts.append(exif_data["Model"])
        details.append(f"Device info: {' '.join(device_parts)}")

    if has_software:
        score += EXIF_OSINT_RISK_MAP["software"]
        details.append(f"Software: {exif_data.get('Software', 'unknown')}")

    if has_artist:
        score += 2
        details.append(f"Creator: {exif_data.get('Artist', exif_data.get('Copyright', 'unknown'))}")

    # Determine risk level
    if score >= 15:
        risk_level = "CRITICAL"
    elif score >= 8:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "details": details,
    }


# ─── Known Hashes / File Meta Patterns ───────────────────────────────────────

def classify_image_url(url: str) -> Dict[str, Any]:
    """Classify an image URL to determine its source type and metadata.

    Analyzes the URL to determine if it's from social media, a CDN,
    a direct upload, or something else.
    """
    import re

    result: Dict[str, Any] = {
        "url": url,
        "source_type": "unknown",
        "platform": None,
        "has_size_params": False,
        "extension": None,
    }

    # Extract extension
    ext_match = re.search(r'\.([a-zA-Z0-9]+)(?:\?|$)', url)
    if ext_match:
        ext = f".{ext_match.group(1).lower()}"
        if ext in COMMON_IMAGE_EXTENSIONS:
            result["extension"] = ext

    # Check for social media platforms
    if "pbs.twimg.com" in url:
        result["source_type"] = "social_media"
        result["platform"] = "twitter"
    elif "avatars.githubusercontent.com" in url:
        result["source_type"] = "social_media"
        result["platform"] = "github"
    elif "media.licdn.com" in url:
        result["source_type"] = "social_media"
        result["platform"] = "linkedin"
    elif "fbcdn.net" in url:
        result["source_type"] = "social_media"
        result["platform"] = "facebook"
    elif "cdn.discordapp.com" in url:
        result["source_type"] = "social_media"
        result["platform"] = "discord"
    elif "i.redd.it" in url or "preview.redd.it" in url:
        result["source_type"] = "social_media"
        result["platform"] = "reddit"
    elif "instagram" in url and "fbcdn.net" in url:
        result["source_type"] = "social_media"
        result["platform"] = "instagram"

    # Check for size/version params
    if re.search(r'[?&](s|size|w|h|width|height)=\d+', url):
        result["has_size_params"] = True

    return result
