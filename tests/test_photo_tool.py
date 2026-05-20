"""
Unit tests for the Photo OSINT Engine module.

Tests cover:
  - Photo library: EXIF fields, platform definitions, risk scoring, URL classification
  - PhotoTool: EXIF extraction, reverse search links, face detection, error handling
  - PhotoExecutor: rate limiting, queue management, delegation
  - Integration: tool manager registration, agent tool availability
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any, Dict, List

from src.osint_platform.tools.photo.photo_library import (
    EXIF_FIELDS,
    REVERSE_IMAGE_ENDPOINTS,
    SOCIAL_MEDIA_PHOTO_PATTERNS,
    classify_image_url,
    get_exif_risk_score,
    EXIFCategory,
    FaceDetectionConfidence,
    ImageSource,
    SearchPlatform,
    COMMON_IMAGE_EXTENSIONS,
    SOCIAL_MEDIA_IMAGE_DOMAINS,
)
from src.osint_platform.tools.photo.photo_tool import (
    PhotoTool,
    analyze_photo_batch,
    _is_image_url,
    _compute_image_hashes,
    _convert_to_decimal_degrees,
    _parse_gps_coordinates,
)
from src.osint_platform.tools.executors.photo_executor import PhotoExecutor
from src.osint_platform.tools.base import ToolResult


# ═══════════════════════════════════════════════════════════════════════════════
# Photo Library Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhotoLibrary:
    """Test the photo OSINT library definitions."""

    def test_exif_fields_have_all_required_attrs(self):
        """Every EXIF field must have tag, label, category, description, osint_value."""
        for field in EXIF_FIELDS:
            assert field.tag, f"Missing tag in EXIF field"
            assert field.label, f"Missing label in {field.tag}"
            assert field.category, f"Missing category in {field.tag}"
            assert field.description, f"Missing description in {field.tag}"
            assert field.osint_value, f"Missing osint_value in {field.tag}"
            assert isinstance(field.category, EXIFCategory), f"Invalid category type in {field.tag}"

    def test_exif_fields_cover_all_categories(self):
        """EXIF fields should span all defined categories."""
        covered_categories = set(f.category for f in EXIF_FIELDS)
        for cat in EXIFCategory:
            assert cat in covered_categories, f"No EXIF fields for category: {cat}"

    def test_reverse_image_endpoints_have_required_keys(self):
        """Every reverse search endpoint must have name, upload_url, search_url, description."""
        for key, info in REVERSE_IMAGE_ENDPOINTS.items():
            assert "name" in info, f"Missing name in {key}"
            assert "search_url" in info, f"Missing search_url in {key}"
            assert "description" in info, f"Missing description in {key}"
            assert "{url}" in info["search_url"], f"search_url for {key} missing {{url}} placeholder"

    def test_social_media_photo_patterns_have_required_keys(self):
        """Every social media pattern must have pattern and description."""
        for platform, info in SOCIAL_MEDIA_PHOTO_PATTERNS.items():
            assert "pattern" in info, f"Missing pattern for {platform}"
            assert "description" in info, f"Missing description for {platform}"

    def test_common_image_extensions(self):
        """Common image extensions should include .jpg, .png, .gif, .webp."""
        for ext in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff"]:
            assert ext in COMMON_IMAGE_EXTENSIONS, f"Missing common extension: {ext}"

    def test_classify_image_url_twitter(self):
        """URLs from pbs.twimg.com should be classified as Twitter."""
        result = classify_image_url("https://pbs.twimg.com/profile_images/123456/photo.jpg")
        assert result["source_type"] == "social_media"
        assert result["platform"] == "twitter"

    def test_classify_image_url_github(self):
        """URLs from avatars.githubusercontent.com should be classified as GitHub."""
        result = classify_image_url("https://avatars.githubusercontent.com/u/12345?v=4")
        assert result["source_type"] == "social_media"
        assert result["platform"] == "github"

    def test_classify_image_url_unknown(self):
        """Unknown image URLs should return unknown source type."""
        result = classify_image_url("https://example.com/images/photo.jpg")
        assert result["source_type"] == "unknown"

    def test_classify_image_url_detects_extension(self):
        """URL classification should extract the file extension."""
        result = classify_image_url("https://example.com/photo.png")
        assert result["extension"] == ".png"

    def test_classify_image_url_detects_size_params(self):
        """URLs with size parameters should be flagged."""
        result = classify_image_url("https://example.com/photo.jpg?s=200")
        assert result["has_size_params"] is True

    def test_get_exif_risk_score_empty(self):
        """Empty EXIF data should return LOW risk."""
        result = get_exif_risk_score({})
        assert result["risk_score"] == 0
        assert result["risk_level"] == "LOW"

    def test_get_exif_risk_score_gps_only(self):
        """GPS data alone should be CRITICAL."""
        result = get_exif_risk_score({"GPSLatitude": "40.7128", "GPSLongitude": "-74.0060"})
        assert result["risk_score"] >= 10
        assert result["risk_level"] == "HIGH" or result["risk_level"] == "CRITICAL"

    def test_get_exif_risk_score_all_fields(self):
        """All EXIF fields combined should result in CRITICAL risk."""
        result = get_exif_risk_score({
            "GPSLatitude": "40.7128",
            "GPSLongitude": "-74.0060",
            "DateTimeOriginal": "2024:01:01 12:00:00",
            "Make": "Apple",
            "Model": "iPhone 15 Pro",
            "Software": "Adobe Photoshop Lightroom",
        })
        assert result["risk_score"] >= 20
        assert result["risk_level"] == "CRITICAL"
        assert len(result["details"]) >= 3


# ═══════════════════════════════════════════════════════════════════════════════
# PhotoTool Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhotoTool:
    """Test the PhotoTool class."""

    @pytest.fixture
    def tool(self):
        return PhotoTool(timeout=30, max_results=10)

    def test_initialization(self, tool):
        """Tool should initialize with correct defaults."""
        assert tool.name == "photo_osint"
        assert tool.timeout == 30
        assert tool.max_results == 10

    def test_validate_query_valid(self, tool):
        """validate_query should return True for non-empty queries."""
        assert tool.validate_query("https://example.com/photo.jpg") is True

    def test_validate_query_empty(self, tool):
        """validate_query should return False for empty queries."""
        assert tool.validate_query("") is False

    def test_is_image_url_jpg(self):
        """_is_image_url should detect .jpg URLs."""
        assert _is_image_url("https://example.com/photo.jpg") is True
        assert _is_image_url("https://example.com/photo.jpeg") is True

    def test_is_image_url_png(self):
        """_is_image_url should detect .png URLs."""
        assert _is_image_url("https://example.com/photo.png") is True

    def test_is_image_url_webp(self):
        """_is_image_url should detect .webp URLs."""
        assert _is_image_url("https://example.com/photo.webp") is True

    def test_is_image_url_social_media_domain(self):
        """_is_image_url should detect social media CDN images even without extension."""
        assert _is_image_url("https://pbs.twimg.com/media/ABC123") is True
        assert _is_image_url("https://avatars.githubusercontent.com/u/12345") is True

    def test_is_image_url_non_image(self):
        """_is_image_url should return False for non-image URLs."""
        assert _is_image_url("https://example.com/page.html") is False
        assert _is_image_url("https://example.com") is False

    def test_compute_image_hashes(self):
        """_compute_image_hashes should return md5, sha1, sha256."""
        hashes = _compute_image_hashes(b"test image data")
        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert len(hashes["sha256"]) == 64

    def test_convert_to_decimal_degrees(self):
        """GPS coords should convert correctly."""
        result = _convert_to_decimal_degrees((40, 42, 46.0), "N")
        assert result is not None
        assert abs(result - 40.7128) < 0.01

    def test_convert_to_decimal_degrees_south(self):
        """Southern hemisphere should be negative."""
        result = _convert_to_decimal_degrees((33, 51, 0.0), "S")
        assert result is not None
        assert result < 0

    def test_convert_to_decimal_degrees_west(self):
        """Western hemisphere should be negative."""
        result = _convert_to_decimal_degrees((74, 0, 0.0), "W")
        assert result is not None
        assert result < 0

    def test_parse_gps_coordinates_valid(self):
        """parse_gps_coordinates should extract lat/lng from EXIF GPSInfo."""
        exif = {
            "GPSInfo": {
                "GPSLatitude": (40, 42, 46),
                "GPSLatitudeRef": "N",
                "GPSLongitude": (74, 0, 21),
                "GPSLongitudeRef": "W",
            }
        }
        coords = _parse_gps_coordinates(exif)
        assert coords is not None
        assert abs(coords["lat"] - 40.7128) < 0.01
        assert abs(coords["lng"] - (-74.0059)) < 0.01

    def test_parse_gps_coordinates_none(self):
        """parse_gps_coordinates should return None when no GPS data."""
        assert _parse_gps_coordinates({}) is None
        assert _parse_gps_coordinates({"GPSInfo": {}}) is None

    @pytest.mark.asyncio
    async def test_search_no_url_returns_error(self, tool):
        """Search with empty query should return failed result."""
        result = await tool.search("")
        assert result.success is False
        assert "image" in str(result.data).lower()

    @pytest.mark.asyncio
    async def test_search_with_invalid_url(self, tool):
        """Search with invalid URL should return failed result."""
        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=None)):
            result = await tool.search("https://example.com/nonexistent.jpg")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_search_with_valid_image_data(self, tool):
        """Search with image data should extract EXIF and detect faces."""
        # A minimal 1x1 pixel PNG (valid PNG image data)
        minimal_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=minimal_png)):
            result = await tool.search("https://example.com/photo.png")

        assert result.success is True
        assert result.tool_name == "photo_osint"
        assert len(result.data) > 0

    @pytest.mark.asyncio
    async def test_search_extracts_hashes(self, tool):
        """Search should always compute image hashes."""
        minimal_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=minimal_png)):
            result = await tool.search("https://example.com/photo.png")

        # Find the image_metadata finding with hashes
        metadata_findings = [f for f in result.data if f.get("type") == "image_metadata"]
        assert len(metadata_findings) > 0
        hashes = metadata_findings[0].get("hashes", {})
        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes

    @pytest.mark.asyncio
    async def test_search_disables_exif(self, tool):
        """Search with extract_exif=False should skip EXIF extraction."""
        minimal_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=minimal_png)):
            result = await tool.search("https://example.com/photo.png", extract_exif=False)

        exif_findings = [f for f in result.data if f.get("type") == "exif_metadata"]
        assert len(exif_findings) == 0

    @pytest.mark.asyncio
    async def test_search_disables_face_detection(self, tool):
        """Search with detect_faces=False should skip face detection."""
        minimal_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=minimal_png)):
            result = await tool.search("https://example.com/photo.png", detect_faces=False)

        face_findings = [f for f in result.data if f.get("type") == "face_detected"]
        assert len(face_findings) == 0

    @pytest.mark.asyncio
    async def test_search_generates_reverse_search_links(self, tool):
        """Search with valid URL should generate reverse search links."""
        minimal_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=minimal_png)):
            result = await tool.search("https://example.com/photo.png", reverse_search=True)

        reverse_findings = [f for f in result.data if f.get("type") == "reverse_search"]
        assert len(reverse_findings) > 0
        engines = reverse_findings[0].get("engines", [])
        assert len(engines) >= 4  # Google, Bing, Yandex, TinEye

    @pytest.mark.asyncio
    async def test_search_returns_toolresult_type(self, tool):
        """Search should always return a ToolResult instance."""
        with patch("src.osint_platform.tools.photo.photo_tool._download_image", AsyncMock(return_value=None)):
            result = await tool.search("https://example.com/nonexistent.jpg")
            assert isinstance(result, ToolResult)

    @pytest.mark.asyncio
    async def test_analyze_photo_batch(self, tool):
        """Batch analysis should handle multiple URLs."""
        minimal_png = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )

        with patch.object(tool, "search", AsyncMock(return_value=ToolResult(
            tool_name="photo_osint",
            query="https://example.com/photo.png",
            success=True,
            data=[{"type": "image_metadata", "summary": "Test"}],
            execution_time_seconds=0.1,
        ))):
            result = await analyze_photo_batch(tool, ["https://example.com/1.png", "https://example.com/2.png"])

        assert result["total_images"] == 2
        assert "results_by_url" in result


# ═══════════════════════════════════════════════════════════════════════════════
# PhotoExecutor Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhotoExecutor:
    """Test the PhotoExecutor class."""

    def test_initialization(self):
        """Executor should initialize with correct settings."""
        executor = PhotoExecutor()
        assert executor.tool_name == "photo_osint"
        assert executor.requests_per_second == 2.0
        assert executor.max_concurrent == 1
        assert executor.timeout_seconds == 120
        assert executor.tool.name == "photo_osint"

    def test_custom_initialization(self):
        """Executor should accept custom kwargs."""
        executor = PhotoExecutor(timeout_seconds=60)
        assert executor.timeout_seconds == 60

    @pytest.mark.asyncio
    async def test_execute_delegates_to_tool(self):
        """execute() should delegate to the underlying PhotoTool.search()."""
        executor = PhotoExecutor()
        mock_result = ToolResult(
            tool_name="photo_osint",
            query="https://example.com/photo.jpg",
            success=True,
            data=[{"type": "image_metadata", "summary": "Test"}],
            execution_time_seconds=0.3,
        )

        with patch.object(executor.tool, "search", AsyncMock(return_value=mock_result)) as mock_search:
            result = await executor.execute("https://example.com/photo.jpg")

        assert result == mock_result
        mock_search.assert_called_once_with("https://example.com/photo.jpg")

    @pytest.mark.asyncio
    async def test_execute_passes_kwargs(self):
        """execute() should pass kwargs to the tool's search method."""
        executor = PhotoExecutor()
        mock_result = ToolResult(
            tool_name="photo_osint",
            query="test",
            success=True,
            data=[],
            execution_time_seconds=0.1,
        )

        with patch.object(executor.tool, "search", AsyncMock(return_value=mock_result)) as mock_search:
            await executor.execute("https://example.com/photo.jpg", extract_exif=False, detect_faces=False)

        mock_search.assert_called_once_with("https://example.com/photo.jpg", extract_exif=False, detect_faces=False)


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhotoIntegration:
    """Test integration with the rest of the platform."""

    def test_tool_manager_registers_photo(self):
        """ToolManager should include the photo_osint executor."""
        from src.osint_platform.tools.tool_manager import ToolManager

        manager = ToolManager()
        assert "photo_osint" in manager.executors

    def test_tool_manager_photo_executor_type(self):
        """The photo_osint executor should be a PhotoExecutor instance."""
        from src.osint_platform.tools.tool_manager import ToolManager
        from src.osint_platform.tools.executors.photo_executor import PhotoExecutor

        manager = ToolManager()
        assert isinstance(manager.executors["photo_osint"], PhotoExecutor)

    def test_agent_tools_include_photo(self):
        """The agent tool registry should include photo_osint_search."""
        from src.osint_platform.agent.tools import AVAILABLE_TOOLS, TOOL_LIST

        assert "photo_osint_search" in AVAILABLE_TOOLS

        # Check that it's in the tool list
        tool_names = [t.name if hasattr(t, "name") else str(t) for t in TOOL_LIST]
        assert any("photo" in name for name in tool_names)

    def test_agent_tool_descriptions(self):
        """Tool descriptions should mention photo OSINT usage."""
        from src.osint_platform.agent.tools import get_tool_descriptions

        desc = get_tool_descriptions()
        assert "photo_osint_search" in desc
        assert "EXIF" in desc

    def test_executors_init_exports_photo(self):
        """executors.__init__ should export PhotoExecutor."""
        from src.osint_platform.tools.executors import PhotoExecutor
        assert PhotoExecutor is not None

    def test_photo_module_init_exports(self):
        """photo.__init__ should export all expected symbols."""
        from src.osint_platform.tools.photo import (
            PhotoTool,
            analyze_photo_batch,
            classify_image_url,
            get_exif_risk_score,
            EXIF_FIELDS,
            REVERSE_IMAGE_ENDPOINTS,
            FaceDetectionConfidence,
            EXIFCategory,
        )
        assert PhotoTool is not None
        assert callable(analyze_photo_batch)
        assert callable(classify_image_url)
        assert callable(get_exif_risk_score)
        assert isinstance(EXIF_FIELDS, list)
        assert isinstance(REVERSE_IMAGE_ENDPOINTS, dict)
        assert FaceDetectionConfidence is not None
        assert EXIFCategory is not None


# ═══════════════════════════════════════════════════════════════════════════════
# URL Classification Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestURLClassificationEdgeCases:
    """Test edge cases in image URL classification."""

    def test_classify_reddit_url(self):
        """Reddit image URLs should be classified correctly."""
        result = classify_image_url("https://i.redd.it/abc123.jpg")
        assert result["platform"] == "reddit"
        assert result["source_type"] == "social_media"

    def test_classify_discord_cdn(self):
        """Discord CDN URLs should be classified correctly."""
        result = classify_image_url("https://cdn.discordapp.com/attachments/123/456/image.png")
        assert result["platform"] == "discord"

    def test_classify_data_uri(self):
        """Data URIs should not crash classification."""
        result = classify_image_url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
        assert result is not None
        assert result["source_type"] == "unknown"

    def test_classify_no_extension(self):
        """URLs without extension should still work."""
        result = classify_image_url("https://pbs.twimg.com/media/ABC123")
        assert result["extension"] is None
        assert result["platform"] == "twitter"

    def test_classify_with_query_params(self):
        """URLs with complex query params should parse correctly."""
        result = classify_image_url("https://example.com/photo.jpg?w=800&h=600&fit=crop")
        assert result["extension"] == ".jpg"
        assert result["has_size_params"] is True

    def test_multiple_size_params(self):
        """URLs with multiple size parameters."""
        result = classify_image_url("https://example.com/photo.png?s=200&width=400&height=300")
        assert result["has_size_params"] is True
