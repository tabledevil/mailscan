import logging
import io
import base64
from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    Image = None


class ImageAnalyzer(Analyzer):
    """Analyzer for image files.

    Extracts EXIF metadata (GPS coordinates, camera info, software,
    timestamps), detects tracking pixels (1x1 images), and generates
    a preview thumbnail.
    """

    compatible_mime_types = [
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/gif",
        "image/bmp",
        "image/webp",
    ]
    description = "Image Analyser"
    specificity = 20
    optional_pip_dependencies = [("PIL", "Pillow")]

    # EXIF tags that may reveal sensitive information
    SENSITIVE_EXIF_TAGS = {
        "GPSInfo": "GPS coordinates embedded in image",
        "GPSLatitude": "GPS latitude",
        "GPSLongitude": "GPS longitude",
    }

    def analysis(self):
        self.modules["basic_info"] = self._basic_info
        self.modules["exif_extraction"] = self._extract_exif
        self.modules["tracking_pixel"] = self._detect_tracking_pixel
        self.modules["preview"] = self._generate_preview
        super().analysis()

    def _basic_info(self):
        if not Image:
            log.warning("Pillow is not installed, cannot analyze images.")
            return

        try:
            img = Image.open(io.BytesIO(self.struct.rawdata))
            self.info = f"{img.format} {img.size[0]}x{img.size[1]} {img.mode}"
            self.reports["dimensions"] = Report(
                f"{img.size[0]}x{img.size[1]}", label="Dimensions"
            )
            self.reports["format"] = Report(
                f"{img.format}", label="Format"
            )
            self.reports["mode"] = Report(
                f"{img.mode}", label="Color mode"
            )
            self._image = img
        except Exception as e:
            log.error(f"Could not open image: {e}")

    def _extract_exif(self):
        if not Image or not hasattr(self, "_image"):
            return

        img = self._image
        try:
            exif_data = img.getexif()
        except Exception:
            return

        if not exif_data:
            return

        exif_entries = []
        gps_info = {}

        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, f"Unknown({tag_id})")

            if tag_name == "GPSInfo":
                # Decode GPS sub-tags
                try:
                    for gps_tag_id, gps_value in value.items():
                        gps_tag_name = GPSTAGS.get(gps_tag_id, f"Unknown({gps_tag_id})")
                        gps_info[gps_tag_name] = str(gps_value)
                except (AttributeError, TypeError):
                    gps_info["raw"] = str(value)
                continue

            # Truncate very long values
            str_value = str(value)
            if len(str_value) > 200:
                str_value = str_value[:200] + "..."

            exif_entries.append(f"{tag_name}: {str_value}")

        if exif_entries:
            self.reports["exif"] = Report(
                "\n".join(exif_entries),
                short=f"{len(exif_entries)} EXIF tag(s)",
                label="EXIF metadata",
            )

        if gps_info:
            gps_text = "\n".join(f"{k}: {v}" for k, v in gps_info.items())
            self.reports["gps"] = Report(
                gps_text,
                short="GPS coordinates found in image",
                label="GPS data",
                severity=Severity.MEDIUM,
            )

        # Flag potentially interesting EXIF fields
        interesting = []
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, "")
            if tag_name == "Software":
                interesting.append(f"Software: {value}")
            elif tag_name == "Make":
                interesting.append(f"Camera make: {value}")
            elif tag_name == "Model":
                interesting.append(f"Camera model: {value}")
            elif tag_name in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                interesting.append(f"{tag_name}: {value}")

        if interesting:
            self.reports["exif_highlights"] = Report(
                "\n".join(interesting),
                label="EXIF highlights",
            )

    def _detect_tracking_pixel(self):
        if not hasattr(self, "_image"):
            return

        img = self._image
        width, height = img.size

        if width <= 3 and height <= 3:
            self.reports["tracking_pixel"] = Report(
                f"Image is {width}x{height} — likely a tracking pixel",
                label="Tracking pixel",
                severity=Severity.MEDIUM,
            )

    def _generate_preview(self):
        if not hasattr(self, "_image"):
            return

        try:
            img = self._image.copy()
            # Resize to thumbnail for preview
            img.thumbnail((300, 300))
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
            self.reports["preview"] = Report(
                "Image preview",
                label="Preview",
                content_type="image/png",
                data=encoded,
            )
        except Exception as e:
            log.warning(f"Could not generate image preview: {e}")
