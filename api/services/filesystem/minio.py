import asyncio
import io
from datetime import timedelta
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from loguru import logger
from minio import Minio
from minio.error import S3Error

from .base import AsyncReadable, BaseFileSystem


# Response types forced by force_inline, so the browser renders instead of
# downloading (same list as the S3 implementation).
_INLINE_TYPES = {".txt": "text/plain", ".wav": "audio/wav", ".mp3": "audio/mpeg"}


class MinioFileSystem(BaseFileSystem):
    """MinIO implementation of the filesystem interface for OSS users.

    Two endpoints, two different purposes:
    - endpoint (host:port) + secure (bool): used by the MinIO SDK for
      container-to-container calls. The SDK requires these split.
    - public_endpoint (full URL, e.g. "https://example.com"): the address
      browsers fetch objects from. Required. URLs for it are presigned by a
      second client configured with that host, because the signature covers
      the Host header the browser will send.

    The bucket is private: every URL handed out is presigned. An anonymous
    bucket policy, which earlier versions set on every start, is removed.
    """

    def __init__(
        self,
        endpoint: str = "localhost:9000",
        access_key: str = "minioadmin",
        secret_key: str = "minioadmin",
        bucket_name: str = "voice-audio",
        secure: bool = False,
        public_endpoint: Optional[str] = None,
    ):
        if not public_endpoint:
            raise ValueError(
                "MinioFileSystem requires public_endpoint (set MINIO_PUBLIC_ENDPOINT). "
                "Expected a full URL with scheme, e.g. 'http://localhost:9000' or 'https://example.com'."
            )
        if not (
            public_endpoint.startswith("http://")
            or public_endpoint.startswith("https://")
        ):
            raise ValueError(
                f"MINIO_PUBLIC_ENDPOINT must include a scheme (http:// or https://), got: {public_endpoint!r}"
            )

        self.bucket_name = bucket_name
        self.endpoint = endpoint
        self.public_endpoint = public_endpoint.rstrip("/")
        self.secure = secure
        self.access_key = access_key
        self.secret_key = secret_key

        # Client for internal operations (uploads, etc.)
        self.client = Minio(
            endpoint, access_key=access_key, secret_key=secret_key, secure=secure
        )

        # Presigns URLs for the public address. Presigning is local, but the
        # SDK would look the region up over the network without one.
        public = urlsplit(self.public_endpoint)
        if public.path not in ("", "/"):
            raise ValueError(
                f"MINIO_PUBLIC_ENDPOINT must not have a path, got: {public_endpoint!r}"
            )
        self.public_client = Minio(
            public.netloc,
            access_key=access_key,
            secret_key=secret_key,
            secure=public.scheme == "https",
            region="us-east-1",
        )

        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
            # Recordings and transcripts must never be readable, writable or
            # listable without a signature.
            try:
                self.client.delete_bucket_policy(self.bucket_name)
            except S3Error as e:
                if e.code != "NoSuchBucketPolicy":
                    raise
        except Exception as e:
            logger.warning(f"MinIO bucket setup failed: {e}")

    async def acreate_file(self, file_path: str, content: AsyncReadable) -> bool:
        try:
            data = await content.read()

            def _put():
                # The MinIO SDK requires a stream with .read(), not raw bytes.
                self.client.put_object(
                    self.bucket_name,
                    file_path,
                    data=io.BytesIO(data),
                    length=len(data),
                )

            await asyncio.to_thread(_put)
            return True
        except S3Error:
            return False

    async def aupload_file(self, local_path: str, destination_path: str) -> bool:
        try:

            def _fput():
                self.client.fput_object(self.bucket_name, destination_path, local_path)

            await asyncio.to_thread(_fput)
            return True
        except S3Error:
            return False

    async def aget_signed_url(
        self,
        file_path: str,
        expiration: int = 3600,
        force_inline: bool = False,
        use_internal_endpoint: bool = False,
    ) -> Optional[str]:
        """Presigned GET URL; inline rendering as in the S3 implementation."""
        response_headers = None
        if force_inline:
            for suffix, content_type in _INLINE_TYPES.items():
                if file_path.endswith(suffix):
                    response_headers = {
                        "response-content-type": content_type,
                        "response-content-disposition": "inline",
                    }
                    break
        signer = self.client if use_internal_endpoint else self.public_client
        try:
            return signer.presigned_get_object(
                self.bucket_name,
                file_path,
                expires=timedelta(seconds=expiration),
                response_headers=response_headers,
            )
        except Exception as e:
            logger.error(f"Error generating MinIO URL: {e}")
            return None

    async def aget_file_metadata(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get MinIO object metadata."""
        try:

            def _stat():
                return self.client.stat_object(self.bucket_name, file_path)

            stat = await asyncio.to_thread(_stat)
            return {
                "size": stat.size,
                "created_at": stat.last_modified,
                "modified_at": stat.last_modified,
                "etag": stat.etag.strip('"') if stat.etag else None,
                "content_type": stat.content_type,
                "storage_class": None,  # MinIO doesn't have storage classes like S3
            }
        except S3Error:
            return None

    async def aget_presigned_put_url(
        self,
        file_path: str,
        expiration: int = 900,
        content_type: str = "text/csv",
        max_size: int = 10_485_760,
    ) -> Optional[str]:
        """Presigned PUT URL for a browser upload to the public address."""
        try:
            return self.public_client.presigned_put_object(
                self.bucket_name, file_path, expires=timedelta(seconds=expiration)
            )
        except Exception as e:
            logger.error(f"Error generating MinIO upload URL: {e}")
            return None

    async def adownload_file(self, source_path: str, local_path: str) -> bool:
        """Download a file from MinIO to local path."""
        try:

            def _fget():
                self.client.fget_object(self.bucket_name, source_path, local_path)

            await asyncio.to_thread(_fget)
            return True
        except S3Error:
            return False

    async def acopy_file(self, source_path: str, destination_path: str) -> bool:
        """Copy a file within MinIO (server-side copy)."""
        try:
            from minio.commonconfig import CopySource

            def _copy():
                self.client.copy_object(
                    self.bucket_name,
                    destination_path,
                    CopySource(self.bucket_name, source_path),
                )

            await asyncio.to_thread(_copy)
            return True
        except S3Error:
            return False
