"""Create the versioned S3 buckets in the local object store (MinIO). Idempotent.

    python -m scripts.init_local_storage
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from src.core.config import secret_value, settings


def main() -> None:
    """Create ``S3_BUCKET_SBOM`` and ``S3_BUCKET_LOGS`` and enable versioning on both."""
    s3 = boto3.client(
        "s3",
        endpoint_url=settings.S3_ENDPOINT_URL,
        aws_access_key_id=secret_value(settings.S3_ACCESS_KEY, "S3_ACCESS_KEY"),
        aws_secret_access_key=secret_value(settings.S3_SECRET_KEY, "S3_SECRET_KEY"),
        region_name=settings.AWS_REGION,
    )
    for bucket in (settings.S3_BUCKET_SBOM, settings.S3_BUCKET_LOGS):
        try:
            s3.create_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        print(f"bucket ready (versioned): {bucket}")


if __name__ == "__main__":
    main()
