"""GCS client for fetching pathmon MTR logs."""

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

from google.cloud import storage

DEFAULT_BUCKET_NAME = os.environ.get("PATHMON_GCS_BUCKET")


@dataclass
class MtrLogFile:
    """Represents an MTR log file in GCS."""

    pathmon_name: str
    timestamp: datetime
    passed: bool
    blob_name: str
    content: str | None = None

    @classmethod
    def from_blob_name(cls, blob_name: str) -> "MtrLogFile":
        """Parse blob name into MtrLogFile.

        Expected format: <pathmon_name>/yyyy-mm-dd/hh:mm:ss.ms.log-<Pass|Fail>
        """
        parts = blob_name.split("/")
        if len(parts) != 3:
            raise ValueError(f"Invalid blob name format: {blob_name}")

        pathmon_name = parts[0]
        date_str = parts[1]
        filename = parts[2]

        time_part, status = filename.rsplit(".log-", 1)
        passed = status == "Pass"

        time_normalized = time_part.replace(":", ".", 3)[:15]
        timestamp_str = f"{date_str} {time_normalized}"
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H.%M.%S.%f").replace(
            tzinfo=timezone.utc
        )

        return cls(
            pathmon_name=pathmon_name,
            timestamp=timestamp,
            passed=passed,
            blob_name=blob_name,
        )


class GcsClient:
    """Client for fetching MTR logs from GCS."""

    def __init__(self, bucket_name: str | None = DEFAULT_BUCKET_NAME):
        if not bucket_name:
            raise ValueError(
                "GCS bucket name is required.\n\n"
                "Set it via:\n"
                "  • Environment variable: export PATHMON_GCS_BUCKET=your-bucket-name\n"
                "  • CLI option: pathmon --bucket your-bucket-name <command>\n"
            )
        self.client = storage.Client()
        self.bucket = self.client.bucket(bucket_name)

    def list_pathmons(self) -> list[str]:
        """List all pathmon names in the bucket."""
        blobs = self.client.list_blobs(self.bucket, delimiter="/")
        list(blobs)  # Consume iterator to populate prefixes
        return [p.rstrip("/") for p in blobs.prefixes]

    def list_logs(
        self,
        pathmon_name: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        only_failures: bool = False,
    ) -> Iterator[MtrLogFile]:
        """List MTR log files for a pathmon within a time range.

        Args:
            pathmon_name: Name of the pathmon to query
            start_time: Start of time range (inclusive), converted to UTC
            end_time: End of time range (inclusive), converted to UTC
            only_failures: If True, only return failed logs

        Yields:
            MtrLogFile objects matching the criteria
        """
        from datetime import timedelta

        if start_time and start_time.tzinfo is None:
            start_time = start_time.astimezone(timezone.utc)
        elif start_time:
            start_time = start_time.astimezone(timezone.utc)

        if end_time and end_time.tzinfo is None:
            end_time = end_time.astimezone(timezone.utc)
        elif end_time:
            end_time = end_time.astimezone(timezone.utc)

        if start_time and end_time:
            current_date = start_time.date()
            end_date = end_time.date()
            dates_to_query = []
            while current_date <= end_date:
                dates_to_query.append(current_date)
                current_date += timedelta(days=1)
        elif start_time:
            dates_to_query = [start_time.date()]
        else:
            dates_to_query = []

        if dates_to_query:
            for date in dates_to_query:
                prefix = f"{pathmon_name}/{date.strftime('%Y-%m-%d')}/"
                yield from self._list_logs_with_prefix(prefix, start_time, end_time, only_failures)
        else:
            prefix = f"{pathmon_name}/"
            yield from self._list_logs_with_prefix(prefix, start_time, end_time, only_failures)

    def _list_logs_with_prefix(
        self,
        prefix: str,
        start_time: datetime | None,
        end_time: datetime | None,
        only_failures: bool,
    ) -> Iterator[MtrLogFile]:
        """Helper to list logs with a specific prefix."""
        blobs = self.client.list_blobs(self.bucket, prefix=prefix)

        for blob in blobs:
            try:
                log_file = MtrLogFile.from_blob_name(blob.name)
            except (ValueError, IndexError):
                continue

            if start_time and log_file.timestamp < start_time:
                continue
            if end_time and log_file.timestamp > end_time:
                continue
            if only_failures and log_file.passed:
                continue

            yield log_file

    def fetch_log_content(self, log_file: MtrLogFile) -> str:
        """Fetch the content of an MTR log file."""
        blob = self.bucket.blob(log_file.blob_name)
        content = blob.download_as_text()
        log_file.content = content
        return content

    def fetch_logs_around_time(
        self,
        pathmon_name: str,
        alert_time: datetime,
        minutes_before: int = 30,
        minutes_after: int = 10,
    ) -> list[MtrLogFile]:
        """Fetch logs around an alert time.

        Useful for investigating a PagerDuty alert.

        Args:
            pathmon_name: Name of the pathmon
            alert_time: Time of the alert
            minutes_before: Minutes before alert to include
            minutes_after: Minutes after alert to include

        Returns:
            List of MtrLogFile objects with content fetched
        """
        from datetime import timedelta

        if alert_time.tzinfo is None:
            alert_time = alert_time.astimezone(timezone.utc)
        else:
            alert_time = alert_time.astimezone(timezone.utc)

        start_time = alert_time - timedelta(minutes=minutes_before)
        end_time = alert_time + timedelta(minutes=minutes_after)

        logs = list(self.list_logs(pathmon_name, start_time, end_time))

        for log in logs:
            self.fetch_log_content(log)

        return sorted(logs, key=lambda x: x.timestamp)
