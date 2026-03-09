// This file is part of S3 Console
// Copyright (c) 2026 SeRP.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import React from "react";
import { Box, ProgressBar } from "mds";
import { useSelector } from "react-redux";
import { AppState } from "../../../../store";

interface DirectoryOperationStatsProps {
  visible: boolean;
}

const DirectoryOperationStats: React.FC<DirectoryOperationStatsProps> = ({
  visible,
}) => {
  const objectManager = useSelector(
    (state: AppState) => state.objectBrowser.objectManager,
  );

  if (!visible || !objectManager) {
    return null;
  }

  const { objectsToManage = [] } = objectManager;

  // Separate uploads and downloads from the unified list
  const uploads = objectsToManage.filter((obj: any) => obj.type === "upload");
  const downloads = objectsToManage.filter((obj: any) => obj.type === "download");

  // Calculate bulk operation statistics
  const activeUploads = uploads.filter((u: any) => !u.done && !u.failed && !u.cancelled);
  const completedUploads = uploads.filter((u: any) => u.done);
  const failedUploads = uploads.filter((u: any) => u.failed);

  const activeDownloads = downloads.filter((d: any) => !d.done && !d.failed && !d.cancelled);
  const completedDownloads = downloads.filter((d: any) => d.done);
  const failedDownloads = downloads.filter((d: any) => d.failed);

  const totalUploads = uploads.length;
  const totalDownloads = downloads.length;

  // Calculate aggregate progress
  const uploadProgress =
    totalUploads > 0
      ? Math.round(
          (uploads.reduce((sum: number, u: any) => sum + (u.percentage || 0), 0) /
            totalUploads)
        )
      : 0;

  const downloadProgress =
    totalDownloads > 0
      ? Math.round(
          (downloads.reduce((sum: number, d: any) => sum + (d.percentage || 0), 0) /
            totalDownloads)
        )
      : 0;

  const showBulkUploadStats = totalUploads > 5; // Show stats for bulk operations
  const showBulkDownloadStats = totalDownloads > 5;

  return (
    <Box
      sx={{
        padding: "10px",
        backgroundColor: "#f5f5f5",
        borderRadius: "4px",
        marginBottom: "10px",
      }}
    >
      {showBulkUploadStats && activeUploads.length > 0 && (
        <Box
          sx={{
            marginBottom: "15px",
            padding: "10px",
            backgroundColor: "#fff",
            borderRadius: "4px",
            border: "1px solid #e0e0e0",
          }}
        >
          <Box
            sx={{
              fontSize: "14px",
              fontWeight: 600,
              marginBottom: "8px",
              color: "#07193E",
            }}
          >
            📁 Bulk Upload in Progress
          </Box>
          <Box
            sx={{
              fontSize: "12px",
              marginBottom: "8px",
              color: "#5E5E5E",
            }}
          >
            {completedUploads.length} of {totalUploads} files uploaded
            {failedUploads.length > 0 && ` • ${failedUploads.length} failed`}
          </Box>
          <ProgressBar value={uploadProgress} sx={{ height: "8px" }} />
          <Box
            sx={{
              fontSize: "11px",
              marginTop: "4px",
              color: "#5E5E5E",
              textAlign: "right",
            }}
          >
            {uploadProgress}% complete
          </Box>
        </Box>
      )}

      {showBulkDownloadStats && activeDownloads.length > 0 && (
        <Box
          sx={{
            padding: "10px",
            backgroundColor: "#fff",
            borderRadius: "4px",
            border: "1px solid #e0e0e0",
          }}
        >
          <Box
            sx={{
              fontSize: "14px",
              fontWeight: 600,
              marginBottom: "8px",
              color: "#07193E",
            }}
          >
            📦 Bulk Download in Progress
          </Box>
          <Box
            sx={{
              fontSize: "12px",
              marginBottom: "8px",
              color: "#5E5E5E",
            }}
          >
            {completedDownloads.length} of {totalDownloads} files downloaded
            {failedDownloads.length > 0 && ` • ${failedDownloads.length} failed`}
          </Box>
          <ProgressBar value={downloadProgress} sx={{ height: "8px" }} />
          <Box
            sx={{
              fontSize: "11px",
              marginTop: "4px",
              color: "#5E5E5E",
              textAlign: "right",
            }}
          >
            {downloadProgress}% complete
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default DirectoryOperationStats;
