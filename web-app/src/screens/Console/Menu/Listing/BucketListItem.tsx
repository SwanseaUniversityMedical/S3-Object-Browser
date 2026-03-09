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
import { useNavigate } from "react-router-dom";
import { Box, BucketsIcon } from "mds";
import { Bucket } from "../../../../api/consoleApi";

interface IBucketListItem {
  bucket: Bucket;
}

const BucketListItem = ({ bucket }: IBucketListItem) => {
  const navigate = useNavigate();

  return (
    <Box
      onClick={() => navigate(`/browser/${bucket.name}`)}
      id={`manageBucket-${bucket.name}`}
      sx={{
        display: "flex",
        alignItems: "center",
        gap: 1,
        padding: "8px 12px",
        cursor: "pointer",
        borderRadius: 1,
        width: "100%",
        color: "#fff",
        "& svg": {
          fill: "#fff",
        },
        "&:hover": {
          backgroundColor: "rgba(255, 255, 255, 0.15)",
        },
      }}
    >
      <BucketsIcon />
      <Box
        sx={{
          textAlign: "left",
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          flexGrow: 1,
          color: "#fff",
        }}
      >
        {bucket.name}
      </Box>
    </Box>
  );
};

export default BucketListItem;
