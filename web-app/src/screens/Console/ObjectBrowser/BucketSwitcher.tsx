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

import React, { Fragment, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { BucketsIcon, DropdownSelector, Button } from "mds";
import { api } from "../../../api";
import { Bucket } from "../../../api/consoleApi";
import { AppState, useAppDispatch } from "../../../store";
import { setErrorSnackMessage } from "../../../systemSlice";
import { errorToHandler } from "../../../api/errors";
import { useSelector } from "react-redux";

interface IBucketSwitcher {
  currentBucket: string;
}

const BucketSwitcher = ({ currentBucket }: IBucketSwitcher) => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [dropdownOpen, setDropdownOpen] = useState<boolean>(false);

  // Load available buckets
  useEffect(() => {
    const fetchBuckets = () => {
      setLoading(true);
      api.buckets
        .listBuckets()
        .then((res) => {
          if (res.data) {
            setBuckets(res.data.buckets || []);
          }
          setLoading(false);
        })
        .catch((err) => {
          dispatch(setErrorSnackMessage(errorToHandler(err)));
          setLoading(false);
        });
    };

    fetchBuckets();
  }, [dispatch]);

  // Convert buckets to dropdown options
  const bucketOptions = buckets.map((bucket) => ({
    label: bucket.name,
    value: bucket.name,
    icon: <BucketsIcon />,
  }));

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setDropdownOpen(!dropdownOpen);
    setAnchorEl(event.currentTarget);
  };

  const handleBucketSelect = (selectedBucket: string) => {
    if (selectedBucket && selectedBucket !== currentBucket) {
      navigate(`/browser/${selectedBucket}`);
    }
    setDropdownOpen(false);
  };

  if (loading || buckets.length === 0) {
    return null;
  }

  return (
    <Fragment>
      <Button
        id={"bucket-switcher"}
        aria-controls={"bucket-switcher-menu"}
        aria-haspopup="true"
        aria-expanded={dropdownOpen ? "true" : undefined}
        onClick={handleClick}
        label={currentBucket}
        icon={<BucketsIcon />}
        variant={"regular"}
        sx={{
          fontSize: "14px",
          fontWeight: "500",
          padding: "6px 12px",
          textTransform: "none",
        }}
      />
      <DropdownSelector
        id={"bucket-switcher-menu"}
        options={bucketOptions}
        selectedOption={currentBucket}
        onSelect={handleBucketSelect}
        hideTriggerAction={() => {
          setDropdownOpen(false);
        }}
        open={dropdownOpen}
        anchorEl={anchorEl}
        anchorOrigin={"end"}
      />
    </Fragment>
  );
};

export default BucketSwitcher;
