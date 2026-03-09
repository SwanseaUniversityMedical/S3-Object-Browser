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
import { Box, BucketsIcon, HelpBox } from "mds";
import { AppState, useAppDispatch } from "../../../../store";
import { Bucket } from "../../../../api/consoleApi";
import { api } from "../../../../api";
import {
  setBucketLoadListing,
  setErrorSnackMessage,
} from "../../../../systemSlice";
import { errorToHandler } from "../../../../api/errors";
import BucketListItem from "./BucketListItem";
import get from "lodash/get";
import { useTheme } from "styled-components";
import BucketFiltering from "./BucketFiltering";
import { useSelector } from "react-redux";

// Local menu component stubs - not exported from mds
const MenuDivider = () => null;
const MenuSectionHeader = (props: any) => null;

const ListBuckets = () => {
  const dispatch = useAppDispatch();
  const theme = useTheme();

  console.log("BucketsListing: Component rendering");

  const filterBuckets = useSelector(
    (state: AppState) => state.system.filterBucketList,
  );
  const loadingBuckets = useSelector(
    (state: AppState) => state.system.loadBucketsListing,
  );
  const sidebarOpen = useSelector(
    (state: AppState) => state.system.sidebarOpen,
  );

  const [records, setRecords] = useState<Bucket[]>([]);

  useEffect(() => {
    const fetchRecords = () => {
      console.log("BucketsListing: Starting fetch");
      dispatch(setBucketLoadListing(true));
      api.buckets
        .listBuckets()
        .then((res) => {
          console.log("BucketsListing: API response:", res);
          if (res.data) {
            console.log("BucketsListing: Setting records:", res.data.buckets);
            setRecords(res.data.buckets || []);
          } else if (res.error) {
            console.log("BucketsListing: API error:", res.error);
            dispatch(setErrorSnackMessage(errorToHandler(res.error)));
          }
        })
        .catch((err) => {
          console.log("BucketsListing: Fetch error:", err);
          dispatch(setErrorSnackMessage(errorToHandler(err)));
        })
        .finally(() => {
          dispatch(setBucketLoadListing(false));
        });
    };

    if (loadingBuckets || records.length === 0) {
      console.log("BucketsListing: Condition met, calling fetch. loadingBuckets:", loadingBuckets, "records.length:", records.length);
      fetchRecords();
    }
  }, [loadingBuckets, records.length, dispatch]);

  const filteredRecords = records.filter((b: Bucket) => {
    if (filterBuckets === "") {
      return true;
    } else {
      return b.name.indexOf(filterBuckets) >= 0;
    }
  });

  return (
    <Fragment>
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          color: "#fff",
          "& .menuHeader": {
            marginTop: 10,
            color: "#fff",
          },
          "& .labelContainer": {
            textAlign: "left",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            flexGrow: 1,
            width: 150,
            color: "#fff",
          },
        }}
      >
        <BucketFiltering />
        <Box
          sx={{
            padding: "10px 15px 5px",
            fontSize: "12px",
            fontWeight: 600,
            color: "rgba(255,255,255,0.7)",
            textTransform: "uppercase",
            letterSpacing: "0.5px",
          }}
        >
          Buckets
        </Box>
        {filteredRecords.length > 0 && (
          <Box
            sx={{
              display: "block",
              flexGrow: 1,
              overflowY: "auto",
              "& .bucketsListing": {
                "&::-webkit-scrollbar": {
                  width: 5,
                },
                "&::-webkit-scrollbar-thumb": {
                  backgroundColor: "rgba(255,255,255,0.3)",
                },
                "&::-webkit-scrollbar-thumb:hover": {
                  backgroundColor: "rgba(255,255,255,0.5)",
                },
              },
            }}
            className={"bucketsListing"}
          >
            {filteredRecords.map((bucket: Bucket) => (
              <BucketListItem key={bucket.name} bucket={bucket} />
            ))}
          </Box>
        )}
        {filteredRecords.length === 0 && filterBuckets !== "" && sidebarOpen && (
          <Box
            sx={{
              "& .helpbox-container": {
                backgroundColor: "transparent",
                color: "#FFF",
                border: 0,
              },
            }}
          >
            <HelpBox
              iconComponent={<BucketsIcon />}
              title={"No Results"}
              help={
                <Box sx={{ textAlign: "center" }}>
                  No buckets match the filtering condition
                </Box>
              }
            />
          </Box>
        )}
      </Box>
      <MenuDivider />
    </Fragment>
  );
};

export default ListBuckets;
