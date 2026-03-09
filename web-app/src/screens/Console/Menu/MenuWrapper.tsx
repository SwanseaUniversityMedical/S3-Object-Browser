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

import React, { Fragment } from "react";
import { useSelector } from "react-redux";
import { AddIcon, Box, DocumentationIcon, LicenseIcon, Menu } from "mds";
import { AppState, useAppDispatch } from "../../../store";
import { menuOpen } from "../../../systemSlice";
import { getLogoApplicationVariant, getLogoVar } from "../../../config";
import { useLocation, useNavigate } from "react-router-dom";
import { IAM_PAGES } from "../../../common/SecureComponent/permissions";
import { setAddBucketOpen } from "../Buckets/ListBuckets/AddBucket/addBucketsSlice";
import BucketsListing from "./Listing/BucketsListing";
import { getLicenseConsent } from "../License/utils";

// MenuItem component wrapper - not an mds export, just a passthrough for Menu structure
const MenuItem = (props: any) => null;

const MenuWrapper = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { pathname = "" } = useLocation();

  const sidebarOpen = useSelector(
    (state: AppState) => state.system.sidebarOpen,
  );

  console.log("MenuWrapper: Rendering, sidebarOpen:", sidebarOpen);

  return (
    <Fragment>
      <Menu
        isOpen={sidebarOpen}
        displayGroupTitles
        applicationLogo={{
          applicationName: getLogoApplicationVariant(),
          subVariant: getLogoVar(),
        }}
        callPathAction={(path) => {
          navigate(path);
        }}
        signOutAction={() => {
          navigate("/logout");
        }}
        collapseAction={() => {
          dispatch(menuOpen(!sidebarOpen));
        }}
        currentPath={pathname}
        mobileModeAuto={false}
        options={[
          {
            name: "Create Bucket",
            icon: <AddIcon />,
            onClick: () => dispatch(setAddBucketOpen(true)),
          },
        ]}
        endComponent={
          <Fragment>
            <MenuItem
              name={"Documentation"}
              icon={<DocumentationIcon />}
              path={
                "https://docs.example.com/object-browser/index.html?ref=con"
              }
            />
            <MenuItem
              name={"License"}
              icon={<LicenseIcon />}
              path={IAM_PAGES.LICENSE}
              onClick={() => navigate(IAM_PAGES.LICENSE)}
              badge={!getLicenseConsent()}
            />
          </Fragment>
        }
      />
      {sidebarOpen && (
        <Box
          sx={{
            position: "fixed",
            left: 0,
            top: "180px",
            width: "250px",
            height: "calc(100vh - 360px)",
            backgroundColor: "#081C42",
            zIndex: 1000,
            paddingTop: "10px",
          }}
        >
          <BucketsListing />
        </Box>
      )}
    </Fragment>
  );
};

export default MenuWrapper;
