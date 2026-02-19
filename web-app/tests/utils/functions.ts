// This file is part of MinIO Console Server
// Copyright (c) 2022 MinIO, Inc.
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

import * as roles from "./roles";
import * as elements from "./elements";
import * as constants from "./constants";
import { createReadStream } from "fs";
import { Selector } from "testcafe";

import {
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectCommand,
  ListObjectsV2Command,
  PutBucketVersioningCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

const getS3Client = () => {
  return new S3Client({
    region: "us-east-1",
    endpoint: "http://localhost:9000",
    forcePathStyle: true,
    credentials: {
      accessKeyId: "s3admin",
      secretAccessKey: "s3admin",
    },
  });
};

export const setUpBucket = (t, modifier) => {
  return setUpNamedBucket(t, `${constants.TEST_BUCKET_NAME}-${modifier}`);
};

export const setUpNamedBucket = (t, name) => {
  const s3Client = getS3Client();
  return s3Client
    .send(
      new CreateBucketCommand({
        Bucket: name,
      }),
    )
    .catch((err) => {
      console.log(err);
    });
};

export const uploadObjectToBucket = (t, modifier, objectName, objectPath) => {
  const bucketName = `${constants.TEST_BUCKET_NAME}-${modifier}`;
  return uploadNamedObjectToBucket(t, bucketName, objectName, objectPath);
};

export const uploadNamedObjectToBucket = async (
  t,
  modifier,
  objectName,
  objectPath,
) => {
  const bucketName = modifier;
  const s3Client = getS3Client();
  return s3Client
    .send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: objectName,
        Body: createReadStream(objectPath),
      }),
    )
    .catch((err) => {
      console.log(err);
    });
};

export const setVersioned = (t, modifier) => {
  return setVersionedBucket(t, `${constants.TEST_BUCKET_NAME}-${modifier}`);
};

export const setVersionedBucket = (t, name) => {
  const s3Client = getS3Client();
  return new Promise((resolve) => {
    s3Client
      .send(
        new PutBucketVersioningCommand({
          Bucket: name,
          VersioningConfiguration: { Status: "Enabled" },
        }),
      )
      .then(resolve)
      .catch(resolve);
  });
};

export const namedManageButtonFor = (name) => {
  return Selector("div").withAttribute("id", `manageBucket-${name}`);
};

export const manageButtonFor = (modifier) => {
  return namedManageButtonFor(`${constants.TEST_BUCKET_NAME}-${modifier}`);
};

export const cleanUpNamedBucket = (t, name) => {
  const s3Client = getS3Client();
  return s3Client.send(new DeleteBucketCommand({ Bucket: name }));
};

export const cleanUpBucket = (t, modifier) => {
  return cleanUpNamedBucket(t, `${constants.TEST_BUCKET_NAME}-${modifier}`);
};

export const namedTestBucketBrowseButtonFor = (name) => {
  return Selector("button").withAttribute("id", `manageBucket-${name}`);
};

export const testBucketBrowseButtonFor = (modifier) => {
  return namedTestBucketBrowseButtonFor(
    `${constants.TEST_BUCKET_NAME}-${modifier}`,
  );
};

export const cleanUpNamedBucketAndUploads = async (t, bucket) => {
  const s3Client = getS3Client();
  let continuationToken: string | undefined;
  do {
    const result = await s3Client.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        ContinuationToken: continuationToken,
      }),
    );
    const objects = result.Contents || [];
    await Promise.all(
      objects
        .filter((obj) => obj.Key)
        .map((obj) =>
          s3Client.send(
            new DeleteObjectCommand({ Bucket: bucket, Key: obj.Key! }),
          ),
        ),
    );
    continuationToken = result.IsTruncated
      ? result.NextContinuationToken
      : undefined;
  } while (continuationToken);

  await s3Client.send(new DeleteBucketCommand({ Bucket: bucket }));
};

export const cleanUpBucketAndUploads = (t, modifier) => {
  const bucket = `${constants.TEST_BUCKET_NAME}-${modifier}`;
  return cleanUpNamedBucketAndUploads(t, bucket);
};

export const createUser = (t) => {
  return t
    .useRole(roles.admin)
    .navigateTo(`http://localhost:9090/identity/users/add-user`)
    .typeText(elements.usersAccessKeyInput, constants.TEST_USER_NAME)
    .typeText(elements.usersSecretKeyInput, constants.TEST_PASSWORD)
    .click(elements.saveButton);
};

export const cleanUpUser = (t) => {
  const userListItem = Selector(".ReactVirtualized__Table__rowColumn").withText(
    constants.TEST_USER_NAME,
  );

  const userDeleteIconButton = userListItem
    .nextSibling()
    .child("button")
    .withAttribute("aria-label", "delete");

  return t
    .useRole(roles.admin)
    .navigateTo("http://localhost:9090/identity/users")
    .click(userDeleteIconButton)
    .click(elements.deleteButton);
};
