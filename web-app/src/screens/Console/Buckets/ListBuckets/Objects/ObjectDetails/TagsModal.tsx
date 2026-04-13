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

import React, { Fragment, useState } from "react";
import get from "lodash/get";
import styled from "styled-components";
import {
  AddNewTagIcon,
  Button,
  DisabledIcon,
  EditTagIcon,
  InputBox,
  SectionTitle,
  Box,
  Grid,
  Tag,
  FormLayout,
} from "mds";
import { BucketObject } from "api/consoleApi";
import { api } from "api";
import { errorToHandler } from "api/errors";
import { useSelector } from "react-redux";
import ModalWrapper from "../../../../Common/ModalWrapper/ModalWrapper";
import { modalStyleUtils } from "../../../../Common/FormComponents/common/styleLibrary";
import { IAM_SCOPES } from "../../../../../../common/SecureComponent/permissions";
import { SecureComponent } from "../../../../../../common/SecureComponent";
import {
  selDistSet,
  setModalErrorSnackMessage,
} from "../../../../../../systemSlice";
import { useAppDispatch } from "../../../../../../store";

interface ITagModal {
  modalOpen: boolean;
  bucketName: string;
  actualInfo: BucketObject;
  onCloseAndUpdate: (refresh: boolean) => void;
}

const DeleteTag = styled.b(({ theme }) => ({
  color: get(theme, "signalColors.danger", "#C83B51"),
  marginLeft: 5,
}));

const TagsModal = ({
  modalOpen,
  onCloseAndUpdate,
  bucketName,
  actualInfo,
}: ITagModal) => {
  const dispatch = useAppDispatch();
  const distributedSetup = useSelector(selDistSet);
  const [newKey, setNewKey] = useState<string>("");
  const [newLabel, setNewLabel] = useState<string>("");
  const [isSending, setIsSending] = useState<boolean>(false);
  const [deleteEnabled, setDeleteEnabled] = useState<boolean>(false);
  const [deleteKey, setDeleteKey] = useState<string>("");
  const [deleteLabel, setDeleteLabel] = useState<string>("");
  const [editMode, setEditMode] = useState<boolean>(false);
  const [editKey, setEditKey] = useState<string>("");
  const [editValue, setEditValue] = useState<string>("");
  const [originalKey, setOriginalKey] = useState<string>("");

  const currentTags = actualInfo.tags;
  const currTagKeys = Object.keys(currentTags || {});

  const allPathData = actualInfo.name?.split("/");
  const currentItem = allPathData?.pop() || "";

  const resetForm = () => {
    setNewLabel("");
    setNewKey("");
  };

  const addTagProcess = () => {
    setIsSending(true);
    const newTag: any = {};

    newTag[newKey] = newLabel;
    const newTagList = { ...currentTags, ...newTag };

    const verID = distributedSetup ? actualInfo.version_id || "" : "null";

    api.buckets
      .putObjectTags(
        bucketName,
        { prefix: actualInfo.name || "", version_id: verID },
        { tags: newTagList },
      )
      .then(() => {
        onCloseAndUpdate(true);
        setIsSending(false);
      })
      .catch((err) => {
        dispatch(setModalErrorSnackMessage(errorToHandler(err.error)));
        setIsSending(false);
      });
  };

  const deleteTagProcess = () => {
    const cleanObject: any = { ...currentTags };
    delete cleanObject[deleteKey];

    const verID = distributedSetup ? actualInfo.version_id || "" : "null";

    api.buckets
      .putObjectTags(
        bucketName,
        { prefix: actualInfo.name || "", version_id: verID },
        { tags: cleanObject },
      )
      .then(() => {
        onCloseAndUpdate(true);
        setIsSending(false);
      })
      .catch((err) => {
        dispatch(setModalErrorSnackMessage(errorToHandler(err.error)));
        setIsSending(false);
      });
  };

  const onDeleteTag = (tagKey: string, tag: string) => {
    setDeleteKey(tagKey);
    setDeleteLabel(tag);
    setDeleteEnabled(true);
  };

  const onEditTag = (tagKey: string, tag: string) => {
    setOriginalKey(tagKey);
    setEditKey(tagKey);
    setEditValue(tag);
    setEditMode(true);
  };

  const cancelEdit = () => {
    setEditKey("");
    setEditValue("");
    setOriginalKey("");
    setEditMode(false);
  };

  const saveEditedTag = () => {
    setIsSending(true);
    const updatedTags: any = { ...currentTags };
    
    // If key changed, delete old key
    if (originalKey !== editKey) {
      delete updatedTags[originalKey];
    }
    
    // Set new/updated key-value pair
    updatedTags[editKey] = editValue;

    const verID = distributedSetup ? actualInfo.version_id || "" : "null";

    api.buckets
      .putObjectTags(
        bucketName,
        { prefix: actualInfo.name || "", version_id: verID },
        { tags: updatedTags },
      )
      .then(() => {
        cancelEdit();
        onCloseAndUpdate(true);
        setIsSending(false);
      })
      .catch((err) => {
        dispatch(setModalErrorSnackMessage(errorToHandler(err.error)));
        setIsSending(false);
      });
  };

  const cancelDelete = () => {
    setDeleteKey("");
    setDeleteLabel("");
    setDeleteEnabled(false);
  };

  const tagsFor = (plural: boolean) => (
    <Box
      sx={{
        fontSize: 16,
        margin: "20px 0 30px",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
        width: "100%",
      }}
    >
      Tag{plural ? "s" : ""} for: <strong>{currentItem}</strong>
    </Box>
  );

  const getModalTitle = () => {
    if (deleteEnabled) return "Delete Tag";
    if (editMode) return "Edit Tag";
    return "Edit Tags";
  };

  const renderDeleteMode = () => (
    <Grid container>
      {tagsFor(false)}
      Are you sure you want to delete the tag{" "}
      <DeleteTag>
        {deleteKey} : {deleteLabel}
      </DeleteTag>{" "}
      ?
      <Grid item xs={12} sx={modalStyleUtils.modalButtonBar}>
        <Button
          id={"cancel"}
          type="button"
          variant="regular"
          onClick={cancelDelete}
          label={"Cancel"}
        />
        <Button
          type="submit"
          variant="secondary"
          onClick={deleteTagProcess}
          id={"deleteTag"}
          label={"Delete Tag"}
        />
      </Grid>
    </Grid>
  );

  const renderEditMode = () => (
    <Grid container>
      {tagsFor(false)}
      <Box sx={{ width: "100%", marginTop: 2 }}>
        <FormLayout containerPadding={false} withBorders={false}>
          <InputBox
            value={editKey}
            label={"Tag Key"}
            id={"editTagKey"}
            name={"editTagKey"}
            placeholder={"Enter Tag Key"}
            onChange={(e) => {
              setEditKey(e.target.value);
            }}
          />
          <InputBox
            value={editValue}
            label={"Tag Value"}
            id={"editTagValue"}
            name={"editTagValue"}
            placeholder={"Enter Tag Value"}
            onChange={(e) => {
              setEditValue(e.target.value);
            }}
          />
        </FormLayout>
      </Box>
      <Grid item xs={12} sx={modalStyleUtils.modalButtonBar}>
        <Button
          id={"cancelEdit"}
          type="button"
          variant="regular"
          onClick={cancelEdit}
          label={"Cancel"}
        />
        <Button
          type="submit"
          variant="callAction"
          disabled={
            editKey.trim() === "" ||
            editValue.trim() === "" ||
            isSending
          }
          onClick={saveEditedTag}
          id={"saveEditedTag"}
          label={"Save"}
        />
      </Grid>
    </Grid>
  );

  const renderContent = () => {
    if (deleteEnabled) return renderDeleteMode();
    if (editMode) return renderEditMode();
    return renderMainView();
  };

  const renderMainView = () => (
    <Box>
      <SecureComponent
        scopes={[
          IAM_SCOPES.S3_GET_OBJECT_TAGGING,
          IAM_SCOPES.S3_GET_ACTIONS,
        ]}
        resource={bucketName}
      >
        <Box
          sx={{
            display: "flex",
            flexFlow: "column",
            width: "100%",
          }}
        >
          {tagsFor(true)}
          <Box
            sx={{
              fontSize: 14,
              fontWeight: "normal",
            }}
          >
            Current Tags:
            <br />
            {currTagKeys.length === 0 ? (
              <span className={"muted"}>
                There are no tags for this object
              </span>
            ) : (
              <Fragment />
            )}
            <Box sx={{ marginTop: "5px", marginBottom: "15px" }}>
              {currTagKeys.map((tagKey: string, index: number) => {
                const tag = get(currentTags, `${tagKey}`, "");
                if (tag !== "") {
                  return (
                    <SecureComponent
                      key={`chip-${index}`}
                      scopes={[
                        IAM_SCOPES.S3_DELETE_OBJECT_TAGGING,
                        IAM_SCOPES.S3_DELETE_ACTIONS,
                      ]}
                      resource={bucketName}
                      errorProps={{
                        deleteIcon: null,
                        onDelete: null,
                      }}
                    >
                      <Tag
                        id={`${tagKey} : ${tag}`}
                        label={`${tagKey} : ${tag}`}
                        variant={"regular"}
                        color={"default"}
                        onDelete={() => {
                          onDeleteTag(tagKey, tag);
                        }}
                        onClick={() => {
                          onEditTag(tagKey, tag);
                        }}
                        sx={{
                          cursor: "pointer",
                          "&:hover": {
                            opacity: 0.8,
                          },
                        }}
                      />
                    </SecureComponent>
                  );
                }
                return null;
              })}
            </Box>
          </Box>
        </Box>
      </SecureComponent>
      <SecureComponent
        scopes={[
          IAM_SCOPES.S3_PUT_OBJECT_TAGGING,
          IAM_SCOPES.S3_PUT_ACTIONS,
        ]}
        resource={bucketName}
        errorProps={{ disabled: true, onClick: null }}
      >
        <Box>
          <SectionTitle icon={<AddNewTagIcon />} separator={false}>
            Add New Tag
          </SectionTitle>
          <FormLayout containerPadding={false} withBorders={false}>
            <InputBox
              value={newKey}
              label={"Tag Key"}
              id={"newTagKey"}
              name={"newTagKey"}
              placeholder={"Enter Tag Key"}
              onChange={(e) => {
                setNewKey(e.target.value);
              }}
            />
            <InputBox
              value={newLabel}
              label={"Tag Label"}
              id={"newTagLabel"}
              name={"newTagLabel"}
              placeholder={"Enter Tag Label"}
              onChange={(e) => {
                setNewLabel(e.target.value);
              }}
            />
            <Grid item xs={12} sx={modalStyleUtils.modalButtonBar}>
              <Button
                id={"clear"}
                type="button"
                variant="regular"
                color="primary"
                onClick={resetForm}
                label={"Clear"}
              />
              <Button
                type="submit"
                variant="callAction"
                disabled={
                  newLabel.trim() === "" ||
                  newKey.trim() === "" ||
                  isSending
                }
                onClick={addTagProcess}
                id="saveTag"
                label={"Save"}
              />
            </Grid>
          </FormLayout>
        </Box>
      </SecureComponent>
    </Box>
  );

  return (
    <Fragment>
      <ModalWrapper
        modalOpen={modalOpen}
        title={getModalTitle()}
        onClose={() => {
          onCloseAndUpdate(true);
        }}
        iconColor={deleteEnabled ? "delete" : "default"}
        titleIcon={deleteEnabled ? <DisabledIcon /> : <EditTagIcon />}
      >
        {renderContent()}
      </ModalWrapper>
    </Fragment>
  );
};

export default TagsModal;
