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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/SwanseaUniversityMedical/S3-Object-Browser/api/operations"
	bucketApi "github.com/SwanseaUniversityMedical/S3-Object-Browser/api/operations/bucket"
	"github.com/SwanseaUniversityMedical/S3-Object-Browser/models"
	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/auth/token"
	"github.com/SwanseaUniversityMedical/S3-Object-Browser/pkg/tenants"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/mc/cmd"
	"github.com/minio/minio-go/v7/pkg/policy"
	minioIAMPolicy "github.com/minio/pkg/v3/policy"
)

func registerBucketsHandlers(api *operations.ConsoleAPI) {
	// list buckets
	api.BucketListBucketsHandler = bucketApi.ListBucketsHandlerFunc(func(params bucketApi.ListBucketsParams, session *models.Principal) middleware.Responder {
		if err := ValidateListBucketsRequest(params.HTTPRequest); err != nil {
			apiErr := ErrorWithContext(params.HTTPRequest.Context(), err)
			return bucketApi.NewListBucketsDefault(apiErr.Code).WithPayload(apiErr.APIError)
		}
		listBucketsResponse, err := getListBucketsResponse(session, params)
		if err != nil {
			return bucketApi.NewListBucketsDefault(err.Code).WithPayload(err.APIError)
		}
		return bucketApi.NewListBucketsOK().WithPayload(listBucketsResponse)
	})
	// make bucket
	api.BucketMakeBucketHandler = bucketApi.MakeBucketHandlerFunc(func(params bucketApi.MakeBucketParams, session *models.Principal) middleware.Responder {
		makeBucketResponse, err := getMakeBucketResponse(session, params)
		if err != nil {
			return bucketApi.NewMakeBucketDefault(err.Code).WithPayload(err.APIError)
		}
		return bucketApi.NewMakeBucketOK().WithPayload(makeBucketResponse)
	})
	// get bucket info
	api.BucketBucketInfoHandler = bucketApi.BucketInfoHandlerFunc(func(params bucketApi.BucketInfoParams, session *models.Principal) middleware.Responder {
		if err := EnforceTenantForBucket(params.HTTPRequest, params.Name); err != nil {
			apiErr := ErrorWithContext(params.HTTPRequest.Context(), err)
			return bucketApi.NewBucketInfoDefault(apiErr.Code).WithPayload(apiErr.APIError)
		}
		bucketInfoResp, err := getBucketInfoResponse(session, params)
		if err != nil {
			return bucketApi.NewBucketInfoDefault(err.Code).WithPayload(err.APIError)
		}

		return bucketApi.NewBucketInfoOK().WithPayload(bucketInfoResp)
	})
	// get bucket versioning
	api.BucketGetBucketVersioningHandler = bucketApi.GetBucketVersioningHandlerFunc(func(params bucketApi.GetBucketVersioningParams, session *models.Principal) middleware.Responder {
		if err := EnforceTenantForBucket(params.HTTPRequest, params.BucketName); err != nil {
			apiErr := ErrorWithContext(params.HTTPRequest.Context(), err)
			return bucketApi.NewGetBucketVersioningDefault(apiErr.Code).WithPayload(apiErr.APIError)
		}
		getBucketVersioning, err := getBucketVersionedResponse(session, params)
		if err != nil {
			return bucketApi.NewGetBucketVersioningDefault(err.Code).WithPayload(err.APIError)
		}
		return bucketApi.NewGetBucketVersioningOK().WithPayload(getBucketVersioning)
	})
	// update bucket versioning
	api.BucketSetBucketVersioningHandler = bucketApi.SetBucketVersioningHandlerFunc(func(params bucketApi.SetBucketVersioningParams, session *models.Principal) middleware.Responder {
		if err := EnforceTenantForBucket(params.HTTPRequest, params.BucketName); err != nil {
			apiErr := ErrorWithContext(params.HTTPRequest.Context(), err)
			return bucketApi.NewSetBucketVersioningDefault(apiErr.Code).WithPayload(apiErr.APIError)
		}
		err := setBucketVersioningResponse(session, params)
		if err != nil {
			return bucketApi.NewSetBucketVersioningDefault(err.Code).WithPayload(err.APIError)
		}
		return bucketApi.NewSetBucketVersioningCreated()
	})
	// get objects rewind for a bucket
	api.BucketGetBucketRewindHandler = bucketApi.GetBucketRewindHandlerFunc(func(params bucketApi.GetBucketRewindParams, session *models.Principal) middleware.Responder {
		if err := EnforceTenantForBucket(params.HTTPRequest, params.BucketName); err != nil {
			apiErr := ErrorWithContext(params.HTTPRequest.Context(), err)
			return bucketApi.NewGetBucketRewindDefault(apiErr.Code).WithPayload(apiErr.APIError)
		}
		getBucketRewind, err := getBucketRewindResponse(session, params)
		if err != nil {
			return bucketApi.NewGetBucketRewindDefault(err.Code).WithPayload(err.APIError)
		}
		return bucketApi.NewGetBucketRewindOK().WithPayload(getBucketRewind)
	})
	// get max allowed share link expiration time
	api.BucketGetMaxShareLinkExpHandler = bucketApi.GetMaxShareLinkExpHandlerFunc(func(params bucketApi.GetMaxShareLinkExpParams, session *models.Principal) middleware.Responder {
		val, err := getMaxShareLinkExpirationResponse(session, params)
		if err != nil {
			return bucketApi.NewGetMaxShareLinkExpDefault(err.Code).WithPayload(err.APIError)
		}
		return bucketApi.NewGetMaxShareLinkExpOK().WithPayload(val)
	})
}

type VersionState string

const (
	VersionEnable  VersionState = "enable"
	VersionSuspend VersionState = "suspend"
)

// removeBucket deletes a bucket
func doSetVersioning(ctx context.Context, client MCClient, state VersionState, excludePrefix []string, excludeFolders bool) error {
	err := client.setVersioning(ctx, string(state), excludePrefix, excludeFolders)
	if err != nil {
		return err.Cause
	}

	return nil
}

func setBucketVersioningResponse(session *models.Principal, params bucketApi.SetBucketVersioningParams) *CodedAPIError {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()

	bucketName := params.BucketName
	s3Client, err := newS3BucketClient(session, bucketName, "", getClientIP(params.HTTPRequest))
	if err != nil {
		return ErrorWithContext(ctx, err)
	}
	// create a mc S3Client interface implementation
	// defining the client to be used
	amcClient := mcClient{client: s3Client}

	versioningState := VersionSuspend

	if params.Body.Enabled {
		versioningState = VersionEnable
	}

	var excludePrefixes []string

	if params.Body.ExcludePrefixes != nil {
		excludePrefixes = params.Body.ExcludePrefixes
	}

	excludeFolders := params.Body.ExcludeFolders

	if err := doSetVersioning(ctx, amcClient, versioningState, excludePrefixes, excludeFolders); err != nil {
		return ErrorWithContext(ctx, fmt.Errorf("error setting versioning for bucket: %s", err))
	}
	return nil
}

func getBucketVersionedResponse(session *models.Principal, params bucketApi.GetBucketVersioningParams) (*models.BucketVersioningResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()

	if err := EnforceTenantForBucket(params.HTTPRequest, params.BucketName); err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	s3Client, err := newS3Client(session, getClientIP(params.HTTPRequest))
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	result, err := s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(params.BucketName),
	})
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	status := "Suspended"
	switch result.Status {
	case types.BucketVersioningStatusEnabled:
		status = "Enabled"
	case types.BucketVersioningStatusSuspended:
		status = "Suspended"
	default:
		if result.Status != "" {
			status = string(result.Status)
		}
	}

	excludedPrefixes := []*models.BucketVersioningResponseExcludedPrefixesItems0{}

	// serialize output
	mfaDelete := "Disabled"
	if result.MFADelete == types.MFADeleteStatusEnabled {
		mfaDelete = "Enabled"
	}
	bucketVResponse := &models.BucketVersioningResponse{
		ExcludeFolders:   false,
		ExcludedPrefixes: excludedPrefixes,
		MFADelete:        mfaDelete,
		Status:           status,
	}
	return bucketVResponse, nil
}

// getAccountBuckets fetches a list of all buckets allowed to that particular client from MinIO Servers
func getAccountBuckets(ctx context.Context, client MinioAdmin) ([]*models.Bucket, error) {
	info, err := client.AccountInfo(ctx)
	if err != nil {
		return []*models.Bucket{}, err
	}
	bucketInfos := []*models.Bucket{}
	for _, bucket := range info.Buckets {
		bucketElem := &models.Bucket{
			CreationDate: bucket.Created.Format(time.RFC3339),
			Details: &models.BucketDetails{
				Quota: nil,
			},
			RwAccess: &models.BucketRwAccess{
				Read:  bucket.Access.Read,
				Write: bucket.Access.Write,
			},
			Name:    swag.String(bucket.Name),
			Objects: int64(bucket.Objects),
			Size:    int64(bucket.Size),
		}

		if bucket.Details != nil {
			if bucket.Details.Tagging != nil {
				bucketElem.Details.Tags = bucket.Details.Tagging.ToMap()
			}

			bucketElem.Details.Locking = bucket.Details.Locking
			bucketElem.Details.Replication = bucket.Details.Replication
			bucketElem.Details.Versioning = bucket.Details.Versioning
			bucketElem.Details.VersioningSuspended = bucket.Details.VersioningSuspended
			if bucket.Details.Quota != nil {
				bucketElem.Details.Quota = &models.BucketDetailsQuota{
					Quota: int64(bucket.Details.Quota.Quota),
					Type:  string(bucket.Details.Quota.Type),
				}
			}
		}

		bucketInfos = append(bucketInfos, bucketElem)
	}
	return bucketInfos, nil
}

// getListBucketsResponse performs listBuckets() and serializes it to the handler's output
func getListBucketsResponse(session *models.Principal, params bucketApi.ListBucketsParams) (*models.ListBucketsResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()

	tenantID, err := tenants.GetTenantFromContext(params.HTTPRequest.Context())
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	s3Client, err := newS3Client(session, getClientIP(params.HTTPRequest))
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	result, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	allowedBuckets := make([]*models.Bucket, 0, len(result.Buckets))
	for _, bucket := range result.Buckets {
		if bucket.Name == nil {
			continue
		}
		bucketName := aws.ToString(bucket.Name)
		if err := tenants.ValidateBucketBelongsToTenant(tenantID, bucketName); err != nil {
			continue
		}
		versioningResult, err := s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			if isAccessDenied(err) {
				continue
			}
			return nil, ErrorWithContext(ctx, err)
		}

		details := &models.BucketDetails{}
		switch versioningResult.Status {
		case types.BucketVersioningStatusEnabled:
			details.Versioning = true
			details.VersioningSuspended = false
		case types.BucketVersioningStatusSuspended:
			details.Versioning = false
			details.VersioningSuspended = true
		default:
			details.Versioning = false
			details.VersioningSuspended = false
		}

		bucketModel := &models.Bucket{
			Name:    swag.String(bucketName),
			Details: details,
		}
		if bucket.CreationDate != nil {
			bucketModel.CreationDate = bucket.CreationDate.Format(time.RFC3339)
		}

		allowedBuckets = append(allowedBuckets, bucketModel)
	}

	// serialize output
	listBucketsResponse := &models.ListBucketsResponse{
		Buckets: allowedBuckets,
		Total:   int64(len(allowedBuckets)),
	}
	return listBucketsResponse, nil
}

func isAccessDenied(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "AllAccessDisabled", "UnauthorizedOperation":
			return true
		}
	}
	return false
}

// makeBucket creates a bucket for an specific minio client
func makeBucket(ctx context.Context, client S3Client, bucketName string, objectLocking bool) error {
	// creates a new bucket with bucketName with a context to control cancellations and timeouts.
	return client.makeBucketWithContext(ctx, bucketName, "", objectLocking)
}

// getMakeBucketResponse performs makeBucket() to create a bucket with its access policy
func getMakeBucketResponse(session *models.Principal, params bucketApi.MakeBucketParams) (*models.MakeBucketsResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	// bucket request needed to proceed
	br := params.Body
	if br == nil {
		return nil, ErrorWithContext(ctx, ErrBucketBodyNotInRequest)
	}
	if err := EnforceTenantForBucket(params.HTTPRequest, *br.Name); err != nil {
		return nil, ErrorWithContext(ctx, err)
	}
	client, err := newS3ClientInterface(session, getClientIP(params.HTTPRequest))
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	if err := makeBucket(ctx, client, *br.Name, false); err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	// make sure to delete bucket if an errors occurs after bucket was created
	defer func() {
		if err != nil {
			ErrorWithContext(ctx, fmt.Errorf("error creating bucket: %v", err))
			if err := removeBucket(client, *br.Name); err != nil {
				ErrorWithContext(ctx, fmt.Errorf("error removing bucket: %v", err))
			}
		}
	}()

	return &models.MakeBucketsResponse{BucketName: *br.Name}, nil
}

// setBucketAccessPolicy set the access permissions on an existing bucket.
func setBucketAccessPolicy(ctx context.Context, client S3Client, bucketName string, access models.BucketAccess, policyDefinition string) error {
	if strings.TrimSpace(bucketName) == "" {
		return fmt.Errorf("error: bucket name not present")
	}
	if strings.TrimSpace(string(access)) == "" {
		return fmt.Errorf("error: bucket access not present")
	}
	// Prepare policyJSON corresponding to the access type
	if access != models.BucketAccessPRIVATE && access != models.BucketAccessPUBLIC && access != models.BucketAccessCUSTOM {
		return fmt.Errorf("access: `%s` not supported", access)
	}

	bucketAccessPolicy := policy.BucketAccessPolicy{Version: minioIAMPolicy.DefaultVersion}
	if access == models.BucketAccessCUSTOM {
		err := client.setBucketPolicyWithContext(ctx, bucketName, policyDefinition)
		if err != nil {
			return err
		}
		return nil
	}
	bucketPolicy := consoleAccess2policyAccess(access)
	bucketAccessPolicy.Statements = policy.SetPolicy(bucketAccessPolicy.Statements,
		bucketPolicy, bucketName, "")
	policyJSON, err := json.Marshal(bucketAccessPolicy)
	if err != nil {
		return err
	}
	return client.setBucketPolicyWithContext(ctx, bucketName, string(policyJSON))
}

// removeBucket deletes a bucket
func removeBucket(client S3Client, bucketName string) error {
	return client.removeBucket(context.Background(), bucketName)
}

// getBucketInfo return bucket information including name, policy access, size and creation date
func getBucketInfo(ctx context.Context, client S3Client, adminClient MinioAdmin, bucketName string) (*models.Bucket, error) {
	var bucketAccess models.BucketAccess
	policyStr, err := client.getBucketPolicy(context.Background(), bucketName)
	if err != nil {
		// we can tolerate this errors
		ErrorWithContext(ctx, fmt.Errorf("error getting bucket policy: %v", err))
	}

	if policyStr == "" {
		bucketAccess = models.BucketAccessPRIVATE
	} else {
		var p policy.BucketAccessPolicy
		if err = json.Unmarshal([]byte(policyStr), &p); err != nil {
			return nil, err
		}
		policyAccess := policy.GetPolicy(p.Statements, bucketName, "")
		if len(p.Statements) > 0 && policyAccess == policy.BucketPolicyNone {
			bucketAccess = models.BucketAccessCUSTOM
		} else {
			bucketAccess = policyAccess2consoleAccess(policyAccess)
		}
	}
	bucketTags, err := client.GetBucketTagging(ctx, bucketName)
	if err != nil {
		// we can tolerate this errors
		ErrorWithContext(ctx, fmt.Errorf("error getting bucket tags: %v", err))
	}
	bucketDetails := &models.BucketDetails{}
	if bucketTags != nil {
		bucketDetails.Tags = bucketTags
	}

	info, err := adminClient.AccountInfo(ctx)
	if err != nil {
		return nil, err
	}

	var bucketInfo madmin.BucketAccessInfo

	for _, bucket := range info.Buckets {
		if bucket.Name == bucketName {
			bucketInfo = bucket
			break
		}
	}

	return &models.Bucket{
		Name:         &bucketName,
		Access:       &bucketAccess,
		Definition:   policyStr,
		CreationDate: bucketInfo.Created.Format(time.RFC3339),
		Size:         int64(bucketInfo.Size),
		Details:      bucketDetails,
		Objects:      int64(bucketInfo.Objects),
	}, nil
}

// getBucketInfoResponse calls getBucketInfo() to get the bucket's info
func getBucketInfoResponse(session *models.Principal, params bucketApi.BucketInfoParams) (*models.Bucket, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	client, err := newS3ClientInterface(session, getClientIP(params.HTTPRequest))
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}

	mAdmin, err := NewMinioAdminClient(params.HTTPRequest.Context(), session)
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}
	// create a minioClient interface implementation
	// defining the client to be used
	adminClient := AdminClient{Client: mAdmin}

	bucket, err := getBucketInfo(ctx, client, adminClient, params.Name)
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}
	return bucket, nil
}

// policyAccess2consoleAccess gets the equivalent of policy.BucketPolicy to models.BucketAccess
func policyAccess2consoleAccess(bucketPolicy policy.BucketPolicy) (bucketAccess models.BucketAccess) {
	switch bucketPolicy {
	case policy.BucketPolicyReadWrite:
		bucketAccess = models.BucketAccessPUBLIC
	case policy.BucketPolicyNone:
		bucketAccess = models.BucketAccessPRIVATE
	default:
		bucketAccess = models.BucketAccessCUSTOM
	}
	return bucketAccess
}

// consoleAccess2policyAccess gets the equivalent of models.BucketAccess to policy.BucketPolicy
func consoleAccess2policyAccess(bucketAccess models.BucketAccess) (bucketPolicy policy.BucketPolicy) {
	switch bucketAccess {
	case models.BucketAccessPUBLIC:
		bucketPolicy = policy.BucketPolicyReadWrite
	case models.BucketAccessPRIVATE:
		bucketPolicy = policy.BucketPolicyNone
	}
	return bucketPolicy
}

// disableBucketEncryption will disable bucket for the provided bucket name
func disableBucketEncryption(ctx context.Context, client S3Client, bucketName string) error {
	return client.removeBucketEncryption(ctx, bucketName)
}

func getBucketRetentionConfig(ctx context.Context, client S3Client, bucketName string) (*models.GetBucketRetentionConfig, error) {
	m, v, u, err := client.getBucketObjectLockConfig(ctx, bucketName)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "ObjectLockConfigurationNotFoundError" {
				return &models.GetBucketRetentionConfig{}, nil
			}
		}
		return nil, err
	}

	// These values can be empty when all are empty, it means
	// object was created with object locking enabled but
	// does not have any default object locking configuration.
	if m == nil && v == nil && u == nil {
		return &models.GetBucketRetentionConfig{}, nil
	}

	var mode models.ObjectRetentionMode
	var unit models.ObjectRetentionUnit

	if m != nil {
		switch strings.ToUpper(*m) {
		case "GOVERNANCE":
			mode = models.ObjectRetentionModeGovernance
		case "COMPLIANCE":
			mode = models.ObjectRetentionModeCompliance
		default:
			return nil, errors.New("invalid retention mode")
		}
	}

	if u != nil {
		switch strings.ToUpper(*u) {
		case "DAYS":
			unit = models.ObjectRetentionUnitDays
		case "YEARS":
			unit = models.ObjectRetentionUnitYears
		default:
			return nil, errors.New("invalid retention unit")
		}
	}

	var validity int32
	if v != nil {
		validity = int32(*v)
	}

	config := &models.GetBucketRetentionConfig{
		Mode:     mode,
		Unit:     unit,
		Validity: validity,
	}
	return config, nil
}

func getBucketRewindResponse(session *models.Principal, params bucketApi.GetBucketRewindParams) (*models.RewindResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	prefix := ""
	if params.Prefix != nil {
		prefix = *params.Prefix
	}
	s3Client, err := newS3BucketClient(session, params.BucketName, prefix, getClientIP(params.HTTPRequest))
	if err != nil {
		return nil, ErrorWithContext(ctx, fmt.Errorf("error creating S3Client: %v", err))
	}

	// create a mc S3Client interface implementation
	// defining the client to be used
	mcClient := mcClient{client: s3Client}

	parsedDate, errDate := time.Parse(time.RFC3339, params.Date)

	if errDate != nil {
		return nil, ErrorWithContext(ctx, errDate)
	}

	var rewindItems []*models.RewindItem

	for content := range mcClient.client.List(ctx, cmd.ListOptions{TimeRef: parsedDate, WithDeleteMarkers: true}) {
		// build object name
		name := strings.ReplaceAll(content.URL.Path, fmt.Sprintf("/%s/", params.BucketName), "")

		listElement := &models.RewindItem{
			LastModified: content.Time.Format(time.RFC3339),
			Size:         content.Size,
			VersionID:    content.VersionID,
			DeleteFlag:   content.IsDeleteMarker,
			Action:       "",
			Name:         name,
		}

		rewindItems = append(rewindItems, listElement)
	}

	return &models.RewindResponse{
		Objects: rewindItems,
	}, nil
}

func getMaxShareLinkExpirationResponse(session *models.Principal, params bucketApi.GetMaxShareLinkExpParams) (*models.MaxShareLinkExpResponse, *CodedAPIError) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()

	maxShareLinkExpSeconds, err := getMaxShareLinkExpirationSeconds(session)
	if err != nil {
		return nil, ErrorWithContext(ctx, err)
	}
	return &models.MaxShareLinkExpResponse{Exp: swag.Int64(maxShareLinkExpSeconds)}, nil
}

// getMaxShareLinkExpirationSeconds returns the max share link expiration time in seconds which is the sts token expiration time
func getMaxShareLinkExpirationSeconds(session *models.Principal) (int64, error) {
	creds := getConsoleCredentialsFromSession(session)
	if creds == nil || creds.AccessKey == "" || creds.SecretKey == "" {
		return 0, ErrAccessDenied
	}
	maxShareLinkExp := token.GetConsoleSTSDuration()

	return int64(maxShareLinkExp.Seconds()), nil
}
