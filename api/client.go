// This file is part of MinIO Console Server
// Copyright (c) 2021 MinIO, Inc.
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
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	xnet "github.com/minio/pkg/v3/net"

	"github.com/minio/console/models"
	"github.com/minio/console/pkg"
	mc "github.com/minio/mc/cmd"
	"github.com/minio/mc/pkg/probe"
)

// S3Client interface with all functions to be implemented
// by mock when testing, it should include all S3 respective api calls
// that are used within this project.
type S3Client interface {
	listBucketsWithContext(ctx context.Context) ([]BucketInfo, error)
	makeBucketWithContext(ctx context.Context, bucketName, location string, objectLocking bool) error
	setBucketPolicyWithContext(ctx context.Context, bucketName, policy string) error
	removeBucket(ctx context.Context, bucketName string) error
	getBucketPolicy(ctx context.Context, bucketName string) (string, error)
	listObjects(ctx context.Context, bucket string, opts ListObjectsOptions) <-chan ObjectInfo
	getObject(ctx context.Context, bucketName, objectName string, versionID string) (io.ReadCloser, error)
	getObjectLegalHold(ctx context.Context, bucketName, objectName string, opts GetObjectLegalHoldOptions) (status *string, err error)
	getObjectRetention(ctx context.Context, bucketName, objectName, versionID string) (mode *string, retainUntilDate *time.Time, err error)
	putObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64, opts PutObjectOptions) (info UploadInfo, err error)
	putObjectRetention(ctx context.Context, bucketName, objectName string, opts PutObjectRetentionOptions) error
	statObject(ctx context.Context, bucketName, prefix string, opts GetObjectOptions) (objectInfo ObjectInfo, err error)
	setBucketEncryption(ctx context.Context, bucketName string, config *EncryptionConfiguration) error
	removeBucketEncryption(ctx context.Context, bucketName string) error
	getBucketEncryption(ctx context.Context, bucketName string) (*EncryptionConfiguration, error)
	putObjectTagging(ctx context.Context, bucketName, objectName string, otags map[string]string, opts PutObjectTaggingOptions) error
	getObjectTagging(ctx context.Context, bucketName, objectName string, opts GetObjectTaggingOptions) (map[string]string, error)
	setObjectLockConfig(ctx context.Context, bucketName string, mode *string, validity *int, unit *string) error
	getBucketObjectLockConfig(ctx context.Context, bucketName string) (mode *string, validity *int, unit *string, err error)
	getObjectLockConfig(ctx context.Context, bucketName string) (lock string, mode *string, validity *int, unit *string, err error)
	copyObject(ctx context.Context, dst CopyDestOptions, src CopySrcOptions) (UploadInfo, error)
	GetBucketTagging(ctx context.Context, bucketName string) (map[string]string, error)
	SetBucketTagging(ctx context.Context, bucketName string, tags map[string]string) error
	RemoveBucketTagging(ctx context.Context, bucketName string) error
}

// Simple wrapper types for AWS SDK compatibility
type BucketInfo struct {
	Name         string
	CreationDate time.Time
}

type ObjectInfo struct {
	Key            string
	Size           int64
	LastModified   time.Time
	ContentType    string
	IsDir          bool
	VersionID      string
	IsLatest       bool
	IsDeleteMarker bool
	UserTags       map[string]string
	UserMetadata   map[string]string
	Metadata       map[string]string
	ETag           string
	Err            error
}

type UploadInfo struct {
	Key  string
	Size int64
}

type ListObjectsOptions struct {
	Prefix       string
	Recursive    bool
	WithVersions bool
	WithMetadata bool
	MaxKeys      int
}

type GetObjectOptions struct {
	VersionID string
}

type PutObjectOptions struct {
	ContentType      string
	UserMetadata     map[string]string
	DisableMultipart bool
}

type PutObjectRetentionOptions struct {
	Mode            *string
	RetainUntilDate *time.Time
	VersionID       string
}

type PutObjectTaggingOptions struct {
	VersionID string
}

type GetObjectTaggingOptions struct {
	VersionID string
}

type GetObjectLegalHoldOptions struct {
	VersionID string
}

type CopyDestOptions struct {
	Bucket       string
	Object       string
	UserMetadata map[string]string
}

type CopySrcOptions struct {
	Bucket    string
	Object    string
	VersionID string
}

type EncryptionConfiguration struct {
	Rules []EncryptionRule
}

type EncryptionRule struct {
	ApplyServerSideEncryptionByDefault EncryptionByDefault
}

type EncryptionByDefault struct {
	SSEAlgorithm   string
	KMSMasterKeyID string
}

// Interface implementation
// Define the structure of an S3 Client and define the functions that are actually used
type s3Client struct {
	client *s3.Client
}

func (c s3Client) GetBucketTagging(ctx context.Context, bucketName string) (map[string]string, error) {
	result, err := c.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string)
	for _, tag := range result.TagSet {
		tags[*tag.Key] = *tag.Value
	}
	return tags, nil
}

func (c s3Client) SetBucketTagging(ctx context.Context, bucketName string, tags map[string]string) error {
	tagSet := []types.Tag{}
	for k, v := range tags {
		tagSet = append(tagSet, types.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}
	_, err := c.client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket: aws.String(bucketName),
		Tagging: &types.Tagging{
			TagSet: tagSet,
		},
	})
	return err
}

func (c s3Client) RemoveBucketTagging(ctx context.Context, bucketName string) error {
	_, err := c.client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
		Bucket: aws.String(bucketName),
	})
	return err
}

// implements s3.ListBuckets(ctx)
func (c s3Client) listBucketsWithContext(ctx context.Context) ([]BucketInfo, error) {
	result, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	var buckets []BucketInfo
	for _, b := range result.Buckets {
		buckets = append(buckets, BucketInfo{
			Name:         *b.Name,
			CreationDate: *b.CreationDate,
		})
	}
	return buckets, nil
}

// implements s3.CreateBucket(ctx, bucketName, region, objectLocking)
func (c s3Client) makeBucketWithContext(ctx context.Context, bucketName, location string, objectLocking bool) error {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	}
	if location != "" && location != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(location),
		}
	}
	if objectLocking {
		input.ObjectLockEnabledForBucket = aws.Bool(true)
	}
	_, err := c.client.CreateBucket(ctx, input)
	return err
}

// implements s3.PutBucketPolicy(ctx, bucketName, policy)
func (c s3Client) setBucketPolicyWithContext(ctx context.Context, bucketName, policy string) error {
	_, err := c.client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(policy),
	})
	return err
}

// implements s3.DeleteBucket(ctx, bucketName)
func (c s3Client) removeBucket(ctx context.Context, bucketName string) error {
	_, err := c.client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	return err
}

// implements s3.GetBucketPolicy(ctx, bucketName)
func (c s3Client) getBucketPolicy(ctx context.Context, bucketName string) (string, error) {
	result, err := c.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return "", err
	}
	return *result.Policy, nil
}

// implements s3.ListObjects(ctx)
func (c s3Client) listObjects(ctx context.Context, bucket string, opts ListObjectsOptions) <-chan ObjectInfo {
	ch := make(chan ObjectInfo)
	go func() {
		defer close(ch)
		paginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String(opts.Prefix),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return
			}
			for _, obj := range page.Contents {
				ch <- ObjectInfo{
					Key:          aws.ToString(obj.Key),
					Size:         aws.ToInt64(obj.Size),
					LastModified: aws.ToTime(obj.LastModified),
					ContentType:  "",
				}
			}
		}
	}()
	return ch
}

// implements s3.GetObject(ctx, bucket, key)
func (c s3Client) getObject(ctx context.Context, bucketName, objectName string, versionID string) (io.ReadCloser, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		return nil, err
	}
	return result.Body, nil
}

func (c s3Client) getObjectLegalHold(ctx context.Context, bucketName, objectName string, opts GetObjectLegalHoldOptions) (status *string, err error) {
	input := &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}
	if opts.VersionID != "" {
		input.VersionId = aws.String(opts.VersionID)
	}
	result, err := c.client.GetObjectLegalHold(ctx, input)
	if err != nil {
		return nil, err
	}
	if result.LegalHold == nil {
		return nil, nil
	}
	statusStr := string(result.LegalHold.Status)
	return &statusStr, nil
}

func (c s3Client) getObjectRetention(ctx context.Context, bucketName, objectName, versionID string) (mode *string, retainUntilDate *time.Time, err error) {
	input := &s3.GetObjectRetentionInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	result, err := c.client.GetObjectRetention(ctx, input)
	if err != nil {
		return nil, nil, err
	}
	mode_str := string(result.Retention.Mode)
	return &mode_str, result.Retention.RetainUntilDate, nil
}

func (c s3Client) putObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64, opts PutObjectOptions) (info UploadInfo, err error) {
	input := &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
		Body:   reader,
	}
	if opts.ContentType != "" {
		input.ContentType = aws.String(opts.ContentType)
	}
	if opts.UserMetadata != nil {
		input.Metadata = opts.UserMetadata
	}
	_, err = c.client.PutObject(ctx, input)
	if err != nil {
		return UploadInfo{}, err
	}
	return UploadInfo{
		Key:  objectName,
		Size: objectSize,
	}, nil
}

func (c s3Client) putObjectRetention(ctx context.Context, bucketName, objectName string, opts PutObjectRetentionOptions) error {
	input := &s3.PutObjectRetentionInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}
	if opts.VersionID != "" {
		input.VersionId = aws.String(opts.VersionID)
	}
	if opts.Mode != nil && opts.RetainUntilDate != nil {
		input.Retention = &types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(*opts.Mode),
			RetainUntilDate: opts.RetainUntilDate,
		}
	}
	_, err := c.client.PutObjectRetention(ctx, input)
	return err
}

func (c s3Client) statObject(ctx context.Context, bucketName, prefix string, opts GetObjectOptions) (objectInfo ObjectInfo, err error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(prefix),
	}
	if opts.VersionID != "" {
		input.VersionId = aws.String(opts.VersionID)
	}
	result, err := c.client.HeadObject(ctx, input)
	if err != nil {
		return ObjectInfo{}, err
	}
	return ObjectInfo{
		Key:          prefix,
		Size:         aws.ToInt64(result.ContentLength),
		LastModified: aws.ToTime(result.LastModified),
		ContentType:  aws.ToString(result.ContentType),
		UserMetadata: result.Metadata,
		Metadata:     result.Metadata,
	}, nil
}

// implements s3.PutBucketEncryption(ctx, bucketName, config)
func (c s3Client) setBucketEncryption(ctx context.Context, bucketName string, config *EncryptionConfiguration) error {
	rules := []types.ServerSideEncryptionRule{}
	for _, rule := range config.Rules {
		rules = append(rules, types.ServerSideEncryptionRule{
			ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
				SSEAlgorithm:   types.ServerSideEncryption(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm),
				KMSMasterKeyID: aws.String(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID),
			},
		})
	}
	_, err := c.client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(bucketName),
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: rules,
		},
	})
	return err
}

// implements s3.DeleteBucketEncryption(ctx, bucketName)
func (c s3Client) removeBucketEncryption(ctx context.Context, bucketName string) error {
	_, err := c.client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	return err
}

// implements s3.GetBucketEncryption(ctx, bucketName)
func (c s3Client) getBucketEncryption(ctx context.Context, bucketName string) (*EncryptionConfiguration, error) {
	result, err := c.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, err
	}
	config := &EncryptionConfiguration{
		Rules: []EncryptionRule{},
	}
	for _, rule := range result.ServerSideEncryptionConfiguration.Rules {
		config.Rules = append(config.Rules, EncryptionRule{
			ApplyServerSideEncryptionByDefault: EncryptionByDefault{
				SSEAlgorithm:   string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm),
				KMSMasterKeyID: *rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID,
			},
		})
	}
	return config, nil
}

func (c s3Client) putObjectTagging(ctx context.Context, bucketName, objectName string, otags map[string]string, opts PutObjectTaggingOptions) error {
	tagSet := []types.Tag{}
	for k, v := range otags {
		tagSet = append(tagSet, types.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}
	input := &s3.PutObjectTaggingInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
		Tagging: &types.Tagging{
			TagSet: tagSet,
		},
	}
	if opts.VersionID != "" {
		input.VersionId = aws.String(opts.VersionID)
	}
	_, err := c.client.PutObjectTagging(ctx, input)
	return err
}

func (c s3Client) getObjectTagging(ctx context.Context, bucketName, objectName string, opts GetObjectTaggingOptions) (map[string]string, error) {
	input := &s3.GetObjectTaggingInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
	}
	if opts.VersionID != "" {
		input.VersionId = aws.String(opts.VersionID)
	}
	result, err := c.client.GetObjectTagging(ctx, input)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string)
	for _, tag := range result.TagSet {
		tags[*tag.Key] = *tag.Value
	}
	return tags, nil
}

func (c s3Client) setObjectLockConfig(ctx context.Context, bucketName string, mode *string, validity *int, unit *string) error {
	input := &s3.PutObjectLockConfigurationInput{
		Bucket: aws.String(bucketName),
	}
	if mode != nil && validity != nil && unit != nil {
		defaultRetention := &types.DefaultRetention{
			Mode: types.ObjectLockRetentionMode(*mode),
		}
		if strings.EqualFold(*unit, "Years") {
			defaultRetention.Years = aws.Int32(int32(*validity))
		} else {
			defaultRetention.Days = aws.Int32(int32(*validity))
		}
		input.ObjectLockConfiguration = &types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabled("Enabled"),
			Rule: &types.ObjectLockRule{
				DefaultRetention: defaultRetention,
			},
		}
	}
	_, err := c.client.PutObjectLockConfiguration(ctx, input)
	return err
}

func (c s3Client) getBucketObjectLockConfig(ctx context.Context, bucketName string) (mode *string, validity *int, unit *string, err error) {
	result, err := c.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if result.ObjectLockConfiguration != nil && result.ObjectLockConfiguration.Rule != nil {
		mode_str := string(result.ObjectLockConfiguration.Rule.DefaultRetention.Mode)
		validity_int := 0
		unit_str := ""
		if result.ObjectLockConfiguration.Rule.DefaultRetention.Days != nil {
			validity_int = int(*result.ObjectLockConfiguration.Rule.DefaultRetention.Days)
			unit_str = "Days"
		}
		if result.ObjectLockConfiguration.Rule.DefaultRetention.Years != nil {
			validity_int = int(*result.ObjectLockConfiguration.Rule.DefaultRetention.Years)
			unit_str = "Years"
		}
		return &mode_str, &validity_int, &unit_str, nil
	}
	return nil, nil, nil, nil
}

func (c s3Client) getObjectLockConfig(ctx context.Context, bucketName string) (lock string, mode *string, validity *int, unit *string, err error) {
	result, err := c.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return "", nil, nil, nil, err
	}
	lock = string(result.ObjectLockConfiguration.ObjectLockEnabled)
	if result.ObjectLockConfiguration.Rule != nil {
		mode_str := string(result.ObjectLockConfiguration.Rule.DefaultRetention.Mode)
		validity_int := 0
		unit_str := ""
		if result.ObjectLockConfiguration.Rule.DefaultRetention.Days != nil {
			validity_int = int(*result.ObjectLockConfiguration.Rule.DefaultRetention.Days)
			unit_str = "Days"
		}
		if result.ObjectLockConfiguration.Rule.DefaultRetention.Years != nil {
			validity_int = int(*result.ObjectLockConfiguration.Rule.DefaultRetention.Years)
			unit_str = "Years"
		}
		return lock, &mode_str, &validity_int, &unit_str, nil
	}
	return lock, nil, nil, nil, nil
}

func (c s3Client) copyObject(ctx context.Context, dst CopyDestOptions, src CopySrcOptions) (UploadInfo, error) {
	copySource := fmt.Sprintf("/%s/%s", src.Bucket, src.Object)
	if src.VersionID != "" {
		copySource += "?" + src.VersionID
	}
	input := &s3.CopyObjectInput{
		Bucket:     aws.String(dst.Bucket),
		CopySource: aws.String(copySource),
		Key:        aws.String(dst.Object),
	}
	if dst.UserMetadata != nil {
		input.Metadata = dst.UserMetadata
		input.MetadataDirective = types.MetadataDirectiveReplace
	}
	_, err := c.client.CopyObject(ctx, input)
	if err != nil {
		return UploadInfo{}, err
	}
	return UploadInfo{
		Key:  dst.Object,
		Size: 0, // AWS SDK doesn't return size directly
	}, nil
}

// MCClient interface with all functions to be implemented
// by mock when testing, it should include all mc/S3Client respective api calls
// that are used within this project.
type MCClient interface {
	addNotificationConfig(ctx context.Context, arn string, events []string, prefix, suffix string, ignoreExisting bool) *probe.Error
	removeNotificationConfig(ctx context.Context, arn string, event string, prefix string, suffix string) *probe.Error
	watch(ctx context.Context, options mc.WatchOptions) (*mc.WatchObject, *probe.Error)
	remove(ctx context.Context, isIncomplete, isRemoveBucket, isBypass, forceDelete bool, contentCh <-chan *mc.ClientContent) <-chan mc.RemoveResult
	list(ctx context.Context, opts mc.ListOptions) <-chan *mc.ClientContent
	get(ctx context.Context, opts mc.GetOptions) (io.ReadCloser, *probe.Error)
	shareDownload(ctx context.Context, versionID string, expires time.Duration) (string, *probe.Error)
	setVersioning(ctx context.Context, status string, excludePrefix []string, excludeFolders bool) *probe.Error
}

// Interface implementation
//
// Define the structure of a mc S3Client and define the functions that are actually used
// from mcS3client api.
type mcClient struct {
	client *mc.S3Client
}

// implements S3Client.AddNotificationConfig()
func (c mcClient) addNotificationConfig(ctx context.Context, arn string, events []string, prefix, suffix string, ignoreExisting bool) *probe.Error {
	return c.client.AddNotificationConfig(ctx, arn, events, prefix, suffix, ignoreExisting)
}

// implements S3Client.RemoveNotificationConfig()
func (c mcClient) removeNotificationConfig(ctx context.Context, arn string, event string, prefix string, suffix string) *probe.Error {
	return c.client.RemoveNotificationConfig(ctx, arn, event, prefix, suffix)
}

func (c mcClient) watch(ctx context.Context, options mc.WatchOptions) (*mc.WatchObject, *probe.Error) {
	return c.client.Watch(ctx, options)
}

func (c mcClient) setVersioning(ctx context.Context, status string, excludePrefix []string, excludeFolders bool) *probe.Error {
	return c.client.SetVersion(ctx, status, excludePrefix, excludeFolders)
}

func (c mcClient) remove(ctx context.Context, isIncomplete, isRemoveBucket, isBypass, forceDelete bool, contentCh <-chan *mc.ClientContent) <-chan mc.RemoveResult {
	return c.client.Remove(ctx, isIncomplete, isRemoveBucket, isBypass, forceDelete, contentCh)
}

func (c mcClient) list(ctx context.Context, opts mc.ListOptions) <-chan *mc.ClientContent {
	return c.client.List(ctx, opts)
}

func (c mcClient) get(ctx context.Context, opts mc.GetOptions) (io.ReadCloser, *probe.Error) {
	rd, _, err := c.client.Get(ctx, opts)
	return rd, err
}

func (c mcClient) shareDownload(ctx context.Context, versionID string, expires time.Duration) (string, *probe.Error) {
	return c.client.ShareDownload(ctx, versionID, expires)
}

// ConsoleCredentialsI interface with all functions to be implemented
// by mock when testing, it should include all needed console credentials
type ConsoleCredentialsI interface {
	GetAccessKey() string
	GetSecretKey() string
	GetSessionToken() string
	GetAccountAccessKey() string
	Expire()
}

// Interface implementation
type ConsoleCredentials struct {
	AccessKey        string
	SecretKey        string
	SessionToken     string
	AccountAccessKey string
}

func (c ConsoleCredentials) GetAccessKey() string {
	return c.AccessKey
}

func (c ConsoleCredentials) GetSecretKey() string {
	return c.SecretKey
}

func (c ConsoleCredentials) GetSessionToken() string {
	return c.SessionToken
}

func (c ConsoleCredentials) GetAccountAccessKey() string {
	return c.AccountAccessKey
}

// Expire is a no-op for static credentials.
func (c ConsoleCredentials) Expire() {}

func NewConsoleCredentials(accessKey, secretKey, location string, client *http.Client) (*ConsoleCredentials, error) {
	return &ConsoleCredentials{
		AccessKey:        accessKey,
		SecretKey:        secretKey,
		SessionToken:     "",
		AccountAccessKey: accessKey,
	}, nil
}

// getConsoleCredentialsFromSession returns the credentials associated to the
// provided session token
func getConsoleCredentialsFromSession(claims *models.Principal) *ConsoleCredentials {
	if claims == nil {
		return &ConsoleCredentials{}
	}
	return &ConsoleCredentials{
		AccessKey:        claims.STSAccessKeyID,
		SecretKey:        claims.STSSecretAccessKey,
		SessionToken:     claims.STSSessionToken,
		AccountAccessKey: claims.STSAccessKeyID,
	}
}

// newS3Client creates a new S3 client based on the ConsoleCredentials extracted
// from the provided session token
func newS3Client(claims *models.Principal, clientIP string) (*s3.Client, error) {
	creds := getConsoleCredentialsFromSession(claims)
	endpoint := getMinIOServer()

	// Create credentials provider
	credProvider := credentials.NewStaticCredentialsProvider(
		creds.AccessKey,
		creds.SecretKey,
		creds.SessionToken,
	)

	cfg := aws.Config{
		Credentials: credProvider,
	}

	// Create client with custom endpoint if provided
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = true  // Required for MinIO compatibility
		o.Region = "us-east-1" // Default region
	})

	return s3Client, nil
}

// newS3ClientInterface creates a new S3Client interface implementation
func newS3ClientInterface(claims *models.Principal, clientIP string) (S3Client, error) {
	rawClient, err := newS3Client(claims, clientIP)
	if err != nil {
		return nil, err
	}
	return s3Client{client: rawClient}, nil
}

// computeObjectURLWithoutEncode returns an S3 url containing the object filename without encoding
func computeObjectURLWithoutEncode(bucketName, prefix string) (string, error) {
	u, err := xnet.ParseHTTPURL(getMinIOServer())
	if err != nil {
		return "", fmt.Errorf("the provided endpoint: '%s' is invalid", getMinIOServer())
	}
	var p string
	if strings.TrimSpace(bucketName) != "" {
		p = path.Join(p, bucketName)
	}
	if strings.TrimSpace(prefix) != "" {
		p = pathJoinFinalSlash(p, prefix)
	}
	return u.String() + "/" + p, nil
}

// newS3BucketClient creates a new mc S3Client to talk to the server based on a bucket
func newS3BucketClient(claims *models.Principal, bucketName string, prefix string, clientIP string) (*mc.S3Client, error) {
	if claims == nil {
		return nil, fmt.Errorf("the provided credentials are invalid")
	}
	// It's very important to avoid encoding the prefix since the S3 client will encode the path itself
	objectURL, err := computeObjectURLWithoutEncode(bucketName, prefix)
	if err != nil {
		return nil, fmt.Errorf("the provided endpoint is invalid")
	}
	s3Config := newS3Config(objectURL, claims.STSAccessKeyID, claims.STSSecretAccessKey, claims.STSSessionToken, clientIP)
	client, pErr := mc.S3New(s3Config)
	if pErr != nil {
		return nil, pErr.Cause
	}
	s3Client, ok := client.(*mc.S3Client)
	if !ok {
		return nil, fmt.Errorf("the provided url doesn't point to a S3 server")
	}
	return s3Client, nil
}

// pathJoinFinalSlash - like path.Join() but retains trailing slashSeparator of the last element
func pathJoinFinalSlash(elem ...string) string {
	if len(elem) > 0 {
		if strings.HasSuffix(elem[len(elem)-1], SlashSeparator) {
			return path.Join(elem...) + SlashSeparator
		}
	}
	return path.Join(elem...)
}

// newS3Config simply creates a new Config struct using the passed
// parameters for S3/MinIO compatibility.
func newS3Config(endpoint, accessKey, secretKey, sessionToken string, clientIP string) *mc.Config {
	return &mc.Config{
		HostURL:      endpoint,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Signature:    "S3v4",
		AppName:      globalAppName,
		AppVersion:   pkg.Version,
		Insecure:     isLocalIPEndpoint(endpoint),
		Transport: &ConsoleTransport{
			ClientIP:  clientIP,
			Transport: GlobalTransport,
		},
	}
}
