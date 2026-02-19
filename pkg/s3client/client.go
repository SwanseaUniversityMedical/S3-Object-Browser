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

package s3client

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Credentials holds S3 credentials and config
type S3Credentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Region       string
	Endpoint     string
}

// S3Client is a pure S3 client using AWS SDK v2
type S3Client struct {
	client *s3.Client
	config *S3Credentials
}

// S3ObjectInfo represents a single S3 object
type S3ObjectInfo struct {
	Key          string
	LastModified time.Time
	Size         int64
	VersionID    string
	DeleteMarker bool
	IsLatest     bool
	Err          error
}

// NewS3Client creates a new S3 client from credentials
func NewS3Client(creds *S3Credentials) (*S3Client, error) {
	ctx := context.Background()
	
	// Create AWS config with static credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(creds.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			creds.AccessKey,
			creds.SecretKey,
			creds.SessionToken,
		)),
	)
	if err != nil {
		return nil, err
	}

	// Create S3 client with optional custom endpoint
	var client *s3.Client
	if creds.Endpoint != "" {
		client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(creds.Endpoint)
			o.UsePathStyle = true
		})
	} else {
		client = s3.NewFromConfig(cfg)
	}

	return &S3Client{
		client: client,
		config: creds,
	}, nil
}

// ListBuckets lists all buckets for the S3 client
func (c *S3Client) ListBuckets(ctx context.Context) ([]string, error) {
	result, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	buckets := make([]string, 0, len(result.Buckets))
	for _, bucket := range result.Buckets {
		if bucket.Name != nil {
			buckets = append(buckets, *bucket.Name)
		}
	}
	return buckets, nil
}

// ListObjects lists objects in a bucket with a given prefix
func (c *S3Client) ListObjects(ctx context.Context, bucket, prefix string, recursive bool) <-chan S3ObjectInfo {
	objectCh := make(chan S3ObjectInfo)

	go func() {
		defer close(objectCh)

		delimiter := ""
		if !recursive {
			delimiter = "/"
		}

		paginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
			Bucket:    aws.String(bucket),
			Prefix:    aws.String(prefix),
			Delimiter: aws.String(delimiter),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				objectCh <- S3ObjectInfo{Err: err}
				return
			}

			for _, obj := range page.Contents {
				objectCh <- S3ObjectInfo{
					Key:          aws.ToString(obj.Key),
					LastModified: aws.ToTime(obj.LastModified),
					Size:         aws.ToInt64(obj.Size),
					Err:          nil,
				}
			}

			// Handle common prefixes (directories) if not recursive
			if !recursive {
				for _, prefix := range page.CommonPrefixes {
					objectCh <- S3ObjectInfo{
						Key:  aws.ToString(prefix.Prefix),
						Size: 0,
						Err:  nil,
					}
				}
			}
		}
	}()

	return objectCh
}

// ListObjectVersions lists objects with versioning information
func (c *S3Client) ListObjectVersions(ctx context.Context, bucket, prefix string) <-chan S3ObjectInfo {
	objectCh := make(chan S3ObjectInfo)

	go func() {
		defer close(objectCh)

		paginator := s3.NewListObjectVersionsPaginator(c.client, &s3.ListObjectVersionsInput{
			Bucket: aws.String(bucket),
			Prefix: aws.String(prefix),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				objectCh <- S3ObjectInfo{Err: err}
				return
			}

			// Process versions
			for _, version := range page.Versions {
				objectCh <- S3ObjectInfo{
					Key:          aws.ToString(version.Key),
					LastModified: aws.ToTime(version.LastModified),
					Size:         aws.ToInt64(version.Size),
					VersionID:    aws.ToString(version.VersionId),
					DeleteMarker: false,
					IsLatest:     aws.ToBool(version.IsLatest),
					Err:          nil,
				}
			}

			// Process delete markers
			for _, marker := range page.DeleteMarkers {
				objectCh <- S3ObjectInfo{
					Key:          aws.ToString(marker.Key),
					LastModified: aws.ToTime(marker.LastModified),
					Size:         0,
					VersionID:    aws.ToString(marker.VersionId),
					DeleteMarker: true,
					IsLatest:     aws.ToBool(marker.IsLatest),
					Err:          nil,
				}
			}
		}
	}()

	return objectCh
}

// GetObject retrieves an object from S3
func (c *S3Client) GetObject(ctx context.Context, bucket, key string, versionID string) (*s3.GetObjectOutput, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	return c.client.GetObject(ctx, input)
}

// PutObject uploads an object to S3
func (c *S3Client) PutObject(ctx context.Context, bucket, key string, body interface{}) error {
	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   body.(interface{ Read([]byte) (int, error) }),
	})
	return err
}

// DeleteObject deletes an object from S3
func (c *S3Client) DeleteObject(ctx context.Context, bucket, key string, versionID string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	_, err := c.client.DeleteObject(ctx, input)
	return err
}

// HeadBucket checks if a bucket exists and is accessible
func (c *S3Client) HeadBucket(ctx context.Context, bucket string) error {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	return err
}

// CreateBucket creates a new S3 bucket
func (c *S3Client) CreateBucket(ctx context.Context, bucket string) error {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}

	// For regions other than us-east-1, must specify location constraint
	if c.config.Region != "" && c.config.Region != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(c.config.Region),
		}
	}

	_, err := c.client.CreateBucket(ctx, input)
	return err
}

// DeleteBucket deletes an S3 bucket
func (c *S3Client) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := c.client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	return err
}
