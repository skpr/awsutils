package ecr

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/pkg/errors"
)

// Helper function to convert a base64 token to a string.
func decodeAuthorizationToken(auth string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", errors.New("auth data contains invalid payload")
	}

	return parts[1], nil
}

// Helper function to derive a region for a URL.
func extractRegionFromURL(url string) (string, error) {
	regions := []string{
		endpoints.ApNortheast1RegionID,
		endpoints.ApNortheast2RegionID,
		endpoints.ApSouth1RegionID,
		endpoints.ApSoutheast1RegionID,
		endpoints.ApSoutheast2RegionID,
		endpoints.CaCentral1RegionID,
		endpoints.EuCentral1RegionID,
		endpoints.EuNorth1RegionID,
		endpoints.EuWest1RegionID,
		endpoints.EuWest2RegionID,
		endpoints.EuWest3RegionID,
		endpoints.SaEast1RegionID,
		endpoints.UsEast1RegionID,
		endpoints.UsEast2RegionID,
		endpoints.UsWest1RegionID,
		endpoints.UsWest2RegionID,
	}

	for _, region := range regions {
		if strings.Contains(url, region) {
			return region, nil
		}
	}

	return "", fmt.Errorf("region not found for url: %s", url)
}
