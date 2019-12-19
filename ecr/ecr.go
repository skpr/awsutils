package ecr

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
)

// Username to pass to the Docker registry.
// https://docs.aws.amazon.com/cli/latest/reference/ecr/get-authorization-token.html
const Username = "AWS"

// IsRegistry managed by AWS ECR.
func IsRegistry(registry string) bool {
	return strings.Contains(registry, ".ecr.")
}

// UpgradeAuth to use an AWS IAM token for authentication..
// https://docs.aws.amazon.com/cli/latest/reference/ecr/get-login.html
func UpgradeAuth(url, username, password string) (string, string, error) {
	region, err := extractRegionFromURL(url)
	if err != nil {
		return "", "", fmt.Errorf("failed to determine registry region: %w", err)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(username, password, ""),
	})
	if err != nil {
		return "", "", fmt.Errorf( "failed to get session: %w", err)
	}

	res, err := ecr.New(sess).GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", fmt.Errorf("failed get authorization token: %w", err)
	}

	if len(res.AuthorizationData) == 0 {
		return "", "", fmt.Errorf("no authorization token was found")
	}

	token, err := decodeAuthorizationToken(aws.StringValue(res.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return "", "", fmt.Errorf("failed to decode authorization token: %w", err)
	}

	return Username, token, nil
}
