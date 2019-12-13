package ecr

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/pkg/errors"
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
func UpgradeAuth(url string, auth docker.AuthConfiguration) (docker.AuthConfiguration, error) {
	region, err := extractRegionFromURL(url)
	if err != nil {
		return auth, errors.Wrap(err, "failed to determine registry region")
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(auth.Username, auth.Password, ""),
	})
	if err != nil {
		return auth, errors.Wrap(err, "failed to get session")
	}

	res, err := ecr.New(sess).GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return auth, err
	}

	if len(res.AuthorizationData) == 0 {
		return auth, errors.New("failed get authorization token")
	}

	password, err := decodeAuthorizationToken(aws.StringValue(res.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return auth, errors.Wrap(err, "failed to decode authorization token")
	}

	auth.Username = Username
	auth.Password = password

	return auth, nil
}
