package eks

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/sts"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
	"github.com/pkg/errors"
	"k8s.io/client-go/rest"
)

type Cluster struct {
	Region string
	Account string
	Name string
}

type Credentials struct {
	AccessID string
	SecretKey string
}

// Kubeconfig as required by EKS.
func Kubeconfig(cluster Cluster, credentials Credentials) (*rest.Config, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(cluster.Region),
		Credentials: credentials.NewStaticCredentials(credentials.AccessID, credentials.SecretKey, ""),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get session")
	}

	var (
		stsclient = sts.New(sess)
		eksclient = eks.New(sess)
	)

	allowed, err := stsVerifyAccount(stsclient, cluster.Account)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get account id")
	}

	if !allowed {
		return nil, errors.New("credentials do not belong to intended account")
	}

	input := &eks.DescribeClusterInput{
		Name: aws.String(cluster.Name),
	}

	resp, err := eksclient.DescribeCluster(input)
	if err != nil {
		return nil, errors.Wrap(err, "failed to describe EKS cluster")
	}

	ca, err := base64.StdEncoding.DecodeString(*resp.Cluster.CertificateAuthority.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate authority")
	}

	// @todo, Look at how we could make this pass in an interface so we can write tests.
	gen, err := token.NewGenerator(false)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create token client")
	}

	token, err := gen.GetWithSTS(cluster.Name, stsclient)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token")
	}

	config := &rest.Config{
		Host:        *resp.Cluster.Endpoint,
		BearerToken: token.Token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: ca,
		},
	}

	return config, nil
}

// Helper function take from https://github.com/hashicorp/aws-sdk-go-base/blob/master/awsauth.go
func stsVerifyAccount(client *sts.STS, accountID string) (bool, error) {
	output, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return false, errors.Wrap(err, "failed to get user details")
	}

	if output == nil || output.Arn == nil {
		return false, errors.New("received empty user details response")
	}

	arn, err := arn.Parse(*output.Arn)
	if err != nil {
		return false, errors.Wrap(err, "failed to parse user arn")
	}

	return arn.AccountID == accountID, nil
}
