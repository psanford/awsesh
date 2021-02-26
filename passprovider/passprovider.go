package passprovider

type Provider interface {
	AWSCreds() (*AwsCreds, error)
}

type AwsCreds struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}
