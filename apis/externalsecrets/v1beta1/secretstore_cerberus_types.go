package v1beta1

// CerberusProvider configures a store to sync secrets with AWS.
type CerberusProvider struct {
	// +optional
	Auth AWSAuth `json:"auth,omitempty"`

	// +optional
	Role string `json:"role,omitempty"`

	// AdditionalRoles is a chained list of Role ARNs which the SecretManager provider will sequentially assume before assuming Role
	// +optional
	AdditionalRoles []string `json:"additionalRoles,omitempty"`

	// AWS STS assume role session tags
	// +optional
	SessionTags []*Tag `json:"sessionTags,omitempty"`

	// AWS STS assume role transitive session tags. Required when multiple rules are used with SecretStore
	// +optional
	TransitiveTagKeys []*string `json:"transitiveTagKeys,omitempty"`

	// AWS External ID set on assumed IAM roles
	ExternalID string `json:"externalID,omitempty"`
	// AWS Region to be used for the provider
	Region string `json:"region"`

	CerberusURL string `json:"cerberusURL"`

	SDB string `json:"sdb"`
}
