package cerberus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Nike-Inc/cerberus-go-client/v3/api"
	cerberussdk "github.com/Nike-Inc/cerberus-go-client/v3/cerberus"
	"github.com/aws/aws-sdk-go/aws"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/find"
	"github.com/external-secrets/external-secrets/pkg/provider/cerberus/util"
)

type cerberus struct {
	client *cerberussdk.Client
	sdb    *api.SafeDepositBox
}

var globalMutex = util.MutexMap{}

func (c *cerberus) GetSecretMap(_ context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return c.readCerberusSecretProperties(ref)
}

func (c *cerberus) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	properties, err := c.GetSecretMap(ctx, ref)
	if err != nil {
		return nil, err
	}
	if ref.Property == "" {
		// workaround so that json.Marshal does not do base64 on []byte :/
		stringProps := map[string]string{}
		for k, v := range properties {
			stringProps[k] = string(v)
		}
		return json.Marshal(stringProps)
	}

	property, ok := properties[ref.Property]
	if !ok {
		return nil, fmt.Errorf("property %s does not exist in secret", ref.Property)
	}

	return property, nil
}

func (c *cerberus) PushSecret(_ context.Context, value []byte, _ v1.SecretType, _ *apiextensionsv1.JSON, remoteRef esv1beta1.PushRemoteRef) error {
	if remoteRef.GetProperty() == "" {
		return fmt.Errorf("property must be set")
	}

	mu := globalMutex.GetLock(remoteRef.GetRemoteKey())
	mu.Lock()
	defer mu.Unlock()

	properties, err := c.readCerberusSecretProperties(esv1beta1.ExternalSecretDataRemoteRef{
		Key: remoteRef.GetRemoteKey(),
	})
	if err != nil {
		return err
	}

	properties[remoteRef.GetProperty()] = value

	return c.overwriteCerberusSecret(properties, remoteRef.GetRemoteKey())
}

func (c *cerberus) DeleteSecret(_ context.Context, remoteRef esv1beta1.PushRemoteRef) error {
	if remoteRef.GetProperty() == "" {
		return fmt.Errorf("property must be set")
	}

	mu := globalMutex.GetLock(remoteRef.GetRemoteKey())
	mu.Lock()
	defer mu.Unlock()

	properties, err := c.readCerberusSecretProperties(esv1beta1.ExternalSecretDataRemoteRef{
		Key: remoteRef.GetRemoteKey(),
	})
	if err != nil {
		return err
	}

	delete(properties, remoteRef.GetProperty())

	if len(properties) > 0 {
		return c.overwriteCerberusSecret(properties, remoteRef.GetRemoteKey())
	}

	return c.deleteCerberusSecret(remoteRef.GetRemoteKey())
}

func (c *cerberus) Validate() (esv1beta1.ValidationResult, error) {
	if c.client == nil {
		return esv1beta1.ValidationResultError, nil
	}

	if c.client.Authentication.IsAuthenticated() {
		return esv1beta1.ValidationResultReady, nil
	}

	return esv1beta1.ValidationResultError, nil
}

func (c *cerberus) GetAllSecrets(ctx context.Context, ref esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	if ref.Tags != nil {
		return nil, fmt.Errorf("tags are not supported")
	}
	if ref.Path != nil && !strings.HasSuffix(*ref.Path, "/") {
		suffixed := fmt.Sprintf("%s/", *ref.Path)
		ref.Path = &suffixed
	}

	if ref.Path == nil {
		ref.Path = aws.String("/")
	}

	matcher, err := find.New(*ref.Name)
	if err != nil {
		return nil, err
	}

	allSecretPaths, err := c.traverseAndFind(*ref.Path, func(name string) bool {
		return matcher.MatchName(name)
	})
	if err != nil {
		return nil, err
	}

	results := make(map[string][]byte)
	for _, path := range allSecretPaths {
		data, err := c.GetSecret(ctx, esv1beta1.ExternalSecretDataRemoteRef{Key: path})
		if err != nil {
			return nil, err
		}
		results[strings.ReplaceAll(strings.TrimPrefix(path, *ref.Path), "/", "_")] = data
	}

	return results, nil
}

func (c *cerberus) Close(_ context.Context) error {
	return nil
}

func (c *cerberus) prependSDBPath(key string) string {
	return fmt.Sprintf("%s%s", c.sdb.Path, strings.TrimPrefix(key, "/"))
}

func (c *cerberus) traverseAndFind(startPath string, predicate func(string) bool) ([]string, error) {
	var collector []string

	list, err := c.client.Secret().List(c.prependSDBPath(startPath))
	if err != nil {
		return nil, err
	}

	if len(list.Data) == 0 {
		return collector, nil
	}

	secretsKeys, ok := list.Data["keys"]
	if !ok {
		return collector, nil
	}

	for _, secretKey := range secretsKeys.([]interface{}) {
		key := secretKey.(string)
		if strings.HasSuffix(key, "/") {
			subtreeCollector, err := c.traverseAndFind(fmt.Sprintf("%s%s", startPath, key), predicate)
			if err != nil {
				return nil, err
			}
			collector = append(collector, subtreeCollector...)
		} else {
			if predicate(key) {
				collector = append(collector, fmt.Sprintf("%s%s", startPath, key))
			}
		}
	}

	return collector, nil
}

func (c *cerberus) readCerberusSecretProperties(ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	properties, err := c.readAllPropsForPath(ref)
	if err != nil {
		return nil, err
	}

	return properties, nil
}

func (c *cerberus) overwriteCerberusSecret(properties map[string][]byte, path string) error {
	fullPath := c.prependSDBPath(path)

	stringProperties := make(map[string]interface{})
	for k, v := range properties {
		stringProperties[k] = string(v)
	}

	written, err := c.client.Secret().Write(fullPath, stringProperties)

	_ = written

	return err
}

func (c *cerberus) deleteCerberusSecret(path string) error {
	fullPath := c.prependSDBPath(path)

	_, err := c.client.Secret().Delete(fullPath)

	return err
}

func (c *cerberus) readAllPropsForPath(ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	data := make(map[string][]string)
	if ref.Version != "" {
		data["versionId"] = []string{ref.Version}
	}

	var secrets, err = c.client.Secret().ReadWithData(c.prependSDBPath(ref.Key), data)

	c.client.Secret()
	if err != nil {
		return nil, err
	}

	if secrets == nil {
		return map[string][]byte{}, nil
	}

	results := make(map[string][]byte)

	for k, v := range secrets.Data {
		results[k] = []byte(v.(string))
	}

	return results, nil
}
