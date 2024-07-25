package encrypt

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/defaults"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPsecCreateKey creates IPsec key.
func (s *Encrypt) IPsecCreateKey(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	key, err := rotateIPsecKey(ipsecKey{}, s.params.IPsecKeyAuthAlgo)
	if err != nil {
		return fmt.Errorf("failed to rotate empty IPsec key: %w", err)
	}

	if s.params.IPsecKeyPerNode != "" {
		key.spiSuffix = mustParseBool(s.params.IPsecKeyPerNode)
	}

	secret := &coreV1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: defaults.EncryptionSecretName},
		Data:       map[string][]byte{"keys": []byte(key.String())},
	}

	_, err = s.client.CreateSecret(ctx, s.params.CiliumNamespace, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create IPsec key: %w", err)
	}

	_, err = fmt.Printf("IPsec key successfully create: %s\n", key.String())
	return err
}
