package encrypt

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/defaults"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPsecDeleteKey deletes IPsec key.
func (s *Encrypt) IPsecDeleteKey(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	err := s.client.DeleteSecret(ctx, s.params.CiliumNamespace, defaults.EncryptionSecretName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete IPsec key: %w", err)
	}

	_, err = fmt.Printf("IPsec key successfully deleted\n")
	return err
}
