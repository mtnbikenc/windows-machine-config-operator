// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	imagev1 "github.com/openshift/api/image/v1"
	v1 "github.com/openshift/client-go/image/applyconfigurations/image/v1"
	scheme "github.com/openshift/client-go/image/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gentype "k8s.io/client-go/gentype"
)

// ImageStreamMappingsGetter has a method to return a ImageStreamMappingInterface.
// A group's client should implement this interface.
type ImageStreamMappingsGetter interface {
	ImageStreamMappings(namespace string) ImageStreamMappingInterface
}

// ImageStreamMappingInterface has methods to work with ImageStreamMapping resources.
type ImageStreamMappingInterface interface {
	Apply(ctx context.Context, imageStreamMapping *v1.ImageStreamMappingApplyConfiguration, opts metav1.ApplyOptions) (result *imagev1.ImageStreamMapping, err error)
	Create(ctx context.Context, imageStreamMapping *imagev1.ImageStreamMapping, opts metav1.CreateOptions) (*metav1.Status, error)

	ImageStreamMappingExpansion
}

// imageStreamMappings implements ImageStreamMappingInterface
type imageStreamMappings struct {
	*gentype.ClientWithApply[*imagev1.ImageStreamMapping, *v1.ImageStreamMappingApplyConfiguration]
}

// newImageStreamMappings returns a ImageStreamMappings
func newImageStreamMappings(c *ImageV1Client, namespace string) *imageStreamMappings {
	return &imageStreamMappings{
		gentype.NewClientWithApply[*imagev1.ImageStreamMapping, *v1.ImageStreamMappingApplyConfiguration](
			"imagestreammappings",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *imagev1.ImageStreamMapping { return &imagev1.ImageStreamMapping{} }),
	}
}

// Create takes the representation of a imageStreamMapping and creates it.  Returns the server's representation of the status, and an error, if there is any.
func (c *imageStreamMappings) Create(ctx context.Context, imageStreamMapping *imagev1.ImageStreamMapping, opts metav1.CreateOptions) (result *metav1.Status, err error) {
	result = &metav1.Status{}
	err = c.GetClient().Post().
		Namespace(c.GetNamespace()).
		Resource("imagestreammappings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imageStreamMapping).
		Do(ctx).
		Into(result)
	return
}
