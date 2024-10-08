// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1 "github.com/openshift/api/operator/v1"
	operatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCloudCredentials implements CloudCredentialInterface
type FakeCloudCredentials struct {
	Fake *FakeOperatorV1
}

var cloudcredentialsResource = v1.SchemeGroupVersion.WithResource("cloudcredentials")

var cloudcredentialsKind = v1.SchemeGroupVersion.WithKind("CloudCredential")

// Get takes name of the cloudCredential, and returns the corresponding cloudCredential object, and an error if there is any.
func (c *FakeCloudCredentials) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.CloudCredential, err error) {
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(cloudcredentialsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}

// List takes label and field selectors, and returns the list of CloudCredentials that match those selectors.
func (c *FakeCloudCredentials) List(ctx context.Context, opts metav1.ListOptions) (result *v1.CloudCredentialList, err error) {
	emptyResult := &v1.CloudCredentialList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(cloudcredentialsResource, cloudcredentialsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.CloudCredentialList{ListMeta: obj.(*v1.CloudCredentialList).ListMeta}
	for _, item := range obj.(*v1.CloudCredentialList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested cloudCredentials.
func (c *FakeCloudCredentials) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(cloudcredentialsResource, opts))
}

// Create takes the representation of a cloudCredential and creates it.  Returns the server's representation of the cloudCredential, and an error, if there is any.
func (c *FakeCloudCredentials) Create(ctx context.Context, cloudCredential *v1.CloudCredential, opts metav1.CreateOptions) (result *v1.CloudCredential, err error) {
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(cloudcredentialsResource, cloudCredential, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}

// Update takes the representation of a cloudCredential and updates it. Returns the server's representation of the cloudCredential, and an error, if there is any.
func (c *FakeCloudCredentials) Update(ctx context.Context, cloudCredential *v1.CloudCredential, opts metav1.UpdateOptions) (result *v1.CloudCredential, err error) {
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(cloudcredentialsResource, cloudCredential, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCloudCredentials) UpdateStatus(ctx context.Context, cloudCredential *v1.CloudCredential, opts metav1.UpdateOptions) (result *v1.CloudCredential, err error) {
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(cloudcredentialsResource, "status", cloudCredential, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}

// Delete takes name of the cloudCredential and deletes it. Returns an error if one occurs.
func (c *FakeCloudCredentials) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(cloudcredentialsResource, name, opts), &v1.CloudCredential{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCloudCredentials) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(cloudcredentialsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.CloudCredentialList{})
	return err
}

// Patch applies the patch and returns the patched cloudCredential.
func (c *FakeCloudCredentials) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.CloudCredential, err error) {
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(cloudcredentialsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied cloudCredential.
func (c *FakeCloudCredentials) Apply(ctx context.Context, cloudCredential *operatorv1.CloudCredentialApplyConfiguration, opts metav1.ApplyOptions) (result *v1.CloudCredential, err error) {
	if cloudCredential == nil {
		return nil, fmt.Errorf("cloudCredential provided to Apply must not be nil")
	}
	data, err := json.Marshal(cloudCredential)
	if err != nil {
		return nil, err
	}
	name := cloudCredential.Name
	if name == nil {
		return nil, fmt.Errorf("cloudCredential.Name must be provided to Apply")
	}
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(cloudcredentialsResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeCloudCredentials) ApplyStatus(ctx context.Context, cloudCredential *operatorv1.CloudCredentialApplyConfiguration, opts metav1.ApplyOptions) (result *v1.CloudCredential, err error) {
	if cloudCredential == nil {
		return nil, fmt.Errorf("cloudCredential provided to Apply must not be nil")
	}
	data, err := json.Marshal(cloudCredential)
	if err != nil {
		return nil, err
	}
	name := cloudCredential.Name
	if name == nil {
		return nil, fmt.Errorf("cloudCredential.Name must be provided to Apply")
	}
	emptyResult := &v1.CloudCredential{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(cloudcredentialsResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.CloudCredential), err
}
