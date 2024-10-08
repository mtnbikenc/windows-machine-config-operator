// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// ImageLabelApplyConfiguration represents a declarative configuration of the ImageLabel type for use
// with apply.
type ImageLabelApplyConfiguration struct {
	Name  *string `json:"name,omitempty"`
	Value *string `json:"value,omitempty"`
}

// ImageLabelApplyConfiguration constructs a declarative configuration of the ImageLabel type for use with
// apply.
func ImageLabel() *ImageLabelApplyConfiguration {
	return &ImageLabelApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *ImageLabelApplyConfiguration) WithName(value string) *ImageLabelApplyConfiguration {
	b.Name = &value
	return b
}

// WithValue sets the Value field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Value field is set to the value of the last call.
func (b *ImageLabelApplyConfiguration) WithValue(value string) *ImageLabelApplyConfiguration {
	b.Value = &value
	return b
}
