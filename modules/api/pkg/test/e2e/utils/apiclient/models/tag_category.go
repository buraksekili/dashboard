// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TagCategory TagCategory is the tag category that is owned by KKP, where it is used to define KKP created tags, such as resources
// ownership tag, where this tag is applied on any vSphere resource that is created by KKP.
//
// swagger:model TagCategory
type TagCategory struct {

	// ID represents the category id for the machine deployment tags.
	ID string `json:"id,omitempty"`

	// Name represents the name of vSphere tag category that will be used to create and attach tags on VMS.
	Name string `json:"name,omitempty"`
}

// Validate validates this tag category
func (m *TagCategory) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this tag category based on context it is used
func (m *TagCategory) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TagCategory) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TagCategory) UnmarshalBinary(b []byte) error {
	var res TagCategory
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
