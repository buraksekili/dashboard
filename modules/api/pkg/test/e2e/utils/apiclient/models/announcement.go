// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Announcement The announcement feature allows administrators to broadcast important messages to all users.
//
// swagger:model Announcement
type Announcement struct {

	// Timestamp when the announcement was created.
	CreatedAt string `json:"createdAt,omitempty"`

	// Expiration date for the announcement.
	// +optional
	Expires string `json:"expires,omitempty"`

	// Indicates whether the announcement is active.
	IsActive bool `json:"isActive,omitempty"`

	// The message content of the announcement.
	Message string `json:"message,omitempty"`
}

// Validate validates this announcement
func (m *Announcement) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this announcement based on context it is used
func (m *Announcement) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Announcement) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Announcement) UnmarshalBinary(b []byte) error {
	var res Announcement
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
