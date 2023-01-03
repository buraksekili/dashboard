// Code generated by go-swagger; DO NOT EDIT.

package openstack

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"k8c.io/dashboard/v2/pkg/test/e2e/utils/apiclient/models"
)

// ListProjectOpenstackNetworksReader is a Reader for the ListProjectOpenstackNetworks structure.
type ListProjectOpenstackNetworksReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListProjectOpenstackNetworksReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListProjectOpenstackNetworksOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewListProjectOpenstackNetworksDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewListProjectOpenstackNetworksOK creates a ListProjectOpenstackNetworksOK with default headers values
func NewListProjectOpenstackNetworksOK() *ListProjectOpenstackNetworksOK {
	return &ListProjectOpenstackNetworksOK{}
}

/*
ListProjectOpenstackNetworksOK describes a response with status code 200, with default header values.

OpenstackNetwork
*/
type ListProjectOpenstackNetworksOK struct {
	Payload []*models.OpenstackNetwork
}

// IsSuccess returns true when this list project openstack networks o k response has a 2xx status code
func (o *ListProjectOpenstackNetworksOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list project openstack networks o k response has a 3xx status code
func (o *ListProjectOpenstackNetworksOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list project openstack networks o k response has a 4xx status code
func (o *ListProjectOpenstackNetworksOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list project openstack networks o k response has a 5xx status code
func (o *ListProjectOpenstackNetworksOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list project openstack networks o k response a status code equal to that given
func (o *ListProjectOpenstackNetworksOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListProjectOpenstackNetworksOK) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/networks][%d] listProjectOpenstackNetworksOK  %+v", 200, o.Payload)
}

func (o *ListProjectOpenstackNetworksOK) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/networks][%d] listProjectOpenstackNetworksOK  %+v", 200, o.Payload)
}

func (o *ListProjectOpenstackNetworksOK) GetPayload() []*models.OpenstackNetwork {
	return o.Payload
}

func (o *ListProjectOpenstackNetworksOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListProjectOpenstackNetworksDefault creates a ListProjectOpenstackNetworksDefault with default headers values
func NewListProjectOpenstackNetworksDefault(code int) *ListProjectOpenstackNetworksDefault {
	return &ListProjectOpenstackNetworksDefault{
		_statusCode: code,
	}
}

/*
ListProjectOpenstackNetworksDefault describes a response with status code -1, with default header values.

errorResponse
*/
type ListProjectOpenstackNetworksDefault struct {
	_statusCode int

	Payload *models.ErrorResponse
}

// Code gets the status code for the list project openstack networks default response
func (o *ListProjectOpenstackNetworksDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this list project openstack networks default response has a 2xx status code
func (o *ListProjectOpenstackNetworksDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this list project openstack networks default response has a 3xx status code
func (o *ListProjectOpenstackNetworksDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this list project openstack networks default response has a 4xx status code
func (o *ListProjectOpenstackNetworksDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this list project openstack networks default response has a 5xx status code
func (o *ListProjectOpenstackNetworksDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this list project openstack networks default response a status code equal to that given
func (o *ListProjectOpenstackNetworksDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *ListProjectOpenstackNetworksDefault) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/networks][%d] listProjectOpenstackNetworks default  %+v", o._statusCode, o.Payload)
}

func (o *ListProjectOpenstackNetworksDefault) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/networks][%d] listProjectOpenstackNetworks default  %+v", o._statusCode, o.Payload)
}

func (o *ListProjectOpenstackNetworksDefault) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ListProjectOpenstackNetworksDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
