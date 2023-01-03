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

// ListProjectOpenstackSubnetPoolsReader is a Reader for the ListProjectOpenstackSubnetPools structure.
type ListProjectOpenstackSubnetPoolsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListProjectOpenstackSubnetPoolsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListProjectOpenstackSubnetPoolsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewListProjectOpenstackSubnetPoolsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewListProjectOpenstackSubnetPoolsOK creates a ListProjectOpenstackSubnetPoolsOK with default headers values
func NewListProjectOpenstackSubnetPoolsOK() *ListProjectOpenstackSubnetPoolsOK {
	return &ListProjectOpenstackSubnetPoolsOK{}
}

/*
ListProjectOpenstackSubnetPoolsOK describes a response with status code 200, with default header values.

OpenstackSubnetPool
*/
type ListProjectOpenstackSubnetPoolsOK struct {
	Payload []*models.OpenstackSubnetPool
}

// IsSuccess returns true when this list project openstack subnet pools o k response has a 2xx status code
func (o *ListProjectOpenstackSubnetPoolsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list project openstack subnet pools o k response has a 3xx status code
func (o *ListProjectOpenstackSubnetPoolsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list project openstack subnet pools o k response has a 4xx status code
func (o *ListProjectOpenstackSubnetPoolsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list project openstack subnet pools o k response has a 5xx status code
func (o *ListProjectOpenstackSubnetPoolsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list project openstack subnet pools o k response a status code equal to that given
func (o *ListProjectOpenstackSubnetPoolsOK) IsCode(code int) bool {
	return code == 200
}

func (o *ListProjectOpenstackSubnetPoolsOK) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/subnetpools][%d] listProjectOpenstackSubnetPoolsOK  %+v", 200, o.Payload)
}

func (o *ListProjectOpenstackSubnetPoolsOK) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/subnetpools][%d] listProjectOpenstackSubnetPoolsOK  %+v", 200, o.Payload)
}

func (o *ListProjectOpenstackSubnetPoolsOK) GetPayload() []*models.OpenstackSubnetPool {
	return o.Payload
}

func (o *ListProjectOpenstackSubnetPoolsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListProjectOpenstackSubnetPoolsDefault creates a ListProjectOpenstackSubnetPoolsDefault with default headers values
func NewListProjectOpenstackSubnetPoolsDefault(code int) *ListProjectOpenstackSubnetPoolsDefault {
	return &ListProjectOpenstackSubnetPoolsDefault{
		_statusCode: code,
	}
}

/*
ListProjectOpenstackSubnetPoolsDefault describes a response with status code -1, with default header values.

errorResponse
*/
type ListProjectOpenstackSubnetPoolsDefault struct {
	_statusCode int

	Payload *models.ErrorResponse
}

// Code gets the status code for the list project openstack subnet pools default response
func (o *ListProjectOpenstackSubnetPoolsDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this list project openstack subnet pools default response has a 2xx status code
func (o *ListProjectOpenstackSubnetPoolsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this list project openstack subnet pools default response has a 3xx status code
func (o *ListProjectOpenstackSubnetPoolsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this list project openstack subnet pools default response has a 4xx status code
func (o *ListProjectOpenstackSubnetPoolsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this list project openstack subnet pools default response has a 5xx status code
func (o *ListProjectOpenstackSubnetPoolsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this list project openstack subnet pools default response a status code equal to that given
func (o *ListProjectOpenstackSubnetPoolsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *ListProjectOpenstackSubnetPoolsDefault) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/subnetpools][%d] listProjectOpenstackSubnetPools default  %+v", o._statusCode, o.Payload)
}

func (o *ListProjectOpenstackSubnetPoolsDefault) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/providers/openstack/subnetpools][%d] listProjectOpenstackSubnetPools default  %+v", o._statusCode, o.Payload)
}

func (o *ListProjectOpenstackSubnetPoolsDefault) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ListProjectOpenstackSubnetPoolsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
