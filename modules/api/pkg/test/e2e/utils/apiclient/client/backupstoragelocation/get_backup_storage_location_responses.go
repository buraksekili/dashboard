// Code generated by go-swagger; DO NOT EDIT.

package backupstoragelocation

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"k8c.io/dashboard/v2/pkg/test/e2e/utils/apiclient/models"
)

// GetBackupStorageLocationReader is a Reader for the GetBackupStorageLocation structure.
type GetBackupStorageLocationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetBackupStorageLocationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetBackupStorageLocationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetBackupStorageLocationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetBackupStorageLocationForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		result := NewGetBackupStorageLocationDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetBackupStorageLocationOK creates a GetBackupStorageLocationOK with default headers values
func NewGetBackupStorageLocationOK() *GetBackupStorageLocationOK {
	return &GetBackupStorageLocationOK{}
}

/*
GetBackupStorageLocationOK describes a response with status code 200, with default header values.

BackupStorageLocation
*/
type GetBackupStorageLocationOK struct {
	Payload *models.BackupStorageLocation
}

// IsSuccess returns true when this get backup storage location o k response has a 2xx status code
func (o *GetBackupStorageLocationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get backup storage location o k response has a 3xx status code
func (o *GetBackupStorageLocationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get backup storage location o k response has a 4xx status code
func (o *GetBackupStorageLocationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get backup storage location o k response has a 5xx status code
func (o *GetBackupStorageLocationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get backup storage location o k response a status code equal to that given
func (o *GetBackupStorageLocationOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetBackupStorageLocationOK) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocationOK  %+v", 200, o.Payload)
}

func (o *GetBackupStorageLocationOK) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocationOK  %+v", 200, o.Payload)
}

func (o *GetBackupStorageLocationOK) GetPayload() *models.BackupStorageLocation {
	return o.Payload
}

func (o *GetBackupStorageLocationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BackupStorageLocation)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetBackupStorageLocationUnauthorized creates a GetBackupStorageLocationUnauthorized with default headers values
func NewGetBackupStorageLocationUnauthorized() *GetBackupStorageLocationUnauthorized {
	return &GetBackupStorageLocationUnauthorized{}
}

/*
GetBackupStorageLocationUnauthorized describes a response with status code 401, with default header values.

EmptyResponse is a empty response
*/
type GetBackupStorageLocationUnauthorized struct {
}

// IsSuccess returns true when this get backup storage location unauthorized response has a 2xx status code
func (o *GetBackupStorageLocationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get backup storage location unauthorized response has a 3xx status code
func (o *GetBackupStorageLocationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get backup storage location unauthorized response has a 4xx status code
func (o *GetBackupStorageLocationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get backup storage location unauthorized response has a 5xx status code
func (o *GetBackupStorageLocationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get backup storage location unauthorized response a status code equal to that given
func (o *GetBackupStorageLocationUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *GetBackupStorageLocationUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocationUnauthorized ", 401)
}

func (o *GetBackupStorageLocationUnauthorized) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocationUnauthorized ", 401)
}

func (o *GetBackupStorageLocationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetBackupStorageLocationForbidden creates a GetBackupStorageLocationForbidden with default headers values
func NewGetBackupStorageLocationForbidden() *GetBackupStorageLocationForbidden {
	return &GetBackupStorageLocationForbidden{}
}

/*
GetBackupStorageLocationForbidden describes a response with status code 403, with default header values.

EmptyResponse is a empty response
*/
type GetBackupStorageLocationForbidden struct {
}

// IsSuccess returns true when this get backup storage location forbidden response has a 2xx status code
func (o *GetBackupStorageLocationForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get backup storage location forbidden response has a 3xx status code
func (o *GetBackupStorageLocationForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get backup storage location forbidden response has a 4xx status code
func (o *GetBackupStorageLocationForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get backup storage location forbidden response has a 5xx status code
func (o *GetBackupStorageLocationForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get backup storage location forbidden response a status code equal to that given
func (o *GetBackupStorageLocationForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *GetBackupStorageLocationForbidden) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocationForbidden ", 403)
}

func (o *GetBackupStorageLocationForbidden) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocationForbidden ", 403)
}

func (o *GetBackupStorageLocationForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetBackupStorageLocationDefault creates a GetBackupStorageLocationDefault with default headers values
func NewGetBackupStorageLocationDefault(code int) *GetBackupStorageLocationDefault {
	return &GetBackupStorageLocationDefault{
		_statusCode: code,
	}
}

/*
GetBackupStorageLocationDefault describes a response with status code -1, with default header values.

errorResponse
*/
type GetBackupStorageLocationDefault struct {
	_statusCode int

	Payload *models.ErrorResponse
}

// Code gets the status code for the get backup storage location default response
func (o *GetBackupStorageLocationDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this get backup storage location default response has a 2xx status code
func (o *GetBackupStorageLocationDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this get backup storage location default response has a 3xx status code
func (o *GetBackupStorageLocationDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this get backup storage location default response has a 4xx status code
func (o *GetBackupStorageLocationDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this get backup storage location default response has a 5xx status code
func (o *GetBackupStorageLocationDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this get backup storage location default response a status code equal to that given
func (o *GetBackupStorageLocationDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *GetBackupStorageLocationDefault) Error() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocation default  %+v", o._statusCode, o.Payload)
}

func (o *GetBackupStorageLocationDefault) String() string {
	return fmt.Sprintf("[GET /api/v2/projects/{project_id}/clusters/{cluster_id}/backupstoragelocation/{bsl_name}][%d] getBackupStorageLocation default  %+v", o._statusCode, o.Payload)
}

func (o *GetBackupStorageLocationDefault) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *GetBackupStorageLocationDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
