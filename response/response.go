package response

const (
	StatusOK    = "OK"
	StatusError = "Error"
)

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func OK() Response {
	return Response{Status: StatusOK}
}

func Error(msg string) Response {
	return Response{
		Status:  StatusError,
		Message: msg,
	}
}
