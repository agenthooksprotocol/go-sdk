package client

// AdmissionError describes a failure before a boundary was admitted. No backend
// call was made for a rejected boundary. Configuration failures use Kind config.
// Protocol delivery failures after admission live in Result.Errors instead.
type AdmissionError struct {
	Kind string
	Err  error
}

func (e *AdmissionError) Error() string { return "client " + e.Kind + ": " + e.Err.Error() }
func (e *AdmissionError) Unwrap() error { return e.Err }
