package interop

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	Transport     string   `json:"transport"`
	Endpoint      string   `json:"endpoint"`
	ReadinessFile string   `json:"readinessFile"`
	ScenarioFile  string   `json:"scenarioFile"`
	ReportFile    string   `json:"reportFile"`
	ServerCommand []string `json:"serverCommand"`
	ServerCwd     string   `json:"serverCwd"`
	ServerConfig  string   `json:"serverConfig"`
	SchemaDir     string   `json:"schemaDir"`
	Auth          Auth     `json:"auth"`
}
type Scenario struct {
	ID          string          `json:"id"`
	Request     json.RawMessage `json:"request"`
	Response    json.RawMessage `json:"response"`
	Expected    Object          `json:"expected"`
	ExpectError bool            `json:"expectError"`
	Barrier     string          `json:"barrier"`
}

func Load(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func scenarios(path string) ([]Scenario, error) {
	var s struct {
		Scenarios []Scenario `json:"scenarios"`
	}
	e := Load(path, &s)
	return s.Scenarios, e
}
func writeAtomic(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".ahp-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
