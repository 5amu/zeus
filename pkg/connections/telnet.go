package connections

type TelnetConnection struct{}

func (s *TelnetConnection) Connect(cs *ConnectionString) error {
	return nil
}

func (s *TelnetConnection) Run(cmd string) (*CMDResult, error) {
	return nil, nil
}

func (s *TelnetConnection) String() string {
	return ""
}

func (s *TelnetConnection) Close() error {
	return nil
}
