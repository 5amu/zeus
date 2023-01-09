package connections

type WinRMConnection struct{}

func (s *WinRMConnection) Connect(cs *ConnectionString) error {
	return nil
}

func (s *WinRMConnection) Run(cmd string) (*CMDResult, error) {
	return nil, nil
}

func (s *WinRMConnection) String() string {
	return ""
}

func (s *WinRMConnection) Close() error {
	return nil
}
