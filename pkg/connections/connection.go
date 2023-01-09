// Package connections implements the underlying protocol(s) that allow the
// engine to run commands on remote machines.
//
// The connection package is designed to be used in the context of the zeus
// project. https://github.com/5amu/zeus
package connections

import (
	"fmt"
	"regexp"
)

// ConnectionString is a struct representing the data contained into the user
// provided connection string. A ConnectionString example could be:
// ssh://username:password@127.0.0.1:22
//
// Important notes about this object are:
//
//   - Scheme must be either "ssh://", "winrm://" or "telnet://"
//   - SSH login with private key is not supported
//   - All fields have to be set
type ConnectionString struct {
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Full     string `json:"connection_string"`
}

// String prints the full connection string except the password. It is mainly
// made for logging purposes, so that a Printf function would print the message
func (cs *ConnectionString) String() string {
	return fmt.Sprintf(
		"%v://%v:xxxx@%v:%v",
		cs.Scheme,
		cs.Username,
		cs.Host,
		cs.Port,
	)
}

func genericErrorPrint(upstream error, message string) string {
	if upstream != nil {
		return fmt.Sprintf("%v, %v", upstream, message)
	}
	return message
}

// ConnectionStringError is returned when the function parsing a connection
// string fails to identify all required fields
type ConnectionStringError struct {
	// Message is a custom string that will be printed by
	// the error formatter, but is defined in the scope
	// of this package
	Message string
	// UpstreamError stores the error that led the parsing
	// function to failure. It will be printed as well (if
	// not nil)
	UpstreamError error
}

// Error is the message that ConnectionStringError would print if returned
func (err *ConnectionStringError) Error() string {
	return genericErrorPrint(err.UpstreamError, err.Message)
}

const (
	schemeRegex   = `^([a-z]+)://`
	usernameRegex = `([^:]+)`
	passwordregex = `:(.*)@`
	fqdnRegex     = `(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.?){4}|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*\.)+[a-zA-Z]{2,})`
	portRegex     = `:([0-9]{1,5})`
	trailingRegex = `/?$`
)

// NewConnectionString creates a ConnectionString object from a raw string.
// please, refer to ConnectionString object to know how to build a valid
// connection string. ConnectionStringError is returned if the provided
// string is not valid.
func NewConnectionString(s string) (*ConnectionString, error) {
	// Look in utils.go to look ath the full regex.
	// It was not reported here for brevity
	res, err := regexp.Compile(
		fmt.Sprintf("%v%v%v%v%v%v",
			schemeRegex,
			usernameRegex,
			passwordregex,
			fqdnRegex,
			portRegex,
			trailingRegex,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("broken regex in NewConnectionString")
	}

	match := res.FindAllStringSubmatch(s, -1)
	if match == nil || len(match) < 1 || len(match[0]) < 11 {
		return nil, &ConnectionStringError{
			Message: fmt.Sprintf("could not parse connection string: %v", s),
		}
	}

	// Credit where credit is due: https://stackoverflow.com/a/20930689
	var (
		scheme   string = match[0][1]
		username string = match[0][2]
		password string = match[0][3]
		hostname string = match[0][4]
		port     string = match[0][10]
	)

	// Check if it is one of the allowed schemes
	var found bool = false
	for i := 0; !found && i < len(allowedSchemes); i++ {
		if scheme == allowedSchemes[i] {
			found = true
		}
	}

	if !found {
		return nil, &ConnectionStringError{
			Message: fmt.Sprintf("scheme is not supperted in: %v", s),
		}
	}

	if username == "" {
		return nil, &ConnectionStringError{
			Message: fmt.Sprintf("no username defined in: %v", s),
		}
	}

	if password == "" {
		return nil, &ConnectionStringError{
			Message: fmt.Sprintf("no password defined in: %v", s),
		}
	}

	if hostname == "" {
		return nil, &ConnectionStringError{
			Message: fmt.Sprintf("no host defined in: %v", s),
		}
	}

	return &ConnectionString{
		Scheme:   scheme,
		Username: username,
		Password: password,
		Host:     hostname,
		Port:     port,
		Full:     s,
	}, nil
}

// CMDResult is a data structure containing information about a command
// execution. It keeps track of the command being launched in Stdin, the
// standard output in Stdout and standard error in Stderr. It can be
// marshalled into a json.
type CMDResult struct {
	Stdin  string `json:"stdin"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Connection is the main interface of this package. It is an abstraction
// for either an SSH, a Telnet or a Winrm connection.
type Connection interface {
	// Connect will establish the connection and authenticate to the
	// chosen server
	Connect(cs *ConnectionString) error
	// Run will execute the provided command and return a CMDResult
	Run(cmd string) (*CMDResult, error)
	// Close will close the connection
	Close() error
	// String will print an identifier for the logger
	String() string
}

var allowedSchemes = []string{"ssh", "telnet", "winrm"}

const (
	SSH = iota
	Telnet
	Winrm
)

// NewConnection is a factory to istance the needed Connection type.
//
// The model was taken from this beautiful resource:
// https://refactoring.guru/design-patterns/factory-method
func NewConnection(c *ConnectionString) (*Connection, error) {
	var conn Connection
	switch c.Scheme {
	case allowedSchemes[SSH]:
		conn = &SSHConnection{}
	case allowedSchemes[Telnet]:
		return nil, fmt.Errorf("telnet not yet implemented")
		//conn = &TelnetConnection{}
	case allowedSchemes[Winrm]:
		return nil, fmt.Errorf("winrm not yet implemented")
		//conn = &WinrmConnection{}
	}
	return &conn, conn.Connect(c)
}

// AuthenticationError is return when authentication fails in any Connect()
// function for any Connection data structure
type AuthenticationError struct {
	Message       string
	UpstreamError error
}

// Error is the message that AuthenticationError would print if returned
func (err *AuthenticationError) Error() string {
	return genericErrorPrint(err.UpstreamError, err.Message)
}

// CommunicationError is made for a connection that has problems establishing a
// connection with the server. Timeout, Network Unreachable, etc
type CommunicationError struct {
	Message       string
	UpstreamError error
}

// Error is the message that CommunicationError would print if returned
func (err *CommunicationError) Error() string {
	return genericErrorPrint(err.UpstreamError, err.Message)
}
