package connections

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConnection implements Connection, and uses the SSH protocol, the "exec"
// directive of the protocol to be precise. So many tty programs won't work
//
// TODO: assess the need for a pseudo-shell to support tty programs. As for
// TODO: now, I don't think it will be necessary except for rare occasions...
type SSHConnection struct {
	Type             string            `json:"target_type"`
	Host             string            `json:"target"`
	ConnectionString *ConnectionString `json:"connection_string"`
	SSHClient        *ssh.Client
}

func (s *SSHConnection) Connect(cs *ConnectionString) error {
	s.Type, s.Host, s.ConnectionString = "ssh", cs.Host, cs

	// Initiate SSH configuration
	config := &ssh.ClientConfig{
		User:            cs.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cs.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}

	// Create an SSH connection (client)
	hostname := fmt.Sprintf("%v:%v", s.Host, s.ConnectionString.Port)
	client, err := ssh.Dial("tcp", hostname, config)
	if err != nil {
		return &AuthenticationError{
			Message:       "authentication failed",
			UpstreamError: err,
		}
	}
	s.SSHClient = client
	return nil
}

func (s *SSHConnection) Run(cmd string) (*CMDResult, error) {
	// Initialize CMDResult for output
	result := &CMDResult{
		Stdin: cmd,
	}

	// Enstablish an SSH session in which we can run commands without
	// closing it. It should be able to keep SSH session number to 1
	// without having to inject canary tokens to know when a command
	// is ended. I guess that paramiko has its flaws :)
	session, err := s.SSHClient.NewSession()
	if err != nil {
		return result, &CommunicationError{
			Message:       "could not establish a session",
			UpstreamError: err,
		}
	}
	defer session.Close()

	// Set Stdout and Stder buffers to be converted as strings
	// later. Errors could not be due to a failed command
	// execution, but to error code returned by one.
	var stdoutBuff, stderrBuff bytes.Buffer
	session.Stdout = &stdoutBuff
	session.Stderr = &stderrBuff
	if err := session.Run(cmd); err != nil {
		switch err.(type) {
		// ExitMissingError is returned when a command does not
		// return an exit code. This means that it could have timed
		// out, or whatever shenanigan the network can do.
		case *ssh.ExitMissingError:
			return result, &CommunicationError{
				Message:       "command did not execute correctly",
				UpstreamError: err,
			}

		// ExitError will be returned if a command returned a non 0
		// code after being executed, for our means, we don't care
		// and we want to treat it as a correct behavior.
		case *ssh.ExitError:
			break

		// Any other error would be an I/O error, so we want to return
		// the error to the caller.
		default:
			return result, err
		}
	}

	// Get the content of stdout and stderr to put into result object
	// and return it to the caller
	result.Stdout = stdoutBuff.String()
	result.Stderr = stderrBuff.String()
	return result, nil
}

func (s *SSHConnection) Close() error {
	return s.SSHClient.Close()
}

func (s *SSHConnection) String() string {
	return s.ConnectionString.String()
}
