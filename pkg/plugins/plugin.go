// Package plugins implements the logic to parse and utilize instructions
// specified in the `.yaml` file provided by the workflow, or manually
//
// The plugins package is designed to be used in the context of the zeus
// project. https://github.com/5amu/zeus
package plugins

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/5amu/zeus/pkg/connections"
	"gopkg.in/yaml.v3"
)

func init() {
	sort.Strings(AllowedMatchConditions)
	sort.Strings(AllowedParts)
	sort.Strings(AllowedRuleTypes)
	sort.Strings(AllowedParserConditions)
}

// Plugin is the class handling plugins content. High level object
// that represents a plugin, with its data and functionalities
type Plugin struct {
	// ID should be unique across every plugin ever created
	ID string `yaml:"id" json:"id"`
	// Author is the maintainer or creator
	Author string `yaml:"author" json:"author"`
	// Name is a custom name (short and descriptive) for the plugin. This name
	// would eventually become part of your report... Choose wisely :)
	Name string `yaml:"name" json:"name"`
	// Description is a long description of the vulnerability, 2 or 3 lines
	// explaining the context and the impact that it would have.
	Description string `yaml:"description" json:"description"`
	// Remediation, being for a generalized vulnerability, might not be very
	// telling, but a simple explanation is sufficient in most cases. The
	// explanation burden should be left on the professional performing the
	// assessment. A modified form of a CWE page could be a good idea at times.
	Remediation string `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	// CVE contains a list (in the format of a string) of CVEs for a given
	// vulnerability that has been found on the machine under assessment.
	CVE string `yaml:"cve,omitempty" json:"cve,omitempty"`
	// Reference is a field that should always be filled with a link, possibly
	// pointing to a resource endorsed by the vendor. It helps the owner of the
	// vulnerable machine understand the problem and seek help in the right
	// direction.
	Reference string `yaml:"reference,omitempty" json:"reference,omitempty"`
	// CVSS, even if not specified, should be the base score for the vector
	// that has been provided. Most of the times it is not possible to know the
	// full context beforehand, that's why no other type of score is supported.
	CVSS float32 `yaml:"cvss,omitempty" json:"cvss,omitempty"`
	// CVSSVector is the CVSS vector that has been calculated for the
	// vulnerability.
	CVSSVector string `yaml:"cvss_vector,omitempty" json:"cvss_vector,omitempty"`
	// Severity is the severity that has been calculated for the
	// vulnerability.
	Severity string `yaml:"severity,omitempty" json:"severity,omitempty"`
	// MatchCondition specifies the strategy to match if a plugin found the
	// vulnerability or not. Since there could be more than one command to run,
	// if tou wish to match the vulnerability even when just one of those
	// succeedes, you'll need to specify "matching: or", otherwise the default
	// value is "and". The default value implies that every test has to
	// succeed in order to mark the target as vulnerable.
	MatchCondition string `yaml:"match_condition,omitempty" json:"match_condition,omitempty"`
	// Tests is the list of tests (commands) that will run on the target
	Tests []PluginTest `yaml:"tests" json:"tests"`
}

// PluginTest is a struct responsible for the content of a plugin's test.
// high level object that represents a single test run by the staresc
// engine using the plugin
type PluginTest struct {
	Command string       `yaml:"command" json:"command"`
	Comment string       `yaml:"comment,omitempty" json:"comment,omitempty"`
	Parsers []TestParser `yaml:"parsers" json:"parsers"`
}

// TestParser is a struct responsible for the parser section of a test command.
type TestParser struct {
	// Rules is a list containing the rules (words or regexes) that have to be
	// run on the selected part
	Rules []string `yaml:"rules" json:"rules"`
	// RuleType can be either "word" or "regex"
	RuleType string `yaml:"rule_type" json:"rule_type"`
	// Parts can contain "stdout", "stderr" or both
	Parts []string `yaml:"parts,omitempty" json:"parts,omitempty"`
	// Condition can be "and" or "or"
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"`
	// InvertMatch means that the test will succed when the rules won't match
	InvertMatch bool `yaml:"invert_match,omitempty" json:"invert_match,omitempty"`
}

var (
	AllowedMatchConditions  = []string{"and", "or"}
	AllowedParts            = []string{"stdout", "stderr"}
	AllowedRuleTypes        = []string{"regex", "word"}
	AllowedParserConditions = []string{"and", "or"}
)

// Validate the content of a plugin object. Returns nil if no error is found.
func Validate(p *Plugin) error {
	if p.MatchCondition == "" {
		// If no match condition is specified, put the default "and" condition
		p.MatchCondition = AllowedMatchConditions[0]
	} else {
		// Otherwise, check if the match condition is allowed
		index := sort.SearchStrings(AllowedMatchConditions, p.MatchCondition)
		if index == len(AllowedMatchConditions) || AllowedMatchConditions[index] != p.MatchCondition {
			return fmt.Errorf("invalid match condition: %v", p.MatchCondition)
		}
	}

	// Check all tests of a plugin
	for _, test := range p.Tests {
		// Check all parsers for a test
		for _, parser := range test.Parsers {
			// Check the part key
			if parser.Parts == nil {
				// If no part is specified, select all
				parser.Parts = make([]string, len(AllowedParts))
				copy(parser.Parts, AllowedParts)
			} else {
				// Otherwise, check if the parts are allowed
				for _, part := range parser.Parts {
					index := sort.SearchStrings(AllowedParts, part)
					if index == len(AllowedParts) || AllowedParts[index] != part {
						return fmt.Errorf("id: %v, %v is not an allowed part", p.ID, part)
					}
				}
			}

			// Check the rule key
			index := sort.SearchStrings(AllowedRuleTypes, parser.RuleType)
			if index == len(AllowedRuleTypes) || AllowedRuleTypes[index] != parser.RuleType {
				return fmt.Errorf("id: %v, %v is not a valid rule type", p.ID, parser.RuleType)
			}

			// Check the condition key
			if parser.Condition == "" {
				// If no condition is specified, choose the first
				parser.Condition = AllowedParserConditions[0]
			} else {
				// Otherwise, check if the condition is allowed
				index := sort.SearchStrings(AllowedParserConditions, parser.Condition)
				if index == len(AllowedParserConditions) || AllowedParserConditions[index] != parser.Condition {
					return fmt.Errorf("id: %v, %v is not a valid condition", p.ID, parser.Condition)
				}
			}
		}
	}
	return nil
}

// NewPlugin gets a byte slice and returns a Plugin object, it will return an
// error if the plugin is not valid.
func NewPlugin(in []byte) (out *Plugin, err error) {
	// Unmarshal the bytes into the struct
	if err = yaml.Unmarshal(in, &out); err != nil {
		return nil, err
	}
	return out, Validate(out)
}

// NewPluginFromFile creates a new Plugin object, but will read the file and
// provide it to NewPlugin
func NewPluginFromFile(fname string) (*Plugin, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	return NewPlugin(data)
}

// PluginResult is a struct containing the tests outputs and the boolean
// with the net result of the checks: (host) vulnerable or not
type PluginResult struct {
	IsVulnerable bool                     `json:"is_vulnerable"`
	PluginID     string                   `json:"plugin_id"`
	Outputs      []*connections.CMDResult `json:"outputs"`
}

func checkResult(res *connections.CMDResult, parsers []TestParser) (bool, error) {
	// boolRes is the result of the parsers. If the length of the parsers
	// slice is 0, then the result is automatically false, otherwise is
	// initialized as true.
	var boolRes bool = len(parsers) != 0

	for _, parser := range parsers {
		// This will make the rule parsing stop after the firts that come out
		// matching. Depending if the match condition is set to "and" or "or"
		var stopAfterFirstRule bool = parser.Condition == "or"

		// Is the match inverted? Is the rule true if no match is found?
		var invert bool = parser.InvertMatch

		// Combine text depending on selected parts
		var builder strings.Builder
		for _, part := range parser.Parts {
			switch part {
			case "stdout":
				builder.WriteString(res.Stdout)
			case "stderr":
				builder.WriteString(res.Stderr)
			}
		}
		text := builder.String()

		for _, rule := range parser.Rules {
			var boolThis bool
			switch parser.RuleType {
			case "regex":
				r, err := regexp.Compile(rule)
				if err != nil {
					return false, err
				}
				// like xor operator, we need the same behavior as C-like:
				// result = inverted? !result : result
				// https://stackoverflow.com/a/23025720
				boolThis = r.MatchString(text) != invert
			case "word":
				// like xor operator, we need the same behavior as C-like:
				// result = inverted? !result : result
				// https://stackoverflow.com/a/23025720
				boolThis = strings.Contains(text, rule) != invert
			}

			boolRes = boolRes && boolThis
			if boolThis && stopAfterFirstRule {
				return true, nil
			}
		}
	}
	return boolRes, nil
}

// RunTests will use the provided connection object to run every test and,
// for each test, run the associated command, get the output and parse it into
// every parser.
func (p *Plugin) RunTests(con *connections.Connection) (*PluginResult, error) {
	// stopAfterFirst will make the tests stop after the first positive match
	var stopAfterFirstTest bool = p.MatchCondition == "or"

	// outputs is a slice containing the outputs for every command in a plugin
	var outputs []*connections.CMDResult

	// boolRes is the result of the tests. If the length of the test slice is
	// 0, then the result is automatically false. Otherwise it is
	// initialized as true. In every iteration should be combined with the
	// boolean result of the test.
	var boolRes bool = len(p.Tests) != 0

	for _, test := range p.Tests {
		// run the command and append it to the output slice
		res, err := (*con).Run(test.Command)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, res)

		// register the current boolean result
		boolThis, err := checkResult(res, test.Parsers)
		if err != nil {
			return nil, err
		}

		// if the plugin returned a positive, and the match condition is set to
		// "or", then stop the execution and return a PluginResult right now
		if boolThis && stopAfterFirstTest {
			return &PluginResult{
				Outputs:      []*connections.CMDResult{res},
				PluginID:     p.ID,
				IsVulnerable: boolThis,
			}, nil
		}
		// make the final boolean result for this cycle
		boolRes = boolRes && boolThis
	}
	return &PluginResult{
		Outputs:      outputs,
		PluginID:     p.ID,
		IsVulnerable: boolRes,
	}, nil
}
