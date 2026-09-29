package survey

import (
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// testTemplate builds a manifest based on the example: select with a nested
// toggle, planned option, multiselect with nested refinements, cross-group
// requires, a patterned string, int, and constraint.
func testTemplate() *manifest.Template {
	return &manifest.Template{
		APIVersion: manifest.APIVersion,
		Kind:       manifest.KindTemplate,
		Settings: []manifest.SettingGroup{
			{
				Group:   "database",
				Title:   "Database",
				Type:    manifest.TypeSelect,
				Default: "none",
				Options: []manifest.Option{
					{ID: "none", Title: "No DB"},
					{
						ID:    "postgres",
						Title: "PostgreSQL",
						Settings: []manifest.SettingGroup{
							{
								Group:   "idempotency",
								Title:   "Idempotency",
								Type:    manifest.TypeToggle,
								Default: false,
							},
						},
					},
					{ID: "mysql", Title: "MySQL", Status: manifest.StatusPlanned},
				},
			},
			{
				Group:   "brokers",
				Title:   "Brokers",
				Type:    manifest.TypeMultiselect,
				Default: []any{},
				Options: []manifest.Option{
					{
						ID:    "kafka",
						Title: "Kafka",
						Settings: []manifest.SettingGroup{
							{Group: "kafka_ssl", Title: "SSL", Type: manifest.TypeToggle, Default: false},
							{Group: "kafka_topics", Title: "Topics", Type: manifest.TypeString, Default: ""},
						},
					},
					{ID: "rabbitmq", Title: "RabbitMQ"},
				},
			},
			{
				Group: "auth",
				Title: "Authentication",
				Type:  manifest.TypeMultiselect,
				Options: []manifest.Option{
					{ID: "sso_provider", Title: "SSO provider", Requires: []string{"database=postgres"}},
				},
			},
			{
				Group:   "svc_name",
				Title:   "Service name",
				Type:    manifest.TypeString,
				Default: "",
				Pattern: "^[a-z][a-z0-9-]*$",
			},
			{
				Group:   "replicas",
				Title:   "Replicas",
				Type:    manifest.TypeInt,
				Default: 3,
			},
		},
		Constraints: []manifest.Constraint{
			{If: "idempotency=true", Require: "database=postgres", Message: "Idempotency requires PostgreSQL"},
		},
	}
}
