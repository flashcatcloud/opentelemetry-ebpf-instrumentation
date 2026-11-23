// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
)

func TestLegacySQLQueryTextConfigRoundTrip(t *testing.T) {
	doc, _, err := schema.ParseStandaloneYAML([]byte(`file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      instrumentation:
        sql:
          sanitize_query_text: true
`))
	require.NoError(t, err)
	cfg, err := DocumentToRuntime(doc)
	require.NoError(t, err)
	require.True(t, cfg.Attributes.SanitizeSQLQueryText)
	require.False(t, cfg.Attributes.SanitizeDBQueryText)

	_, ext := RuntimeToV2(cfg)
	require.True(t, ext.Capture.Instrumentation.SQL.SanitizeQueryText)
	require.False(t, ext.Capture.Instrumentation.DB.SanitizeQueryText)
	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.True(t, got.Attributes.SanitizeSQLQueryText)
	require.False(t, got.Attributes.SanitizeDBQueryText)
}
