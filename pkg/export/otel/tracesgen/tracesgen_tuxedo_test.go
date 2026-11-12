// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestTraceAttributesSelectorTuxedoClient(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeTuxedoClient,
		Method: "ACCOUNT_QUERY",
	}

	attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})
	rpcSystem, ok := attrValue(attrs, string(semconv.RPCSystemNameKey))
	require.True(t, ok)
	assert.Equal(t, request.RPCSystemTuxedo, rpcSystem.AsString())
	rpcMethod, ok := attrValue(attrs, string(semconv.RPCMethodKey))
	require.True(t, ok)
	assert.Equal(t, "ACCOUNT_QUERY", rpcMethod.AsString())
	assert.Equal(t, "ACCOUNT_QUERY", span.TraceName())
}

func TestTraceAttributesSelectorTuxedoServer(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeTuxedoServer,
		Method: "fuzhai_01",
	}

	attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})
	rpcMethod, ok := attrValue(attrs, string(semconv.RPCMethodKey))
	require.True(t, ok)
	assert.Equal(t, "fuzhai_01", rpcMethod.AsString())
	assert.Equal(t, oteltrace.SpanKindServer, spanKind(span))
}

func TestTraceAttributesSelectorTuxedoFailure(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeTuxedoClient,
		Method: "ACCOUNT_QUERY",
		Status: 1,
	}

	attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{attr.ErrorType: {}})
	errorType, ok := errorTypeValue(attrs)
	require.True(t, ok)
	assert.Equal(t, request.ErrorTypeOther, errorType.AsString())
}
