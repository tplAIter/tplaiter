package contextsource

import (
	"context"
	"testing"
)

func TestNativeModifierZeroAndClosedCarrierRefuse(t *testing.T) {
	if _, e := PrepareNativeModifier(context.Background(), nil, "root", nil, nil); e == nil {
		t.Fatal("nil runtime admitted")
	}
	var p *PreparedNativeModifier
	if e := p.RecheckFor(context.Background(), nil); e == nil {
		t.Fatal("nil carrier admitted")
	}
	p = &PreparedNativeModifier{}
	if e := p.RecheckFor(context.Background(), nil); e == nil {
		t.Fatal("caller zero carrier admitted")
	}
	p.Close()
	if e := p.RecheckFor(context.Background(), nil); e == nil {
		t.Fatal("closed carrier admitted")
	}
}
