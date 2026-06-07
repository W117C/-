package main

import "testing"

func TestRuntimeCiSmoke(t *testing.T) {
	if 2+2 != 4 {
		t.Fatal("runtime smoke arithmetic failed")
	}
}
