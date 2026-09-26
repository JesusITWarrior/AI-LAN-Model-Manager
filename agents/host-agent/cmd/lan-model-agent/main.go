// LAN Model Manager host agent.
//
// This initial binary intentionally exposes no network listener or command
// execution surface. Pairing and mutually authenticated transport must land
// before host capabilities are reachable over the LAN.
package main

import "fmt"

var version = "dev"

func main() {
	fmt.Printf("lan-model-agent %s (network capabilities not yet enabled)\n", version)
}
