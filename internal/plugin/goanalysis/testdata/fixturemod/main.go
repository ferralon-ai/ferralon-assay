// Command fixturemod is a stdlib-only fixture program with a known call chain
// main -> service.Handle -> util.Sink, used by the goanalysis hermetic tests.
package main

import (
	"fmt"

	"tegron.test/fixturemod/httpapi"
	"tegron.test/fixturemod/service"
)

func main() {
	svc := service.New("demo")
	fmt.Println(svc.Handle("payload"))
	httpapi.Register()
}
