// ws2812test is a bench tool: blink the digital LEDs through whatever driver
// OpenNeoPixel picks for this SoC, printing each step. It ships in no package
// and exists for exactly the "is it the driver or the wiring" question.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"agent/pkg/infrastructure/hardware"
)

func main() {
	gpio := flag.Int("gpio", 18, "data GPIO")
	count := flag.Int("count", 8, "LED count")
	cycles := flag.Int("cycles", 10, "on/off cycles")
	half := flag.Duration("half", 500*time.Millisecond, "half period")
	flag.Parse()

	neo, err := hardware.OpenNeoPixel(*gpio)
	if err != nil {
		fmt.Println("open failed:", err)
		os.Exit(1)
	}
	fmt.Printf("driver open ok (gpio %d)\n", *gpio)
	for i := 0; i < *cycles; i++ {
		if err := neo.WriteFrame(*count, 0, 0, 255); err != nil {
			fmt.Println("write on failed:", err)
			os.Exit(1)
		}
		time.Sleep(*half)
		if err := neo.WriteFrame(*count, 0, 0, 0); err != nil {
			fmt.Println("write off failed:", err)
			os.Exit(1)
		}
		time.Sleep(*half)
	}
	if err := neo.Close(); err != nil {
		fmt.Println("close failed:", err)
		os.Exit(1)
	}
	fmt.Println("done: blinked blue", *cycles, "times")
}
