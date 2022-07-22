package leaf

import (
	"fmt"
	"os"
	"time"
)

type samples struct {
	num uint64 // number of samples
	sum uint64 // total query time (ms)
	min uint64 // minimum query time (ms)
	max uint64 // maximum query time (ms)
}

func newSamples() samples {
	return samples{min: 18446744073709551615}
}

func (s *samples) update(sample uint64) {
	s.num += 1
	s.sum += sample
	if sample < s.min {
		s.min = sample
	}
	if sample > s.max {
		s.max = sample
	}
}

func (s *samples) avg() uint64 {
	if s.num == 0 {
		return 0
	}
	return s.sum / s.num
}

type status struct {
	start time.Time // time that measurement started

	num3xx uint64 // number of 3xx responses since last status
	num4xx uint64 // number of 4xx responses since last status
	num5xx uint64 // number of 5xx responses since last status

	status200 samples // info about 200 responses since last status
	status202 samples // info about 202 responses since last status
}

func newStatus() status {
	return status{
		start:     time.Now(),
		status200: newSamples(),
		status202: newSamples(),
	}
}

func (s *status) reset() {
	s.num3xx = 0
	s.num4xx = 0
	s.num5xx = 0

	s.status200 = newSamples()
	s.status202 = newSamples()
}

func (s *status) register(ev *event) {
	s.num3xx += ev.num3xx
	s.num4xx += ev.num4xx
	s.num5xx += ev.num5xx

	delay := uint64(ev.end.Sub(ev.start).Milliseconds())
	if ev.got200 {
		s.status200.update(delay)
	} else {
		s.status202.update(delay)
	}

	ev.resetCounters()
}

func (s *status) rotate(f *os.File) error {
	str := fmt.Sprintf("%s ", time.Now().Format(time.RFC3339))
	str += fmt.Sprintf("%d ", uint64(time.Now().Sub(s.start).Milliseconds()/1000))
	str += fmt.Sprintf("%d ", s.status200.num)
	str += fmt.Sprintf("%d ", s.status202.num)
	str += fmt.Sprintf("%d ", s.num3xx)
	str += fmt.Sprintf("%d ", s.num4xx)
	str += fmt.Sprintf("%d ", s.num5xx)
	str += fmt.Sprintf("%d ", s.status200.min)
	str += fmt.Sprintf("%d ", s.status200.avg())
	str += fmt.Sprintf("%d ", s.status200.max)
	str += fmt.Sprintf("%d ", s.status202.min)
	str += fmt.Sprintf("%d ", s.status202.avg())
	str += fmt.Sprintf("%d\n", s.status202.max)
	s.reset()

	_, err := f.WriteString(str)
	return err
}

func (s *status) format() string {
	return "Time RelTime Num200 Num202 Num3xx Num4xx Num5xx Min200 Avg200 Max200 Min202 Avg202 Max202\n" +
		"      (s)                                       ----> observed response delays (ms) <----"
}
