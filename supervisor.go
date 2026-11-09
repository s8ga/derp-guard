package main

// derper child process supervisor: startup, supervision, graceful restarts and
// exponential-backoff self-healing.

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type supervisor struct {
	mu        sync.Mutex
	binPath   string
	args      []string
	cmd       *exec.Cmd
	stopping  bool          // deliberate stop in progress (restart/shutdown); exit is not a crash
	done      chan struct{} // shuts the whole supervisor down
	kick      chan struct{} // fired after argument updates to trigger a (re)start
	wg        sync.WaitGroup
	restartMu sync.Mutex // serializes restart/shutdown calls
}

func newSupervisor(binPath string, args []string) *supervisor {
	return &supervisor{
		binPath: binPath,
		args:    args,
		done:    make(chan struct{}),
		kick:    make(chan struct{}, 1),
	}
}

func (s *supervisor) start() {
	s.wg.Add(1)
	go s.loop()
}

// loop keeps a derper child process running: unexpected exits are retried with
// exponential backoff (1s, 2s, 4s, 8s, 16s, capped at 30s); the counter resets
// once the child has stayed up for more than 60 seconds.
func (s *supervisor) loop() {
	defer s.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-s.done:
			return
		default:
		}
		s.mu.Lock()
		args := s.args
		s.mu.Unlock()

		cmd := exec.Command(s.binPath, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		started := time.Now()
		if err := cmd.Start(); err != nil {
			log.Printf("[DERPER] WARN failed to start: %v (retrying in %.0fs)", err, backoff.Seconds())
			if !s.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		s.mu.Lock()
		s.cmd = cmd
		s.mu.Unlock()
		log.Printf("[DERPER] child process started pid=%d", cmd.Process.Pid)
		log.Printf("[DERPER] command line: %s %s", s.binPath, strings.Join(args, " "))

		err := cmd.Wait()
		s.mu.Lock()
		s.cmd = nil
		deliberate := s.stopping
		s.mu.Unlock()
		if deliberate {
			// Deliberate stop (restart or shutdown): wait for the next instruction.
			select {
			case <-s.kick:
				log.Printf("[DERPER] restarting child process with new arguments")
				backoff = time.Second
				continue
			case <-s.done:
				log.Printf("[DERPER] child process stopped along with supervisor")
				return
			}
		}
		if time.Since(started) > 60*time.Second {
			backoff = time.Second // the child ran stably; reset backoff
		}
		log.Printf("[DERPER] WARN derper exited unexpectedly: %v (restarting in %.0fs)", err, backoff.Seconds())
		if !s.sleep(backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

func (s *supervisor) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-s.kick: // a restart was requested during backoff: wake up immediately
	case <-s.done:
		return false
	}
	return true
}

func nextBackoff(d time.Duration) time.Duration {
	if d >= 16*time.Second {
		return 30 * time.Second
	}
	return d * 2
}

// currentPID returns the current child PID (0 if not running).
func (s *supervisor) currentPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Pid
	}
	return 0
}

func (s *supervisor) terminateCurrent() {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		alive := s.cmd == cmd
		s.mu.Unlock()
		if !alive {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.mu.Lock()
	alive := s.cmd == cmd
	s.mu.Unlock()
	if alive {
		log.Printf("[DERPER] child did not exit within 5s, sending SIGKILL")
		_ = cmd.Process.Kill()
	}
}

// restart gracefully restarts: SIGTERM -> wait up to 5s -> SIGKILL, then spawn
// again with the (possibly updated) arguments.
func (s *supervisor) restart(newArgs []string) {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()

	s.mu.Lock()
	s.args = newArgs
	running := s.cmd != nil
	s.stopping = true
	s.mu.Unlock()

	if running {
		s.terminateCurrent()
	}

	s.mu.Lock()
	s.stopping = false
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// shutdown gracefully stops: terminate the child and end the loop.
func (s *supervisor) shutdown() {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()

	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.terminateCurrent()
	close(s.done)
	s.wg.Wait()
}
