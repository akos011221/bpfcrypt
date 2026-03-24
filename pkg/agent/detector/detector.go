package detector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" -type crypto_event Crypto ../../../bpf/crypto_kprobe.c -- -I../../../bpf

type Detector struct {
	objs  CryptoObjects
	links []link.Link
	rd    *ringbuf.Reader
}

func New(targetPID uint32) (*Detector, error) {
	d := &Detector{}

	if err := LoadCryptoObjects(&d.objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Taget PID filter
	key := uint32(0)
	if err := d.objs.TargetPid.Update(key, targetPID, ebpf.UpdateAny); err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("setting target PID: %w", err)
	}

	kprobes := []struct {
		fn   string
		prog *ebpf.Program
	}{
		{"crypto_alloc_aead", d.objs.KprobeCryptoAllocAead},
		{"crypto_alloc_skash", d.objs.KprobeCryptoAllocShash},
		{"crypto_alloc_skcipher", d.objs.KprobeCryptoAllocSkcipher},
	}

	for _, kp := range kprobes {
		l, err := link.Kprobe(kp.fn, kp.prog, nil)
		if err != nil {
			log.Printf("WARNING: failed to attach kprobe/s: %v", kp.fn, err)
			continue
		}
		d.links = append(d.links, l)
	}

	if len(d.links) == 0 {
		d.objs.Close()
		return nil, fmt.Errorf("no kprobes attached")
	}

	rd, err := ringbuf.NewReader(d.objs.Events)
	if err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	d.rd = rd

	return d, nil
}

func (d *Detector) Read() (*CryptoCryptoEvent, error) {
	record, err := d.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("reading ring buffer: %w", err)
	}

	var event CryptoCryptoEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("decoding event: %w", err)
	}

	return &event, nil
}

func (d *Detector) Close() {
	if d.rd != nil {
		d.rd.Close()
	}
	for _, l := range d.links {
		l.Close()
	}
	d.objs.Close()
}
