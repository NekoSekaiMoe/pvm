package jail

// SockFilter describes a single classic BPF instruction. It mirrors
// unix.SockFilter so that BuildUMLSeccompFilter can be compiled and unit
// tested on non-Linux platforms where unix.SockFilter is unavailable.
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}
