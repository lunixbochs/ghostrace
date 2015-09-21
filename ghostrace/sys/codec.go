package sys

import (
	"encoding/binary"
	"errors"
	"fmt"

	"../memio"
	"./call"
	"./num"
)

type Codec struct {
	Arch ArchType
	OS   OSType
	Mem  memio.MemIO
}

func NewCodec(arch ArchType, os OSType, mem memio.MemIO) (*Codec, error) {
	if arch != ARCH_X86_64 && os != OS_LINUX {
		return nil, errors.New("unsupported arch/os")
	}
	return &Codec{arch, os, mem}, nil
}

func (c *Codec) DecodeCall(n int, args []uint64) (Syscall, error) {
	return c.decode(n, args, 0, false)
}

func (c *Codec) DecodeRet(n int, args []uint64, ret uint64) (Syscall, error) {
	return c.decode(n, args, ret, true)
}

func (c *Codec) decode(n int, args []uint64, ret uint64, done bool) (Syscall, error) {
	name, ok := num.Linux_x86_64[n]
	if !ok {
		return nil, fmt.Errorf("unknown syscall: %d\n", n)
	}
	if !done {
		return nil, errors.New("decoding unfinished syscalls is unimplemented")
	}
	var out Syscall
	var err error
	switch name {
	case "open":
		path, err := c.Mem.ReadStrAt(args[0])
		if err != nil {
			return nil, err
		}
		out = &call.Open{path, int(args[1]), int(args[2]), int(ret)}
	case "close":
		out = &call.Close{int(args[0])}
	case "read":
		length := int(int64(ret))
		var data []byte
		if length > 0 {
			data = make([]byte, ret)
			_, err = c.Mem.ReadAt(data, args[1])
		}
		out = &call.Read{int(args[0]), data, args[1], args[2], length}
	case "readv":
		length := int(int64(ret))
		var data []byte
		if length > 0 {
			data = make([]byte, length)
			mem := c.Mem.StreamAt(args[1])
			// TODO: platform specific
			var pos uint64
			for _, vec := range iovecRead(mem, args[2], 64, binary.LittleEndian) {
				end := vec.Len
				if int(pos+end) > length {
					end = uint64(length)
				}
				c.Mem.ReadAt(data[pos:end], vec.Base)
				if end == uint64(length) {
					break
				}
			}
		}
		out = &call.Read{int(args[0]), data, args[1], args[2], length}
	case "write":
		data := make([]byte, args[2])
		_, err = c.Mem.ReadAt(data, args[1])
		out = &call.Write{int(args[0]), data, args[1], args[2], int(int64(ret))}
	case "writev":
		mem := c.Mem.StreamAt(args[1])
		vecs := iovecRead(mem, args[2], 64, binary.LittleEndian)
		var size uint64
		for _, v := range vecs {
			size += v.Len
		}
		data := make([]byte, 0, size)
		for _, vec := range vecs {
			pos := uint64(len(data))
			data = data[:pos+vec.Len]
			c.Mem.ReadAt(data[pos:pos+vec.Len], vec.Base)
		}
		out = &call.Write{int(args[0]), data, args[1], args[2], int(int64(ret))}
	}
	if out == nil {
		out = &call.Generic{n, name, args, ret}
	}
	return out, err
}
