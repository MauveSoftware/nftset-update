package nftset

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// All messages of a transaction are sent with one sendmsg call, which
	// must fit into the socket send buffer (default ~208 KiB). The nft CLI
	// enlarges the buffer the same way.
	sendBufferSize = 32 << 20

	// The kernel sizes netlink dump chunks by the largest buffer the socket
	// has ever received into (capped at 32 KiB).
	dumpChunkSize = 32 << 10
)

func enlargeSendBuffer(c *netlink.Conn) error {
	raw, err := c.SyscallConn()
	if err == nil {
		var sockErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			// SO_SNDBUFFORCE ignores net.core.wmem_max but needs CAP_NET_ADMIN.
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sendBufferSize)
		})
		if ctrlErr == nil && sockErr == nil {
			return nil
		}
	}
	// Best effort fallback, capped by net.core.wmem_max. Large transactions
	// may then fail with EMSGSIZE, which is reported as a transaction error.
	_ = c.SetWriteBuffer(sendBufferSize)
	return nil
}

// enlargeDumpChunks makes the kernel use 32 KiB chunks when dumping set
// elements. Dumping an rbtree interval set restarts the tree walk for every
// chunk and skips the elements already sent, so the cost grows with
// elements²/chunk size. The netlink library receives into page-sized
// buffers, which yields ~4 KiB chunks; with 200k intervals this makes the
// dump take seconds of kernel time. The kernel remembers the largest receive
// buffer per socket, so a single receive of a NOOP acknowledgement into a
// 32 KiB buffer is enough.
func enlargeDumpChunks(c *netlink.Conn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("enlarge dump chunks: %w", err)
	}

	req := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(req[0:4], unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint16(req[4:6], unix.NLMSG_NOOP)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)

	var sendErr error
	if err := raw.Write(func(fd uintptr) bool {
		sendErr = unix.Sendto(int(fd), req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		return !errors.Is(sendErr, unix.EAGAIN)
	}); err != nil {
		return fmt.Errorf("enlarge dump chunks: %w", err)
	}
	if sendErr != nil {
		return fmt.Errorf("enlarge dump chunks: send: %w", sendErr)
	}

	buf := make([]byte, dumpChunkSize)
	var recvErr error
	if err := raw.Read(func(fd uintptr) bool {
		_, _, _, _, recvErr = unix.Recvmsg(int(fd), buf, nil, 0)
		return !errors.Is(recvErr, unix.EAGAIN)
	}); err != nil {
		return fmt.Errorf("enlarge dump chunks: %w", err)
	}
	if recvErr != nil {
		return fmt.Errorf("enlarge dump chunks: receive: %w", recvErr)
	}
	return nil
}
