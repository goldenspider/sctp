// +build amd64,linux

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	SCTP_INITMSG = 2
	SCTP_EVENTS  = 11

	MSG_EOR = 0x80

	MSG_NOTIFICATION = 0x8000
)

type sctp_initmsg struct {
	sinit_num_ostreams   uint16
	sinit_max_instreams  uint16
	sinit_max_attempts   uint16
	sinit_max_init_timeo uint16
}

type sctp_event_subscribe struct {
	sctp_data_io_event          uint8
	sctp_association_event      uint8
	sctp_address_event          uint8
	sctp_send_failure_event     uint8
	sctp_peer_error_event       uint8
	sctp_shutdown_event         uint8
	sctp_partial_delivery_event uint8
	sctp_adaptation_layer_event uint8
	sctp_authentication_event   uint8
	sctp_sender_dry_event       uint8
}

type sctp_sndrcvinfo struct {
	sinfo_stream     uint16
	sinfo_ssn        uint16
	sinfo_flags      uint16
	resv             uint16 //align
	sinfo_ppid       uint32
	sinfo_context    uint32
	sinfo_timetolive uint32
	sinfo_tsn        uint32
	sinfo_cumtsn     uint32
	sinfo_assoc_id   int32
}

type sctp_notification struct {
	sn_type   uint16 /* Notification type. */
	sn_flags  uint16
	sn_length uint32
}

func Setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func handleEvent(cbuf []byte) {

}
func getmsg(fd int) (rbuf []byte, recvflags int) {
	const BUFSTEP = 1024
	buf := make([]byte, BUFSTEP, 1024*1024*4)
	controlbuf := make([]byte, syscall.SizeofCmsghdr+32)

	var buflen int
	for {
		n, _, flag, _, err := syscall.Recvmsg(fd, buf[buflen:buflen+BUFSTEP], controlbuf, 0)
		if err != nil {
			fmt.Println("getmsg error:", err.Error())
			break
		}

		if n <= 0 {
			fmt.Println("EOF!!!!!")
			break
		}

		//MSG_EOR
		//Whole message is received, return it.
		if (flag & MSG_EOR) != 0 {
			buflen = buflen + n
			rbuf = buf[:buflen]
			recvflags = flag
			fmt.Printf("buflen = %d recv %v\n", buflen, rbuf)
			return
		}

		//Set the next read offset
		buflen = buflen + n
	}

	return nil, 0
}

func echo(fd int) {
	for {
		buf, recvflag := getmsg(fd)
		if len(buf) == 0 {
			break
		}

		if (recvflag & MSG_NOTIFICATION) != 0 {
			fmt.Println("control!!")
			continue
		}
	}

}

func main() {
	var sfd int

	var err error
	if sfd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP); err != nil {
		fmt.Println("Socket() error: ", err.Error())
		return
	}
	var sa syscall.SockaddrInet4
	sa.Addr = [4]byte{0, 0, 0, 0} //INADDR_ANY
	sa.Port = 5000
	if err = syscall.Bind(sfd, &sa); err != nil {
		fmt.Println("Bind() error: ", err.Error())
		return
	}
	if err = syscall.Listen(sfd, 1); err != nil {
		fmt.Println("Listen() error: ", err.Error())
		return
	}

	initmsg := sctp_initmsg{sinit_num_ostreams: 64, sinit_max_instreams: 64, sinit_max_attempts: 64}
	if err = Setsockopt(sfd, syscall.IPPROTO_SCTP, SCTP_INITMSG, unsafe.Pointer(&initmsg), 8); err != nil {
		fmt.Println("Setsockopt() error: ", err.Error())
		return
	}

	event := sctp_event_subscribe{
		sctp_data_io_event:      1,
		sctp_association_event:  1,
		sctp_send_failure_event: 1,
		sctp_address_event:      1,
		sctp_peer_error_event:   1,
		sctp_shutdown_event:     1,
	}

	for {
		var cfd int
		if cfd, _, err = syscall.Accept(sfd); err != nil {
			fmt.Println("Accept() error: ", err.Error())
			return
		}
		if err = Setsockopt(cfd, syscall.IPPROTO_SCTP, SCTP_EVENTS, unsafe.Pointer(&event), 10); err != nil {
			fmt.Println("Setsockopt() error: ", err.Error())
			return
		}
		// Echo back any and all data
		echo(cfd)
	}

	fmt.Println("good")
}
