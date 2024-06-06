package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/ws", handleWebSocket)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Connection") != "Upgrade" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	websocketKey := r.Header.Get("Sec-WebSocket-Key")
	if websocketKey == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	acceptKey := computeAcceptKey(websocketKey)
	headers := http.Header{
		"Upgrade":              {"websocket"},
		"Connection":           {"Upgrade"},
		"Sec-WebSocket-Accept": {acceptKey},
	}

	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	response := "HTTP/1.1 101 Switching Protocols\r\n"
	for key, values := range headers {
		response += fmt.Sprintf("%s: %s\r\n", key, strings.Join(values, ", "))
	}
	response += "\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		log.Println("Failed to send handshake response:", err)
		return
	}

	// Launch the message handling in a new goroutine
	go handleMessages(conn)
}

func computeAcceptKey(key string) string {
	magicString := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.New()
	hash.Write([]byte(key + magicString))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func handleMessages(conn net.Conn) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	messageChan := make(chan []byte)

	// Launch reading messages in a goroutine
	go readPump(reader, messageChan)
	// Launch writing messages in a goroutine
	go writePump(writer, messageChan)

	// Block until the connection is closed
	<-messageChan
	log.Println("Connection closed")
}

func readPump(reader *bufio.Reader, messageChan chan []byte) {
	for {
		message, err := readMessage(reader)
		if err != nil {
			log.Println("Failed to read message:", err)
			close(messageChan)
			return
		}
		log.Println("Received message:", string(message))
		messageChan <- message
	}
}

func writePump(writer *bufio.Writer, messageChan chan []byte) {
	for message := range messageChan {
		if err := writeMessage(writer, message); err != nil {
			log.Println("Failed to write message:", err)
			close(messageChan)
			return
		}
	}
}

func readMessage(reader *bufio.Reader) ([]byte, error) {
	firstByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// The first byte contains information about the frame type
	fin := firstByte & 0x80    // Fin bit
	opcode := firstByte & 0x0F // Frame type

	if fin == 0 {
		return nil, fmt.Errorf("fragmented frames are not supported")
	}
	if opcode != 0x1 {
		return nil, fmt.Errorf("only text frames are supported")
	}

	secondByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	payloadLen := int(secondByte & 0x7F)
	if payloadLen == 126 {
		var extendedLen uint16
		if err := binary.Read(reader, binary.BigEndian, &extendedLen); err != nil {
			return nil, err
		}
		payloadLen = int(extendedLen)
	} else if payloadLen == 127 {
		var extendedLen uint64
		if err := binary.Read(reader, binary.BigEndian, &extendedLen); err != nil {
			return nil, err
		}
		payloadLen = int(extendedLen)
	}

	mask := make([]byte, 4)
	if secondByte&0x80 != 0 {
		if _, err := reader.Read(mask); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := reader.Read(payload); err != nil {
		return nil, err
	}

	for i := 0; i < payloadLen; i++ {
		payload[i] ^= mask[i%4]
	}

	return payload, nil
}

func writeMessage(writer *bufio.Writer, message []byte) error {
	if len(message) > 125 {
		return fmt.Errorf("Message too long")
	}

	writer.WriteByte(0x81) // Text frame
	writer.WriteByte(byte(len(message)))
	writer.Write(message)
	return writer.Flush()
}
