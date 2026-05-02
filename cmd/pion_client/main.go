package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/go-gst/go-gst/gst"
	"github.com/go-gst/go-gst/gst/app"
	"github.com/pion/webrtc/v4"
)
func BytesToHexArray(data []byte) []string {
	hexArray := make([]string, len(data))
	for i, b := range data {
		hexArray[i] = fmt.Sprintf("%02x", b)
	}
	return hexArray
}

func main() {
	gst.Init(nil)

	const readPipePath = "/tmp/go_pipe"
	const writePipePath = "/tmp/jai_pipe"

	if err := os.Remove(readPipePath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatal(err)
			os.Exit(1)
		}
	}

	if err := os.Remove(writePipePath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatal(err)
			os.Exit(1)
		}
	}
	// Create the named pipe
	err := syscall.Mkfifo(readPipePath, 0666)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	err = syscall.Mkfifo(writePipePath, 0666)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	// Open the pipe for writing
	read_pipe, err := os.OpenFile(readPipePath, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		log.Fatal(err)
	}

	write_pipe, err2 := os.OpenFile(writePipePath, os.O_RDWR, os.ModeNamedPipe)
	if err2 != nil {
		log.Fatal(err2)
	}
	defer func() {
		read_pipe.Close()
		write_pipe.Close()
	}()

	settingEngine := webrtc.SettingEngine{}
	settingEngine.SetReceiveMTU(5000)

	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	var inputReadLineChan chan string = make(chan string, 10)
	go readUntilNewline(read_pipe, inputReadLineChan)

	peerConnection, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{{}},
	})

	// need this for sdp to have ufrag and shit
	videoTrack, videoTrackErr := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264}, "video", "pion",
	)
	if videoTrackErr != nil {
		panic(videoTrackErr)
	}

	rtpSender, videoTrackErr := peerConnection.AddTrack(videoTrack)
	if videoTrackErr != nil {
		panic(videoTrackErr)
	}
	_ = rtpSender

	// file,err := os.OpenFile("go_nalus.h264", os.O_RDWR | os.O_CREATE, 0o777);
	// if err != nil {panic("we are cooked")}
	peerConnection.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if track.Kind() == webrtc.RTPCodecTypeVideo {
			fmt.Println("got the trakckkk")
		}
			codecName := strings.Split(track.Codec().RTPCodecCapability.MimeType, "/")[1]
		fmt.Printf("Track has started, of type %d: %s \n", track.PayloadType(), codecName)

		appSrc := pipelineForCodec(track, codecName)
		buf := make([]byte, 5000)
		for {
			i, _, readErr := track.Read(buf)
			if readErr != nil {
				panic(err)
			}
			appSrc.PushBuffer(gst.NewBufferFromBytes(buf[:i]))
		}
	})

	defer func() {
		if cErr := peerConnection.Close(); cErr != nil {
			fmt.Printf("cannot close peerConnection: %v\n", cErr)
		}
	}()

	iceConnectedCtx, iceConnectedCtxCancel := context.WithCancel(context.Background())
	go func() {
		<-iceConnectedCtx.Done()
	}()

	peerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			str, err := json.Marshal(candidate.ToJSON())
			if err != nil {
				panic(err)
			}
			writeMessage(write_pipe, string(str))
		}
	})

	peerConnection.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		fmt.Printf("Connection State has changed %s \n", connectionState.String())
		if connectionState == webrtc.ICEConnectionStateConnected {
			iceConnectedCtxCancel()
		}
	})

	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		// go func() {
		// 	ticker := time.NewTicker(time.Second * 1)
		// 	for range ticker.C {
		// 		err := dc.SendText("lessss gooooooo i guess idk tho bru")
		// 		fmt.Println(err.Error())
		// 	}
		// }()
		//
		fmt.Printf("Peer Connection State has changed: %s\n", state.String())
		if state == webrtc.PeerConnectionStateFailed {
			fmt.Println("Peer Connection has gone to failed exiting")
			os.Exit(0)
		}
		if state == webrtc.PeerConnectionStateClosed {
			fmt.Println("Peer Connection has gone to closed exiting")
			os.Exit(0)
		}
	})

	fmt.Println("local description", peerConnection.LocalDescription())

	options := webrtc.OfferOptions{}
	offer, err := peerConnection.CreateOffer(&options)
	if err != nil {
		panic(err)
	}

	peerConnection.SetLocalDescription(offer)

	str, err := json.Marshal(peerConnection.LocalDescription())
	if err != nil {
		panic("we are cooked")
	}

	writeMessage(write_pipe, string(str))
	fmt.Println(string(str))
	sdp := "{\"sdp\":\"v=0\\r\\no=- 2508192892581753534 2 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0\\r\\na=fingerprint:sha-256 13:E2:FB:4A:FB:99:79:6B:D0:BB:D4:6C:26:43:E7:C3:5D:40:4C:C8:E5:82:3E:E4:A6:9D:00:06:E0:F7:95:45\\r\\na=group:BUNDLE 0\\r\\nm=video 9 UDP/TLS/RTP/SAVPF 96\\r\\nc=IN IP4 0.0.0.0\\r\\na=setup:active\\r\\na=mid:0\\r\\na=ice-ufrag:MuJd\\r\\na=ice-pwd:M7tLfiCRCC7WR8iTB+kEpoKD\\r\\na=rtcp-mux\\r\\na=rtcp-rsize\\r\\na=rtpmap:96 H264/90000\\r\\na=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\\r\\na=rtcp-fb:96 nack\\r\\na=rtcp-fb:96 nack pli\\r\\na=rtcp-fb:96 transport-cc\\r\\na=ssrc:3477136883 msid:jairtc video\\r\\na=ssrc:3477136883 mslabel:jairtc\\r\\na=ssrc:3477136883 label:video\\r\\na=msid:jairtc video\\r\\na=sendrecv\\r\\n\",\"type\":\"answer\"}"
	var as_sd webrtc.SessionDescription
	err = json.Unmarshal([]byte(sdp), &as_sd)
	if err != nil {
		fmt.Println("err is this", err)
		panic(err)
	}
	err = peerConnection.SetRemoteDescription(as_sd)
	if err != nil {
		fmt.Println("err is this", err)
		panic(err)
	}
	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)

	<-gatherComplete

	for {
		select {
		case input, ok := <-inputReadLineChan:
			if !ok {
				fmt.Println("channel closed")
				return
			}
			var parsed_ice_cand webrtc.ICECandidateInit
			err := json.Unmarshal([]byte(input), &parsed_ice_cand)
			if err != nil {
				fmt.Println("err is this", err)
				panic(err)
			}
			err = peerConnection.AddICECandidate(parsed_ice_cand)

			if err != nil {
				fmt.Println("err is this", err)
				panic(err)
			}
		default:
			{}

		}

	}
}

func readUntilNewline(pipe *os.File, readChan chan string) {
	r := bufio.NewReader(pipe)
	for {
		lenBytes := make([]byte, 4)
		_, err := io.ReadFull(r, lenBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				close(readChan)
				return
			}
			panic(err)
		}

		// Convert bytes -> length (uint32, big-endian)
		length := binary.BigEndian.Uint32(lenBytes)

		// Read the payload
		data := make([]byte, length)
		_, err = io.ReadFull(r, data)
		if err != nil {
			if errors.Is(err, io.EOF) {
				close(readChan)
				return
			}
			panic(err)
		}

		readChan <- string(data)
	}
}
func writeMessage(w io.Writer, msg string) error {
	data := []byte(msg)
	length := uint32(len(data))

	// 4-byte length prefix
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, length)

	// write length
	_, err := w.Write(lenBytes)
	if err != nil {
		return err
	}

	// write payload
	_, err = w.Write(data)
	if err != nil {
		return err
	}

	return nil
}
func pipelineForCodec(track *webrtc.TrackRemote, codecName string) *app.Source {
	pipelineString := "appsrc format=time is-live=true do-timestamp=true name=src ! application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96"
	pipelineString += " ! rtph264depay ! decodebin ! videoconvert ! autovideosink"

	pipeline, err := gst.NewPipelineFromString(pipelineString)
	if err != nil { panic(err) }

	if err = pipeline.SetState(gst.StatePlaying); err != nil {
		panic(err)
	}

	appSrc, err := pipeline.GetElementByName("src")
	if err != nil {
		panic(err)
	}

	return app.SrcFromElement(appSrc)
}

