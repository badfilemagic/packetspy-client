package main

import (
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"strconv"
	"time"
)

type PacketSpy struct {
	PcapDev			string
	SnapLen			int32
	Promisc			bool
	Timeout			time.Duration
	Bpf				string
	OffloadServer	string

	err			error
	handle		*pcap.Handle
}

func NewPacketSpy(dev string, snap int32, prom bool, t time.Duration, bpf string) *PacketSpy {
	return &PacketSpy{PcapDev:dev, SnapLen:snap, Promisc:prom, Timeout:t, Bpf:bpf}
}

func (p *PacketSpy) Gather(bsize int) error {
	var buf []gopacket.Packet

	p.handle, p.err = pcap.OpenLive(p.PcapDev, p.SnapLen, p.Promisc, p.Timeout)
	if p.err != nil {
		return p.err
	}
	defer p.handle.Close()

	p.err = p.handle.SetBPFFilter(p.Bpf)
	if p.err != nil {
		return p.err
	}

	packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	for pkt := range packetSource.Packets() {
		buf = append(buf, pkt)

		if len(buf) >= bsize {
			p.err = p.Offload(buf)
			if p.err != nil {
				continue
			} else {
				buf = nil
			}
		}
	}
	return nil
}

func (p *PacketSpy) Offload(pkts []gopacket.Packet) error {
	for _, pkt := range pkts {
		enc_pkt := encodedata(pkt)

		conn, err := net.Dial("tcp", p.OffloadServer)
		if err != nil {
			return err
		}
		_, err = conn.Write(enc_pkt)
		if err != nil {
			return err
		}
	}
	return nil
}

func encodedata(pkt gopacket.Packet) []byte {
	data := ""
	data += strconv.FormatInt(pkt.Metadata().Timestamp.UnixNano(), 10) + ","
	data += strconv.Itoa(pkt.Metadata().CaptureLength) + ","
	data += strconv.Itoa(pkt.Metadata().Length) + ","
	data += strconv.Itoa(pkt.Metadata().InterfaceIndex) + ","
	data += hex.EncodeToString(pkt.Data())
	return []byte(data)
}
