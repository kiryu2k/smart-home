package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	url           string
	addr          uint64
	crc8Table     [256]byte
	encoding      = base64.URLEncoding.WithPadding(base64.NoPadding)
	connDevices   = make(map[uint64]*switchInfo)
	devicesInfo   = make(map[uint64]*deviceInfo)
	nameToAddr    = make(map[string]uint64)
	envSensorInfo = make(map[uint64]*envSensorProps)
	hubSerial     = uint64(0x01)
)

const maxDelay uint64 = 300

const (
	addrBroadcast uint64 = 0x3FFF
	addrZeros     uint64 = 0x0000
)

const (
	cmdWHOISHERE uint8 = 0x01
	cmdIAMHERE   uint8 = 0x02
	cmdGETSTATUS uint8 = 0x03
	cmdSTATUS    uint8 = 0x04
	cmdSETSTATUS uint8 = 0x05
	cmdTICK      uint8 = 0x06
)

const (
	devSmartHub  uint8 = 0x01
	devEnvSensor uint8 = 0x02
	devSwitch    uint8 = 0x03
	devLamp      uint8 = 0x04
	devSocket    uint8 = 0x05
	devClock     uint8 = 0x06
)

type packet struct {
	Length uint64
	payload
	Crc8 byte
}

type payload struct {
	src     uint64
	dst     uint64
	serial  uint64
	devType byte
	cmd     byte
	cmdBody any
}

type device struct {
	devName  string
	devProps any
}

type envSensorProps struct {
	sensors  byte
	triggers []trigger
}

type trigger struct {
	op    byte
	value uint64
	name  string
}

type switchInfo struct {
	status       byte
	connDevNames []string
}

type deviceInfo struct {
	devName                string
	devType                byte
	lastRespTimestamp      uint64
	isDisabled             bool
	isWaitingForStatusResp bool
}

type deviceStatus struct {
	devName string
	status  byte
}

func main() {
	loadArgs()
	calcTableCRC8()
	var (
		WHOISHEREtimestamp uint64
		hubPayload         = &payload{
			src:     addr,
			dst:     addrBroadcast,
			serial:  hubSerial,
			devType: devSmartHub,
			cmd:     cmdWHOISHERE,
			cmdBody: &device{
				devName: "HUB01",
			},
		}
		req = encodeBase64(serializePacket(hubPayload))
	)
	for {
		var (
			resp         = sendPostRequest(req)
			packets      = deserializePackets(decodeBase64(resp.Body))
			buf          []byte
			curTimestamp uint64
		)
		defer resp.Body.Close()
		for _, p := range packets {
			switch p.cmd {
			case cmdWHOISHERE:
				hubSerial++
				buf = serializePacket(&payload{
					src:     addr,
					dst:     addrBroadcast,
					serial:  hubSerial,
					devType: devSmartHub,
					cmd:     cmdIAMHERE,
					cmdBody: &device{
						devName: "HUB01",
					},
				})
				fallthrough
			case cmdIAMHERE:
				if isPacketDelayed(p, curTimestamp, WHOISHEREtimestamp) {
					break
				}
				dev := p.cmdBody.(*device)
				devicesInfo[p.src] = &deviceInfo{
					devName:                dev.devName,
					devType:                p.devType,
					lastRespTimestamp:      curTimestamp,
					isDisabled:             false,
					isWaitingForStatusResp: true,
				}
				nameToAddr[dev.devName] = p.src
				if p.devType == devSwitch {
					connDevices[p.src] = &switchInfo{
						connDevNames: dev.devProps.([]string),
					}
				} else if p.devType == devEnvSensor {
					envSensorInfo[p.src] = dev.devProps.(*envSensorProps)
				}
				hubSerial++
				buf = append(buf, serializePacket(&payload{
					src:     addr,
					dst:     p.src,
					serial:  hubSerial,
					devType: p.devType,
					cmd:     cmdGETSTATUS,
				})...)
			case cmdSTATUS:
				if isPacketDelayed(p, curTimestamp) {
					break
				}
				if p.devType == devSwitch {
					swInfo, ok := connDevices[p.src]
					if !ok {
						break
					}
					buf = swInfo.switchToNewStatus(p, buf, curTimestamp)
				} else if p.devType == devEnvSensor {
					envSensor, ok := envSensorInfo[p.src]
					if !ok {
						break
					}
					buf = envSensor.executeEnvSensorProps(p, buf, curTimestamp)
				}
			case cmdTICK:
				curTimestamp = p.cmdBody.(uint64)
				if WHOISHEREtimestamp == 0 {
					WHOISHEREtimestamp = curTimestamp
				}
			}
		}
		req = encodeBase64(buf)
	}
}

func (e *envSensorProps) executeEnvSensorProps(p *packet, buf []byte, timestamp uint64) []byte {
	var (
		values  = p.cmdBody.([]uint64)
		sensors = e.getSensors()
	)
	for i, value := range values {
		statuses := e.getDeviceStatuses(sensors[i], value)
		for _, s := range statuses {
			var (
				curDevAddr  = nameToAddr[s.devName]
				devInfo, ok = devicesInfo[curDevAddr]
			)
			if !ok || devInfo.isDisabled {
				continue
			}
			hubSerial++
			buf = append(buf, serializePacket(&payload{
				src:     addr,
				dst:     curDevAddr,
				serial:  hubSerial,
				devType: devInfo.devType,
				cmd:     cmdSETSTATUS,
				cmdBody: s.status,
			})...)
			devicesInfo[curDevAddr].lastRespTimestamp = timestamp
			devicesInfo[curDevAddr].isWaitingForStatusResp = true
		}
	}
	return buf
}

func (e *envSensorProps) getDeviceStatuses(sensorType byte, value uint64) []*deviceStatus {
	statuses := make([]*deviceStatus, 0)
	for _, trig := range e.triggers {
		if ((trig.op >> 2) & 0x3) != sensorType {
			continue
		}
		var (
			status      = trig.op & 0x1
			compareType = (trig.op >> 1) & 0x1
		)
		switch compareType {
		case 0:
			if value < trig.value {
				statuses = append(statuses, &deviceStatus{
					devName: trig.name,
					status:  status,
				})
			}
		case 1:
			if value > trig.value {
				statuses = append(statuses, &deviceStatus{
					devName: trig.name,
					status:  status,
				})
			}
		}
	}
	return statuses
}

func (e *envSensorProps) getSensors() []byte {
	var (
		sensors = make([]byte, 0)
		number  byte
	)
	for s := e.sensors; s > 0; s >>= 1 {
		if s&0x1 == 1 {
			sensors = append(sensors, number)
		}
		number++
	}
	return sensors
}

func (s *switchInfo) switchToNewStatus(p *packet, buf []byte, timestamp uint64) []byte {
	/* nothing to switch */
	newStatus := p.cmdBody.(byte)
	if s.status == newStatus {
		return buf
	}
	s.status = newStatus
	for _, name := range s.connDevNames {
		var (
			curDevAddr  = nameToAddr[name]
			devInfo, ok = devicesInfo[curDevAddr]
		)
		if !ok || devInfo.isDisabled {
			continue
		}
		hubSerial++
		buf = append(buf, serializePacket(&payload{
			src:     addr,
			dst:     curDevAddr,
			serial:  hubSerial,
			devType: devInfo.devType,
			cmd:     cmdSETSTATUS,
			cmdBody: newStatus,
		})...)
		devicesInfo[curDevAddr].lastRespTimestamp = timestamp
		devicesInfo[curDevAddr].isWaitingForStatusResp = true
	}
	return buf
}

/* first timestamp is current, second is WHOISHERE request timestamp */
func isPacketDelayed(p *packet, timestamps ...uint64) bool {
	switch p.cmd {
	case cmdIAMHERE:
		delay := timestamps[0] - timestamps[1]
		return delay > maxDelay
	case cmdSTATUS:
		devInfo, ok := devicesInfo[p.src]
		if !ok || devInfo.isDisabled {
			return true
		}
		delay := timestamps[0] - devInfo.lastRespTimestamp
		if devInfo.isWaitingForStatusResp && delay > maxDelay {
			devicesInfo[p.src].isDisabled = true
			return true
		}
		devicesInfo[p.src].isWaitingForStatusResp = false
	}
	return false
}

func encodeVaruint(value uint64) []byte {
	if value == 0 {
		return []byte{0}
	}
	bytes := make([]byte, 0)
	for i := 0; value > 0; i++ {
		bytes = append(bytes, 0)
		bytes[i] = byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			bytes[i] |= 0x80
		}
	}
	return bytes
}

func decodeVaruint(bytes []byte) uint64 {
	var (
		shift  uint64
		length int
		value  uint64
	)
	for {
		b := bytes[length]
		length++
		value |= (uint64(b&0x7F) << shift)
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return value
}

func findVaruint(buf *bytes.Buffer) []byte {
	bytes := buf.Next(1)
	for bytes[len(bytes)-1]&0x80 != 0 {
		bytes = append(bytes, buf.Next(1)...)
	}
	return bytes
}

func serializePayload(p *payload) []byte {
	buf := encodeVaruint(p.src)
	buf = append(buf, encodeVaruint(p.dst)...)
	buf = append(buf, encodeVaruint(p.serial)...)
	buf = append(buf, p.devType)
	buf = append(buf, p.cmd)
	switch p.cmd {
	case cmdWHOISHERE:
		fallthrough
	case cmdIAMHERE:
		dev := p.cmdBody.(*device)
		buf = append(buf, byte(len(dev.devName)))
		buf = append(buf, []byte(dev.devName)...)
		if p.devType == devEnvSensor {
			props := dev.devProps.(*envSensorProps)
			buf = append(buf, props.sensors)
			buf = append(buf, byte(len(props.triggers)))
			for _, trigger := range props.triggers {
				buf = append(buf, trigger.op)
				buf = append(buf, encodeVaruint(trigger.value)...)
				buf = append(buf, byte(len(trigger.name)))
				buf = append(buf, []byte(trigger.name)...)
			}
		} else if p.devType == devSwitch {
			devNames := dev.devProps.([]string)
			buf = append(buf, byte(len(devNames)))
			for _, devName := range devNames {
				buf = append(buf, byte(len(devName)))
				buf = append(buf, []byte(devName)...)
			}
		}
	case cmdSTATUS:
		buf = append(buf, p.cmdBody.(byte))
	case cmdSETSTATUS:
		buf = append(buf, p.cmdBody.(byte))
	case cmdTICK:
		return []byte{}
	}
	return buf
}

func deserializePayload(buf *bytes.Buffer) *payload {
	p := &payload{
		src:     decodeVaruint(findVaruint(buf)),
		dst:     decodeVaruint(findVaruint(buf)),
		serial:  decodeVaruint(findVaruint(buf)),
		devType: buf.Next(1)[0],
		cmd:     buf.Next(1)[0],
	}
	switch p.cmd {
	case cmdWHOISHERE:
		fallthrough
	case cmdIAMHERE:
		var (
			devNameLen = int(buf.Next(1)[0])
			dev        = &device{
				devName: string(buf.Next(devNameLen)),
			}
		)
		if p.devType == devEnvSensor {
			props := &envSensorProps{
				sensors:  buf.Next(1)[0],
				triggers: make([]trigger, int(buf.Next(1)[0])),
			}
			for i := range props.triggers {
				props.triggers[i] = trigger{
					op:    buf.Next(1)[0],
					value: decodeVaruint(findVaruint(buf)),
					name:  string(buf.Next(int(buf.Next(1)[0]))),
				}
			}
			dev.devProps = props
		} else if p.devType == devSwitch {
			props := make([]string, int(buf.Next(1)[0]))
			for i := range props {
				len := int(buf.Next(1)[0])
				props[i] = string(buf.Next(len))
			}
			dev.devProps = props
		}
		p.cmdBody = dev
	case cmdSTATUS:
		if p.devType == devSmartHub || p.devType == devClock {
			break
		}
		if p.devType == devEnvSensor {
			values := make([]uint64, int(buf.Next(1)[0]))
			for i := range values {
				values[i] = decodeVaruint(findVaruint(buf))
			}
			p.cmdBody = values
			break
		}
		p.cmdBody = buf.Next(1)[0]
	case cmdTICK:
		p.cmdBody = decodeVaruint(findVaruint(buf))
	}
	return p
}

func deserializePackets(buf *bytes.Buffer) []*packet {
	packets := make([]*packet, 0)
	for buf.Len() != 0 && buf.Bytes()[0] != 0 {
		p := new(packet)
		p.Length, _ = binary.ReadUvarint(buf)
		crc8 := computeCRC8(buf.Bytes()[:p.Length])
		p.payload = *deserializePayload(buf)
		p.Crc8 = buf.Next(1)[0]
		if crc8 != p.Crc8 {
			continue
		}
		packets = append(packets, p)
	}
	return packets
}

func serializePacket(p *payload) []byte {
	serializedPayload := serializePayload(p)
	crc8 := computeCRC8(serializedPayload)
	buf := []byte{byte(len(serializedPayload))}
	buf = append(buf, serializedPayload...)
	return append(buf, crc8)
}

func encodeBase64(p []byte) string {
	return encoding.EncodeToString(p)
}

func decodeBase64(r io.Reader) *bytes.Buffer {
	buf := bytes.NewBuffer(make([]byte, 0))
	buf.ReadFrom(base64.NewDecoder(encoding, r))
	return buf
}

func calcTableCRC8() {
	const generator byte = 0x1D
	for i := 0; i < len(crc8Table); i++ {
		curByte := byte(i)
		for bit := 0; bit < 8; bit++ {
			if (curByte & 0x80) != 0 {
				curByte <<= 1
				curByte ^= generator
			} else {
				curByte <<= 1
			}
		}
		crc8Table[i] = curByte
	}
}

func computeCRC8(bytes []byte) byte {
	var crc byte
	for _, b := range bytes {
		data := b ^ crc
		crc = crc8Table[data]
	}
	return crc
}

func sendPostRequest(req string) *http.Response {
	resp, err := http.Post(url, "text/plain", strings.NewReader(req))
	if err != nil {
		os.Exit(99)
	}
	if resp.StatusCode == http.StatusNoContent {
		os.Exit(0)
	} else if resp.StatusCode != http.StatusOK {
		os.Exit(99)
	}
	return resp
}

func loadArgs() {
	url = os.Args[1]
	var (
		addrStr = os.Args[2]
		err     error
	)
	addr, err = strconv.ParseUint(addrStr, 16, 14)
	if err != nil {
		addr = 0xef0
	}
}
