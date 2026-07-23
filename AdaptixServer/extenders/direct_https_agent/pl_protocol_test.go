package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	adaptix "github.com/Adaptix-Framework/axc2"
)

func TestDirectHTTPSPacketEnvelopeNegotiation(t *testing.T) {
	if directHTTPSAgentSupportsPacketEnvelopeV2(adaptix.AgentData{}) {
		t.Fatalf("agent without custom capabilities must use legacy task body")
	}

	schema1 := adaptix.AgentData{CustomData: packDirectHTTPSCapabilities(directHTTPSBeatV2Schema, 0)}
	if directHTTPSAgentSupportsPacketEnvelopeV2(schema1) {
		t.Fatalf("DHB2 schema 1 agent must not receive DHT2 task envelope")
	}

	caps := directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2
	schema2 := adaptix.AgentData{CustomData: packDirectHTTPSCapabilities(directHTTPSBeatV2CapsSchema, caps)}
	if !directHTTPSAgentSupportsPacketEnvelopeV2(schema2) {
		t.Fatalf("DHB2 schema 2 agent with packet caps should receive DHT2 task envelope")
	}
	if directHTTPSAgentSupportsSectionEnvelopeV3(schema2) {
		t.Fatalf("DHB2 schema 2 agent must not receive sectioned DHT2 task envelope")
	}

	sectionCaps := caps | directHTTPSCapSectionEnvelopeV3
	schema3 := adaptix.AgentData{CustomData: packDirectHTTPSCapabilities(directHTTPSBeatV3SectionSchema, sectionCaps)}
	if !directHTTPSAgentSupportsSectionEnvelopeV3(schema3) {
		t.Fatalf("DHB2 schema 3 agent with section caps should receive sectioned DHT2 task envelope")
	}
	if selfC2AgentSupportsNativeFrameV4(schema3) {
		t.Fatalf("DHB2 schema 3 agent must not receive neutral LPT4 task frame")
	}

	nativeCaps := sectionCaps | selfC2CapNativeFrameV4
	schema4 := adaptix.AgentData{CustomData: packDirectHTTPSCapabilities(selfC2BeatV4Schema, nativeCaps)}
	if !selfC2AgentSupportsNativeFrameV4(schema4) {
		t.Fatalf("LPH4 schema 4 agent with native caps should receive neutral LPT4 task frame")
	}

	schema5 := adaptix.AgentData{CustomData: packDirectHTTPSCapabilities(selfC2BeatV5Schema, nativeCaps)}
	if !selfC2AgentSupportsNativeFrameV4(schema5) {
		t.Fatalf("LPH5 schema 5 agent with native caps should preserve the schema4 task frame")
	}
	if selfC2BeatV5Magic != 0x4c504835 {
		t.Fatalf("unexpected LPH5 magic: %08x", selfC2BeatV5Magic)
	}
}

func TestPackTaskEnvelopeV2(t *testing.T) {
	body := []byte{0x2b, 0, 0, 0, 0xaa, 0xbb}
	packet := packTaskEnvelopeV2(body, 3)
	if len(packet) != 20+len(body) {
		t.Fatalf("unexpected packet length: got %d", len(packet))
	}
	if string(packet[:4]) != directHTTPSTaskV2Magic {
		t.Fatalf("unexpected magic: %q", string(packet[:4]))
	}
	if got := binary.LittleEndian.Uint32(packet[4:8]); got != directHTTPSTaskV2Schema {
		t.Fatalf("unexpected schema: %d", got)
	}
	if got := binary.LittleEndian.Uint32(packet[12:16]); got != 3 {
		t.Fatalf("unexpected task count: %d", got)
	}
	if got := binary.LittleEndian.Uint32(packet[16:20]); got != uint32(len(body)) {
		t.Fatalf("unexpected body length: %d", got)
	}
	if !bytes.Equal(packet[20:], body) {
		t.Fatalf("body was changed")
	}
}

func TestPackTaskSectionEnvelopeV3(t *testing.T) {
	body := []byte{0x2b, 0, 0, 0, 0xaa, 0xbb}
	packet := packTaskSectionEnvelopeV3(body, 1)
	if string(packet[:4]) != directHTTPSTaskV2Magic {
		t.Fatalf("unexpected magic: %q", string(packet[:4]))
	}
	if got := binary.LittleEndian.Uint32(packet[8:12]); got != directHTTPSEnvelopeFlagSectioned {
		t.Fatalf("unexpected flags: %d", got)
	}
	sectionBody := packet[20:]
	if got := binary.LittleEndian.Uint32(sectionBody[:4]); got != 2 {
		t.Fatalf("unexpected section count: %d", got)
	}
	legacyOffset := 4 + 8 + 16
	if got := binary.LittleEndian.Uint32(sectionBody[legacyOffset : legacyOffset+4]); got != directHTTPSSectionLegacyRecords {
		t.Fatalf("unexpected legacy section type: %d", got)
	}
	if got := binary.LittleEndian.Uint32(sectionBody[legacyOffset+4 : legacyOffset+8]); got != uint32(len(body)) {
		t.Fatalf("unexpected legacy section len: %d", got)
	}
	if !bytes.Equal(sectionBody[legacyOffset+8:], body) {
		t.Fatalf("legacy section body was changed")
	}
}

func TestPackSelfC2TaskFrameV4(t *testing.T) {
	tasks := []selfC2NativeTaskRecord{{TaskID: 0x11223344, ActionID: selfC2ActionRunProcess, ArgumentBytes: []byte{0xaa, 0xbb}}}
	packet := packSelfC2TaskFrameV4(tasks)
	if string(packet[:4]) != selfC2TaskFrameV4Magic {
		t.Fatalf("unexpected native magic: %q", string(packet[:4]))
	}
	if got := binary.LittleEndian.Uint32(packet[8:12]); got != directHTTPSEnvelopeFlagSectioned {
		t.Fatalf("unexpected flags: %d", got)
	}
	sectionBody := packet[20:]
	if got := binary.LittleEndian.Uint32(sectionBody[:4]); got != 2 {
		t.Fatalf("unexpected native section count: %d", got)
	}
	metaLen := binary.LittleEndian.Uint32(sectionBody[8:12])
	meta := sectionBody[12 : 12+metaLen]
	if got := binary.LittleEndian.Uint32(meta[:4]); got != uint32(selfC2BeatV4Schema) {
		t.Fatalf("unexpected native section schema: %d", got)
	}
	if got := binary.LittleEndian.Uint32(meta[4:8]); got&uint32(selfC2CapNativeFrameV4) == 0 {
		t.Fatalf("native capability missing: %d", got)
	}
	recordOffset := 4 + 8 + int(metaLen)
	if got := binary.LittleEndian.Uint32(sectionBody[recordOffset : recordOffset+4]); got != selfC2SectionTaskRecordV4 {
		t.Fatalf("unexpected native task section type: %d", got)
	}
	recordLen := binary.LittleEndian.Uint32(sectionBody[recordOffset+4 : recordOffset+8])
	record := sectionBody[recordOffset+8 : recordOffset+8+int(recordLen)]
	if got := binary.LittleEndian.Uint32(record[:4]); got != selfC2TaskRecordV4Schema {
		t.Fatalf("unexpected native task schema: %d", got)
	}
	if got := binary.LittleEndian.Uint32(record[4:8]); got != 0x11223344 {
		t.Fatalf("unexpected native task id: %08x", got)
	}
	if got := binary.LittleEndian.Uint32(record[8:12]); got != selfC2ActionRunProcess {
		t.Fatalf("unexpected native action id: %d", got)
	}
	if got := binary.LittleEndian.Uint32(record[12:16]); got != 2 {
		t.Fatalf("unexpected native argument len: %d", got)
	}
	if !bytes.Equal(record[16:], []byte{0xaa, 0xbb}) {
		t.Fatalf("native arguments were changed")
	}
}

func TestDisksCommandSurface(t *testing.T) {
	action, ok := selfC2ActionFromCommand(COMMAND_DISKS)
	if !ok || action != selfC2ActionDisks {
		t.Fatalf("unexpected disks action mapping: ok=%v action=%08x", ok, action)
	}

	ext := &ExtenderAgent{}
	task, message, err := ext.CreateCommand(adaptix.AgentData{}, map[string]any{"command": "disks"})
	if err != nil {
		t.Fatalf("disks command creation failed: %v", err)
	}
	if message.Message != "Task: list logical drives" {
		t.Fatalf("unexpected disks message: %q", message.Message)
	}
	if len(task.Data) != 4 || binary.LittleEndian.Uint32(task.Data) != COMMAND_DISKS {
		t.Fatalf("unexpected disks task data: %x", task.Data)
	}
}

func TestUnpackResultEnvelopeV2AndLegacy(t *testing.T) {
	body := []byte{0, 0, 0, 1, 0, 0, 0, 0x2b}
	v2 := []byte{'D', 'H', 'R', '2'}
	for _, value := range []uint32{uint32(directHTTPSResultV2Schema), 0, uint32(len(body))} {
		field := make([]byte, 4)
		binary.BigEndian.PutUint32(field, value)
		v2 = append(v2, field...)
	}
	v2 = append(v2, body...)
	got, err := unpackResultEnvelope(v2)
	if err != nil {
		t.Fatalf("v2 unpack failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("v2 body mismatch")
	}

	legacy := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(legacy, uint32(4+len(body)))
	legacy = append(legacy, body...)
	got, err = unpackResultEnvelope(legacy)
	if err != nil {
		t.Fatalf("legacy unpack failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("legacy body mismatch")
	}
}

func TestUnpackNativeResultBundleV4(t *testing.T) {
	body := []byte{0, 0, 0, 1, 0, 0, 0, 0x2b}
	meta := []byte{}
	for _, value := range []uint32{uint32(selfC2BeatV4Schema), uint32(directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3 | selfC2CapNativeFrameV4), uint32(selfC2ResultBundleV4Schema), 0} {
		meta = appendBE32(meta, value)
	}
	bundle := []byte{}
	bundle = appendBE32(bundle, selfC2ResultBundleV4Schema)
	bundle = appendBE32(bundle, selfC2ResultCodecCompatBody)
	bundle = appendBE32(bundle, 0)
	bundle = appendBE32(bundle, uint32(len(body)))
	bundle = append(bundle, body...)
	sectioned := []byte{}
	sectioned = appendBE32(sectioned, 2)
	sectioned = appendBE32(sectioned, directHTTPSSectionMeta)
	sectioned = appendBE32(sectioned, uint32(len(meta)))
	sectioned = append(sectioned, meta...)
	sectioned = appendBE32(sectioned, selfC2SectionResultBundleV4)
	sectioned = appendBE32(sectioned, uint32(len(bundle)))
	sectioned = append(sectioned, bundle...)

	v4 := []byte{'L', 'P', 'R', '4'}
	for _, value := range []uint32{uint32(directHTTPSResultV2Schema), directHTTPSEnvelopeFlagSectioned, uint32(len(sectioned))} {
		v4 = appendBE32(v4, value)
	}
	v4 = append(v4, sectioned...)

	got, err := unpackResultEnvelope(v4)
	if err != nil {
		t.Fatalf("native result bundle unpack failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("native result bundle body mismatch")
	}
}

func TestUnpackNativeResultBundleCodec2Hello(t *testing.T) {
	message := []byte("hello from schema4 codec2")
	payload := []byte{}
	payload = appendBE32(payload, 1)
	payload = appendBE32(payload, selfC2NativeResultRecordV4Schema)
	payload = appendBE32(payload, 0x11223344)
	payload = appendBE32(payload, selfC2ActionHello)
	payload = appendBE32(payload, selfC2NativeResultFieldText)
	payload = appendBE32(payload, uint32(len(message)))
	payload = append(payload, message...)

	meta := []byte{}
	for _, value := range []uint32{uint32(selfC2BeatV4Schema), uint32(directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3 | selfC2CapNativeFrameV4), uint32(selfC2ResultBundleV4Schema), 0} {
		meta = appendBE32(meta, value)
	}
	bundle := []byte{}
	bundle = appendBE32(bundle, selfC2ResultBundleV4Schema)
	bundle = appendBE32(bundle, selfC2ResultCodecNativeFields)
	bundle = appendBE32(bundle, 0)
	bundle = appendBE32(bundle, uint32(len(payload)))
	bundle = append(bundle, payload...)
	sectioned := []byte{}
	sectioned = appendBE32(sectioned, 2)
	sectioned = appendBE32(sectioned, directHTTPSSectionMeta)
	sectioned = appendBE32(sectioned, uint32(len(meta)))
	sectioned = append(sectioned, meta...)
	sectioned = appendBE32(sectioned, selfC2SectionResultBundleV4)
	sectioned = appendBE32(sectioned, uint32(len(bundle)))
	sectioned = append(sectioned, bundle...)

	v4 := []byte{'L', 'P', 'R', '4'}
	for _, value := range []uint32{uint32(directHTTPSResultV2Schema), directHTTPSEnvelopeFlagSectioned, uint32(len(sectioned))} {
		v4 = appendBE32(v4, value)
	}
	v4 = append(v4, sectioned...)

	got, err := unpackResultEnvelope(v4)
	if err != nil {
		t.Fatalf("native result bundle codec2 unpack failed: %v", err)
	}

	want := []byte{}
	want = appendBE32(want, 0x11223344)
	want = appendBE32(want, COMMAND_HELLO)
	want = appendBE32(want, uint32(len(message)))
	want = append(want, message...)
	if !bytes.Equal(got, want) {
		t.Fatalf("native result bundle codec2 body mismatch")
	}
}

func TestUnpackNativeResultStreamV4(t *testing.T) {
	body := []byte{0, 0, 0, 1, 0, 0, 0, 0x2b}
	meta := []byte{}
	for _, value := range []uint32{uint32(selfC2BeatV4Schema), uint32(directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3 | selfC2CapNativeFrameV4), uint32(selfC2ResultStreamV4Schema), 0} {
		meta = appendBE32(meta, value)
	}
	stream := []byte{}
	stream = appendBE32(stream, selfC2ResultStreamV4Schema)
	stream = appendBE32(stream, uint32(len(body)))
	stream = append(stream, body...)
	sectioned := []byte{}
	sectioned = appendBE32(sectioned, 2)
	sectioned = appendBE32(sectioned, directHTTPSSectionMeta)
	sectioned = appendBE32(sectioned, uint32(len(meta)))
	sectioned = append(sectioned, meta...)
	sectioned = appendBE32(sectioned, selfC2SectionResultStreamV4)
	sectioned = appendBE32(sectioned, uint32(len(stream)))
	sectioned = append(sectioned, stream...)

	v4 := []byte{'L', 'P', 'R', '4'}
	for _, value := range []uint32{uint32(directHTTPSResultV2Schema), directHTTPSEnvelopeFlagSectioned, uint32(len(sectioned))} {
		v4 = appendBE32(v4, value)
	}
	v4 = append(v4, sectioned...)

	got, err := unpackResultEnvelope(v4)
	if err != nil {
		t.Fatalf("native result stream unpack failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("native result stream body mismatch")
	}
}

func TestUnpackSectionedResultEnvelope(t *testing.T) {
	body := []byte{0, 0, 0, 1, 0, 0, 0, 0x2b}
	meta := []byte{}
	for _, value := range []uint32{uint32(directHTTPSBeatV3SectionSchema), uint32(directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3), 0, uint32(len(body))} {
		meta = appendBE32(meta, value)
	}
	sectioned := []byte{}
	sectioned = appendBE32(sectioned, 2)
	sectioned = appendBE32(sectioned, directHTTPSSectionMeta)
	sectioned = appendBE32(sectioned, uint32(len(meta)))
	sectioned = append(sectioned, meta...)
	sectioned = appendBE32(sectioned, directHTTPSSectionLegacyRecords)
	sectioned = appendBE32(sectioned, uint32(len(body)))
	sectioned = append(sectioned, body...)

	v2 := []byte{'L', 'P', 'R', '4'}
	for _, value := range []uint32{uint32(directHTTPSResultV2Schema), directHTTPSEnvelopeFlagSectioned, uint32(len(sectioned))} {
		v2 = appendBE32(v2, value)
	}
	v2 = append(v2, sectioned...)

	got, err := unpackResultEnvelope(v2)
	if err != nil {
		t.Fatalf("sectioned v2 unpack failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("sectioned legacy body mismatch")
	}
}
