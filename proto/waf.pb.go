// Code generated by protoc-gen-go. DO NOT EDIT.
// source: waf.proto

package wafservice

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type HeaderPair struct {
	Key                  string   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value                string   `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HeaderPair) Reset()         { *m = HeaderPair{} }
func (m *HeaderPair) String() string { return proto.CompactTextString(m) }
func (*HeaderPair) ProtoMessage()    {}
func (*HeaderPair) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{0}
}
func (m *HeaderPair) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HeaderPair.Unmarshal(m, b)
}
func (m *HeaderPair) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HeaderPair.Marshal(b, m, deterministic)
}
func (dst *HeaderPair) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HeaderPair.Merge(dst, src)
}
func (m *HeaderPair) XXX_Size() int {
	return xxx_messageInfo_HeaderPair.Size(m)
}
func (m *HeaderPair) XXX_DiscardUnknown() {
	xxx_messageInfo_HeaderPair.DiscardUnknown(m)
}

var xxx_messageInfo_HeaderPair proto.InternalMessageInfo

func (m *HeaderPair) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *HeaderPair) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type WafHttpRequest struct {
	// Types that are valid to be assigned to Content:
	//	*WafHttpRequest_HeadersAndFirstChunk
	//	*WafHttpRequest_NextBodyChunk
	Content              isWafHttpRequest_Content `protobuf_oneof:"content"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *WafHttpRequest) Reset()         { *m = WafHttpRequest{} }
func (m *WafHttpRequest) String() string { return proto.CompactTextString(m) }
func (*WafHttpRequest) ProtoMessage()    {}
func (*WafHttpRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{1}
}
func (m *WafHttpRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WafHttpRequest.Unmarshal(m, b)
}
func (m *WafHttpRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WafHttpRequest.Marshal(b, m, deterministic)
}
func (dst *WafHttpRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WafHttpRequest.Merge(dst, src)
}
func (m *WafHttpRequest) XXX_Size() int {
	return xxx_messageInfo_WafHttpRequest.Size(m)
}
func (m *WafHttpRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_WafHttpRequest.DiscardUnknown(m)
}

var xxx_messageInfo_WafHttpRequest proto.InternalMessageInfo

type isWafHttpRequest_Content interface {
	isWafHttpRequest_Content()
}

type WafHttpRequest_HeadersAndFirstChunk struct {
	HeadersAndFirstChunk *HeadersAndFirstChunk `protobuf:"bytes,1,opt,name=headersAndFirstChunk,proto3,oneof"`
}

type WafHttpRequest_NextBodyChunk struct {
	NextBodyChunk *NextBodyChunk `protobuf:"bytes,2,opt,name=nextBodyChunk,proto3,oneof"`
}

func (*WafHttpRequest_HeadersAndFirstChunk) isWafHttpRequest_Content() {}

func (*WafHttpRequest_NextBodyChunk) isWafHttpRequest_Content() {}

func (m *WafHttpRequest) GetContent() isWafHttpRequest_Content {
	if m != nil {
		return m.Content
	}
	return nil
}

func (m *WafHttpRequest) GetHeadersAndFirstChunk() *HeadersAndFirstChunk {
	if x, ok := m.GetContent().(*WafHttpRequest_HeadersAndFirstChunk); ok {
		return x.HeadersAndFirstChunk
	}
	return nil
}

func (m *WafHttpRequest) GetNextBodyChunk() *NextBodyChunk {
	if x, ok := m.GetContent().(*WafHttpRequest_NextBodyChunk); ok {
		return x.NextBodyChunk
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*WafHttpRequest) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _WafHttpRequest_OneofMarshaler, _WafHttpRequest_OneofUnmarshaler, _WafHttpRequest_OneofSizer, []interface{}{
		(*WafHttpRequest_HeadersAndFirstChunk)(nil),
		(*WafHttpRequest_NextBodyChunk)(nil),
	}
}

func _WafHttpRequest_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*WafHttpRequest)
	// content
	switch x := m.Content.(type) {
	case *WafHttpRequest_HeadersAndFirstChunk:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.HeadersAndFirstChunk); err != nil {
			return err
		}
	case *WafHttpRequest_NextBodyChunk:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.NextBodyChunk); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("WafHttpRequest.Content has unexpected type %T", x)
	}
	return nil
}

func _WafHttpRequest_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*WafHttpRequest)
	switch tag {
	case 1: // content.headersAndFirstChunk
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(HeadersAndFirstChunk)
		err := b.DecodeMessage(msg)
		m.Content = &WafHttpRequest_HeadersAndFirstChunk{msg}
		return true, err
	case 2: // content.nextBodyChunk
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(NextBodyChunk)
		err := b.DecodeMessage(msg)
		m.Content = &WafHttpRequest_NextBodyChunk{msg}
		return true, err
	default:
		return false, nil
	}
}

func _WafHttpRequest_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*WafHttpRequest)
	// content
	switch x := m.Content.(type) {
	case *WafHttpRequest_HeadersAndFirstChunk:
		s := proto.Size(x.HeadersAndFirstChunk)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *WafHttpRequest_NextBodyChunk:
		s := proto.Size(x.NextBodyChunk)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type HeadersAndFirstChunk struct {
	ConfigID             string        `protobuf:"bytes,7,opt,name=configID,proto3" json:"configID,omitempty"`
	Method               string        `protobuf:"bytes,1,opt,name=method,proto3" json:"method,omitempty"`
	Uri                  string        `protobuf:"bytes,2,opt,name=uri,proto3" json:"uri,omitempty"`
	Headers              []*HeaderPair `protobuf:"bytes,3,rep,name=headers,proto3" json:"headers,omitempty"`
	FirstBodyChunk       []byte        `protobuf:"bytes,4,opt,name=firstBodyChunk,proto3" json:"firstBodyChunk,omitempty"`
	MoreBodyChunks       bool          `protobuf:"varint,5,opt,name=moreBodyChunks,proto3" json:"moreBodyChunks,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *HeadersAndFirstChunk) Reset()         { *m = HeadersAndFirstChunk{} }
func (m *HeadersAndFirstChunk) String() string { return proto.CompactTextString(m) }
func (*HeadersAndFirstChunk) ProtoMessage()    {}
func (*HeadersAndFirstChunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{2}
}
func (m *HeadersAndFirstChunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HeadersAndFirstChunk.Unmarshal(m, b)
}
func (m *HeadersAndFirstChunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HeadersAndFirstChunk.Marshal(b, m, deterministic)
}
func (dst *HeadersAndFirstChunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HeadersAndFirstChunk.Merge(dst, src)
}
func (m *HeadersAndFirstChunk) XXX_Size() int {
	return xxx_messageInfo_HeadersAndFirstChunk.Size(m)
}
func (m *HeadersAndFirstChunk) XXX_DiscardUnknown() {
	xxx_messageInfo_HeadersAndFirstChunk.DiscardUnknown(m)
}

var xxx_messageInfo_HeadersAndFirstChunk proto.InternalMessageInfo

func (m *HeadersAndFirstChunk) GetConfigID() string {
	if m != nil {
		return m.ConfigID
	}
	return ""
}

func (m *HeadersAndFirstChunk) GetMethod() string {
	if m != nil {
		return m.Method
	}
	return ""
}

func (m *HeadersAndFirstChunk) GetUri() string {
	if m != nil {
		return m.Uri
	}
	return ""
}

func (m *HeadersAndFirstChunk) GetHeaders() []*HeaderPair {
	if m != nil {
		return m.Headers
	}
	return nil
}

func (m *HeadersAndFirstChunk) GetFirstBodyChunk() []byte {
	if m != nil {
		return m.FirstBodyChunk
	}
	return nil
}

func (m *HeadersAndFirstChunk) GetMoreBodyChunks() bool {
	if m != nil {
		return m.MoreBodyChunks
	}
	return false
}

type NextBodyChunk struct {
	BodyChunk            []byte   `protobuf:"bytes,1,opt,name=bodyChunk,proto3" json:"bodyChunk,omitempty"`
	MoreBodyChunks       bool     `protobuf:"varint,2,opt,name=moreBodyChunks,proto3" json:"moreBodyChunks,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NextBodyChunk) Reset()         { *m = NextBodyChunk{} }
func (m *NextBodyChunk) String() string { return proto.CompactTextString(m) }
func (*NextBodyChunk) ProtoMessage()    {}
func (*NextBodyChunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{3}
}
func (m *NextBodyChunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NextBodyChunk.Unmarshal(m, b)
}
func (m *NextBodyChunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NextBodyChunk.Marshal(b, m, deterministic)
}
func (dst *NextBodyChunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NextBodyChunk.Merge(dst, src)
}
func (m *NextBodyChunk) XXX_Size() int {
	return xxx_messageInfo_NextBodyChunk.Size(m)
}
func (m *NextBodyChunk) XXX_DiscardUnknown() {
	xxx_messageInfo_NextBodyChunk.DiscardUnknown(m)
}

var xxx_messageInfo_NextBodyChunk proto.InternalMessageInfo

func (m *NextBodyChunk) GetBodyChunk() []byte {
	if m != nil {
		return m.BodyChunk
	}
	return nil
}

func (m *NextBodyChunk) GetMoreBodyChunks() bool {
	if m != nil {
		return m.MoreBodyChunks
	}
	return false
}

type WafDecision struct {
	Allow                bool     `protobuf:"varint,1,opt,name=allow,proto3" json:"allow,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WafDecision) Reset()         { *m = WafDecision{} }
func (m *WafDecision) String() string { return proto.CompactTextString(m) }
func (*WafDecision) ProtoMessage()    {}
func (*WafDecision) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{4}
}
func (m *WafDecision) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WafDecision.Unmarshal(m, b)
}
func (m *WafDecision) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WafDecision.Marshal(b, m, deterministic)
}
func (dst *WafDecision) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WafDecision.Merge(dst, src)
}
func (m *WafDecision) XXX_Size() int {
	return xxx_messageInfo_WafDecision.Size(m)
}
func (m *WafDecision) XXX_DiscardUnknown() {
	xxx_messageInfo_WafDecision.DiscardUnknown(m)
}

var xxx_messageInfo_WafDecision proto.InternalMessageInfo

func (m *WafDecision) GetAllow() bool {
	if m != nil {
		return m.Allow
	}
	return false
}

type WAFConfig struct {
	ConfigVersion        int32           `protobuf:"varint,1,opt,name=configVersion,proto3" json:"configVersion,omitempty"`
	PolicyConfigs        []*PolicyConfig `protobuf:"bytes,2,rep,name=policyConfigs,proto3" json:"policyConfigs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *WAFConfig) Reset()         { *m = WAFConfig{} }
func (m *WAFConfig) String() string { return proto.CompactTextString(m) }
func (*WAFConfig) ProtoMessage()    {}
func (*WAFConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{5}
}
func (m *WAFConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WAFConfig.Unmarshal(m, b)
}
func (m *WAFConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WAFConfig.Marshal(b, m, deterministic)
}
func (dst *WAFConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WAFConfig.Merge(dst, src)
}
func (m *WAFConfig) XXX_Size() int {
	return xxx_messageInfo_WAFConfig.Size(m)
}
func (m *WAFConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_WAFConfig.DiscardUnknown(m)
}

var xxx_messageInfo_WAFConfig proto.InternalMessageInfo

func (m *WAFConfig) GetConfigVersion() int32 {
	if m != nil {
		return m.ConfigVersion
	}
	return 0
}

func (m *WAFConfig) GetPolicyConfigs() []*PolicyConfig {
	if m != nil {
		return m.PolicyConfigs
	}
	return nil
}

type PolicyConfig struct {
	ConfigID             string              `protobuf:"bytes,1,opt,name=configID,proto3" json:"configID,omitempty"`
	SecRuleConfig        *SecRuleConfig      `protobuf:"bytes,2,opt,name=secRuleConfig,proto3" json:"secRuleConfig,omitempty"`
	GeoDBConfig          *GeoDBConfig        `protobuf:"bytes,3,opt,name=geoDBConfig,proto3" json:"geoDBConfig,omitempty"`
	IpReputationConfig   *IPReputationConfig `protobuf:"bytes,4,opt,name=ipReputationConfig,proto3" json:"ipReputationConfig,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *PolicyConfig) Reset()         { *m = PolicyConfig{} }
func (m *PolicyConfig) String() string { return proto.CompactTextString(m) }
func (*PolicyConfig) ProtoMessage()    {}
func (*PolicyConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{6}
}
func (m *PolicyConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PolicyConfig.Unmarshal(m, b)
}
func (m *PolicyConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PolicyConfig.Marshal(b, m, deterministic)
}
func (dst *PolicyConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PolicyConfig.Merge(dst, src)
}
func (m *PolicyConfig) XXX_Size() int {
	return xxx_messageInfo_PolicyConfig.Size(m)
}
func (m *PolicyConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_PolicyConfig.DiscardUnknown(m)
}

var xxx_messageInfo_PolicyConfig proto.InternalMessageInfo

func (m *PolicyConfig) GetConfigID() string {
	if m != nil {
		return m.ConfigID
	}
	return ""
}

func (m *PolicyConfig) GetSecRuleConfig() *SecRuleConfig {
	if m != nil {
		return m.SecRuleConfig
	}
	return nil
}

func (m *PolicyConfig) GetGeoDBConfig() *GeoDBConfig {
	if m != nil {
		return m.GeoDBConfig
	}
	return nil
}

func (m *PolicyConfig) GetIpReputationConfig() *IPReputationConfig {
	if m != nil {
		return m.IpReputationConfig
	}
	return nil
}

type SecRuleConfig struct {
	Enabled              bool     `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	RuleSetId            string   `protobuf:"bytes,2,opt,name=ruleSetId,proto3" json:"ruleSetId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecRuleConfig) Reset()         { *m = SecRuleConfig{} }
func (m *SecRuleConfig) String() string { return proto.CompactTextString(m) }
func (*SecRuleConfig) ProtoMessage()    {}
func (*SecRuleConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{7}
}
func (m *SecRuleConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SecRuleConfig.Unmarshal(m, b)
}
func (m *SecRuleConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SecRuleConfig.Marshal(b, m, deterministic)
}
func (dst *SecRuleConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecRuleConfig.Merge(dst, src)
}
func (m *SecRuleConfig) XXX_Size() int {
	return xxx_messageInfo_SecRuleConfig.Size(m)
}
func (m *SecRuleConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_SecRuleConfig.DiscardUnknown(m)
}

var xxx_messageInfo_SecRuleConfig proto.InternalMessageInfo

func (m *SecRuleConfig) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

func (m *SecRuleConfig) GetRuleSetId() string {
	if m != nil {
		return m.RuleSetId
	}
	return ""
}

type GeoDBConfig struct {
	Enabled              bool     `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GeoDBConfig) Reset()         { *m = GeoDBConfig{} }
func (m *GeoDBConfig) String() string { return proto.CompactTextString(m) }
func (*GeoDBConfig) ProtoMessage()    {}
func (*GeoDBConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{8}
}
func (m *GeoDBConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GeoDBConfig.Unmarshal(m, b)
}
func (m *GeoDBConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GeoDBConfig.Marshal(b, m, deterministic)
}
func (dst *GeoDBConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GeoDBConfig.Merge(dst, src)
}
func (m *GeoDBConfig) XXX_Size() int {
	return xxx_messageInfo_GeoDBConfig.Size(m)
}
func (m *GeoDBConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_GeoDBConfig.DiscardUnknown(m)
}

var xxx_messageInfo_GeoDBConfig proto.InternalMessageInfo

func (m *GeoDBConfig) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

type IPReputationConfig struct {
	Enabled              bool     `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *IPReputationConfig) Reset()         { *m = IPReputationConfig{} }
func (m *IPReputationConfig) String() string { return proto.CompactTextString(m) }
func (*IPReputationConfig) ProtoMessage()    {}
func (*IPReputationConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{9}
}
func (m *IPReputationConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IPReputationConfig.Unmarshal(m, b)
}
func (m *IPReputationConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IPReputationConfig.Marshal(b, m, deterministic)
}
func (dst *IPReputationConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IPReputationConfig.Merge(dst, src)
}
func (m *IPReputationConfig) XXX_Size() int {
	return xxx_messageInfo_IPReputationConfig.Size(m)
}
func (m *IPReputationConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_IPReputationConfig.DiscardUnknown(m)
}

var xxx_messageInfo_IPReputationConfig proto.InternalMessageInfo

func (m *IPReputationConfig) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

type PutConfigResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PutConfigResponse) Reset()         { *m = PutConfigResponse{} }
func (m *PutConfigResponse) String() string { return proto.CompactTextString(m) }
func (*PutConfigResponse) ProtoMessage()    {}
func (*PutConfigResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{10}
}
func (m *PutConfigResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PutConfigResponse.Unmarshal(m, b)
}
func (m *PutConfigResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PutConfigResponse.Marshal(b, m, deterministic)
}
func (dst *PutConfigResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PutConfigResponse.Merge(dst, src)
}
func (m *PutConfigResponse) XXX_Size() int {
	return xxx_messageInfo_PutConfigResponse.Size(m)
}
func (m *PutConfigResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PutConfigResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PutConfigResponse proto.InternalMessageInfo

type WAFConfigVersion struct {
	ConfigVersion        int32    `protobuf:"varint,1,opt,name=configVersion,proto3" json:"configVersion,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WAFConfigVersion) Reset()         { *m = WAFConfigVersion{} }
func (m *WAFConfigVersion) String() string { return proto.CompactTextString(m) }
func (*WAFConfigVersion) ProtoMessage()    {}
func (*WAFConfigVersion) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{11}
}
func (m *WAFConfigVersion) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WAFConfigVersion.Unmarshal(m, b)
}
func (m *WAFConfigVersion) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WAFConfigVersion.Marshal(b, m, deterministic)
}
func (dst *WAFConfigVersion) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WAFConfigVersion.Merge(dst, src)
}
func (m *WAFConfigVersion) XXX_Size() int {
	return xxx_messageInfo_WAFConfigVersion.Size(m)
}
func (m *WAFConfigVersion) XXX_DiscardUnknown() {
	xxx_messageInfo_WAFConfigVersion.DiscardUnknown(m)
}

var xxx_messageInfo_WAFConfigVersion proto.InternalMessageInfo

func (m *WAFConfigVersion) GetConfigVersion() int32 {
	if m != nil {
		return m.ConfigVersion
	}
	return 0
}

type DisPoseConfigResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DisPoseConfigResponse) Reset()         { *m = DisPoseConfigResponse{} }
func (m *DisPoseConfigResponse) String() string { return proto.CompactTextString(m) }
func (*DisPoseConfigResponse) ProtoMessage()    {}
func (*DisPoseConfigResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_waf_23bda0e66b1371e8, []int{12}
}
func (m *DisPoseConfigResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DisPoseConfigResponse.Unmarshal(m, b)
}
func (m *DisPoseConfigResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DisPoseConfigResponse.Marshal(b, m, deterministic)
}
func (dst *DisPoseConfigResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DisPoseConfigResponse.Merge(dst, src)
}
func (m *DisPoseConfigResponse) XXX_Size() int {
	return xxx_messageInfo_DisPoseConfigResponse.Size(m)
}
func (m *DisPoseConfigResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DisPoseConfigResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DisPoseConfigResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*HeaderPair)(nil), "wafservice.HeaderPair")
	proto.RegisterType((*WafHttpRequest)(nil), "wafservice.WafHttpRequest")
	proto.RegisterType((*HeadersAndFirstChunk)(nil), "wafservice.HeadersAndFirstChunk")
	proto.RegisterType((*NextBodyChunk)(nil), "wafservice.NextBodyChunk")
	proto.RegisterType((*WafDecision)(nil), "wafservice.WafDecision")
	proto.RegisterType((*WAFConfig)(nil), "wafservice.WAFConfig")
	proto.RegisterType((*PolicyConfig)(nil), "wafservice.PolicyConfig")
	proto.RegisterType((*SecRuleConfig)(nil), "wafservice.SecRuleConfig")
	proto.RegisterType((*GeoDBConfig)(nil), "wafservice.GeoDBConfig")
	proto.RegisterType((*IPReputationConfig)(nil), "wafservice.IPReputationConfig")
	proto.RegisterType((*PutConfigResponse)(nil), "wafservice.PutConfigResponse")
	proto.RegisterType((*WAFConfigVersion)(nil), "wafservice.WAFConfigVersion")
	proto.RegisterType((*DisPoseConfigResponse)(nil), "wafservice.DisPoseConfigResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// WafServiceClient is the client API for WafService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type WafServiceClient interface {
	EvalRequest(ctx context.Context, opts ...grpc.CallOption) (WafService_EvalRequestClient, error)
	PutConfig(ctx context.Context, in *WAFConfig, opts ...grpc.CallOption) (*PutConfigResponse, error)
	DisposeConfig(ctx context.Context, in *WAFConfigVersion, opts ...grpc.CallOption) (*DisPoseConfigResponse, error)
}

type wafServiceClient struct {
	cc *grpc.ClientConn
}

func NewWafServiceClient(cc *grpc.ClientConn) WafServiceClient {
	return &wafServiceClient{cc}
}

func (c *wafServiceClient) EvalRequest(ctx context.Context, opts ...grpc.CallOption) (WafService_EvalRequestClient, error) {
	stream, err := c.cc.NewStream(ctx, &_WafService_serviceDesc.Streams[0], "/wafservice.WafService/EvalRequest", opts...)
	if err != nil {
		return nil, err
	}
	x := &wafServiceEvalRequestClient{stream}
	return x, nil
}

type WafService_EvalRequestClient interface {
	Send(*WafHttpRequest) error
	CloseAndRecv() (*WafDecision, error)
	grpc.ClientStream
}

type wafServiceEvalRequestClient struct {
	grpc.ClientStream
}

func (x *wafServiceEvalRequestClient) Send(m *WafHttpRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *wafServiceEvalRequestClient) CloseAndRecv() (*WafDecision, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(WafDecision)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *wafServiceClient) PutConfig(ctx context.Context, in *WAFConfig, opts ...grpc.CallOption) (*PutConfigResponse, error) {
	out := new(PutConfigResponse)
	err := c.cc.Invoke(ctx, "/wafservice.WafService/PutConfig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wafServiceClient) DisposeConfig(ctx context.Context, in *WAFConfigVersion, opts ...grpc.CallOption) (*DisPoseConfigResponse, error) {
	out := new(DisPoseConfigResponse)
	err := c.cc.Invoke(ctx, "/wafservice.WafService/DisposeConfig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WafServiceServer is the server API for WafService service.
type WafServiceServer interface {
	EvalRequest(WafService_EvalRequestServer) error
	PutConfig(context.Context, *WAFConfig) (*PutConfigResponse, error)
	DisposeConfig(context.Context, *WAFConfigVersion) (*DisPoseConfigResponse, error)
}

func RegisterWafServiceServer(s *grpc.Server, srv WafServiceServer) {
	s.RegisterService(&_WafService_serviceDesc, srv)
}

func _WafService_EvalRequest_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(WafServiceServer).EvalRequest(&wafServiceEvalRequestServer{stream})
}

type WafService_EvalRequestServer interface {
	SendAndClose(*WafDecision) error
	Recv() (*WafHttpRequest, error)
	grpc.ServerStream
}

type wafServiceEvalRequestServer struct {
	grpc.ServerStream
}

func (x *wafServiceEvalRequestServer) SendAndClose(m *WafDecision) error {
	return x.ServerStream.SendMsg(m)
}

func (x *wafServiceEvalRequestServer) Recv() (*WafHttpRequest, error) {
	m := new(WafHttpRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _WafService_PutConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WAFConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WafServiceServer).PutConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wafservice.WafService/PutConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WafServiceServer).PutConfig(ctx, req.(*WAFConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _WafService_DisposeConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WAFConfigVersion)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WafServiceServer).DisposeConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wafservice.WafService/DisposeConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WafServiceServer).DisposeConfig(ctx, req.(*WAFConfigVersion))
	}
	return interceptor(ctx, in, info, handler)
}

var _WafService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "wafservice.WafService",
	HandlerType: (*WafServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PutConfig",
			Handler:    _WafService_PutConfig_Handler,
		},
		{
			MethodName: "DisposeConfig",
			Handler:    _WafService_DisposeConfig_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "EvalRequest",
			Handler:       _WafService_EvalRequest_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "waf.proto",
}

func init() { proto.RegisterFile("waf.proto", fileDescriptor_waf_23bda0e66b1371e8) }

var fileDescriptor_waf_23bda0e66b1371e8 = []byte{
	// 617 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x54, 0x5d, 0x53, 0xd3, 0x40,
	0x14, 0x6d, 0x28, 0x50, 0x7a, 0x4b, 0x18, 0x5c, 0xf9, 0x88, 0x1d, 0x74, 0xea, 0xea, 0x68, 0x9f,
	0x3a, 0x0e, 0xfa, 0xa0, 0x2f, 0x3a, 0x40, 0x85, 0xf2, 0xc2, 0x74, 0x96, 0x91, 0x3e, 0x2f, 0xed,
	0x0d, 0xec, 0x10, 0xb2, 0x21, 0xbb, 0x01, 0xf9, 0x63, 0xfe, 0x1c, 0xff, 0x81, 0xaf, 0x3e, 0x3b,
	0xd9, 0xa4, 0xe9, 0xa6, 0x8d, 0x8e, 0x6f, 0xb9, 0x77, 0xcf, 0x3d, 0xb9, 0xe7, 0xec, 0x99, 0x85,
	0xe6, 0x03, 0xf7, 0x7b, 0x51, 0x2c, 0xb5, 0x24, 0xf0, 0xc0, 0x7d, 0x85, 0xf1, 0xbd, 0x18, 0x23,
	0xfd, 0x00, 0x30, 0x40, 0x3e, 0xc1, 0x78, 0xc8, 0x45, 0x4c, 0x36, 0xa1, 0x7e, 0x83, 0x8f, 0x9e,
	0xd3, 0x71, 0xba, 0x4d, 0x96, 0x7e, 0x92, 0x2d, 0x58, 0xb9, 0xe7, 0x41, 0x82, 0xde, 0x92, 0xe9,
	0x65, 0x05, 0xfd, 0xe1, 0xc0, 0xc6, 0x88, 0xfb, 0x03, 0xad, 0x23, 0x86, 0x77, 0x09, 0x2a, 0x4d,
	0x2e, 0x60, 0xeb, 0xda, 0x10, 0xa9, 0x83, 0x70, 0x72, 0x2c, 0x62, 0xa5, 0x8f, 0xae, 0x93, 0xf0,
	0xc6, 0x70, 0xb5, 0xf6, 0x3b, 0xbd, 0xd9, 0x3f, 0x7b, 0x83, 0x0a, 0xdc, 0xa0, 0xc6, 0x2a, 0xe7,
	0xc9, 0x01, 0xb8, 0x21, 0x7e, 0xd7, 0x87, 0x72, 0xf2, 0x98, 0x11, 0x2e, 0x19, 0xc2, 0x67, 0x36,
	0xe1, 0x99, 0x0d, 0x18, 0xd4, 0x58, 0x79, 0xe2, 0xb0, 0x09, 0x8d, 0xb1, 0x0c, 0x35, 0x86, 0x9a,
	0xfe, 0x74, 0x60, 0xab, 0xea, 0xf7, 0xa4, 0x0d, 0x6b, 0x63, 0x19, 0xfa, 0xe2, 0xea, 0xb4, 0xef,
	0x35, 0x8c, 0xd4, 0xa2, 0x26, 0x3b, 0xb0, 0x7a, 0x8b, 0xfa, 0x5a, 0x4e, 0x72, 0x63, 0xf2, 0x2a,
	0x75, 0x2b, 0x89, 0x45, 0xee, 0x4c, 0xfa, 0x49, 0xde, 0x41, 0x23, 0x17, 0xe1, 0xd5, 0x3b, 0xf5,
	0x6e, 0x6b, 0x7f, 0x67, 0x51, 0x77, 0x6a, 0x34, 0x9b, 0xc2, 0xc8, 0x1b, 0xd8, 0xf0, 0xd3, 0x2d,
	0x66, 0xfa, 0x96, 0x3b, 0x4e, 0x77, 0x9d, 0xcd, 0x75, 0x53, 0xdc, 0xad, 0x8c, 0xb1, 0x68, 0x28,
	0x6f, 0xa5, 0xe3, 0x74, 0xd7, 0xd8, 0x5c, 0x97, 0x7e, 0x03, 0xb7, 0xe4, 0x06, 0xd9, 0x83, 0xe6,
	0x65, 0xc1, 0xed, 0x18, 0xee, 0x59, 0xa3, 0x82, 0x76, 0xa9, 0x92, 0xf6, 0x15, 0xb4, 0x46, 0xdc,
	0xef, 0xe3, 0x58, 0x28, 0x21, 0xc3, 0x34, 0x15, 0x3c, 0x08, 0xe4, 0x83, 0x21, 0x5c, 0x63, 0x59,
	0x41, 0xef, 0xa0, 0x39, 0x3a, 0x38, 0x3e, 0x32, 0xb6, 0x91, 0xd7, 0xe0, 0x66, 0x06, 0x5e, 0x60,
	0x9c, 0xce, 0x18, 0xe8, 0x0a, 0x2b, 0x37, 0xc9, 0x67, 0x70, 0x23, 0x19, 0x88, 0xf1, 0x63, 0x36,
	0x95, 0xfe, 0x3e, 0xb5, 0xcd, 0xb3, 0x6d, 0x1b, 0x5a, 0x00, 0x56, 0x86, 0xd3, 0xdf, 0x0e, 0xac,
	0xdb, 0xe7, 0xa5, 0x7b, 0x74, 0xe6, 0xee, 0xf1, 0x0b, 0xb8, 0x0a, 0xc7, 0x2c, 0x09, 0x30, 0x03,
	0x57, 0x45, 0xe9, 0xdc, 0x06, 0xb0, 0x32, 0x9e, 0x7c, 0x82, 0xd6, 0x15, 0xca, 0xfe, 0x61, 0x3e,
	0x5e, 0x37, 0xe3, 0xbb, 0xf6, 0xf8, 0xc9, 0xec, 0x98, 0xd9, 0x58, 0x72, 0x06, 0x44, 0x44, 0x0c,
	0xa3, 0x44, 0x73, 0x2d, 0x64, 0x98, 0x33, 0x2c, 0x1b, 0x86, 0x17, 0x36, 0xc3, 0xe9, 0x70, 0x1e,
	0xc5, 0x2a, 0x26, 0xe9, 0x09, 0xb8, 0xa5, 0x55, 0x89, 0x07, 0x0d, 0x0c, 0xf9, 0x65, 0x80, 0x93,
	0xfc, 0x52, 0xa6, 0x65, 0x9a, 0x80, 0x38, 0x09, 0xf0, 0x1c, 0xf5, 0xe9, 0x24, 0x0f, 0xeb, 0xac,
	0x41, 0xdf, 0x42, 0xcb, 0x5a, 0xfa, 0xef, 0x34, 0xb4, 0x07, 0x64, 0x71, 0xb7, 0x7f, 0xe0, 0x9f,
	0xc2, 0x93, 0x61, 0xa2, 0x73, 0x09, 0xa8, 0x22, 0x19, 0x2a, 0xa4, 0x1f, 0x61, 0xb3, 0x88, 0xc8,
	0x34, 0x03, 0xff, 0x95, 0x14, 0xba, 0x0b, 0xdb, 0x7d, 0xa1, 0x86, 0x52, 0x61, 0x99, 0x72, 0xff,
	0x97, 0x03, 0x30, 0xe2, 0xfe, 0x79, 0xe6, 0x1f, 0x39, 0x86, 0xd6, 0xd7, 0x7b, 0x1e, 0x4c, 0x9f,
	0xa5, 0xb6, 0xed, 0x6d, 0xf9, 0xc9, 0x6a, 0xef, 0xce, 0x9d, 0x4d, 0xe3, 0x4d, 0x6b, 0x5d, 0x87,
	0x1c, 0x41, 0xb3, 0x58, 0x9f, 0x6c, 0x97, 0x90, 0x53, 0x01, 0xed, 0xe7, 0xa5, 0x98, 0x2e, 0x88,
	0xad, 0x11, 0x06, 0x6e, 0x5f, 0xa8, 0xa8, 0x58, 0x9a, 0xec, 0x55, 0x12, 0xe5, 0x1a, 0xdb, 0x2f,
	0xed, 0xd3, 0x4a, 0xb5, 0xb4, 0x76, 0xb9, 0x6a, 0x1e, 0xf1, 0xf7, 0x7f, 0x02, 0x00, 0x00, 0xff,
	0xff, 0x48, 0x7f, 0x1c, 0xac, 0xd1, 0x05, 0x00, 0x00,
}
