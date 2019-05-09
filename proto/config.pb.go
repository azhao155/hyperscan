// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

package azwaf

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ServiceID struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ServiceID) Reset()         { *m = ServiceID{} }
func (m *ServiceID) String() string { return proto.CompactTextString(m) }
func (*ServiceID) ProtoMessage()    {}
func (*ServiceID) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_677190b94289d902, []int{0}
}
func (m *ServiceID) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceID.Unmarshal(m, b)
}
func (m *ServiceID) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceID.Marshal(b, m, deterministic)
}
func (dst *ServiceID) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceID.Merge(dst, src)
}
func (m *ServiceID) XXX_Size() int {
	return xxx_messageInfo_ServiceID.Size(m)
}
func (m *ServiceID) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceID.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceID proto.InternalMessageInfo

func (m *ServiceID) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

//
// This is an example service that we will be using as a place holder till we
// light up a service on AzWaf.
type ServiceDummy struct {
	Id                   *ServiceID `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *ServiceDummy) Reset()         { *m = ServiceDummy{} }
func (m *ServiceDummy) String() string { return proto.CompactTextString(m) }
func (*ServiceDummy) ProtoMessage()    {}
func (*ServiceDummy) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_677190b94289d902, []int{1}
}
func (m *ServiceDummy) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceDummy.Unmarshal(m, b)
}
func (m *ServiceDummy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceDummy.Marshal(b, m, deterministic)
}
func (dst *ServiceDummy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceDummy.Merge(dst, src)
}
func (m *ServiceDummy) XXX_Size() int {
	return xxx_messageInfo_ServiceDummy.Size(m)
}
func (m *ServiceDummy) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceDummy.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceDummy proto.InternalMessageInfo

func (m *ServiceDummy) GetId() *ServiceID {
	if m != nil {
		return m.Id
	}
	return nil
}

type Services struct {
	Dummies              []*ServiceDummy `protobuf:"bytes,1,rep,name=dummies,proto3" json:"dummies,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *Services) Reset()         { *m = Services{} }
func (m *Services) String() string { return proto.CompactTextString(m) }
func (*Services) ProtoMessage()    {}
func (*Services) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_677190b94289d902, []int{2}
}
func (m *Services) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Services.Unmarshal(m, b)
}
func (m *Services) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Services.Marshal(b, m, deterministic)
}
func (dst *Services) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Services.Merge(dst, src)
}
func (m *Services) XXX_Size() int {
	return xxx_messageInfo_Services.Size(m)
}
func (m *Services) XXX_DiscardUnknown() {
	xxx_messageInfo_Services.DiscardUnknown(m)
}

var xxx_messageInfo_Services proto.InternalMessageInfo

func (m *Services) GetDummies() []*ServiceDummy {
	if m != nil {
		return m.Dummies
	}
	return nil
}

type Path struct {
	Prefix               string       `protobuf:"bytes,1,opt,name=prefix,proto3" json:"prefix,omitempty"`
	Services             []*ServiceID `protobuf:"bytes,2,rep,name=services,proto3" json:"services,omitempty"`
	Paths                []*Path      `protobuf:"bytes,3,rep,name=paths,proto3" json:"paths,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *Path) Reset()         { *m = Path{} }
func (m *Path) String() string { return proto.CompactTextString(m) }
func (*Path) ProtoMessage()    {}
func (*Path) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_677190b94289d902, []int{3}
}
func (m *Path) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Path.Unmarshal(m, b)
}
func (m *Path) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Path.Marshal(b, m, deterministic)
}
func (dst *Path) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Path.Merge(dst, src)
}
func (m *Path) XXX_Size() int {
	return xxx_messageInfo_Path.Size(m)
}
func (m *Path) XXX_DiscardUnknown() {
	xxx_messageInfo_Path.DiscardUnknown(m)
}

var xxx_messageInfo_Path proto.InternalMessageInfo

func (m *Path) GetPrefix() string {
	if m != nil {
		return m.Prefix
	}
	return ""
}

func (m *Path) GetServices() []*ServiceID {
	if m != nil {
		return m.Services
	}
	return nil
}

func (m *Path) GetPaths() []*Path {
	if m != nil {
		return m.Paths
	}
	return nil
}

type Site struct {
	Domain               string       `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	Services             []*ServiceID `protobuf:"bytes,2,rep,name=services,proto3" json:"services,omitempty"`
	Paths                []*Path      `protobuf:"bytes,3,rep,name=paths,proto3" json:"paths,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *Site) Reset()         { *m = Site{} }
func (m *Site) String() string { return proto.CompactTextString(m) }
func (*Site) ProtoMessage()    {}
func (*Site) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_677190b94289d902, []int{4}
}
func (m *Site) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Site.Unmarshal(m, b)
}
func (m *Site) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Site.Marshal(b, m, deterministic)
}
func (dst *Site) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Site.Merge(dst, src)
}
func (m *Site) XXX_Size() int {
	return xxx_messageInfo_Site.Size(m)
}
func (m *Site) XXX_DiscardUnknown() {
	xxx_messageInfo_Site.DiscardUnknown(m)
}

var xxx_messageInfo_Site proto.InternalMessageInfo

func (m *Site) GetDomain() string {
	if m != nil {
		return m.Domain
	}
	return ""
}

func (m *Site) GetServices() []*ServiceID {
	if m != nil {
		return m.Services
	}
	return nil
}

func (m *Site) GetPaths() []*Path {
	if m != nil {
		return m.Paths
	}
	return nil
}

//
// A representation of AzWaf configuration.
type Config struct {
	Services             *Services `protobuf:"bytes,1,opt,name=services,proto3" json:"services,omitempty"`
	Sites                []*Site   `protobuf:"bytes,2,rep,name=sites,proto3" json:"sites,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *Config) Reset()         { *m = Config{} }
func (m *Config) String() string { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()    {}
func (*Config) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_677190b94289d902, []int{5}
}
func (m *Config) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Config.Unmarshal(m, b)
}
func (m *Config) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Config.Marshal(b, m, deterministic)
}
func (dst *Config) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Config.Merge(dst, src)
}
func (m *Config) XXX_Size() int {
	return xxx_messageInfo_Config.Size(m)
}
func (m *Config) XXX_DiscardUnknown() {
	xxx_messageInfo_Config.DiscardUnknown(m)
}

var xxx_messageInfo_Config proto.InternalMessageInfo

func (m *Config) GetServices() *Services {
	if m != nil {
		return m.Services
	}
	return nil
}

func (m *Config) GetSites() []*Site {
	if m != nil {
		return m.Sites
	}
	return nil
}

func init() {
	proto.RegisterType((*ServiceID)(nil), "azwaf.ServiceID")
	proto.RegisterType((*ServiceDummy)(nil), "azwaf.ServiceDummy")
	proto.RegisterType((*Services)(nil), "azwaf.Services")
	proto.RegisterType((*Path)(nil), "azwaf.Path")
	proto.RegisterType((*Site)(nil), "azwaf.Site")
	proto.RegisterType((*Config)(nil), "azwaf.Config")
}

func init() { proto.RegisterFile("config.proto", fileDescriptor_config_677190b94289d902) }

var fileDescriptor_config_677190b94289d902 = []byte{
	// 252 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x91, 0xcf, 0x4f, 0x83, 0x40,
	0x10, 0x85, 0x03, 0x6d, 0xb1, 0x1d, 0x9a, 0x68, 0xc6, 0xc4, 0x70, 0x13, 0x39, 0x35, 0x51, 0x89,
	0xa9, 0x27, 0xcf, 0xf6, 0xe2, 0xcd, 0x6c, 0x2f, 0x5e, 0xd7, 0xb2, 0xd8, 0x39, 0x2c, 0x4b, 0xd8,
	0xc5, 0x5f, 0x7f, 0xbd, 0x61, 0x58, 0x88, 0xc4, 0xab, 0x37, 0x86, 0xf9, 0xf8, 0xde, 0x0b, 0x03,
	0xeb, 0x83, 0xa9, 0x4a, 0x7a, 0xcb, 0xeb, 0xc6, 0x38, 0x83, 0x0b, 0xf9, 0xfd, 0x21, 0xcb, 0xec,
	0x12, 0x56, 0x7b, 0xd5, 0xbc, 0xd3, 0x41, 0x3d, 0xed, 0x10, 0x61, 0x5e, 0x49, 0xad, 0x92, 0x20,
	0x0d, 0x36, 0x2b, 0xc1, 0xcf, 0xd9, 0x1d, 0xac, 0x3d, 0xb0, 0x6b, 0xb5, 0xfe, 0xc2, 0x14, 0x42,
	0x2a, 0x98, 0x88, 0xb7, 0x67, 0x39, 0x4b, 0xf2, 0xd1, 0x20, 0x42, 0x2a, 0xb2, 0x07, 0x58, 0xfa,
	0x17, 0x16, 0x6f, 0xe1, 0xa4, 0x68, 0xb5, 0x26, 0x65, 0x93, 0x20, 0x9d, 0x6d, 0xe2, 0xed, 0xf9,
	0xf4, 0x13, 0x76, 0x8a, 0x81, 0xc9, 0x0c, 0xcc, 0x9f, 0xa5, 0x3b, 0xe2, 0x05, 0x44, 0x75, 0xa3,
	0x4a, 0xfa, 0xf4, 0x55, 0xfc, 0x84, 0x37, 0xb0, 0xb4, 0x5e, 0x9d, 0x84, 0xec, 0xfb, 0x5b, 0x61,
	0x24, 0xf0, 0x0a, 0x16, 0xb5, 0x74, 0x47, 0x9b, 0xcc, 0x18, 0x8d, 0x3d, 0xda, 0x25, 0x88, 0x7e,
	0xd3, 0x05, 0xee, 0xc9, 0xa9, 0x2e, 0xb0, 0x30, 0x5a, 0x52, 0x35, 0x04, 0xf6, 0xd3, 0xff, 0x07,
	0xbe, 0x40, 0xf4, 0xc8, 0x67, 0xc0, 0xeb, 0x5f, 0xea, 0xfe, 0x77, 0x9e, 0x4e, 0xd5, 0x76, 0x6a,
	0xb6, 0xe4, 0xc6, 0x12, 0x83, 0xb9, 0xeb, 0x2e, 0xfa, 0xcd, 0x6b, 0xc4, 0x77, 0xbd, 0xff, 0x09,
	0x00, 0x00, 0xff, 0xff, 0x18, 0x3d, 0x76, 0xf8, 0xe7, 0x01, 0x00, 0x00,
}
