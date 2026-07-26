package zip

import "core:mem"
import "core:os"
import "core:time/datetime"

ZipArchive :: struct {
	file:      ^os.File,
	reader:    ^Reader,
	allocator: mem.Allocator,
	entries:   [dynamic]ZipEntry,
	comment:   string,
}

ZipEntry :: struct {
	name:              string,
	compressed_size:   i64,
	uncompressed_size: i64,
	local_offset:      u64,
	modified_datetime: datetime.DateTime,
	crc32:             u32,
	method:            CompressioMethod,
	is_directory:      bool,
	is_encrypted:      bool,
}

CompressioMethod :: enum u16le {
	STORE   = 0,
	DEFLATE = 8,
	AEX     = 99,
}

Error :: enum {
	None,

	// General Errors
	Invalid_Argument,
	OS_Error,
	Corrupted_Data,
	Not_Supported,
	Datetime_Error,
	Entry_Not_Found,
	Deflate_Error,

	// Reader Errors
	Short_Read,
	Invalid_Offset,
	Invalid_EOCD_Signature,
	EOCD_Signature_Not_Found,
	Invalid_Comment_Length,
}

Magic :: enum u32le {
	EOCD          = 0x06054b50,
	ZIP64_EOCD    = 0x06064B50,
	ZIP64_LOCATOR = 0x07064B50,
	CDH           = 0x02014b50,
	LFH           = 0x04034b50,
}

Platform :: enum i64 {
	MS_DOS  = 0,
	UNIX    = 3,
	WINDOWS = 10,
}


// Private types. Used only for reading the raw binary headers according
// to the spec


@(private)
_EocdHdr :: struct #packed {
	magic:                             u32le, // end of central dir signature
	disk_number:                       u16le, // number of this disk
	starting_disk:                     u16le, // number of the disk with the start of the central directory
	total_central_records_disk:        u16le, // total number of entries in the central directory on this disk
	total_central_records:             u16le, // total number of entries in the central directory
	total_size_central_directory:      u32le, // size of the central directory
	offset_to_central_directory_start: u32le, // offset of start of central directory with respect to  the starting disk number
	comment_length:                    u16le, // .ZIP file comment length
}

@(private)
_Zip64EocdHdr :: struct #packed {
	magic:                   u32le, // zip64 end of central dir signature
	size:                    i64le, // size of zip64 end of central directory record
	version:                 u16le, // version made by
	version_needed:          u16le, // version needed to extract
	disk_num:                u32le, // number of this disk
	disk_start:              u32le, //  number of the disk with the start of the central directory
	entries_count_this_disk: i64le, // total number of entries in the central directory on this disk
	entries_total:           i64le, // total number of entries in the central directory
	size_cd:                 i64le, // size of the central directory
	offset_cd:               i64le, // offset of start of central directory with respect to the starting disk number
}

@(private)
_Zip64_Locator :: struct #packed {
	magic:       u32le, // zip64 end of central dir locator signature
	disk_start:  u32le, // number of the disk with the start of the zip64 end of central directory
	offset_eocd: u64le, // relative offset of the zip64 end of central directory record
	total_disks: u32le, // total number of disks
}

@(private)
_LfHdr :: struct #packed {
	magic:           u32le,
	version_needed:  u16le,
	flags:           u16le,
	comp_method:     CompressioMethod,
	mod_time:        MsDosTime,
	mod_date:        MsDosDate,
	crc32:           u32le,
	comp_size:       u32le,
	uncomp_size:     u32le,
	file_name_len:   u16le,
	extra_field_len: u16le,
}

MsDosTime :: bit_field u16le {
	second: u32le | 5,
	minute: u32le | 6,
	hour:   u32le | 5,
}

MsDosDate :: bit_field u16le {
	day:   u32le | 5,
	month: u32le | 4,
	year:  u32le | 7,
}


@(private)
_CdHdr :: struct #packed {
	magic:               u32le,
	version:             u16le,
	version_needed:      u16le,
	flag:                u16le,
	compression_method:  CompressioMethod,
	last_modified_time:  MsDosTime,
	last_modified_date:  MsDosDate,
	crc:                 u32le,
	compressed_size:     u32le,
	uncompressed_size:   u32le,
	file_name_length:    u16le,
	extra_field_length:  u16le,
	file_comment_length: u16le,
	file_start_disk:     u16le,
	internal_attrib:     u16le,
	external_attrib:     u32le,
	local_hdr_offset:    u32le,
}

@(private)
ExtraFieldType :: enum {
	Zip64 = 0x0001,
}

@(private)
ExtraField :: struct {
	id:   ExtraFieldType,
	size: u64,
	data: []u8,
}

U32_MAX :: 0xFFFFFFFF
U16_MAX :: 0xFFFF
