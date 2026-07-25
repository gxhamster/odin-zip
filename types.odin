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

