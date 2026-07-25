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
