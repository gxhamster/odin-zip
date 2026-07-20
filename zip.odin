package zip

import "core:compress"

/*
  === References ===
  - https://libzip.org/documentation
  - https://github.com/open-xml-templating/pizzip/blob/master/docs/ZIP%20spec.txt
  - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT (Official spec)
  - https://github.com/odin-lang/Odin/blob/master/core/compress/zlib/zlib.odin (odin zlib)
*/

LocalFileHeader :: struct {}

CentralDirectoryFlags :: enum {}

CompressioMethod :: enum u16le {
	No_Compression = 0,
	Shrunk         = 1,
	Factor_1       = 2,
	Factor_2       = 3,
	Factor_3       = 4,
	Factor_4       = 5,
	Imploded       = 6,
	Tokenized      = 7,
	Deflate        = 8,
	Deflate64      = 9,
	IBM_Terse_Old  = 10,
	Reserved1      = 11,
	Bzip2          = 12,
	Reserved2      = 13,
	LZMA           = 14,
	Reserved3      = 15,
	Cmpsc          = 16,
	Reserved4      = 17,
	IBM_Terse_New  = 18,
	IBM_LZ77       = 19,
	Deprecated     = 20,
	Zstd           = 93,
	MP3            = 94,
	XZ             = 95,
	JPEG           = 96,
	WavPack        = 97,
	PPMd_Ver_1     = 98,
	AE_x           = 99,
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

CentralDirectoryFileHeader :: struct #packed {
	magic:               u32le,
	version:             u16le,
	version_needed:      u16le,
	flag:                bit_set[CentralDirectoryFlags],
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
  // File name
  // Extra field
  // File comment
}


EOCD_MAGIC :: 0x06054b50
EOCD_HEADER_SIZE_BYTES :: 22
EndOfCentralDirectoryRecord :: struct #packed {
	magic:                             u32le,
	disk_number:                       u16le,
	starting_disk:                     u16le,
	total_central_records_disk:        u16le,
	total_central_records:             u16le,
	total_size_central_directory:      u32le,
	offset_to_central_directory_start: u32le,
	comment_length:                    u16le,
	// Rest of this header will be the comment which is of variable size (2 bytes max)
	// 65,536 + 22 (EOCD header) = 65557
	// From the end read this much into a buffer and search backwards until we find the EOCD
	// signature, then we can read the EOCD header contents.
}

#assert(size_of(EndOfCentralDirectoryRecord) == EOCD_HEADER_SIZE_BYTES)


load :: proc() {
  
}